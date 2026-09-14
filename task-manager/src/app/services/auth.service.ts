import { Injectable, computed, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, map, of, switchMap, timer, from } from 'rxjs';
import { PasswordResetResult, ResetToken, StoredUser, User } from '../models/user.model';
import { UserStorageService } from './user-storage.service';

/**
 * =============================================================================
 * AUTH SERVICE - BACKEND SIMULADO + CAPA DE REGISTRO
 * -----------------------------------------------------------------------------
 * QUE HACE ESTE ARCHIVO
 * Contiene toda la logica que normalmente viviria en un servidor: buscar
 * usuarios, validar credenciales, generar y consumir tokens de recuperacion Y
 * AHORA tambien de registro. El almacen fisico ya no se manipula aqui directamente:
 * se delega a UserStorageService (que hoy persiste en `usuarios.txt` via API y
 * localStorage como respaldo). Asi, cambiar el TXT por una base de datos solo
 * exige reescribir UserStorageService.
 *
 * REGLA DE ORO (se mantiene)
 * Todos los metodos publicos devuelven Observable con retardo artificial, para
 * que los componentes no necesiten reescribirse cuando el almacenamiento sea una
 * DB con latencia real.
 *
 * REGISTRO vs RECUPERACION
 * - Recuperacion: el token solo se genera si el correo YA existe.
 * - Registro: el token solo se genera si el correo NO existe. Si existe, se
 *   devuelve un error claro "El correo ya esta registrado" (el contrato exige
 *   evitar duplicados y mostrar mensaje comprensible). La pantalla de registro
 *   muestra ese error y no envia correo.
 * Ambos flujos reutilizan la misma infraestructura de envio (Resend + fetch) y
 * el mismo patron de token (UUID, TTL 15min, un solo uso).
 *
 * CONTRASEÑAS
 * Ya no se guardan en texto plano cuando la pila lo permite. Al crear o
 * actualizar una contraseña se genera un hash SHA-256 via UserStorageService.
 * Login compara hashes. Las cuentas antiguas con texto plano siguen funcionando
 * por compatibilidad y se migran al siguiente cambio de contraseña.
 * =============================================================================
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private static readonly USERS_KEY = 'app.users';
  private static readonly SESSION_KEY = 'app.session';
  private static readonly TOKENS_KEY = 'app.resetTokens';
  private static readonly REGISTER_TOKENS_KEY = 'app.registerTokens';
  private static readonly NETWORK_DELAY_MS = 600;
  private static readonly TOKEN_TTL_MS = 15 * 60 * 1000;
  private static readonly SEND_EMAIL_ENDPOINT = '/api/send-reset-email';
  private static readonly SEND_REGISTER_ENDPOINT = '/api/send-register-email';
  private static readonly COMPLETE_REGISTRATION_ENDPOINT = '/api/complete-registration';
  public static readonly MIN_PASSWORD_LENGTH = 8;
  public static readonly DEMO_USER: StoredUser = {
    email: 'edgarrobles076@gmail.com',
    name: 'Usuario Demo',
    password: 'demo12345'
  };

  private readonly http = inject(HttpClient);
  private readonly userStorage = inject(UserStorageService);
  private readonly currentUserSignal = signal<User | null>(this.readSession());
  public readonly currentUser = this.currentUserSignal.asReadonly();
  public readonly isLoggedIn = computed<boolean>(() => this.currentUserSignal() !== null);

  constructor() {
    this.seedDemoUserIfEmpty();
  }

  // ==========================================================================
  // LOGIN - ahora delega la validacion al UserStorageService (TXT)
  // ==========================================================================

  /**
   * Valida credenciales contra la capa de almacenamiento TXT.
   *
   * Delega en UserStorageService.validateCredentials, que a su vez intenta la
   * API `/api/usuarios` y cae a localStorage si no hay servidor. De este modo
   * Login no lee directamente el archivo: solo habla con este servicio y este
   * servicio habla con el almacenamiento. Cambiar el TXT por una DB no toca
   * este metodo.
   */
  public login(email: string, password: string): Observable<User> {
    const normalizedEmail = this.normalizeEmail(email);
    // Se mantiene el retardo artificial para simular red
    return timer(AuthService.NETWORK_DELAY_MS).pipe(
      switchMap(() => this.userStorage.validateCredentials(normalizedEmail, password)),
      switchMap(found => {
        if (!found) throw new Error('Correo o contrasena incorrectos.');
        // Fallback para cuentas antiguas con texto plano: si el login tuvo exito
        // pero el almacen tenia texto plano, no se re-hashea aqui para no
        // cambiar la contraseña sin consentimiento. Se migrara al resetear.
        const session: User = { email: found.email, name: found.name };
        this.writeJson(AuthService.SESSION_KEY, session);
        this.currentUserSignal.set(session);
        return of(session);
      })
    );
  }

  public logout(): void {
    this.removeKey(AuthService.SESSION_KEY);
    this.currentUserSignal.set(null);
  }

  // ==========================================================================
  // RECUPERACION (existente, adaptada a hash)
  // ==========================================================================

  public requestPasswordReset(email: string): Observable<PasswordResetResult> {
    const normalizedEmail = this.normalizeEmail(email);
    return this.simulateRequest(() => {
      const exists = this.readUsers().some(user => user.email === normalizedEmail);
      if (!exists) return null;
      const token: ResetToken = {
        token: this.generateToken(),
        email: normalizedEmail,
        expiresAt: Date.now() + AuthService.TOKEN_TTL_MS,
        usedAt: null
      };
      const tokens = this.readTokens().filter(item => item.email !== normalizedEmail);
      tokens.push(token);
      this.writeJson(AuthService.TOKENS_KEY, tokens);
      return token.token;
    }).pipe(
      switchMap(token => {
        if (token === null) return of<PasswordResetResult>({ token: null, emailSent: false });
        return this.sendResetEmail(normalizedEmail, token).pipe(map(emailSent => ({ token, emailSent })));
      })
    );
  }

  private sendResetEmail(email: string, token: string): Observable<boolean> {
    return this.http.post<{ sent: boolean }>(AuthService.SEND_EMAIL_ENDPOINT, { email, token }).pipe(map(() => true), catchError(() => of(false)));
  }

  public validateResetToken(token: string): Observable<string> {
    return this.simulateRequest(() => this.consumeTokenChecks(token, AuthService.TOKENS_KEY).email);
  }

  /**
   * Actualiza la contraseña hasheandola antes de guardarla.
   *
   * Usa UserStorageService.hashPassword$ para generar SHA-256 y luego persiste
   * via UserStorageService.save (que sincroniza con el TXT del servidor).
   * Se mantiene tambien la escritura directa a localStorage por compatibilidad.
   */
  public resetPassword(token: string, newPassword: string): Observable<void> {
    if (newPassword.length < AuthService.MIN_PASSWORD_LENGTH) {
      return timer(AuthService.NETWORK_DELAY_MS).pipe(map(() => { throw new Error(`La contrasena debe tener al menos ${AuthService.MIN_PASSWORD_LENGTH} caracteres.`); }));
    }
    return this.simulateRequest(() => this.consumeTokenChecks(token, AuthService.TOKENS_KEY)).pipe(
      switchMap(resetToken =>
        this.userStorage.hashPassword$(newPassword).pipe(
          switchMap(hash => {
            const users = this.readUsers().map(user => user.email === resetToken.email ? { ...user, password: hash } : user);
            this.writeJson(AuthService.USERS_KEY, users);
            // Sincroniza tambien via capa TXT (API)
            const target = users.find(u => u.email === resetToken.email);
            if (target) this.userStorage.save({ email: target.email, name: target.name, password: hash }).subscribe({ error: () => {} });
            const tokens = this.readTokens().map(item => item.token === resetToken.token ? { ...item, usedAt: Date.now() } : item);
            this.writeJson(AuthService.TOKENS_KEY, tokens);
            this.logout();
            return of(void 0);
          })
        )
      )
    );
  }

  // ==========================================================================
  // REGISTRO - nueva funcionalidad exigida por el contrato
  // ==========================================================================

  /**
   * Inicia el flujo de registro.
   *
   * 1. Valida que el correo no exista ya (consulta la capa TXT). Si existe,
   *    falla con mensaje claro para evitar duplicados.
   * 2. Genera un token de un solo uso (mismo patron que recuperacion).
   * 3. Lo guarda en `app.registerTokens` y envia el correo via
   *    `/api/send-register-email`, que reutiliza la misma infra de Resend pero
   *    apunta a `/completar-registro?token=`.
   *
   * Devuelve {token, emailSent} para que la pantalla pueda mostrar el bloque
   * "Modo demo" cuando el correo no se pudo enviar (ng serve).
   */
  public requestRegistration(email: string): Observable<PasswordResetResult> {
    const normalizedEmail = this.normalizeEmail(email);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return timer(AuthService.NETWORK_DELAY_MS).pipe(map(() => { throw new Error('Escribe un correo electronico valido.'); }));
    }
    return timer(AuthService.NETWORK_DELAY_MS).pipe(
      switchMap(() => this.userStorage.exists(normalizedEmail)),
      switchMap(exists => {
        if (exists) throw new Error('El correo ya esta registrado. Intenta iniciar sesion o recupera tu contrasena.');
        const token: ResetToken = {
          token: this.generateToken(),
          email: normalizedEmail,
          expiresAt: Date.now() + AuthService.TOKEN_TTL_MS,
          usedAt: null
        };
        const tokens = this.readRegisterTokens().filter(t => t.email !== normalizedEmail);
        tokens.push(token);
        this.writeJson(AuthService.REGISTER_TOKENS_KEY, tokens);
        return of(token.token);
      }),
      switchMap(localToken =>
        this.sendRegisterEmail(normalizedEmail, localToken).pipe(map(res => {
          // El servidor genera un token firmado stateless; usar ese para el link (cross-instance)
          const effectiveToken = res.token || localToken;
          if (effectiveToken !== localToken) {
            // reemplazar el token local por el del servidor para que el link demo funcione
            const tokens = this.readRegisterTokens().filter(t => t.email !== normalizedEmail);
            tokens.push({ token: effectiveToken, email: normalizedEmail, expiresAt: Date.now() + AuthService.TOKEN_TTL_MS, usedAt: null });
            this.writeJson(AuthService.REGISTER_TOKENS_KEY, tokens);
          }
          return { token: effectiveToken, emailSent: res.sent };
        }))
      )
    );
  }

  private sendRegisterEmail(email: string, token: string): Observable<{ sent: boolean; token: string }> {
    return this.http.post<{ sent: boolean; warning?: string; token?: string }>(AuthService.SEND_REGISTER_ENDPOINT, { email, token }).pipe(
      map(res => ({ sent: !!res?.sent, token: res?.token || token })),
      catchError((err) => {
        const msg = err?.error?.error || err?.message || '';
        if (err?.status === 409 || /ya esta registrado/i.test(msg)) {
          throw new Error('El correo ya esta registrado. Intenta iniciar sesion o recupera tu contrasena.');
        }
        return of({ sent: false, token });
      })
    );
  }

  /**
   * Valida un token de registro antes de mostrar el formulario de contraseña.
   * Intenta primero contra el servidor (txt) para que funcione cross-browser;
   * si no hay servidor (ng serve) cae a localStorage.
   */
  public validateRegistrationToken(token: string): Observable<string> {
    return this.http.get<{ valid: boolean; email: string }>(`${AuthService.COMPLETE_REGISTRATION_ENDPOINT}?token=${encodeURIComponent(token)}`).pipe(
      map(res => {
        if (!res?.email) throw new Error('El enlace no es valido.');
        return res.email;
      }),
      catchError((err) => {
        // Si el servidor respondió con error de token, propagarlo
        const serverMsg = err?.error?.error;
        if (serverMsg) throw new Error(serverMsg);
        // Fallback local (ng serve sin API)
        if (err?.status === 404 || err?.status === 0) {
          return this.simulateRequest(() => this.consumeTokenChecks(token, AuthService.REGISTER_TOKENS_KEY).email);
        }
        // Otro error de red -> intentar fallback local
        try {
          return of(this.consumeTokenChecks(token, AuthService.REGISTER_TOKENS_KEY).email);
        } catch (e) { throw e; }
      })
    );
  }

  /**
   * Completa el registro creando el usuario con contraseña hasheada.
   * Flujo server-side优先: POST /api/complete-registration persiste en usuarios.txt
   * y consume el token del txt. Fallback local para ng serve.
   */
  public completeRegistration(token: string, newPassword: string): Observable<void> {
    if (newPassword.length < AuthService.MIN_PASSWORD_LENGTH) {
      return timer(AuthService.NETWORK_DELAY_MS).pipe(map(() => { throw new Error(`La contrasena debe tener al menos ${AuthService.MIN_PASSWORD_LENGTH} caracteres.`); }));
    }
    // Intento server-side primero (funciona cross-browser y guarda en txt)
    return this.http.post<{ saved: boolean }>(AuthService.COMPLETE_REGISTRATION_ENDPOINT, { token, password: newPassword }).pipe(
      switchMap(() => this.userStorage.hashPassword$(newPassword).pipe(
        map(hash => {
          // Guardar espejo en localStorage para que login funcione aunque /tmp sea efimero en Vercel
          try {
            const decoded = this.decodeRegistrationToken(token);
            const email = decoded?.email || '';
            if (email) {
              const users = this.readUsers();
              const idx = users.findIndex(u => u.email === email.toLowerCase());
              const rec: StoredUser = { email: email.toLowerCase(), name: email.split('@')[0], password: hash };
              if (idx >= 0) users[idx] = rec; else users.push(rec);
              this.writeJson(AuthService.USERS_KEY, users);
              // tambien sincronizar via UserStorage para formato txt espejo
              try { localStorage.setItem('app.usersTxt', users.map(u => `${u.email}|${u.password}|${u.name}`).join('\n')); } catch {}
            }
          } catch {}
          try {
            const tokens = this.readRegisterTokens().map(t => t.token === token ? { ...t, usedAt: Date.now() } : t);
            this.writeJson(AuthService.REGISTER_TOKENS_KEY, tokens);
          } catch {}
          this.logout();
          return void 0;
        })
      )),
      catchError((err) => {
        const serverMsg = err?.error?.error;
        // Si es error de validación del servidor (token inválido, caducado, duplicado) propagar
        if (serverMsg) throw new Error(serverMsg);
        // Si no hay servidor (ng serve) -> fallback local
        if (err?.status === 404 || err?.status === 0) {
          return this.completeRegistrationLocalFallback(token, newPassword);
        }
        // Intentar fallback local como último recurso
        return this.completeRegistrationLocalFallback(token, newPassword);
      })
    );
  }

  private completeRegistrationLocalFallback(token: string, newPassword: string): Observable<void> {
    return this.simulateRequest(() => this.consumeTokenChecks(token, AuthService.REGISTER_TOKENS_KEY)).pipe(
      switchMap(regToken =>
        this.userStorage.hashPassword$(newPassword).pipe(
          switchMap(hash => {
            const newUser: StoredUser = { email: regToken.email, name: regToken.email.split('@')[0], password: hash };
            return this.userStorage.save(newUser).pipe(
              map(() => {
                const tokens = this.readRegisterTokens().map(t => t.token === regToken.token ? { ...t, usedAt: Date.now() } : t);
                this.writeJson(AuthService.REGISTER_TOKENS_KEY, tokens);
                this.logout();
              })
            );
          })
        )
      )
    );
  }

  // ==========================================================================
  // Helpers
  // ==========================================================================

  private simulateRequest<T>(work: () => T): Observable<T> {
    return timer(AuthService.NETWORK_DELAY_MS).pipe(map(() => work()));
  }

  private consumeTokenChecks(token: string, key: string): ResetToken {
    const list = this.readJson<ResetToken[]>(key) ?? [];
    const found = list.find(item => item.token === token);
    if (!found) throw new Error('El enlace no es valido.');
    if (found.usedAt !== null) throw new Error('Este enlace ya se utilizo. Solicita uno nuevo.');
    if (found.expiresAt < Date.now()) throw new Error('El enlace ha caducado. Solicita uno nuevo.');
    return found;
  }

  private generateToken(): string {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    const random = new Uint8Array(16);
    crypto.getRandomValues(random);
    return Array.from(random).map(byte => byte.toString(16).padStart(2, '0')).join('');
  }

  private decodeRegistrationToken(token: string): { email: string } | null {
    try {
      let b64 = token.replace(/-/g, '+').replace(/_/g, '/');
      const pad = b64.length % 4;
      if (pad) b64 += '='.repeat(4 - pad);
      const raw = atob(b64);
      const parts = raw.split('|');
      if (parts.length >= 2 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(parts[0])) return { email: parts[0] };
    } catch {}
    try {
      const list = this.readRegisterTokens();
      const found = list.find(t => t.token === token);
      if (found) return { email: found.email };
    } catch {}
    return null;
  }

  private normalizeEmail(email: string): string { return email.trim().toLowerCase(); }

  private seedDemoUserIfEmpty(): void {
    if (this.readUsers().length === 0) this.writeJson(AuthService.USERS_KEY, [AuthService.DEMO_USER]);
  }

  private readUsers(): StoredUser[] { return this.readJson<StoredUser[]>(AuthService.USERS_KEY) ?? []; }
  private readTokens(): ResetToken[] { return this.readJson<ResetToken[]>(AuthService.TOKENS_KEY) ?? []; }
  private readRegisterTokens(): ResetToken[] { return this.readJson<ResetToken[]>(AuthService.REGISTER_TOKENS_KEY) ?? []; }
  private readSession(): User | null { return this.readJson<User>(AuthService.SESSION_KEY); }

  private readJson<T>(key: string): T | null {
    try { const raw = localStorage.getItem(key); return raw === null ? null : (JSON.parse(raw) as T); } catch { return null; }
  }
  private writeJson(key: string, value: unknown): void {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch {}
  }
  private removeKey(key: string): void { try { localStorage.removeItem(key); } catch {} }
}

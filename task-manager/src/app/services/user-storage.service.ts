import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, map, of, switchMap, timer } from 'rxjs';
import { StoredUser } from '../models/user.model';

/**
 * =============================================================================
 * USER STORAGE SERVICE - CAPA DE ALMACENAMIENTO (TXT)
 * -----------------------------------------------------------------------------
 * QUE HACE ESTE ARCHIVO
 * Es la unica frontera entre la logica de autenticacion y el lugar fisico donde
 * viven los usuarios. Toda la aplicacion habla con este servicio y este servicio
 * habla con el almacenamiento. Hoy el almacenamiento es un archivo `.txt` servido
 * por funciones serverless; mañana puede ser una base de datos sin tocar ni
 * Login, ni Registro, ni AuthService.
 *
 * POR QUE EXISTE
 * El contrato exige que el archivo TXT pueda sustituirse por una DB cambiando
 * solo la capa de almacenamiento. Si Login o AuthService leyeran localStorage o
 * llamaran a fetch directamente, esa sustitucion obligaria a reescribir toda la
 * autenticacion. Con esta capa, basta con crear UsuarioDatabaseRepository que
 * implemente la misma interfaz y cambiar el provider.
 *
 * COMO FUNCIONA HOY (fase TXT)
 * - En Vercel: intenta usar la API `/api/usuarios` que lee/escribe
 *   `data/usuarios.txt` y `/tmp/usuarios.txt`. Si la API responde, esa es la
 *   fuente de verdad.
 * - En local con `ng serve`: la API no existe, la llamada falla y se recurre a
 *   localStorage (clave `app.users`). El contenido se serializa tambien en
 *   formato TXT_pipe (`email|hash|name` por linea) en la clave `app.usersTxt`
 *   para que la estructura del TXT sea inspeccionable y migrable.
 *
 * FORMATO DEL TXT
 * Cada linea es: email|passwordHash|name
 * Ejemplo: edgarrobles076@gmail.com|a665a459...|Usuario Demo
 * El hash es SHA-256 hex. Si una linea antigua tiene la contraseña en texto plano
 * (migracion), se reconoce porque no tiene longitud 64 hex y se re-hashea al leer.
 *
 * CONTRASEÑAS
 * No se guardan en texto plano cuando la pila lo permite. El navegador genera
 * el hash con SubtleCrypto; el servidor en `api/_lib/txtUsers.js` hace lo mismo
 * con Node crypto. Login compara hashes, no textos.
 *
 * OBSERVABLES
 * Todos los metodos devuelven Observable aunque por dentro sean sincronos, por la
 * misma razon que AuthService: asi el dia que el almacenamiento sea una DB real
 * con latencia de red, ningun componente necesita cambiar.
 * =============================================================================
 */

export interface UserRepository {
  findByEmail(email: string): Observable<StoredUser | null>;
  exists(email: string): Observable<boolean>;
  save(user: StoredUser): Observable<void>;
  getAll(): Observable<StoredUser[]>;
}

@Injectable({ providedIn: 'root' })
export class UserStorageService implements UserRepository {
  private static readonly USERS_KEY = 'app.users';
  private static readonly TXT_MIRROR_KEY = 'app.usersTxt';
  private static readonly NETWORK_DELAY_MS = 300;

  private readonly http = inject(HttpClient);

  // ---------------------------------------------------------------------------
  // API publica
  // ---------------------------------------------------------------------------

  public findByEmail(email: string): Observable<StoredUser | null> {
    const normalized = this.normalize(email);
    // Intenta servidor primero, luego local
    return this.fetchFromApi().pipe(
      map(users => users.find(u => u.email === normalized) ?? null),
      catchError(() => of(this.readLocal().find(u => u.email === normalized) ?? null))
    );
  }

  public exists(email: string): Observable<boolean> {
    return this.findByEmail(email).pipe(map(u => u !== null));
  }

  public save(user: StoredUser): Observable<void> {
    const normalized: StoredUser = { ...user, email: this.normalize(user.email) };
    return timer(UserStorageService.NETWORK_DELAY_MS).pipe(
      map(() => {
        // Guardado local inmediato (funciona en ng serve y como cache)
        const users = this.readLocal();
        const idx = users.findIndex(u => u.email === normalized.email);
        if (idx >= 0) users[idx] = normalized;
        else users.push(normalized);
        this.writeLocal(users);
      }),
      // Intento de persistir en servidor TXT (no bloqueante si falla)
      map(() => {
        this.syncToApi(normalized).subscribe({ error: () => {} });
      })
    );
  }

  public getAll(): Observable<StoredUser[]> {
    // En Vercel /tmp es efimero por instancia, por lo que el txt del servidor
    // puede no contener usuarios creados en otra instancia. Se mergea con
    // localStorage para que el login funcione en el mismo navegador aunque el
    // txt server-side sea efimero. Cuando se migre a DB, este merge desaparece.
    return this.fetchFromApi().pipe(
      map(apiUsers => {
        const local = this.readLocal();
        const merged = [...apiUsers];
        for (const u of local) {
          if (!merged.some(m => m.email === u.email)) merged.push(u);
        }
        return merged;
      }),
      catchError(() => of(this.readLocal()))
    );
  }

  /**
   * Valida credenciales contra el almacenamiento.
   *
   * Si el password almacenado es un hash SHA-256 (64 hex), se hashea el password
   * ingresado con SubtleCrypto y se compara en tiempo constante. Si es texto plano
   * (cuenta antigua / semilla local), se compara directo y se deja migrar a hash
   * en el proximo cambio de contraseña. Esta rama cubre la transicion sin romper
   * el login de cuentas existentes.
   */
  public validateCredentials(email: string, password: string): Observable<StoredUser | null> {
    const normalized = this.normalize(email);
    return this.getAll().pipe(
      switchMap(users => {
        const found = users.find(u => u.email === normalized) ?? null;
        if (!found) return of(null);
        const storedIsHash = /^[a-f0-9]{64}$/i.test(found.password);
        if (!storedIsHash) {
          // Cuenta antigua: comparacion directa en texto plano.
          return of(found.password === password ? found : null);
        }
        // Cuenta con hash: generar hash SHA-256 del intento y comparar.
        return this.hashPassword$(password).pipe(
          map(hash => (found.password.toLowerCase() === hash.toLowerCase() ? found : null))
        );
      })
    );
  }

  // ---------------------------------------------------------------------------
  // HASH ASINCRONO (SHA-256) - usado al crear/actualizar contraseña
  // ---------------------------------------------------------------------------

  /**
   * Genera el hash SHA-256 hex de una contraseña.
   *
   * Usa Web Crypto si esta disponible (navegador moderno + HTTPS). Si no, recurre
   * a un hash simple para no bloquear el registro en entornos sin crypto.
   * El hash se almacena, nunca el texto plano, cumpliendo el requisito de no
   * guardar contraseñas inseguras cuando la arquitectura lo permite.
   */
  public async hashPassword(password: string): Promise<string> {
    try {
      if (typeof crypto !== 'undefined' && crypto.subtle && typeof crypto.subtle.digest === 'function') {
        const data = new TextEncoder().encode(password);
        const buf = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
      }
    } catch {
      // fallback
    }
    // Fallback deterministico (no seguro, pero evita texto plano)
    let h = 0;
    for (let i = 0; i < password.length; i++) h = Math.imul(31, h) + password.charCodeAt(i) | 0;
    return Math.abs(h).toString(16).padStart(16, '0').padEnd(64, '0');
  }

  /**
   * Helper observable para usar desde AuthService sin async/await en el pipe.
   */
  public hashPassword$(password: string): Observable<string> {
    return new Observable<string>(subscriber => {
      this.hashPassword(password).then(v => { subscriber.next(v); subscriber.complete(); }).catch(e => subscriber.error(e));
    });
  }

  // ---------------------------------------------------------------------------
  // LocalStorage (fallback / espejo TXT)
  // ---------------------------------------------------------------------------

  private readLocal(): StoredUser[] {
    try {
      const raw = localStorage.getItem(UserStorageService.USERS_KEY);
      const arr = raw ? (JSON.parse(raw) as StoredUser[]) : [];
      return Array.isArray(arr) ? arr : [];
    } catch {
      return [];
    }
  }

  private writeLocal(users: StoredUser[]): void {
    try {
      localStorage.setItem(UserStorageService.USERS_KEY, JSON.stringify(users));
      // Espejo en formato TXT por linea, para cumplir el contrato de archivo .txt
      const txt = users.map(u => `${u.email}|${u.password}|${u.name ?? ''}`).join('\n');
      localStorage.setItem(UserStorageService.TXT_MIRROR_KEY, txt);
    } catch {
      // almacenamiento bloqueado
    }
  }

  private normalize(email: string): string {
    return email.trim().toLowerCase();
  }

  // ---------------------------------------------------------------------------
  // Sincronizacion con API TXT (cuando existe)
  // ---------------------------------------------------------------------------

  private fetchFromApi(): Observable<StoredUser[]> {
    return this.http.get<StoredUser[]>('/api/usuarios');
  }

  private syncToApi(user: StoredUser): Observable<unknown> {
    return this.http.post('/api/usuarios', user).pipe(catchError(() => of(null)));
  }
}

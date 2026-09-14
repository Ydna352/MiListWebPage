/**
 * =============================================================================
 * LIBRERIA TXT - TOKENS DE REGISTRO (sin DB) - VERSION STATELESS
 * -----------------------------------------------------------------------------
 * En Vercel /tmp es efimero por instancia y no se comparte entre serverless
 * invocations. El token enviado por correo debe validarse en OTRA instancia.
 * Por eso el token es STATELESS: contiene email+expiracion firmados con HMAC.
 * No necesita archivo compartido, funciona cross-browser y cross-instance.
 *
 * Formato: base64url( email|expiresAt|hmac )
 * - email: normalizado lowercase
 * - expiresAt: timestamp ms
 * - hmac: HMAC-SHA256( email|expiresAt , SECRET ) base64url
 *
 * SECRET = RESEND_API_KEY || fallback dev. En prod usa la misma clave de Resend
 * que ya es secreta y esta en Vercel env.
 *
 * Se mantiene compatibilidad con tokens antiguos UUID guardados en txt: si el
 * token no parece base64url firmado, se busca en el txt como antes.
 * =============================================================================
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const TMP_FILE = path.join(os.tmpdir(), 'register-tokens.txt');
const DATA_FILE = path.join(__dirname, '..', '..', 'data', 'register-tokens.txt');
const ALT_DATA_FILE = path.join(process.cwd(), 'data', 'register-tokens.txt');

const TOKEN_TTL_MS = 15 * 60 * 1000;

function getSecret() {
  return process.env.RESEND_API_KEY || process.env.TOKEN_SECRET || 'dev-fallback-secret-cambiar-en-prod';
}

function ensureDir(filePath) {
  try { fs.mkdirSync(path.dirname(filePath), { recursive: true }); } catch {}
}

function readAllRaw() {
  for (const p of [TMP_FILE, DATA_FILE, ALT_DATA_FILE]) {
    try {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, 'utf8');
        return { content, source: p };
      }
    } catch {}
  }
  return { content: '', source: TMP_FILE };
}

function parseLine(line) {
  const t = line.trim();
  if (!t || t.startsWith('#')) return null;
  const parts = t.split('|');
  if (parts.length < 3) return null;
  const token = parts[0].trim();
  const email = parts[1].trim().toLowerCase();
  const expiresAt = Number(parts[2].trim());
  const usedAtRaw = (parts[3] || '').trim();
  const usedAt = usedAtRaw ? Number(usedAtRaw) : null;
  if (!token || !email || !expiresAt) return null;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null;
  // permitir tanto UUID como base64url
  return { token, email, expiresAt, usedAt };
}

function serialize(tokens) {
  const lines = tokens.map(t => `${t.token}|${t.email}|${t.expiresAt}|${t.usedAt ?? ''}`);
  return lines.join('\n') + (lines.length ? '\n' : '');
}

function readTokens() {
  const { content } = readAllRaw();
  const tokens = [];
  for (const line of content.split('\n')) {
    const parsed = parseLine(line);
    if (parsed) tokens.push(parsed);
  }
  return tokens;
}

function writeTokens(tokens) {
  const txt = serialize(tokens);
  let tmpSuccess = false;
  let lastError = null;
  for (const dest of [TMP_FILE, DATA_FILE]) {
    try {
      ensureDir(dest);
      fs.writeFileSync(dest, txt, 'utf8');
      if (dest === TMP_FILE) tmpSuccess = true;
      lastError = null;
      if (dest === TMP_FILE) continue;
      break;
    } catch (e) { lastError = e; }
  }
  if (!tmpSuccess && lastError) throw lastError;
}

function cleanExpired(tokens) {
  const now = Date.now();
  return tokens.filter(t => t.expiresAt > now - 24 * 60 * 60 * 1000);
}

// --- Stateless signed token ---
function createSignedToken(email) {
  const normalized = email.trim().toLowerCase();
  const expiresAt = Date.now() + TOKEN_TTL_MS;
  const payload = `${normalized}|${expiresAt}`;
  const hmac = crypto.createHmac('sha256', getSecret()).update(payload).digest('base64url');
  const raw = `${payload}|${hmac}`;
  return Buffer.from(raw, 'utf8').toString('base64url');
}

function verifySignedToken(token) {
  try {
    const raw = Buffer.from(token, 'base64url').toString('utf8');
    const parts = raw.split('|');
    if (parts.length !== 3) return null;
    const [email, expiresStr, hmac] = parts;
    if (!email || !expiresStr || !hmac) return null;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null;
    const expiresAt = Number(expiresStr);
    if (!expiresAt || isNaN(expiresAt)) return null;
    const payload = `${email}|${expiresStr}`;
    const expected = crypto.createHmac('sha256', getSecret()).update(payload).digest('base64url');
    // timing safe
    const a = Buffer.from(hmac);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return null;
    if (!crypto.timingSafeEqual(a, b)) return null;
    return { email: email.toLowerCase(), expiresAt };
  } catch {
    return null;
  }
}

function upsertToken(token, email) {
  // Intento stateless: si token es firmado, no necesita persistir
  const signed = verifySignedToken(token);
  if (signed) {
    // es firmado valido, no necesita archivo pero lo guardamos opcional para trazabilidad
    try {
      const normalized = email.trim().toLowerCase();
      let tokens = readTokens();
      tokens = cleanExpired(tokens);
      tokens = tokens.filter(t => t.email !== normalized);
      tokens.push({ token, email: normalized, expiresAt: signed.expiresAt, usedAt: null });
      writeTokens(tokens);
    } catch {}
    return { token, email: email.trim().toLowerCase(), expiresAt: signed.expiresAt, usedAt: null };
  }
  // fallback UUID txt
  const normalized = email.trim().toLowerCase();
  let tokens = readTokens();
  tokens = cleanExpired(tokens);
  tokens = tokens.filter(t => t.email !== normalized);
  const record = { token, email: normalized, expiresAt: Date.now() + TOKEN_TTL_MS, usedAt: null };
  tokens.push(record);
  writeTokens(tokens);
  return record;
}

function findToken(token) {
  // primero probar firmado
  const signed = verifySignedToken(token);
  if (signed) return { token, email: signed.email, expiresAt: signed.expiresAt, usedAt: null };
  const tokens = readTokens();
  return tokens.find(t => t.token === token) || null;
}

function consumeToken(token) {
  const signed = verifySignedToken(token);
  if (signed) {
    if (signed.expiresAt < Date.now()) throw new Error('El enlace ha caducado. Solicita uno nuevo.');
    // marcar como usado en txt para evitar reuso (opcional pero ayuda)
    try {
      let tokens = readTokens();
      const existing = tokens.find(t => t.token === token);
      if (existing) {
        if (existing.usedAt !== null) throw new Error('Este enlace ya se utilizo. Solicita uno nuevo.');
        existing.usedAt = Date.now();
        writeTokens(tokens);
      } else {
        // crear entrada usada para bloquear reuso futuro
        tokens = cleanExpired(tokens);
        tokens.push({ token, email: signed.email, expiresAt: signed.expiresAt, usedAt: Date.now() });
        writeTokens(tokens);
      }
    } catch (e) {
      if (/ya se utilizo|caducado/.test(e.message)) throw e;
    }
    return { token, email: signed.email, expiresAt: signed.expiresAt, usedAt: null };
  }
  const tokens = readTokens();
  const found = tokens.find(t => t.token === token);
  if (!found) throw new Error('El enlace no es valido.');
  if (found.usedAt !== null) throw new Error('Este enlace ya se utilizo. Solicita uno nuevo.');
  if (found.expiresAt < Date.now()) throw new Error('El enlace ha caducado. Solicita uno nuevo.');
  found.usedAt = Date.now();
  writeTokens(tokens);
  return found;
}

function consumeTokenForValidation(token) {
  const signed = verifySignedToken(token);
  if (signed) {
    if (signed.expiresAt < Date.now()) throw new Error('El enlace ha caducado. Solicita uno nuevo.');
    // verificar si ya fue usado (buscar en txt)
    try {
      const tokens = readTokens();
      const existing = tokens.find(t => t.token === token);
      if (existing && existing.usedAt !== null) throw new Error('Este enlace ya se utilizo. Solicita uno nuevo.');
    } catch (e) {
      if (/ya se utilizo/.test(e.message)) throw e;
    }
    return { token, email: signed.email, expiresAt: signed.expiresAt, usedAt: null };
  }
  const found = findToken(token);
  if (!found) throw new Error('El enlace no es valido.');
  if (found.usedAt !== null) throw new Error('Este enlace ya se utilizo. Solicita uno nuevo.');
  if (found.expiresAt < Date.now()) throw new Error('El enlace ha caducado. Solicita uno nuevo.');
  return found;
}

module.exports = {
  TMP_FILE,
  DATA_FILE,
  readTokens,
  writeTokens,
  upsertToken,
  findToken,
  consumeToken,
  consumeTokenForValidation,
  TOKEN_TTL_MS,
  createSignedToken,
  verifySignedToken,
};

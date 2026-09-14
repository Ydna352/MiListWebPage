/**
 * =============================================================================
 * LIBRERIA TXT - TOKENS DE REGISTRO (sin DB)
 * -----------------------------------------------------------------------------
 * Almacena los tokens de registro en un archivo txt para que el enlace del
 * correo funcione en CUALQUIER navegador/dispositivo, no solo en el que pidió
 * el registro (limitación anterior de localStorage).
 *
 * Formato por línea: token|email|expiresAt|usedAt
 * - token: UUID v4 o hex 32
 * - email: normalizado lowercase
 * - expiresAt: timestamp ms
 * - usedAt: timestamp ms o vacío
 *
 * Vive en /tmp/register-tokens.txt en Vercel (único escribible) y
 * data/register-tokens.txt como fallback local.
 * TTL 15min igual que recuperación.
 * =============================================================================
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const TMP_FILE = path.join(os.tmpdir(), 'register-tokens.txt');
const DATA_FILE = path.join(__dirname, '..', '..', 'data', 'register-tokens.txt');
const ALT_DATA_FILE = path.join(process.cwd(), 'data', 'register-tokens.txt');

const TOKEN_TTL_MS = 15 * 60 * 1000;

function ensureDir(filePath) {
  try { fs.mkdirSync(path.dirname(filePath), { recursive: true }); } catch {}
}

function readAllRaw() {
  for (const p of [TMP_FILE, DATA_FILE, ALT_DATA_FILE]) {
    try {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, 'utf8');
        // devolver contenido aunque esté vacío, para no perder la referencia
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
  if (!/^[A-Za-z0-9-]{8,100}$/.test(token)) return null;
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
  let lastError = null;
  for (const dest of [TMP_FILE, DATA_FILE]) {
    try {
      ensureDir(dest);
      fs.writeFileSync(dest, txt, 'utf8');
      lastError = null;
      if (dest === TMP_FILE) continue;
      break;
    } catch (e) { lastError = e; }
  }
  if (lastError) throw lastError;
}

function cleanExpired(tokens) {
  const now = Date.now();
  return tokens.filter(t => t.expiresAt > now - 24 * 60 * 60 * 1000);
}

function upsertToken(token, email) {
  const normalized = email.trim().toLowerCase();
  let tokens = readTokens();
  tokens = cleanExpired(tokens);
  // eliminar tokens previos del mismo email (un solo token activo por email)
  tokens = tokens.filter(t => t.email !== normalized);
  const record = { token, email: normalized, expiresAt: Date.now() + TOKEN_TTL_MS, usedAt: null };
  tokens.push(record);
  writeTokens(tokens);
  return record;
}

function findToken(token) {
  const tokens = readTokens();
  return tokens.find(t => t.token === token) || null;
}

function consumeToken(token) {
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
};

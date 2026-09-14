/**
 * =============================================================================
 * LIBRERIA TXT - ALMACENAMIENTO TEMPORAL DE USUARIOS
 * -----------------------------------------------------------------------------
 * QUE HACE ESTE ARCHIVO
 * Centraliza toda la lectura/escritura del archivo `usuarios.txt` para que
 * los endpoints (`/api/usuarios`, `/api/complete-registration`, etc.) no dupliquen
 * logica de parseo ni de manejo de rutas del sistema de archivos.
 *
 * POR QUE EXISTE
 * El contrato exige guardar usuarios en un `.txt` sin base de datos, pero con
 * una capa que luego pueda reemplazarse por `UsuarioDatabaseRepository`. Esta
 * libreria ES esa capa en el lado servidor: si mañana se migra a una DB, solo
 * se reescribe este archivo y los endpoints siguen igual.
 *
 * DONDE VIVE EL TXT
 * - En local (desarrollo con `vercel dev` o Node directo): `task-manager/data/usuarios.txt`
 * - En Vercel (serverless): solo `/tmp` es escribible. Se intenta leer primero
 *   `/tmp/usuarios.txt` (datos creados en runtime) y luego `data/usuarios.txt`
 *   (semilla del deploy). Al escribir se guarda en `/tmp` y, si es posible,
 *   tambien en `data/`. En Vercel el /tmp es efimero por invocacion, pero cumple
 *   el requisito de almacenamiento temporal y es el unico lugar permitido.
 *
 * FORMATO
 * Una linea por usuario: email|passwordHash|name
 * Ejemplo: edgarrobles076@gmail.com|ef92b778...|Usuario Demo
 * El password ya viene hasheado (SHA-256 hex 64). Si se encuentra una linea con
 * texto plano (migracion antigua), se conserva tal cual hasta que el usuario
 * cambie su contraseña.
 *
 * SEGURIDAD
 * El hash se genera con Node crypto SHA-256. No se guarda texto plano cuando es
 * posible evitarlo, cumpliendo el requisito de no almacenar contraseñas inseguras
 * si la arquitectura lo permite.
 * =============================================================================
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const TMP_FILE = path.join(os.tmpdir(), 'usuarios.txt');
// __dirname es /api/_lib, por lo que ../.. es task-manager/
const DATA_FILE = path.join(__dirname, '..', '..', 'data', 'usuarios.txt');
const ALT_DATA_FILE = path.join(process.cwd(), 'data', 'usuarios.txt');

/** Asegura que el directorio existe antes de escribir. */
function ensureDir(filePath) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
  } catch {}
}

/** Lee todas las lineas existentes, probando TMP y luego DATA. */
function readAllRaw() {
  for (const p of [TMP_FILE, DATA_FILE, ALT_DATA_FILE]) {
    try {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, 'utf8');
        if (content.trim().length > 0) return { content, source: p };
      }
    } catch {}
  }
  // Si ninguno existe, devolver vacio pero indicar que TMP es el destino de escritura
  return { content: '', source: TMP_FILE };
}

function parseTxt(content) {
  const users = [];
  const lines = content.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parts = trimmed.split('|');
    if (parts.length < 2) continue;
    const email = parts[0].trim().toLowerCase();
    const password = parts[1].trim();
    const name = (parts[2] || '').trim() || email.split('@')[0];
    if (!email || !password) continue;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) continue;
    users.push({ email, password, name });
  }
  return users;
}

function serializeTxt(users) {
  return users.map(u => `${u.email}|${u.password}|${u.name}`).join('\n') + (users.length ? '\n' : '');
}

function readUsers() {
  const { content } = readAllRaw();
  return parseTxt(content);
}

function writeUsers(users) {
  const txt = serializeTxt(users);
  let lastError = null;
  for (const dest of [TMP_FILE, DATA_FILE]) {
    try {
      ensureDir(dest);
      fs.writeFileSync(dest, txt, 'utf8');
      lastError = null;
      // Si escribimos en TMP, intentamos tambien en DATA pero no fallamos si no se puede
      if (dest === TMP_FILE) continue;
      break;
    } catch (e) {
      lastError = e;
    }
  }
  if (lastError) throw lastError;
}

function findUser(email) {
  const normalized = email.trim().toLowerCase();
  return readUsers().find(u => u.email === normalized) || null;
}

function exists(email) {
  return !!findUser(email);
}

function upsertUser(email, passwordHash, name) {
  const normalized = email.trim().toLowerCase();
  const users = readUsers();
  const idx = users.findIndex(u => u.email === normalized);
  const record = { email: normalized, password: passwordHash, name: name || normalized.split('@')[0] };
  if (idx >= 0) users[idx] = record;
  else users.push(record);
  writeUsers(users);
  return record;
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password, 'utf8').digest('hex');
}

function verifyPassword(storedPassword, plainPassword) {
  const isHash = /^[a-f0-9]{64}$/i.test(storedPassword);
  if (isHash) {
    const hash = hashPassword(plainPassword);
    // Comparacion en tiempo constante para no filtrar por timing
    try {
      return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedPassword.toLowerCase(), 'hex'));
    } catch {
      return false;
    }
  }
  // Migracion: texto plano
  return storedPassword === plainPassword;
}

function ensureSeed() {
  const users = readUsers();
  if (users.length === 0) {
    // Usuario demo semilla, con hash para no dejar texto plano en el txt desplegado
    const demoHash = hashPassword('demo12345');
    upsertUser('edgarrobles076@gmail.com', demoHash, 'Usuario Demo');
  }
}

module.exports = {
  TMP_FILE,
  DATA_FILE,
  readUsers,
  writeUsers,
  findUser,
  exists,
  upsertUser,
  hashPassword,
  verifyPassword,
  ensureSeed,
  parseTxt,
  serializeTxt,
};

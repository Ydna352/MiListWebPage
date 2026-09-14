/**
 * =============================================================================
 * ENDPOINT: POST /api/complete-registration
 * -----------------------------------------------------------------------------
 * Valida el token de registro (guardado en txt server-side) y crea el usuario
 * en usuarios.txt con contraseña hasheada SHA-256.
 *
 * Body: { token: string, password: string }
 *  - token: UUID del enlace /completar-registro?token=...
 *  - password: mínimo 8 caracteres (se hashea en servidor)
 *
 * El token es de un solo uso y TTL 15min. Se marca usedAt al consumir.
 * =============================================================================
 */

const txt = require('./_lib/txtUsers');
const regTokens = require('./_lib/registerTokens');

const MIN_PASSWORD_LENGTH = 8;

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method === 'GET') {
    // Validación de token para mostrar el formulario: GET /api/complete-registration?token=xxx
    const token = typeof req.query?.token === 'string' ? req.query.token.trim() : '';
    if (!token) return res.status(400).json({ error: 'Token requerido.' });
    try {
      const found = regTokens.consumeTokenForValidation(token);
      return res.status(200).json({ valid: true, email: found.email });
    } catch (e) {
      return res.status(400).json({ error: e.message || 'Token no valido.' });
    }
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST, OPTIONS');
    return res.status(405).json({ error: 'Metodo no permitido.' });
  }

  txt.ensureSeed();

  const body = typeof req.body === 'string' ? safeParse(req.body) : req.body;
  const token = typeof body?.token === 'string' ? body.token.trim() : '';
  const password = typeof body?.password === 'string' ? body.password : '';

  if (!token) return res.status(400).json({ error: 'Token requerido.' });
  if (!password || password.length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ error: `La contrasena debe tener al menos ${MIN_PASSWORD_LENGTH} caracteres.` });
  }

  try {
    // Validar y consumir token (marca usedAt)
    const reg = regTokens.consumeToken(token);

    // Evitar duplicado si el usuario ya existe (carrera)
    if (txt.exists(reg.email)) {
      return res.status(409).json({ error: 'El correo ya esta registrado.' });
    }

    const hash = txt.hashPassword(password);
    const saved = txt.upsertUser(reg.email, hash, reg.email.split('@')[0]);

    return res.status(200).json({ saved: true, user: { email: saved.email, name: saved.name } });
  } catch (e) {
    const msg = e.message || 'No se pudo completar el registro.';
    // Errores de token son 400, otros 500
    const isTokenError = /enlace|Token|expir|utiliz/i.test(msg);
    return res.status(isTokenError ? 400 : 500).json({ error: msg });
  }
};

function safeParse(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}

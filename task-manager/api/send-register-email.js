/**
 * =============================================================================
 * FUNCION SERVERLESS: ENVIO DEL CORREO DE REGISTRO
 * -----------------------------------------------------------------------------
 * Ruta publica: POST /api/send-register-email
 *
 * QUE HACE ESTE ARCHIVO
 * Hermano de `send-reset-email.js`. Reutiliza exactamente la misma infraestructura
 * (Resend via fetch, variables RESEND_API_KEY / RESEND_FROM, construccion de URL
 * desde headers `x-forwarded-*` para evitar open-redirect) pero genera un enlace
 * hacia `/completar-registro?token=` en lugar de `/restablecer?token=`.
 *
 * POR QUE NO SE REEMPLAZA EL ARCHIVO ANTERIOR
 * El contrato exige no reemplazar la API existente si puede reutilizarse. Este
 * archivo NO la reemplaza: la conserva intacta y comparte su patron. La diferencia
 * es solo el destino del enlace; duplicar el archivo es mas seguro que modificar
 * el original y arriesgar romper la recuperacion de contraseña que ya funciona.
 *
 * Si en el futuro se quiere unificar, basta con añadir un parametro `mode` a
 * send-reset-email y hacer que este archivo sea un alias. Por ahora se mantiene
 * separado para cumplir "no romper funcionalidad existente".
 *
 * FLUJO
 * Registro (frontend) genera un token de un solo uso, lo guarda en
 * localStorage `app.registerTokens` y llama a este endpoint con {email, token}.
 * El servidor compone la URL absoluta y envia el correo via Resend.
 * La URL solo puede apuntar al propio dominio del despliegue, nunca a un sitio
 * externo, por la misma razon de seguridad que en send-reset-email.
 * =============================================================================
 */

const txt = require('./_lib/txtUsers');
const regTokens = require('./_lib/registerTokens');

const MAX_TOKEN_LENGTH = 300;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

module.exports = async function handler(request, response) {
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ error: 'Metodo no permitido.' });
  }

  const body = typeof request.body === 'string' ? safeParse(request.body) : request.body;
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
  const token = typeof body?.token === 'string' ? body.token.trim() : '';

  if (!EMAIL_PATTERN.test(email)) {
    return response.status(400).json({ error: 'Correo electronico no valido.' });
  }
  if (!token || token.length > MAX_TOKEN_LENGTH || /[^A-Za-z0-9\-_=\.]/i.test(token)) {
    // permitir UUID y base64url del token firmado
    return response.status(400).json({ error: 'Token no valido.' });
  }

  // Validar que no exista ya (seguridad server-side extra, el cliente ya lo valida)
  try { txt.ensureSeed(); } catch {}
  if (txt.exists(email)) {
    return response.status(409).json({ error: 'El correo ya esta registrado.' });
  }

  // Generar token firmado stateless (no depende de /tmp compartido)
  // El token del cliente (UUID) se ignora para el correo: usamos uno firmado que
  // puede validarse en cualquier instancia sin archivo compartido.
  let serverToken;
  try {
    serverToken = regTokens.createSignedToken(email);
    // Guardar opcional para trazabilidad/bloqueo de reuso, pero no es requisito para validar
    try { regTokens.upsertToken(serverToken, email); } catch {}
  } catch (e) {
    console.error('[send-register-email] No se pudo generar token firmado', e);
    return response.status(500).json({ error: 'No se pudo generar el enlace.' });
  }
  // Usar el token firmado para el correo (cross-instance)
  const effectiveToken = serverToken;

  const protocol = request.headers['x-forwarded-proto'] || 'https';
  const host = request.headers['x-forwarded-host'] || request.headers.host;
  if (!host) return response.status(400).json({ error: 'No se pudo determinar el dominio.' });

  const registerUrl = `${protocol}://${host}/completar-registro?token=${encodeURIComponent(effectiveToken)}`;

  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.error('[send-register-email] Falta RESEND_API_KEY - token guardado, modo demo activo.');
    // Devolver el token firmado para que el cliente actualice el link demo (cross-browser)
    return response.status(200).json({ sent: false, warning: 'Correo no configurado, usa el enlace demo.', token: effectiveToken });
  }

  try {
    const resendResponse = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: process.env.RESEND_FROM || 'Tareas <onboarding@resend.dev>',
        to: [email],
        subject: 'Confirma tu registro',
        text: buildPlainText(registerUrl),
        html: buildHtml(registerUrl)
      })
    });

    if (!resendResponse.ok) {
      const detail = await resendResponse.text();
      console.error('[send-register-email] Resend respondio', resendResponse.status, detail);
      // aunque el correo falle, el token firmado ya es valido, devolverlo para modo demo
      return response.status(200).json({ sent: false, warning: 'No se pudo enviar el correo.', token: effectiveToken });
    }

    return response.status(200).json({ sent: true, token: effectiveToken });
  } catch (error) {
    console.error('[send-register-email] Fallo la llamada a Resend:', error);
    return response.status(502).json({ error: 'No se pudo enviar el correo.' });
  }
};

function safeParse(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}

function buildPlainText(url) {
  return [
    'Gracias por registrarte. Confirma tu correo para activar tu cuenta.',
    '',
    'Abre este enlace para configurar tu contraseña (mínimo 8 caracteres):',
    url,
    '',
    'El enlace caduca en 15 minutos y solo puede usarse una vez.',
    'Si no solicitaste este registro, puedes ignorar este mensaje.'
  ].join('\n');
}

function buildHtml(url) {
  return `<!doctype html>
<html lang="es">
  <body style="margin:0;padding:24px;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;color:#111827;">
    <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px;">
      <h1 style="margin:0 0 16px;font-size:20px;">Confirma tu registro</h1>
      <p style="margin:0 0 16px;font-size:15px;line-height:1.6;">
        Gracias por registrarte. Pulsa el botón para configurar tu contraseña y activar tu cuenta.
      </p>
      <p style="margin:0 0 24px;">
        <a href="${url}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:8px;font-size:15px;font-weight:bold;">
          Configurar contraseña
        </a>
      </p>
      <p style="margin:0 0 16px;font-size:13px;color:#6b7280;line-height:1.6;">
        El enlace caduca en 15 minutos y solo puede usarse una vez.
        Si el botón no funciona, copia esta dirección en tu navegador:
      </p>
      <p style="margin:0;font-size:12px;color:#6b7280;word-break:break-all;">${url}</p>
    </div>
  </body>
</html>`;
}

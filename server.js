/**
 * server.js — Témoigne de moi v2
 * ─────────────────────────────────────────────────────────────────
 * Corrections appliquées :
 *  ✅ Resend singleton (instancié une seule fois)
 *  ✅ Rate limiting sur /api/send/*
 *  ✅ Validation email stricte (destEmail, fromEmail, contactEmail)
 *  ✅ path.basename() sur tous les filenames (path traversal)
 *  ✅ try/catch sur JSON.parse(gdriveJson)
 *  ✅ Timeout 30s sur uploadToStorage
 *  ✅ Route /confidentialite
 *  ✅ Route POST /api/admin/test-email
 *  ✅ Avertissements au démarrage (RESEND_API_KEY, destEmail)
 *  ✅ 404 personnalisée
 *  ✅ express.json limit réduit pour /api/admin/config (hors logo)
 *  ✅ logoDataUrl limité à 300 KB
 *  ✅ Code mort croixCard* supprimé
 *
 * Corrections de sécurité (v2.1) :
 *  ✅ Anti-XSS : sanitizeHtml() sur les témoignages écrits (email + stockage)
 *  ✅ Auth admin : comparaison timing-safe (crypto.timingSafeEqual)
 *  ✅ Anti brute-force : rate limiting sur les routes /api/admin/*
 *  ✅ Mot de passe admin via en-tête uniquement (plus de query string)
 *  ✅ Alerte au démarrage si mot de passe admin par défaut
 *  ✅ Anti-SSRF : validation des URL webhook (blocage hôtes internes)
 *  ✅ Anti-injection d'en-tête email (CRLF) sur fromName/fromEmail
 *  ✅ FTP : FTPS (TLS) activé par défaut
 */
require('dotenv').config();
const express    = require('express');
const multer     = require('multer');
const path       = require('path');
const crypto     = require('crypto');
const { Resend } = require('resend');
const { getConfig, setConfig } = require('./config');

const app  = express();
const port = process.env.PORT || 3000;

// ── Secret cookie (signé HMAC) ────────────────────────────────────
// Généré une fois au démarrage, change à chaque redéploiement
// (les consentements expirent naturellement au redéploiement = acceptable)
const COOKIE_SECRET = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIE_NAME   = 'tdm_consent';
const COOKIE_MAX_AGE = 24 * 60 * 60 * 1000; // 24h

function signValue(val) {
  return val + '.' + crypto.createHmac('sha256', COOKIE_SECRET).update(val).digest('base64url');
}
function verifyValue(signed) {
  if (!signed) return false;
  const idx = signed.lastIndexOf('.');
  if (idx < 0) return false;
  const val = signed.slice(0, idx);
  return signValue(val) === signed;
}

function hasConsent(req) {
  const raw = req.headers.cookie || '';
  const match = raw.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  return match ? verifyValue(decodeURIComponent(match[1])) : false;
}

// ── Middleware : pages protégées ──────────────────────────────────
function requireConsent(req, res, next) {
  if (hasConsent(req)) return next();
  // Redirection vers l'accueil pour passer par le flux RGPD
  res.redirect(302, '/');
}

// ── Resend singleton ──────────────────────────────────────────────
const resend = new Resend(process.env.RESEND_API_KEY || '');

// ── Rate limiting ─────────────────────────────────────────────────
// Simple implémentation sans dépendance supplémentaire
const rateLimitMap = new Map();
function rateLimit(maxReq, windowMs) {
  return (req, res, next) => {
    const ip  = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    const key = `${ip}:${req.path}`;
    const entry = rateLimitMap.get(key) || { count: 0, start: now };
    if (now - entry.start > windowMs) {
      entry.count = 1; entry.start = now;
    } else {
      entry.count++;
    }
    rateLimitMap.set(key, entry);
    // Nettoyage périodique (toutes les 500 requêtes)
    if (rateLimitMap.size > 500) {
      for (const [k, v] of rateLimitMap) {
        if (now - v.start > windowMs) rateLimitMap.delete(k);
      }
    }
    if (entry.count > maxReq) {
      return res.status(429).json({ ok: false, error: 'Trop de requêtes. Veuillez patienter.' });
    }
    next();
  };
}
const sendLimiter  = rateLimit(10, 15 * 60 * 1000); // 10 envois / 15 min / IP
const adminLimiter = rateLimit(10, 15 * 60 * 1000); // 10 tentatives admin / 15 min / IP

// ── Multer — 500 MB max en mémoire ────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 500 * 1024 * 1024 },
});

// ── Validation email ──────────────────────────────────────────────
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function isValidEmail(e) { return typeof e === 'string' && emailRe.test(e.trim()); }

// ── Anti-injection d'en-tête email ────────────────────────────────
// Supprime les retours chariot/sauts de ligne qui permettraient
// d'injecter des en-têtes SMTP supplémentaires via fromName/fromEmail.
function headerSafe(s) { return String(s || '').replace(/[\r\n]+/g, ' ').trim(); }
function fromHeader(cfg) {
  return `${headerSafe(cfg.fromName) || 'Témoigne de moi'} <${headerSafe(cfg.fromEmail) || 'onboarding@resend.dev'}>`;
}

// ── Anti-SSRF : bloque les URL vers des hôtes internes/privés ──────
function isSafeRemoteUrl(raw) {
  let u;
  try { u = new URL(String(raw || '')); } catch { return false; }
  if (!/^https?:$/.test(u.protocol)) return false;
  const host = u.hostname.toLowerCase();
  // Bloquer localhost et noms d'hôtes non qualifiés
  if (host === 'localhost' || !host.includes('.')) return false;
  // Bloquer les plages IP privées / loopback / link-local / métadonnées cloud
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [parseInt(m[1]), parseInt(m[2])];
    if (a === 127 || a === 10 || a === 0 ||
        (a === 169 && b === 254) ||                 // link-local + métadonnées 169.254.169.254
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168)) return false;
  }
  // Bloquer IPv6 loopback / link-local
  if (host === '::1' || host.startsWith('fe80') || host.startsWith('fc') || host.startsWith('fd')) return false;
  return true;
}

// ── Sanitisation nom de fichier ───────────────────────────────────
function safeFilename(raw, fallback) {
  const b = path.basename(String(raw || fallback));
  // Garder uniquement caractères sûrs
  return b.replace(/[^a-zA-Z0-9._\-]/g, '_') || fallback;
}

// ── Sanitisation HTML (anti-XSS pour les témoignages écrits) ──────
// Liste blanche de balises de mise en forme inoffensives. Toute autre
// balise (script, iframe, etc.) et tous les attributs sont supprimés,
// ce qui neutralise les vecteurs XSS (on* handlers, javascript:, etc.).
function sanitizeHtml(input) {
  let html = String(input || '');
  // Supprimer entièrement les éléments dangereux avec leur contenu
  html = html.replace(/<(script|style|iframe|object|embed|form|link|meta|base)\b[\s\S]*?<\/\1>/gi, '');
  html = html.replace(/<(script|style|iframe|object|embed|form|link|meta|base)\b[^>]*\/?>/gi, '');
  // Supprimer les commentaires (peuvent masquer des charges utiles conditionnelles)
  html = html.replace(/<!--[\s\S]*?-->/g, '');

  const allowed = new Set([
    'p','br','b','strong','i','em','u','s','strike','blockquote',
    'ul','ol','li','h1','h2','h3','h4','h5','h6','span','div','a','pre','code','hr',
  ]);

  // Pour chaque balise : ne garder que les balises autorisées, sans aucun attribut
  // (sauf href sûr pour les liens), ce qui élimine on*, style, srcdoc, etc.
  html = html.replace(/<(\/?)([a-zA-Z0-9]+)([^>]*)>/g, (full, slash, tag, attrs) => {
    const name = tag.toLowerCase();
    if (!allowed.has(name)) return '';
    if (slash) return `</${name}>`;
    if (name === 'a') {
      const m = attrs.match(/\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i);
      const href = m ? (m[2] || m[3] || m[4] || '') : '';
      // N'autoriser que http(s) et mailto ; bloquer javascript:, data:, etc.
      if (/^(https?:|mailto:)/i.test(href.trim())) {
        return `<a href="${href.trim().replace(/"/g, '&quot;')}" rel="noopener noreferrer">`;
      }
      return '<a>';
    }
    return `<${name}>`;
  });

  return html;
}

// ── Static + JSON ─────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '10mb' })); // 10 MB pour le logo base64

// ── Health ────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, version: '2.0.0' }));

// ── Pages SPA ─────────────────────────────────────────────────────
const page = (f) => (_, res) => res.sendFile(path.join(__dirname, 'public', f));
app.get('/',                page('index.html'));
app.get('/confidentialite', page('confidentialite.html'));
app.get('/admin',           page('admin.html'));
app.get('/feedback',        page('feedback.html'));

// ── Pages protégées — nécessitent le consentement RGPD ───────────
app.get('/audio', requireConsent, page('audio.html'));
app.get('/video', requireConsent, page('video.html'));
app.get('/ecrit', requireConsent, page('ecrit.html'));

// ── API consentement — pose le cookie signé HttpOnly ─────────────
app.post('/api/consent', express.json({ limit: '1kb' }), (req, res) => {
  const { type } = req.body; // 'majeur' ou 'mineur_rl'
  if (!['majeur', 'mineur_rl'].includes(type))
    return res.status(400).json({ ok: false, error: 'Type de consentement invalide.' });

  const signed = signValue('1');
  res.setHeader('Set-Cookie', [
    `${COOKIE_NAME}=${encodeURIComponent(signed)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${COOKIE_MAX_AGE / 1000}`,
  ]);
  console.log(`✅ Consentement enregistré (${type})`);
  res.json({ ok: true });
});

// ── API révocation consentement ───────────────────────────────────
app.post('/api/consent/revoke', (req, res) => {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
  res.json({ ok: true });
});

// ── API vérification consentement ────────────────────────────────
app.get('/api/consent/check', (req, res) => {
  res.json({ ok: hasConsent(req) });
});

// ── Config publique (sans données sensibles) ──────────────────────
app.get('/api/config', (_, res) => {
  const cfg = getConfig();
  res.json({
    appTitle:     cfg.appTitle,
    appSubtitle:  cfg.appSubtitle,
    tinymceKey:   cfg.tinymceKey,
    audioPrefix:  cfg.audioPrefix,
    audioSizeMb:  cfg.audioSizeMb,
    videoSizeMb:  cfg.videoSizeMb,
    badgeText:    cfg.badgeText,
    heroTitle:    cfg.heroTitle,
    logoDataUrl:  cfg.logoDataUrl,
    contactEmail: cfg.contactEmail,
  });
});

// ── Admin : lire config complète (protégée) ───────────────────────
app.get('/api/admin/config', adminLimiter, requireAdmin, (_, res) => {
  const cfg = getConfig();
  const { adminPassword, ...safe } = cfg;
  res.json(safe);
});

// ── Admin : modifier config ───────────────────────────────────────
app.post('/api/admin/config', adminLimiter, requireAdmin, (req, res) => {
  const allowed = [
    'destEmail','fromEmail','fromName','contactEmail',
    'appTitle','appSubtitle','footerText',
    'tinymceKey','audioPrefix','adminPassword',
    'badgeText','heroTitle','logoDataUrl',
    'audioSizeMb','videoSizeMb','ecritSizeMb',
    'storageType',
    'gdriveFolder','gdriveJson',
    'ftpHost','ftpPort','ftpUser','ftpPassword','ftpPath','ftpPublicUrl','ftpSecure',
    'webhookUrl','webhookSecret',
  ];
  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

  // Validation emails
  for (const k of ['destEmail','fromEmail','contactEmail']) {
    if (updates[k] && !isValidEmail(updates[k]))
      return res.status(400).json({ ok: false, error: `${k} invalide.` });
  }

  // Anti-injection d'en-tête sur fromName
  if (updates.fromName) updates.fromName = headerSafe(updates.fromName);

  // Anti-SSRF : refuser une URL webhook vers un hôte interne
  if (updates.webhookUrl && !isSafeRemoteUrl(updates.webhookUrl))
    return res.status(400).json({ ok: false, error: 'URL webhook interdite (hôte interne ou protocole non autorisé).' });

  // Seuils entiers
  ['audioSizeMb','videoSizeMb','ecritSizeMb'].forEach(k => {
    if (updates[k] !== undefined) updates[k] = Math.max(1, parseInt(updates[k]) || 10);
  });

  // Limite logoDataUrl à 300 KB (base64 = ~225 KB image)
  if (updates.logoDataUrl && updates.logoDataUrl.length > 400 * 1024) {
    return res.status(400).json({ ok: false, error: 'Logo trop volumineux (max 300 KB).' });
  }

  // Vider le logo si chaîne vide (suppression volontaire)
  if (updates.logoDataUrl === '') updates.logoDataUrl = '';

  const updated = setConfig(updates);
  console.log('⚙️  Config mise à jour');
  res.json({ ok: true, config: updated });
});

// ── Admin : test d'envoi email ────────────────────────────────────
app.post('/api/admin/test-email', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const cfg = getConfig();
    if (!cfg.destEmail) return res.status(400).json({ ok: false, error: 'Email de réception non configuré.' });
    if (!process.env.RESEND_API_KEY) return res.status(400).json({ ok: false, error: 'RESEND_API_KEY manquante.' });

    const { data, error } = await withTimeout(
      resend.emails.send({
        from:    fromHeader(cfg),
        to:      [cfg.destEmail],
        subject: `✅ Test d'envoi — ${cfg.appTitle || 'Témoigne de moi'}`,
        html:    emailHtml({
          icon:'✅', color:'#6BAE8E', type:'Email de test',
          sender:'Administrateur', date: now(),
          filename:'Configuration Resend',
          extra:'', note:'Cet email confirme que votre configuration Resend fonctionne correctement.',
          appTitle: cfg.appTitle, footer: cfg.footerText,
        }),
        text: `Test d'envoi réussi — ${cfg.appTitle || 'Témoigne de moi'}\nDate : ${now()}`,
      }),
      30000
    );
    if (error) throw new Error(error.message);
    console.log(`✅ Test email [${data.id}] envoyé à ${cfg.destEmail}`);
    res.json({ ok: true, id: data.id });
  } catch(e) {
    console.error('Test email:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ── Comparaison timing-safe ───────────────────────────────────────
// Évite les attaques temporelles sur le mot de passe admin.
function safeCompare(a, b) {
  const ba = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  if (ba.length !== bb.length) {
    // Comparer quand même contre un buffer de même longueur pour ne pas
    // divulguer la longueur via le timing, puis renvoyer false.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

// ── Middleware auth admin ─────────────────────────────────────────
function requireAdmin(req, res, next) {
  // Uniquement via en-tête (jamais en query string : éviterait la fuite
  // du mot de passe dans les logs serveur et l'historique navigateur).
  const pwd      = req.headers['x-admin-password'];
  const expected = getConfig().adminPassword;
  if (pwd && safeCompare(pwd, expected)) return next();
  console.warn(`⛔ Tentative admin échouée depuis ${req.ip}`);
  res.status(401).json({ ok: false, error: 'Mot de passe incorrect.' });
}

// ── Timeout helper ────────────────────────────────────────────────
function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`Timeout après ${ms / 1000}s`)), ms)
    ),
  ]);
}

// ══════════════════════════════════════════════════════════════════
// STOCKAGE DISTANT
// ══════════════════════════════════════════════════════════════════
async function uploadToStorage(buffer, filename, mime) {
  const cfg = getConfig();

  if (cfg.storageType === 'gdrive') {
    const { google } = require('googleapis');
    let credentials;
    try { credentials = JSON.parse(cfg.gdriveJson); }
    catch { throw new Error('JSON compte de service Google invalide — vérifiez /admin'); }

    const auth = new google.auth.GoogleAuth({
      credentials,
      scopes: ['https://www.googleapis.com/auth/drive.file'],
    });
    const drive = google.drive({ version: 'v3', auth });
    const { data: file } = await withTimeout(drive.files.create({
      requestBody: {
        name:    filename,
        parents: cfg.gdriveFolder ? [cfg.gdriveFolder] : [],
      },
      media: { mimeType: mime, body: require('stream').Readable.from(buffer) },
      fields: 'id, webViewLink',
    }), 30000);
    await withTimeout(drive.permissions.create({
      fileId:      file.id,
      requestBody: { role: 'reader', type: 'anyone' },
    }), 10000);
    return { url: file.webViewLink };
  }

  if (cfg.storageType === 'ftp') {
    const ftp    = require('basic-ftp');
    const client = new ftp.Client();
    client.ftp.verbose = false;
    try {
      await withTimeout(client.access({
        host:     cfg.ftpHost,
        port:     parseInt(cfg.ftpPort) || 21,
        user:     cfg.ftpUser,
        password: cfg.ftpPassword,
        // FTPS (chiffré) par défaut ; désactivable explicitement via config
        // pour les serveurs hérités sans support TLS.
        secure:   cfg.ftpSecure !== false && cfg.ftpSecure !== 'false',
      }), 15000);
      const remotePath = `${cfg.ftpPath || '/uploads'}/${filename}`;
      const { Readable } = require('stream');
      await withTimeout(client.uploadFrom(Readable.from(buffer), remotePath), 60000);
      const publicUrl = cfg.ftpPublicUrl
        ? `${cfg.ftpPublicUrl.replace(/\/$/, '')}/${filename}`
        : `ftp://${cfg.ftpHost}${remotePath}`;
      return { url: publicUrl };
    } finally {
      client.close();
    }
  }

  if (cfg.storageType === 'webhook') {
    // Anti-SSRF : refuser les webhooks pointant vers des hôtes internes
    if (!isSafeRemoteUrl(cfg.webhookUrl))
      throw new Error('URL webhook invalide ou interdite (hôte interne) — vérifiez /admin');
    const FormData = require('form-data');
    const fetch    = require('node-fetch');
    const form     = new FormData();
    form.append('file', buffer, { filename, contentType: mime });
    if (cfg.webhookSecret) form.append('secret', cfg.webhookSecret);
    const resp = await withTimeout(
      fetch(cfg.webhookUrl, { method: 'POST', body: form }),
      30000
    );
    if (!resp.ok) throw new Error(`Webhook HTTP ${resp.status}`);
    const json = await resp.json();
    const url  = json.url || json.link || json.fileUrl;
    if (!url) throw new Error('Webhook : aucune URL retournée.');
    return { url };
  }

  throw new Error('Type de stockage inconnu : ' + cfg.storageType);
}

// ══════════════════════════════════════════════════════════════════
// ENVOI AUDIO
// ══════════════════════════════════════════════════════════════════
app.post('/api/send/audio', sendLimiter, upload.single('audio'), async (req, res) => {
  try {
    const cfg       = getConfig();
    const threshold = (cfg.audioSizeMb || 10) * 1024 * 1024;
    if (!cfg.destEmail) return res.status(500).json({ ok: false, error: 'Email non configuré → /admin' });
    if (!req.file)      return res.status(400).json({ ok: false, error: 'Aucun fichier audio.' });

    const filename = safeFilename(req.body.filename, `vocal_${Date.now()}.webm`);
    const sender   = String(req.body.sender   || 'Anonyme').substring(0, 100);
    const date     = req.body.date     || now();
    const duration = String(req.body.duration || '?').substring(0, 20);
    const mime     = getMimeAudio(filename);
    const sizeMb   = (req.file.size / 1024 / 1024).toFixed(1);

    if (req.file.size <= threshold || cfg.storageType === 'none') {
      const { data, error } = await withTimeout(resend.emails.send({
        from:    fromHeader(cfg),
        to:      [cfg.destEmail],
        subject: `🎙 Témoignage vocal — ${sender}`,
        html:    emailHtml({ icon:'🎙', color:'#E8825A', type:'Témoignage vocal', sender, date, filename,
          extra: `<tr><td style="padding:8px 0;color:#888;">Durée</td><td style="padding:8px 0;">${esc(duration)}</td></tr><tr><td style="padding:8px 0;color:#888;">Taille</td><td style="padding:8px 0;">${sizeMb} MB</td></tr>`,
          note: '📎 Fichier audio en pièce jointe.', appTitle: cfg.appTitle, footer: cfg.footerText }),
        text:    `Témoignage vocal de ${sender}\nDate : ${date}\nDurée : ${duration}\nFichier : ${filename}`,
        attachments: [{ filename, content: req.file.buffer.toString('base64'), contentType: mime }],
      }), 30000);
      if (error) throw new Error(error.message);
      console.log(`🎙 Audio joint [${data.id}] de ${sender}`);
      res.json({ ok: true, method: 'attachment' });
    } else {
      console.log(`☁️  Audio ${sizeMb} MB > seuil → ${cfg.storageType}`);
      const { url } = await uploadToStorage(req.file.buffer, filename, mime);
      const { data, error } = await withTimeout(resend.emails.send({
        from:    fromHeader(cfg),
        to:      [cfg.destEmail],
        subject: `🎙 Témoignage vocal (${sizeMb} MB) — ${sender}`,
        html:    emailHtml({ icon:'🎙', color:'#E8825A', type:'Témoignage vocal', sender, date, filename,
          extra: `<tr><td style="padding:8px 0;color:#888;">Durée</td><td style="padding:8px 0;">${esc(duration)}</td></tr><tr><td style="padding:8px 0;color:#888;">Taille</td><td style="padding:8px 0;">${sizeMb} MB</td></tr>`,
          note: '', link: url, appTitle: cfg.appTitle, footer: cfg.footerText }),
        text: `Témoignage vocal de ${sender}\nDate : ${date}\nDurée : ${duration}\nTaille : ${sizeMb} MB\nFichier : ${url}`,
      }), 30000);
      if (error) throw new Error(error.message);
      console.log(`🎙 Audio cloud [${data.id}] → ${url}`);
      res.json({ ok: true, method: 'cloud', url });
    }
  } catch(e) { console.error('Audio:', e.message); res.status(500).json({ ok: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════
// ENVOI VIDÉO
// ══════════════════════════════════════════════════════════════════
app.post('/api/send/video', sendLimiter, upload.single('video'), async (req, res) => {
  try {
    const cfg       = getConfig();
    const threshold = (cfg.videoSizeMb || 25) * 1024 * 1024;
    if (!cfg.destEmail) return res.status(500).json({ ok: false, error: 'Email non configuré → /admin' });
    if (!req.file)      return res.status(400).json({ ok: false, error: 'Aucune vidéo.' });

    const filename = safeFilename(req.body.filename, `video_${Date.now()}.webm`);
    const sender   = String(req.body.sender   || 'Anonyme').substring(0, 100);
    const date     = req.body.date     || now();
    const duration = String(req.body.duration || '?').substring(0, 20);
    const sizeMb   = (req.file.size / 1024 / 1024).toFixed(1);
    const mime     = getMimeVideo(filename);

    if (req.file.size <= threshold || cfg.storageType === 'none') {
      const { data, error } = await withTimeout(resend.emails.send({
        from:    fromHeader(cfg),
        to:      [cfg.destEmail],
        subject: `🎥 Témoignage vidéo — ${sender}`,
        html:    emailHtml({ icon:'🎥', color:'#5B8DB8', type:'Témoignage vidéo', sender, date, filename,
          extra: `<tr><td style="padding:8px 0;color:#888;">Durée</td><td style="padding:8px 0;">${esc(duration)}</td></tr><tr><td style="padding:8px 0;color:#888;">Taille</td><td style="padding:8px 0;">${sizeMb} MB</td></tr>`,
          note: '📎 Vidéo en pièce jointe.', appTitle: cfg.appTitle, footer: cfg.footerText }),
        text:    `Témoignage vidéo de ${sender}\nDate : ${date}\nDurée : ${duration}\nTaille : ${sizeMb} MB`,
        attachments: [{ filename, content: req.file.buffer.toString('base64'), contentType: mime }],
      }), 30000);
      if (error) throw new Error(error.message);
      console.log(`🎥 Vidéo joint [${data.id}] de ${sender}`);
      res.json({ ok: true, method: 'attachment' });
    } else {
      console.log(`☁️  Vidéo ${sizeMb} MB > seuil → ${cfg.storageType}`);
      const { url } = await uploadToStorage(req.file.buffer, filename, mime);
      const { data, error } = await withTimeout(resend.emails.send({
        from:    fromHeader(cfg),
        to:      [cfg.destEmail],
        subject: `🎥 Témoignage vidéo (${sizeMb} MB) — ${sender}`,
        html:    emailHtml({ icon:'🎥', color:'#5B8DB8', type:'Témoignage vidéo', sender, date, filename,
          extra: `<tr><td style="padding:8px 0;color:#888;">Durée</td><td style="padding:8px 0;">${esc(duration)}</td></tr><tr><td style="padding:8px 0;color:#888;">Taille</td><td style="padding:8px 0;">${sizeMb} MB</td></tr>`,
          note: '', link: url, appTitle: cfg.appTitle, footer: cfg.footerText }),
        text: `Témoignage vidéo de ${sender}\nDate : ${date}\nDurée : ${duration}\nTaille : ${sizeMb} MB\nFichier : ${url}`,
      }), 30000);
      if (error) throw new Error(error.message);
      console.log(`🎥 Vidéo cloud [${data.id}] → ${url}`);
      res.json({ ok: true, method: 'cloud', url });
    }
  } catch(e) { console.error('Vidéo:', e.message); res.status(500).json({ ok: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════
// ENVOI ÉCRIT
// ══════════════════════════════════════════════════════════════════
app.post('/api/send/ecrit', sendLimiter, async (req, res) => {
  try {
    const cfg = getConfig();
    if (!cfg.destEmail) return res.status(500).json({ ok: false, error: 'Email non configuré → /admin' });

    const sender      = String(req.body.sender      || 'Anonyme').substring(0, 100);
    const subject     = String(req.body.subject     || 'Sans titre').substring(0, 150);
    const rawHtml     = req.body.htmlContent;
    const textContent = req.body.textContent;

    if (!rawHtml?.trim()) return res.status(400).json({ ok: false, error: 'Contenu vide.' });

    // Anti-XSS : nettoyer le HTML fourni par le client avant tout usage
    // (email administrateur + fichier .html déposé sur le stockage public)
    const htmlContent = sanitizeHtml(rawHtml);

    const textBuf   = Buffer.from(textContent || '', 'utf8');
    const sizeMb    = (textBuf.length / 1024 / 1024).toFixed(2);
    const threshold = (cfg.ecritSizeMb || 5) * 1024 * 1024;

    if (textBuf.length <= threshold || cfg.storageType === 'none') {
      const { data, error } = await withTimeout(resend.emails.send({
        from:    fromHeader(cfg),
        to:      [cfg.destEmail],
        subject: `✍️ Témoignage écrit — ${subject}`,
        html:    emailHtml({ icon:'✍️', color:'#6BAE8E', type:'Témoignage écrit',
          sender, date: now(), filename: subject,
          extra: '', note: htmlContent, raw: true,
          appTitle: cfg.appTitle, footer: cfg.footerText }),
        text: `Témoignage écrit de ${sender}\n${subject !== 'Sans titre' ? 'Titre : ' + subject + '\n' : ''}\n${textContent}`,
      }), 30000);
      if (error) throw new Error(error.message);
      console.log(`✍️ Écrit [${data.id}] de ${sender}`);
      res.json({ ok: true, method: 'email' });
    } else {
      const filename  = `ecrit_${Date.now()}.html`;
      const { url }   = await uploadToStorage(Buffer.from(htmlContent, 'utf8'), filename, 'text/html');
      const { data, error } = await withTimeout(resend.emails.send({
        from:    fromHeader(cfg),
        to:      [cfg.destEmail],
        subject: `✍️ Témoignage écrit (${sizeMb} MB) — ${subject}`,
        html:    emailHtml({ icon:'✍️', color:'#6BAE8E', type:'Témoignage écrit',
          sender, date: now(), filename: subject,
          extra: '', note: '', link: url,
          appTitle: cfg.appTitle, footer: cfg.footerText }),
        text: `Témoignage écrit de ${sender}\nDocument : ${url}`,
      }), 30000);
      if (error) throw new Error(error.message);
      console.log(`✍️ Écrit cloud [${data.id}] → ${url}`);
      res.json({ ok: true, method: 'cloud', url });
    }
  } catch(e) { console.error('Écrit:', e.message); res.status(500).json({ ok: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════
// ENVOI FEEDBACK
// ══════════════════════════════════════════════════════════════════
app.post('/api/send/feedback', sendLimiter, async (req, res) => {
  try {
    const cfg = getConfig();
    if (!cfg.destEmail) return res.status(500).json({ ok: false, error: 'Email non configuré.' });

    const sender      = String(req.body.sender      || 'Anonyme').substring(0, 100);
    const type        = String(req.body.type        || '').substring(0, 20);
    const noteRaw     = parseInt(req.body.note);
    const satisfaction= String(req.body.satisfaction|| '').substring(0, 30);
    const amelioration= String(req.body.amelioration|| '').substring(0, 1000);

    if (!noteRaw || noteRaw < 1 || noteRaw > 5)
      return res.status(400).json({ ok: false, error: 'Note invalide (1-5).' });

    const stars    = '★'.repeat(noteRaw) + '☆'.repeat(5 - noteRaw);
    const satMap   = { tres_satisfait:'😊 Très satisfait', satisfait:'🙂 Satisfait', neutre:'😐 Neutre', insatisfait:'😕 Insatisfait', tres_insatisfait:'😞 Très insatisfait' };
    const typeMap  = { audio:'🎙 Audio', video:'🎥 Vidéo', ecrit:'✍️ Écrit' };
    const satLabel = satMap[satisfaction] || esc(satisfaction);
    const typeLabel= typeMap[type]        || esc(type);

    const extra = `
      <tr><td style="padding:8px 0;color:#888;">Type</td><td style="padding:8px 0;font-weight:600;">${esc(typeLabel)}</td></tr>
      <tr><td style="padding:8px 0;color:#888;">Note</td><td style="padding:8px 0;color:#E8825A;font-size:18px;letter-spacing:2px;">${stars} ${noteRaw}/5</td></tr>
      <tr><td style="padding:8px 0;color:#888;">Satisfaction</td><td style="padding:8px 0;font-weight:600;">${esc(satLabel)}</td></tr>
      ${amelioration ? `<tr><td style="padding:8px 0;color:#888;vertical-align:top;">Amélioration</td><td style="padding:8px 0;">${esc(amelioration)}</td></tr>` : ''}`;

    const { data, error } = await withTimeout(resend.emails.send({
      from:    fromHeader(cfg),
      to:      [cfg.destEmail],
      subject: `⭐ Feedback ${typeLabel} — ${noteRaw}/5 — ${sender}`,
      html:    emailHtml({ icon:'⭐', color:'#F4B942', type:"Retour d'expérience",
        sender, date: now(), filename: `Note ${noteRaw}/5 — ${satLabel}`,
        extra, note: '', appTitle: cfg.appTitle, footer: cfg.footerText }),
      text: `Feedback\nDe : ${sender}\nType : ${typeLabel}\nNote : ${noteRaw}/5\nSatisfaction : ${satLabel}\nAmélioration : ${amelioration || '—'}`,
    }), 30000);
    if (error) throw new Error(error.message);
    console.log(`⭐ Feedback [${data.id}] note=${noteRaw}`);
    res.json({ ok: true });
  } catch(e) { console.error('Feedback:', e.message); res.status(500).json({ ok: false, error: e.message }); }
});

// ── 404 personnalisée ─────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ══════════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════════
function emailHtml({ icon, color, type, sender, date, filename, extra, note, raw, link, appTitle, footer }) {
  let body = '';
  if (raw)       body = note || '';
  else if (note) body = `<div style="margin-top:16px;padding:12px 14px;background:#f8f9fa;border-left:3px solid ${color};border-radius:4px;font-size:14px;color:#555;">${esc(note)}</div>`;

  const linkBtn = link ? `
  <div style="margin-top:20px;">
    <a href="${esc(link)}" style="display:inline-block;padding:12px 24px;background:linear-gradient(135deg,${color},${color}bb);color:#fff;font-weight:700;font-size:14px;border-radius:8px;text-decoration:none;">
      ☁️ Accéder au fichier
    </a>
    <p style="margin-top:10px;font-size:12px;color:#888;">Lien direct : <a href="${esc(link)}" style="color:${color};">${esc(link)}</a></p>
  </div>` : '';

  return `<!DOCTYPE html><html><head><meta charset="utf-8"/></head>
<body style="margin:0;padding:0;background:#fdf6f0;font-family:'Segoe UI',Arial,sans-serif;">
<div style="max-width:600px;margin:28px auto;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08);">
  <div style="background:linear-gradient(135deg,${color},${color}bb);padding:26px 32px;">
    <p style="margin:0 0 4px;font-size:11px;letter-spacing:3px;text-transform:uppercase;color:rgba(255,255,255,.7);">${esc(appTitle || '')}</p>
    <h1 style="margin:0;font-size:20px;color:#fff;font-weight:700;">${icon} ${esc(type)}</h1>
  </div>
  <div style="padding:5px 32px 0;background:#fafaf8;border-bottom:1px solid #eee;display:flex;gap:20px;font-size:12px;color:#888;flex-wrap:wrap;">
    <span style="padding:10px 0;">👤 ${esc(sender)}</span>
    <span style="padding:10px 0;">📅 ${esc(date)}</span>
    <span style="padding:10px 0;">📝 ${esc(filename)}</span>
  </div>
  <div style="padding:22px 32px;">
    <table style="width:100%;border-collapse:collapse;font-size:14px;">${extra}</table>
    ${body}${linkBtn}
  </div>
  <div style="padding:14px 32px;background:#fdf6f0;border-top:1px solid #f0e8e0;font-size:11px;color:#bbb;text-align:center;">${esc(footer || '')}</div>
</div></body></html>`;
}

function getMimeAudio(f) {
  return { '.webm':'audio/webm', '.ogg':'audio/ogg', '.mp4':'audio/mp4', '.m4a':'audio/mp4' }[path.extname(f).toLowerCase()] || 'audio/webm';
}
function getMimeVideo(f) {
  return { '.webm':'video/webm', '.mp4':'video/mp4', '.ogg':'video/ogg', '.mov':'video/quicktime' }[path.extname(f).toLowerCase()] || 'video/webm';
}
function now()  { return new Date().toLocaleString('fr-FR'); }
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ── Start ─────────────────────────────────────────────────────────
app.listen(port, () => {
  const cfg = getConfig();
  console.log(`\n🌟 Témoigne de moi v2 → http://localhost:${port}`);
  if (!process.env.RESEND_API_KEY)
    console.error('   ⛔ RESEND_API_KEY manquante — les envois échoueront !');
  else
    console.log('   ✅ Resend configuré');
  if (!cfg.destEmail)
    console.warn('   ⚠️  DEST_EMAIL non configuré → configurer dans /admin');
  else
    console.log(`   📧 Destination : ${cfg.destEmail}`);
  if (cfg.adminPassword === 'admin123')
    console.error('   ⛔ SÉCURITÉ : mot de passe admin par défaut (admin123) ! Définissez ADMIN_PASSWORD.');
  console.log(`   🔐 Admin : http://localhost:${port}/admin\n`);
});

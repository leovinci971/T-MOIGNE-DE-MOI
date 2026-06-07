/**
 * config.js — Source unique de vérité pour tous les paramètres
 * Priorité : config.json (admin) > .env (déploiement) > valeurs par défaut
 * Pour changer d'hébergeur : seul .env change, rien d'autre.
 */
const fs   = require('fs');
const path = require('path');

const CONFIG_FILE = path.join(__dirname, 'config.json');

function defaults() {
  return {
    // ── Email ──────────────────────────────────────────────────
    destEmail:      process.env.DEST_EMAIL       || '',
    fromEmail:      process.env.FROM_EMAIL       || 'onboarding@resend.dev',
    fromName:       process.env.FROM_NAME        || 'Témoigne de moi',
    contactEmail:   process.env.CONTACT_EMAIL    || '',

    // ── Application ────────────────────────────────────────────
    appTitle:       process.env.APP_TITLE        || 'Témoigne de moi',
    appSubtitle:    process.env.APP_SUBTITLE     || 'Votre voix, votre histoire',
    footerText:     process.env.FOOTER_TEXT      || 'Envoyé via Témoigne de moi',

    // ── Page d'accueil personnalisable ─────────────────────────
    badgeText:      process.env.BADGE_TEXT       || 'Votre voix compte',
    heroTitle:      process.env.HERO_TITLE       || 'Témoigne|de moi',
    logoDataUrl:    '',

    // ── TinyMCE ────────────────────────────────────────────────
    tinymceKey:     process.env.TINYMCE_KEY      || 'no-api-key',

    // ── Admin ──────────────────────────────────────────────────
    adminPassword:  process.env.ADMIN_PASSWORD   || 'admin123',

    // ── Audio ──────────────────────────────────────────────────
    audioPrefix:    process.env.AUDIO_PREFIX     || 'vocal',
    audioSizeMb:    parseInt(process.env.AUDIO_SIZE_MB  || '10'),
    audioMaxMin:    parseInt(process.env.AUDIO_MAX_MIN  || '10'),  // durée max en minutes

    // ── Vidéo ──────────────────────────────────────────────────
    videoPrefix:    process.env.VIDEO_PREFIX     || 'video',
    videoSizeMb:    parseInt(process.env.VIDEO_SIZE_MB  || '25'),
    videoMaxMin:    parseInt(process.env.VIDEO_MAX_MIN  || '5'),   // durée max en minutes

    // ── Écrit ──────────────────────────────────────────────────
    ecritSizeMb:    parseInt(process.env.ECRIT_SIZE_MB  || '5'),

    // ── Compteurs mensuels (sauvegardés dans config.json) ──────
    stats: {
      month:    '',   // 'YYYY-MM' — remis à zéro chaque mois automatiquement
      audio:    0,
      video:    0,
      ecrit:    0,
      feedback: 0,
    },

    // ── Stockage distant ───────────────────────────────────────
    // Type : 'none' | 'gdrive' | 'ftp' | 'webhook'
    storageType:    process.env.STORAGE_TYPE     || 'none',

    // Google Drive
    gdriveFolder:   process.env.GDRIVE_FOLDER_ID                  || '',
    gdriveJson:     process.env.GDRIVE_SERVICE_ACCOUNT_JSON        || '',

    // FTP / SFTP
    ftpHost:        process.env.FTP_HOST         || '',
    ftpPort:        process.env.FTP_PORT         || '21',
    ftpUser:        process.env.FTP_USER         || '',
    ftpPassword:    process.env.FTP_PASSWORD      || '',
    ftpPath:        process.env.FTP_PATH         || '/uploads',
    ftpPublicUrl:   process.env.FTP_PUBLIC_URL   || '',
    // FTPS (TLS) activé par défaut ; mettre FTP_SECURE=false pour serveur hérité
    ftpSecure:      process.env.FTP_SECURE !== 'false',

    // Webhook (POST multipart)
    webhookUrl:     process.env.WEBHOOK_URL      || '',
    webhookSecret:  process.env.WEBHOOK_SECRET   || '',
  };
}

function getConfig() {
  const d = defaults();
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const saved = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
      return { ...d, ...saved };
    }
  } catch(e) { console.warn('config.json illisible, valeurs par défaut.'); }
  return d;
}

function setConfig(updates) {
  const next = { ...getConfig(), ...updates };
  // Ne jamais stocker la clé Resend dans config.json (sécurité)
  delete next.resendKey;
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(next, null, 2), 'utf8');
  return next;
}

module.exports = { getConfig, setConfig };

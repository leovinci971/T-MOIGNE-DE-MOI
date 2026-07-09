/**
 * supabaseStorage.js — Intégration Supabase pour Témoigne de moi
 * ─────────────────────────────────────────────────────────────────
 * • Connexion serveur via service_role key (variables d'environnement).
 * • uploadFileToSupabase() : dépose un fichier audio/vidéo dans le
 *   bucket privé "temoignages" et renvoie une URL signée (7 jours).
 * • insertTemoignage() : insère la ligne en table "temoignages" avec
 *   la catégorie proposée par le classement automatique.
 * • saveToSupabase() : orchestre upload (si fichier) + classement +
 *   insertion. C'est la seule fonction appelée par server.js.
 *
 * Sécurité / RGPD :
 *  • Bucket PRIVÉ — aucun accès public direct.
 *  • URL signée temporaire (expire) au lieu d'une URL publique.
 *  • La service_role key ne vit que dans l'environnement serveur.
 *
 * Robustesse :
 *  • Si SUPABASE_URL / SUPABASE_KEY absentes → isSupabaseEnabled() = false,
 *    saveToSupabase() ne lève pas d'erreur bloquante (l'email part quand même).
 */
const { createClient } = require('@supabase/supabase-js');
const { classifyTestimony } = require('./categoriesConfig');

const SUPABASE_URL    = process.env.SUPABASE_URL    || '';
const SUPABASE_KEY    = process.env.SUPABASE_KEY    || ''; // service_role
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || 'temoignages';
const SIGNED_URL_TTL  = 60 * 60 * 24 * 7; // 7 jours en secondes

// ── Client singleton (créé une seule fois) ────────────────────────
let _client = null;
function getClient() {
  if (!SUPABASE_URL || !SUPABASE_KEY) return null;
  if (!_client) {
    _client = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
  }
  return _client;
}

function isSupabaseEnabled() {
  return Boolean(SUPABASE_URL && SUPABASE_KEY);
}

// ── Upload fichier vers le bucket privé ───────────────────────────
// @returns {string|null} chemin (path) du fichier dans le bucket
async function uploadFileToSupabase(buffer, filename, mime) {
  const supabase = getClient();
  if (!supabase) throw new Error('Supabase non configuré (SUPABASE_URL / SUPABASE_KEY).');

  // Chemin unique : horodatage + nom sécurisé (évite collisions)
  const stamp = Date.now();
  const path  = `${stamp}_${filename}`;

  const { error } = await supabase.storage
    .from(SUPABASE_BUCKET)
    .upload(path, buffer, { contentType: mime, upsert: false });

  if (error) throw new Error(`Upload Supabase échoué : ${error.message}`);
  return path;
}

// ── Génère une URL signée temporaire pour un fichier du bucket ────
async function getSignedUrl(path) {
  const supabase = getClient();
  if (!supabase || !path) return null;
  const { data, error } = await supabase.storage
    .from(SUPABASE_BUCKET)
    .createSignedUrl(path, SIGNED_URL_TTL);
  if (error) { console.warn('URL signée échouée :', error.message); return null; }
  return data?.signedUrl || null;
}

// ── Insertion d'une ligne en table temoignages ────────────────────
async function insertTemoignage(row) {
  const supabase = getClient();
  if (!supabase) throw new Error('Supabase non configuré.');

  const { data, error } = await supabase
    .from('temoignages')
    .insert([row])
    .select()
    .single();

  if (error) throw new Error(`Insertion Supabase échouée : ${error.message}`);
  return data;
}

/**
 * saveToSupabase(params)
 * ──────────────────────
 * Orchestration complète : classement + (upload si fichier) + insertion.
 *
 * @param {object} params
 *   - type          : 'audio' | 'video' | 'ecrit'   (obligatoire)
 *   - prenom        : string
 *   - nom           : string
 *   - transcription : string  (texte écrit OU transcription audio/vidéo)
 *   - fileBuffer    : Buffer  (optionnel — audio/vidéo)
 *   - filename      : string  (optionnel — nom du fichier)
 *   - mime          : string  (optionnel — type MIME du fichier)
 *
 * @returns {object} { ok, id, categorie, fichier_url } OU { ok:false, error }
 *
 * Ne JAMAIS lever : renvoie { ok:false, error } pour ne pas casser
 * le flux email principal de server.js.
 */
async function saveToSupabase(params) {
  try {
    if (!isSupabaseEnabled()) {
      return { ok: false, error: 'Supabase désactivé (variables manquantes).' };
    }

    const {
      type, prenom = '', nom = '', transcription = '',
      fileBuffer = null, filename = null, mime = null,
    } = params;

    // 1. Classement automatique sur la transcription
    const categorie = classifyTestimony(transcription); // null si aucun match

    // 2. Upload fichier (audio/vidéo) si présent
    let storagePath = null;
    let fichierUrl  = null;
    if (fileBuffer && filename) {
      storagePath = await uploadFileToSupabase(fileBuffer, filename, mime || 'application/octet-stream');
      fichierUrl  = await getSignedUrl(storagePath);
    }

    // 3. Insertion en table
    const inserted = await insertTemoignage({
      type,
      prenom:             prenom || null,
      nom:                nom || null,
      transcription:      transcription || null,
      categorie_proposee: categorie,        // null accepté
      fichier_url:        storagePath,      // on stocke le PATH (URL signée régénérable)
    });

    return {
      ok:          true,
      id:          inserted.id,
      categorie:   categorie,
      fichier_url: fichierUrl, // URL signée temporaire (pour info immédiate)
    };
  } catch (e) {
    console.error('Supabase saveToSupabase:', e.message);
    return { ok: false, error: e.message };
  }
}

module.exports = {
  isSupabaseEnabled,
  saveToSupabase,
  getSignedUrl,
  uploadFileToSupabase,
  insertTemoignage,
};

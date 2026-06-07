/**
 * app.js — Témoigne de moi v2
 * Helpers partagés entre toutes les pages front
 */
'use strict';

// ── Config dynamique ──────────────────────────────────────────────
window.TDM = window.TDM || {};

async function tdmLoadConfig() {
  try {
    const res = await fetch('/api/config');
    if (!res.ok) return;
    const cfg = await res.json();
    window.TDM.cfg = cfg;

    // Titre de page
    if (cfg.appTitle) document.title = cfg.appTitle;

    // Topbar logo + titre
    const icon  = document.getElementById('topbarIcon');
    const title = document.getElementById('topbarTitle');
    if (title && cfg.appTitle)  title.textContent = cfg.appTitle;
    if (icon  && cfg.logoDataUrl) {
      icon.innerHTML = `<img src="${cfg.logoDataUrl}" alt="Logo" style="width:22px;height:22px;border-radius:4px;object-fit:cover;" loading="lazy">`;
    }

    return cfg;
  } catch(e) {
    console.warn('TDM config load failed:', e.message);
    return {};
  }
}

// ── Toast ─────────────────────────────────────────────────────────
let _toastT;
function toast(msg, type = 'inf') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.className = `toast ${type} show`;
  el.textContent = msg;
  clearTimeout(_toastT);
  _toastT = setTimeout(() => el.classList.remove('show'), 3500);
}

// ── Helpers date/heure ────────────────────────────────────────────
function tdmPad(n) { return String(n).padStart(2, '0'); }

function tdmFormatDate(d) {
  return `${d.getFullYear()}-${tdmPad(d.getMonth() + 1)}-${tdmPad(d.getDate())}`;
}

function tdmFormatTime(d) {
  return `${tdmPad(d.getHours())}h${tdmPad(d.getMinutes())}m${tdmPad(d.getSeconds())}s`;
}

function tdmFormatDuration(sec) {
  return `${tdmPad(Math.floor(sec / 60))}:${tdmPad(sec % 60)}`;
}

// ── Favicon SVG inline ────────────────────────────────────────────
(function injectFavicon() {
  if (document.querySelector('link[rel="icon"]')) return;
  const link = document.createElement('link');
  link.rel  = 'icon';
  link.type = 'image/svg+xml';
  link.href = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect x='10' y='2' width='4' height='20' rx='1' fill='%23E8825A'/%3E%3Crect x='2' y='8' width='20' height='4' rx='1' fill='%23E8825A'/%3E%3C/svg%3E";
  document.head.appendChild(link);
})();

// Exporter en global
window.tdmLoadConfig   = tdmLoadConfig;
window.toast           = toast;
window.tdmPad          = tdmPad;
window.tdmFormatDate   = tdmFormatDate;
window.tdmFormatTime   = tdmFormatTime;
window.tdmFormatDuration = tdmFormatDuration;

// ── Mode sombre ───────────────────────────────────────────────────
(function initTheme() {
  const saved = localStorage.getItem('tdm_theme');
  if (saved) {
    document.documentElement.setAttribute('data-theme', saved);
  }
  // Pas d'attribut = détection auto via @media (prefers-color-scheme)
})();

function toggleTheme() {
  const root    = document.documentElement;
  const current = root.getAttribute('data-theme');
  const isDark  = current === 'dark' ||
    (!current && window.matchMedia('(prefers-color-scheme: dark)').matches);
  const next = isDark ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  localStorage.setItem('tdm_theme', next);
  // Mettre à jour l'icône de tous les boutons bascule
  document.querySelectorAll('.theme-toggle').forEach(btn => {
    btn.textContent = next === 'dark' ? '☀️' : '🌙';
    btn.title       = next === 'dark' ? 'Passer en mode clair' : 'Passer en mode sombre';
  });
}

function getThemeIcon() {
  const saved = localStorage.getItem('tdm_theme');
  const isDark = saved === 'dark' ||
    (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches);
  return isDark ? '☀️' : '🌙';
}

// Injecter le bouton bascule dans la topbar si elle existe
document.addEventListener('DOMContentLoaded', function() {
  const topbarRight = document.querySelector('.topbar-right');
  const topbar      = document.querySelector('.topbar');
  if (topbar && !document.querySelector('.theme-toggle')) {
    const btn = document.createElement('button');
    btn.className = 'theme-toggle';
    btn.textContent = getThemeIcon();
    btn.title = 'Changer de thème';
    btn.onclick = toggleTheme;
    if (topbarRight) {
      topbarRight.appendChild(btn);
    } else {
      // Créer un topbar-right si absent
      const div = document.createElement('div');
      div.className = 'topbar-right';
      div.appendChild(btn);
      topbar.appendChild(div);
    }
  }
});

// ── Footer RGPD partagé ───────────────────────────────────────────
function injectRgpdFooter(contactEmail) {
  // Ne pas injecter sur index (a son propre footer) ni admin/confidentialite
  const path = window.location.pathname;
  if (path === '/' || path === '/admin' || path === '/confidentialite') return;
  if (document.querySelector('.rgpd-footer-bar')) return;

  const email = contactEmail || '';
  const bar   = document.createElement('div');
  bar.className = 'rgpd-footer-bar';
  bar.style.cssText = 'text-align:center;padding:10px 16px 20px;font-size:.68rem;color:var(--muted);border-top:1px solid var(--border);display:flex;align-items:center;justify-content:center;gap:8px;flex-wrap:wrap;';
  bar.innerHTML = `
    <span>🛡️ Données religieuses — RGPD Art. 9</span>
    <span style="color:var(--border);">·</span>
    <a href="/confidentialite" style="color:var(--warm1);text-decoration:none;">Confidentialité</a>
    <span style="color:var(--border);">·</span>
    <a href="https://www.cnil.fr" target="_blank" rel="noopener" style="color:var(--warm1);text-decoration:none;">CNIL</a>
    ${email ? `<span style="color:var(--border);">·</span><a href="mailto:${email}" style="color:var(--warm1);text-decoration:none;">${email}</a>` : ''}
  `;
  document.body.appendChild(bar);
}

// Surcharger tdmLoadConfig pour injecter le footer auto
const _origLoadConfig = window.tdmLoadConfig;
window.tdmLoadConfig = async function() {
  const cfg = await _origLoadConfig();
  if (cfg) injectRgpdFooter(cfg.contactEmail);
  return cfg;
};

window.toggleTheme   = toggleTheme;
window.getThemeIcon  = getThemeIcon;

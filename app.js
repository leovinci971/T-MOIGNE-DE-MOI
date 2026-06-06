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

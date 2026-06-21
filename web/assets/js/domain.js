'use strict';

/* ── URL param ──────────────────────────────────────────────────────── */

const params = new URLSearchParams(window.location.search);
const domain = params.get('d');

if (!domain) {
  window.location.href = 'risk-board.html';
}

/* ── Constants ──────────────────────────────────────────────────────── */

const RISK_ORDER = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

/* ── Helpers ────────────────────────────────────────────────────────── */

/**
 * Format an ISO-8601 timestamp as "YYYY-MM-DD HH:MM UTC".
 * Returns '' if the value is falsy.
 */
function formatDateTime(isoStr) {
  if (!isoStr) return '';
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return isoStr;
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
         `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

/**
 * Format an ISO-8601 date string as "YYYY-MM-DD".
 */
function formatDate(isoStr) {
  if (!isoStr) return '';
  return isoStr.slice(0, 10);
}

/**
 * Build a single .infra-row div with a key label and value.
 * If value is null / undefined / '' the value span gets class .empty.
 */
function renderInfraRow(label, value) {
  const row = document.createElement('div');
  row.className = 'infra-row';

  const keySpan = document.createElement('span');
  keySpan.className = 'infra-key';
  keySpan.textContent = label;

  const valSpan = document.createElement('span');
  const isEmpty = (value === null || value === undefined || value === '');
  valSpan.className = isEmpty ? 'infra-val empty' : 'infra-val';
  valSpan.textContent = isEmpty ? '—' : value;

  row.appendChild(keySpan);
  row.appendChild(valSpan);
  return row;
}

/* ── Error display ──────────────────────────────────────────────────── */

function showError(domainStr, msg) {
  const box = document.getElementById('error-box');
  const msgEl = document.getElementById('error-message');
  if (box) box.style.display = 'block';
  if (msgEl) msgEl.textContent = msg;
  document.title = `whois-extracter — ${domainStr || 'error'}`;
}

/* ── Render functions ───────────────────────────────────────────────── */

function renderHeader(data) {
  const nameEl = document.getElementById('domain-name-display');
  if (nameEl) nameEl.textContent = data.domain || domain;

  const contribEl = document.getElementById('contributor-meta');
  if (contribEl) {
    const name = data.display_name || '';
    const loc  = data.display_loc  || '';
    if (name || loc) {
      contribEl.textContent = [name, loc].filter(Boolean).join(' · ');
    } else {
      contribEl.textContent = '';
    }
  }

  document.title = `whois-extracter — ${data.domain || domain}`;
}

function renderStats(data) {
  const analysis = data.analysis || {};
  const dates    = (data.parsed || {}).dates || {};

  const level = analysis.risk_level || 'INFO';
  const score = analysis.risk_score ?? '—';

  const scoreEl = document.getElementById('val-risk-score');
  if (scoreEl) {
    scoreEl.textContent = `${score}/100`;
    scoreEl.classList.add(`risk-${level}`);
  }

  const levelEl = document.getElementById('val-risk-level');
  if (levelEl) {
    levelEl.textContent = level;
    levelEl.classList.add(`risk-${level}`);
  }

  const signalsEl = document.getElementById('val-signals');
  if (signalsEl) {
    const signals = analysis.signals;
    signalsEl.textContent = Array.isArray(signals) ? signals.length : '0';
  }

  const ageEl = document.getElementById('val-age');
  if (ageEl) {
    ageEl.textContent = dates.age_days ?? '—';
  }
}

function renderQueriedAt(data) {
  const el = document.getElementById('queried-at');
  if (!el) return;
  const ts = data.last_refreshed || data.queried_at || '';
  el.textContent = ts ? formatDateTime(ts) : '—';
}

function renderDates(data) {
  const grid = document.getElementById('dates-grid');
  if (!grid) return;
  const d = (data.parsed || {}).dates || {};

  grid.appendChild(renderInfraRow('Created',          formatDate(d.creation)));
  grid.appendChild(renderInfraRow('Updated',          formatDate(d.updated)));
  grid.appendChild(renderInfraRow('Expires',          formatDate(d.expiry)));
  grid.appendChild(renderInfraRow('Age (days)',        d.age_days ?? null));
  grid.appendChild(renderInfraRow('Days to Expiry',   d.days_to_expiry ?? null));
}

function renderInfra(data) {
  const grid = document.getElementById('infra-grid');
  if (!grid) return;

  const parsed   = data.parsed   || {};
  const analysis = data.analysis || {};
  const reg      = parsed.registrar || {};
  const ns       = parsed.name_servers;

  const nsDisplay = Array.isArray(ns) && ns.length
    ? ns.join(' · ')
    : null;

  const statuses = parsed.statuses;
  const statusDisplay = Array.isArray(statuses) && statuses.length
    ? statuses.join(', ')
    : null;

  grid.appendChild(renderInfraRow('Registrar',       reg.name         || null));
  grid.appendChild(renderInfraRow('IANA ID',         reg.iana_id      || null));
  grid.appendChild(renderInfraRow('NS Type',         analysis.ns_type || null));
  grid.appendChild(renderInfraRow('Nameservers',     nsDisplay));
  grid.appendChild(renderInfraRow('DNSSEC',          parsed.dnssec    || null));
  grid.appendChild(renderInfraRow('EPP Statuses',    statusDisplay));
  grid.appendChild(renderInfraRow('Registrar Tier',  analysis.registrar_tier || null));
}

function renderContacts(data) {
  const grid = document.getElementById('contacts-grid');
  if (!grid) return;

  const contacts   = (data.parsed || {}).contacts || {};
  const registrant = contacts.registrant || {};

  const fields = {
    Name:    registrant.name,
    Org:     registrant.org,
    Email:   registrant.email,
    Phone:   registrant.phone,
    Country: registrant.country,
    State:   registrant.state,
    City:    registrant.city,
    Address: registrant.address,
  };

  const allNull = Object.values(fields).every(
    (v) => v === null || v === undefined || v === ''
  );

  if (allNull) {
    const row = document.createElement('div');
    row.className = 'infra-row';
    const span = document.createElement('span');
    span.className = 'infra-val empty';
    span.textContent = 'redacted (GDPR / privacy service)';
    row.appendChild(span);
    grid.appendChild(row);
    return;
  }

  for (const [label, value] of Object.entries(fields)) {
    if (value !== null && value !== undefined && value !== '') {
      grid.appendChild(renderInfraRow(label, value));
    }
  }
}

function renderSignals(data) {
  const list = document.getElementById('signals-list');
  if (!list) return;

  const signals = (data.analysis || {}).signals;
  if (!Array.isArray(signals) || !signals.length) {
    const empty = document.createElement('div');
    empty.className = 'signal-row';
    const span = document.createElement('span');
    span.className = 'signal-detail empty';
    span.textContent = 'No signals fired.';
    empty.appendChild(span);
    list.appendChild(empty);
    return;
  }

  const sorted = [...signals].sort((a, b) => {
    const ai = RISK_ORDER.indexOf(a.level || 'INFO');
    const bi = RISK_ORDER.indexOf(b.level || 'INFO');
    return ai - bi;
  });

  for (const sig of sorted) {
    const level = sig.level || 'INFO';

    const row = document.createElement('div');
    row.className = 'signal-row';

    const levelSpan = document.createElement('span');
    levelSpan.className = `signal-level risk-${level}`;
    levelSpan.textContent = level;

    const fieldSpan = document.createElement('span');
    fieldSpan.className = 'signal-field';
    fieldSpan.textContent = sig.field || '';

    const detailSpan = document.createElement('span');
    detailSpan.className = 'signal-detail';
    detailSpan.textContent = sig.detail || '';

    row.appendChild(levelSpan);
    row.appendChild(fieldSpan);
    row.appendChild(detailSpan);
    list.appendChild(row);
  }
}

/* ── Bootstrap ──────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', async () => {
  if (!domain) return; // already redirected above, guard for static analysis

  try {
    const res = await fetch(`data/domains/${encodeURIComponent(domain)}.json`);
    if (!res.ok) throw new Error(`HTTP ${res.status} — ${res.statusText}`);
    const data = await res.json();

    renderHeader(data);
    renderStats(data);
    renderQueriedAt(data);
    renderDates(data);
    renderInfra(data);
    renderContacts(data);
    renderSignals(data);
  } catch (err) {
    showError(domain, err.message || `Failed to load data for ${domain}`);
  }
});

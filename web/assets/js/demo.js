/**
 * demo.js — powers demo.html for whois-extracter
 * Fetches data/demo.json and renders the full whois analysis result.
 * Vanilla ES6, no frameworks.
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SIGNAL_ORDER = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

// ---------------------------------------------------------------------------
// Helper: renderInfraRow(label, value)
// Returns an infra-row div. Null/undefined/"" values render as em-dash.
// ---------------------------------------------------------------------------

function renderInfraRow(label, value) {
  const row = document.createElement('div');
  row.className = 'infra-row';

  const key = document.createElement('span');
  key.className = 'infra-key';
  key.textContent = label;

  const val = document.createElement('span');
  const isEmpty = value === null || value === undefined || value === '';
  val.className = isEmpty ? 'infra-val empty' : 'infra-val';
  val.textContent = isEmpty ? '—' : value;

  row.appendChild(key);
  row.appendChild(val);
  return row;
}

// ---------------------------------------------------------------------------
// Helper: formatDate(isoString) → "YYYY-MM-DD HH:MM UTC"
// ---------------------------------------------------------------------------

function formatDate(isoString) {
  if (!isoString) return null;
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return isoString;
  const yyyy = d.getUTCFullYear();
  const mm   = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd   = String(d.getUTCDate()).padStart(2, '0');
  const hh   = String(d.getUTCHours()).padStart(2, '0');
  const min  = String(d.getUTCMinutes()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd} ${hh}:${min} UTC`;
}

// ---------------------------------------------------------------------------
// Helper: formatShortDate(isoString) → "YYYY-MM-DD"
// ---------------------------------------------------------------------------

function formatShortDate(isoString) {
  if (!isoString) return null;
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return isoString;
  const yyyy = d.getUTCFullYear();
  const mm   = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd   = String(d.getUTCDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

// ---------------------------------------------------------------------------
// Render: #val-* summary cards
// ---------------------------------------------------------------------------

function renderSummaryCards(data) {
  const analysis = data.analysis;
  const parsed   = data.parsed;

  const riskScoreEl = document.getElementById('val-risk-score');
  if (riskScoreEl) {
    riskScoreEl.textContent = `${analysis.risk_score}/100`;
  }

  const riskLevelEl = document.getElementById('val-risk-level');
  if (riskLevelEl) {
    riskLevelEl.textContent = analysis.risk_level;
    // Remove any existing risk-* classes first
    SIGNAL_ORDER.forEach(lvl => riskLevelEl.classList.remove(`risk-${lvl}`));
    riskLevelEl.classList.add(`risk-${analysis.risk_level}`);
  }

  const signalsEl = document.getElementById('val-signals');
  if (signalsEl) {
    signalsEl.textContent = analysis.signals.length;
  }

  const ageEl = document.getElementById('val-age');
  if (ageEl) {
    const ageDays = parsed.dates && parsed.dates.age_days;
    ageEl.textContent = ageDays !== null && ageDays !== undefined ? `${ageDays} days` : '—';
  }
}

// ---------------------------------------------------------------------------
// Render: #queried-at
// ---------------------------------------------------------------------------

function renderQueriedAt(data) {
  const el = document.getElementById('queried-at');
  if (el) {
    el.textContent = formatDate(data.queried_at) || '—';
  }
}

// ---------------------------------------------------------------------------
// Render: #dates-grid
// ---------------------------------------------------------------------------

function renderDatesGrid(parsed) {
  const grid = document.getElementById('dates-grid');
  if (!grid) return;
  grid.innerHTML = '';

  const dates = parsed.dates || {};

  const rows = [
    ['Created',        formatShortDate(dates.creation)],
    ['Updated',        formatShortDate(dates.updated)],
    ['Expires',        formatShortDate(dates.expiry)],
    ['Age',            dates.age_days !== null && dates.age_days !== undefined
                         ? `${dates.age_days} days`
                         : null],
    ['Days to Expiry', dates.days_to_expiry !== null && dates.days_to_expiry !== undefined
                         ? `${dates.days_to_expiry} days`
                         : null],
  ];

  rows.forEach(([label, value]) => {
    grid.appendChild(renderInfraRow(label, value));
  });
}

// ---------------------------------------------------------------------------
// Render: #infra-grid
// ---------------------------------------------------------------------------

function renderInfraGrid(parsed, analysis) {
  const grid = document.getElementById('infra-grid');
  if (!grid) return;
  grid.innerHTML = '';

  const reg = parsed.registrar || {};
  const ns  = parsed.name_servers || [];

  const nsJoined       = ns.length > 0 ? ns.join(' · ') : null;
  const statusesJoined = (parsed.statuses || []).length > 0
    ? parsed.statuses.join(', ')
    : null;

  const rows = [
    ['Registrar',      reg.name   || null],
    ['IANA ID',        reg.iana_id || null],
    ['NS Type',        analysis.ns_type || null],
    ['Nameservers',    nsJoined],
    ['DNSSEC',         parsed.dnssec || null],
    ['EPP Statuses',   statusesJoined],
    ['Registrar Tier', analysis.registrar_tier || null],
  ];

  rows.forEach(([label, value]) => {
    grid.appendChild(renderInfraRow(label, value));
  });
}

// ---------------------------------------------------------------------------
// Render: #contacts-grid
// ---------------------------------------------------------------------------

function renderContactsGrid(parsed) {
  const grid = document.getElementById('contacts-grid');
  if (!grid) return;
  grid.innerHTML = '';

  const contacts   = parsed.contacts || {};
  const registrant = contacts.registrant || {};

  // Collect non-null fields from registrant
  const fieldLabels = {
    name:    'Name',
    org:     'Organisation',
    email:   'Email',
    phone:   'Phone',
    country: 'Country',
    address: 'Address',
    city:    'City',
    state:   'State',
    postal:  'Postal Code',
  };

  const nonNullEntries = Object.entries(fieldLabels)
    .filter(([key]) => registrant[key] !== null && registrant[key] !== undefined && registrant[key] !== '')
    .map(([key, label]) => [label, registrant[key]]);

  if (nonNullEntries.length === 0) {
    // All null — show redacted notice
    const row = document.createElement('div');
    row.className = 'infra-row';

    const key = document.createElement('span');
    key.className = 'infra-key';
    key.textContent = 'Registrant';

    const val = document.createElement('span');
    val.className = 'infra-val empty';
    val.textContent = 'redacted (GDPR / privacy service)';

    row.appendChild(key);
    row.appendChild(val);
    grid.appendChild(row);
  } else {
    nonNullEntries.forEach(([label, value]) => {
      grid.appendChild(renderInfraRow(label, value));
    });
  }
}

// ---------------------------------------------------------------------------
// Render: #signals-list
// ---------------------------------------------------------------------------

function renderSignals(analysis) {
  const list = document.getElementById('signals-list');
  if (!list) return;
  list.innerHTML = '';

  const signals = (analysis.signals || []).slice();

  // Sort: HIGH → MEDIUM → LOW → INFO, preserve original order within level
  signals.sort((a, b) => {
    const ai = SIGNAL_ORDER.indexOf(a.level);
    const bi = SIGNAL_ORDER.indexOf(b.level);
    const aIdx = ai === -1 ? SIGNAL_ORDER.length : ai;
    const bIdx = bi === -1 ? SIGNAL_ORDER.length : bi;
    return aIdx - bIdx;
  });

  signals.forEach(signal => {
    const row = document.createElement('div');
    row.className = 'signal-row';

    const badge = document.createElement('span');
    badge.className = `signal-level risk-${signal.level}`;
    badge.textContent = signal.level;

    const field = document.createElement('span');
    field.className = 'signal-field';
    field.textContent = signal.field || '';

    const detail = document.createElement('span');
    detail.className = 'signal-detail';
    detail.textContent = signal.detail || '';

    row.appendChild(badge);
    row.appendChild(field);
    row.appendChild(detail);
    list.appendChild(row);
  });
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

function showError(message) {
  const errorBox = document.getElementById('error-box');
  const errorMsg = document.getElementById('error-message');
  if (errorBox) {
    errorBox.style.display = 'block';
  }
  if (errorMsg) {
    errorMsg.textContent = message;
  }
}

// ---------------------------------------------------------------------------
// Main: fetch + render
// ---------------------------------------------------------------------------

async function init() {
  let data;

  try {
    const response = await fetch('data/demo.json');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }
    data = await response.json();
  } catch (err) {
    showError(`Failed to load demo.json: ${err.message}`);
    return;
  }

  try {
    renderQueriedAt(data);
    renderSummaryCards(data);
    renderDatesGrid(data.parsed);
    renderInfraGrid(data.parsed, data.analysis);
    renderContactsGrid(data.parsed);
    renderSignals(data.analysis);
  } catch (err) {
    showError(`Render error: ${err.message}`);
    console.error(err);
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', init);

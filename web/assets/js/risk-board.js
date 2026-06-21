'use strict';

const RISK_ORDER = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

function formatDate(isoStr) {
  if (!isoStr) return '';
  return isoStr.slice(0, 10);
}

function buildCard(entry) {
  const card = document.createElement('div');
  card.className = 'domain-card';
  card.dataset.domain = entry.domain;

  const date = formatDate(entry.queried_at || entry.last_refreshed);
  const level = entry.risk_level || 'INFO';
  const score = entry.risk_score ?? 0;

  card.innerHTML = `
    <div class="card-header-row">
      <span class="card-domain">${entry.domain}</span>
      <span class="card-date">${date}</span>
    </div>
    <div class="card-stats">
      <span class="card-stat risk-chip risk-${level}">${level} ${score}/100</span>
      <span class="card-stat">${entry.signals_count ?? 0} signals</span>
      <span class="card-stat">${entry.ns_type ?? ''}</span>
      <span class="card-stat">${entry.registrar_tier ?? ''} reg.</span>
      <span class="card-stat">${entry.age_days ?? 0} days old</span>
    </div>
    <div class="card-contributor">
      <span class="card-name">${entry.display_name ?? ''}</span>
      <span>${entry.display_loc ?? ''}</span>
    </div>
  `;

  card.addEventListener('click', () => {
    window.location.href = `domain.html?d=${encodeURIComponent(entry.domain)}`;
  });

  return card;
}

function buildHeading(level) {
  const h = document.createElement('div');
  h.className = `rb-level-heading risk-${level}`;
  h.dataset.level = level;
  h.textContent = level === 'INFO' ? 'INFO' : `${level} RISK`;
  return h;
}

function renderDomains(domains) {
  const list = document.getElementById('domain-list');
  list.innerHTML = '';

  const sorted = [...domains].sort((a, b) => {
    const ai = RISK_ORDER.indexOf(a.risk_level || 'INFO');
    const bi = RISK_ORDER.indexOf(b.risk_level || 'INFO');
    if (ai !== bi) return ai - bi;
    return (a.domain || '').localeCompare(b.domain || '');
  });

  const groups = {};
  for (const level of RISK_ORDER) groups[level] = [];
  for (const entry of sorted) {
    const level = entry.risk_level || 'INFO';
    if (!groups[level]) groups[level] = [];
    groups[level].push(entry);
  }

  for (const level of RISK_ORDER) {
    if (!groups[level].length) continue;

    const heading = buildHeading(level);
    list.appendChild(heading);

    for (const entry of groups[level]) {
      list.appendChild(buildCard(entry));
    }
  }
}

function updateSearchCount() {
  const cards = document.querySelectorAll('#domain-list .domain-card');
  let visible = 0;
  for (const card of cards) {
    if (card.style.display !== 'none') visible++;
  }
  const el = document.getElementById('search-count');
  if (el) el.textContent = visible;
}

function updateHeadingVisibility() {
  const headings = document.querySelectorAll('#domain-list .rb-level-heading');
  for (const heading of headings) {
    const level = heading.dataset.level;
    const cards = document.querySelectorAll(
      `#domain-list .domain-card[data-domain]`
    );
    // Find cards that belong to this level heading: those between this heading
    // and the next heading in DOM order.
    let sibling = heading.nextElementSibling;
    let anyVisible = false;
    while (sibling && !sibling.classList.contains('rb-level-heading')) {
      if (sibling.classList.contains('domain-card') && sibling.style.display !== 'none') {
        anyVisible = true;
        break;
      }
      sibling = sibling.nextElementSibling;
    }
    heading.style.display = anyVisible ? '' : 'none';
  }
}

function applySearch(term) {
  const lower = term.toLowerCase().trim();
  const cards = document.querySelectorAll('#domain-list .domain-card');
  for (const card of cards) {
    const domain = (card.dataset.domain || '').toLowerCase();
    card.style.display = (!lower || domain.includes(lower)) ? '' : 'none';
  }
  updateHeadingVisibility();
  updateSearchCount();
}

function showError(msg) {
  const box = document.getElementById('error-box');
  const msgEl = document.getElementById('error-message');
  if (box) box.style.display = 'block';
  if (msgEl) msgEl.textContent = msg;
}

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const res = await fetch('data/index.json');
    if (!res.ok) throw new Error(`HTTP ${res.status} — ${res.statusText}`);
    const data = await res.json();

    const statsEl = document.getElementById('rb-stats');
    if (statsEl) {
      statsEl.textContent = `${data.total_domains} domains · ${data.total_scans} scans indexed`;
    }

    renderDomains(data.domains || []);
    updateSearchCount();

    const searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.addEventListener('keyup', () => {
        applySearch(searchInput.value);
      });
    }
  } catch (err) {
    showError(err.message || 'Failed to load index.json');
  }
});

'use strict';

const severityWeights = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const activeFilters = new Set(['critical', 'high', 'medium', 'low', 'info']);

// ── Theme ───────────────────────────────────────────────────────

function initTheme() {
  const saved = localStorage.getItem('huginn-theme');
  const preferred = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  applyTheme(saved || preferred);
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('huginn-theme', theme);
  const btn = document.getElementById('theme-toggle');
  if (!btn) return;
  const label = btn.querySelector('span:first-child');
  const icon  = btn.querySelector('.theme-toggle-icon');
  if (theme === 'dark') {
    if (label) label.textContent = 'Dark Mode';
    if (icon)  icon.textContent  = '☽';
  } else {
    if (label) label.textContent = 'Light Mode';
    if (icon)  icon.textContent  = '☀';
  }
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'dark' ? 'light' : 'dark');
}

// ── Severity filter buttons ─────────────────────────────────────

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const sev = btn.dataset.severity;
    if (activeFilters.has(sev)) {
      if (activeFilters.size > 1) {
        activeFilters.delete(sev);
        btn.classList.remove('active');
      }
    } else {
      activeFilters.add(sev);
      btn.classList.add('active');
    }
    applyFilters();
  });
});

function setOnlyFilter(sev) {
  activeFilters.clear();
  if (sev === 'all') {
    ['critical', 'high', 'medium', 'low', 'info'].forEach(s => activeFilters.add(s));
  } else {
    activeFilters.add(sev);
  }
  document.querySelectorAll('.filter-btn').forEach(btn => {
    const active = sev === 'all' || btn.dataset.severity === sev;
    btn.classList.toggle('active', active);
  });
  applyFilters();
}

function applyFilters() {
  document.querySelectorAll('.finding-row').forEach(row => {
    row.style.display = activeFilters.has(row.dataset.severity) ? '' : 'none';
  });
  document.querySelectorAll('.finding-card').forEach(card => {
    card.style.display = activeFilters.has(card.dataset.severity) ? '' : 'none';
  });
}

// ── Summary card clicks → filter + scroll ──────────────────────

document.querySelectorAll('.summary-card[data-filter]').forEach(card => {
  card.addEventListener('click', e => {
    e.preventDefault();
    const filter = card.dataset.filter;
    setOnlyFilter(filter);
    const findingsSection = document.getElementById('findings');
    if (findingsSection) {
      findingsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// ── Table sort ──────────────────────────────────────────────────

let sortCol = 'severity';
let sortDir = -1;

document.querySelectorAll('th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.sort;
    if (!th.classList.contains('sortable')) return;

    document.querySelectorAll('th[data-sort]').forEach(h => {
      h.textContent = h.textContent.replace(/ [▲▼]$/, '');
    });

    if (sortCol === col) {
      sortDir *= -1;
    } else {
      sortCol = col;
      sortDir = col === 'severity' ? -1 : 1;
    }

    th.textContent += sortDir === -1 ? ' ▼' : ' ▲';
    sortTable();
  });
});

function sortTable() {
  const tbody = document.getElementById('findings-tbody');
  if (!tbody) return;
  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a, b) => {
    const aVal = (a.dataset[sortCol] || '').toLowerCase();
    const bVal = (b.dataset[sortCol] || '').toLowerCase();
    if (sortCol === 'severity') {
      return sortDir * ((severityWeights[bVal] || 0) - (severityWeights[aVal] || 0));
    }
    return sortDir * aVal.localeCompare(bVal);
  });
  rows.forEach(r => tbody.appendChild(r));
}

// ── Finding row click → expand card + scroll ───────────────────

document.querySelectorAll('.finding-row').forEach(row => {
  row.addEventListener('click', () => {
    const cardId = 'card-' + row.dataset.card;
    const card = document.getElementById(cardId);
    if (!card) return;

    // Ensure visible (might be filtered out by severity filter in card list)
    if (card.style.display === 'none') {
      card.style.display = '';
    }

    if (!card.classList.contains('expanded')) {
      card.classList.add('expanded');
    }

    card.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Pulse highlight
    card.classList.remove('highlight');
    void card.offsetWidth; // force reflow to restart animation
    card.classList.add('highlight');
    setTimeout(() => card.classList.remove('highlight'), 1400);
  });
});

// ── Finding accordion ───────────────────────────────────────────

document.querySelectorAll('.finding-header').forEach(header => {
  header.addEventListener('click', () => {
    header.closest('.finding-card').classList.toggle('expanded');
  });
});

// Auto-expand the first few critical/high findings
let autoExpanded = 0;
document.querySelectorAll('.finding-card').forEach(card => {
  const sev = card.dataset.severity;
  if (autoExpanded < 3 && (sev === 'critical' || sev === 'high')) {
    card.classList.add('expanded');
    autoExpanded++;
  }
});

// ── Service table filter ────────────────────────────────────────

function filterServices(query) {
  const q = query.toLowerCase();
  document.querySelectorAll('#svc-table .svc-row').forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(q) ? '' : 'none';
  });
}

// ── Smooth sidebar navigation ───────────────────────────────────

document.querySelectorAll('.nav-list a').forEach(link => {
  link.addEventListener('click', e => {
    const href = link.getAttribute('href');
    if (href && href.startsWith('#')) {
      e.preventDefault();
      const target = document.querySelector(href);
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// ── Highlight active nav section on scroll ──────────────────────

const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.nav-list a');

function updateActiveNav() {
  // Find the last section whose top edge is at or above 120px from the viewport top.
  // This fires the highlight as soon as the section title scrolls into view,
  // not when the previous section leaves.
  const threshold = 120;
  let current = sections[0];
  sections.forEach(section => {
    if (section.getBoundingClientRect().top <= threshold) {
      current = section;
    }
  });
  navLinks.forEach(link => link.classList.remove('active'));
  if (current) {
    const active = document.querySelector(`.nav-list a[href="#${current.id}"]`);
    if (active) active.classList.add('active');
  }
}

window.addEventListener('scroll', updateActiveNav, { passive: true });
updateActiveNav();

// ── Init ────────────────────────────────────────────────────────

initTheme();

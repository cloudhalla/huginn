'use strict';

const severityWeights = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const activeFilters = new Set(['critical', 'high', 'medium', 'low', 'info']);

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

function applyFilters() {
  document.querySelectorAll('.finding-row').forEach(row => {
    row.style.display = activeFilters.has(row.dataset.severity) ? '' : 'none';
  });
  document.querySelectorAll('.finding-card').forEach(card => {
    card.style.display = activeFilters.has(card.dataset.severity) ? '' : 'none';
  });
}

// ── Table sort ──────────────────────────────────────────────────

let sortCol = 'severity';
let sortDir = -1;

document.querySelectorAll('th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.sort;
    if (!th.classList.contains('sortable')) return;

    // Clear sort indicators from all headers
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

// ── Smooth sidebar navigation ───────────────────────────────────

document.querySelectorAll('.nav-list a').forEach(link => {
  link.addEventListener('click', e => {
    const href = link.getAttribute('href');
    if (href && href.startsWith('#')) {
      e.preventDefault();
      const target = document.querySelector(href);
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
  });
});

// ── Highlight active nav section on scroll ──────────────────────

const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.nav-list a');

const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      navLinks.forEach(link => {
        link.style.color = '';
        link.style.borderLeftColor = '';
      });
      const active = document.querySelector(`.nav-list a[href="#${entry.target.id}"]`);
      if (active) {
        active.style.color = 'var(--text)';
        active.style.borderLeftColor = 'var(--accent)';
      }
    }
  });
}, { threshold: 0.2 });

sections.forEach(s => observer.observe(s));

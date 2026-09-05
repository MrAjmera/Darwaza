// Darwaza dashboard -- vanilla JS, no build step, no framework.
// Talks only to the API this same FastAPI process already serves
// (same-origin, since dashboard/ is mounted on the app itself). Every
// fetch here hits an endpoint that already exists for the CLI/API's
// own sake, plus the two dashboard-only additions documented in
// api.py (GET /v1/audit-log, POST /v1/demo/simulate/{scenario}).

(function () {
  'use strict';

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $all = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  let isOnline = null; // null = unknown yet, true/false once we've asked

  async function api(path, opts) {
    const res = await fetch(path, opts);
    if (!res.ok && res.status >= 500) throw new Error('server error ' + res.status);
    return res;
  }

  function setConnection(ok) {
    if (ok === isOnline) return;
    isOnline = ok;
    const pill = $('#conn-status');
    const text = $('#conn-text');
    const banner = $('#offline-banner');
    pill.classList.toggle('ok', ok);
    pill.classList.toggle('bad', !ok);
    text.textContent = ok ? 'live' : 'offline';
    banner.style.display = ok ? 'none' : 'flex';
  }

  // ---------------------------------------------------------------
  // Tabs
  // ---------------------------------------------------------------
  // Diagram panels are only rendered by Mermaid the first time they
  // become visible. mermaid.run() measures text via real DOM layout --
  // an element still sitting under display:none (any tab that hasn't
  // been opened yet) has no layout box, so rendering it at page load
  // (before the user ever switches tabs) fails with a misleading
  // "Syntax error in text" that has nothing to do with the diagram
  // source. Rendering on first activation, once the panel is already
  // display:block, sidesteps that entirely.
  const MERMAID_PANELS = new Set(['hld', 'lld']);
  const mermaidRendered = new Set();

  async function renderMermaidIfNeeded(name) {
    if (!MERMAID_PANELS.has(name) || mermaidRendered.has(name) || !window.mermaid) return;
    mermaidRendered.add(name);
    try {
      await window.mermaid.run({ querySelector: '#panel-' + name + ' pre.mermaid' });
    } catch (e) {
      // Leave the raw diagram source visible rather than an opaque
      // failure state -- still readable, just not drawn.
      mermaidRendered.delete(name);
      console.error('mermaid render failed for panel', name, e);
    }
  }

  function initTabs() {
    const buttons = $all('.tabbtn');
    function activate(name, pushHash) {
      buttons.forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
      $all('.panel').forEach((p) => p.classList.toggle('active', p.id === 'panel-' + name));
      if (pushHash) history.replaceState(null, '', '#' + name);
      if (name === 'audit') refreshAudit();
      if (name === 'approvals') refreshApprovals();
      if (name === 'overview') refreshOverview();
      renderMermaidIfNeeded(name);
    }
    buttons.forEach((b) => b.addEventListener('click', () => activate(b.dataset.tab, true)));
    const initial = (location.hash || '#overview').slice(1);
    if ($('#panel-' + initial)) activate(initial, false);
  }

  // ---------------------------------------------------------------
  // Overview + top bar counters
  // ---------------------------------------------------------------
  // Two genuinely different numbers, both real -- see
  // DECISIONS.md #15. /metrics' `counters` is in-process memory: it
  // resets to zero on every restart, which looks like data loss if
  // it's the headline number and the server gets restarted mid-demo.
  // The audit log is the durable, cumulative one -- everything this
  // gate has ever decided, across every restart -- so it's what the
  // header and the big tiles show. The in-process count is still
  // surfaced, just clearly labeled as "since this server started"
  // rather than presented as the total.
  function tallyOutcomes(entries) {
    const tally = { ALLOW: 0, DENY: 0, NEEDS_HUMAN: 0 };
    entries.forEach((e) => { if (tally[e.outcome] !== undefined) tally[e.outcome]++; });
    return tally;
  }

  async function refreshOverview() {
    try {
      const [metricsRes, auditRes] = await Promise.all([api('/metrics'), api('/v1/audit-log?limit=500')]);
      setConnection(true);
      const metrics = await metricsRes.json();
      const audit = await auditRes.json();
      const allTime = tallyOutcomes(audit.entries);
      const sessionByOutcome = metrics.counters.by_outcome || {};

      $('#tc-allow').textContent = allTime.ALLOW;
      $('#tc-deny').textContent = allTime.DENY;
      $('#tc-human').textContent = allTime.NEEDS_HUMAN;
      $('#ov-allow').textContent = allTime.ALLOW;
      $('#ov-deny').textContent = allTime.DENY;
      $('#ov-human').textContent = allTime.NEEDS_HUMAN;
      $('#ov-entries').textContent = audit.total_entries;

      $('#ov-session-line').textContent =
        'Since this server process last started: ' + (sessionByOutcome.ALLOW ?? 0) + ' ALLOW, ' +
        (sessionByOutcome.DENY ?? 0) + ' DENY, ' + (sessionByOutcome.NEEDS_HUMAN ?? 0) +
        ' NEEDS_HUMAN (in-process only -- resets on restart, see /metrics).';

      const chainOk = audit.chain_intact;
      const chainPill = $('#ov-chain-pill');
      chainPill.textContent = chainOk ? 'chain intact' : 'chain BROKEN';
      chainPill.className = 'pill ' + (chainOk ? 'allow' : 'deny');
      $('#ov-chain-detail').textContent = chainOk
        ? audit.total_entries + ' entries verified, none tampered.'
        : (audit.chain_break_reason || 'see Audit Trail tab');
    } catch (e) {
      setConnection(false);
    }
  }

  // ---------------------------------------------------------------
  // Live Demo
  // ---------------------------------------------------------------
  const SCENARIO_LABEL = {
    'happy-path': 'Happy path',
    'poisoned-catalog': 'Poisoned catalog',
    'needs-human': 'Large legitimate purchase',
  };

  function outcomeClass(outcome) {
    if (outcome === 'ALLOW') return 'allow';
    if (outcome === 'DENY') return 'deny';
    return 'human';
  }

  function renderDemoResult(body) {
    const container = $('#demo-results');
    if ($('.empty', container)) container.innerHTML = '';

    const card = document.createElement('div');
    card.className = 'result fresh';
    const cls = outcomeClass(body.outcome);
    const time = new Date().toLocaleTimeString();

    card.innerHTML =
      '<div class="result-head">' +
        '<span class="pill ' + cls + '">' + body.outcome + '</span>' +
        '<span class="result-meta">' + SCENARIO_LABEL[body.scenario] + ' · ' + time + '</span>' +
      '</div>' +
      '<p style="margin:0; font-size:13.5px;">' + escapeHtml(body.reason) + '</p>' +
      '<dl class="kv">' +
        (body.failed_check ? '<dt>failed_check</dt><dd><code>' + body.failed_check + '</code></dd>' : '') +
        '<dt>mandate_id</dt><dd><code>' + escapeHtml(body.mandate_id) + '</code></dd>' +
        '<dt>proposed</dt><dd>' + '₹' + body.proposed_tx.amount + ' · ' + escapeHtml(body.proposed_tx.category || '—') + ' · ' + escapeHtml(body.proposed_tx.merchant_id) + '</dd>' +
        (body.request_id ? '<dt>request_id</dt><dd><code>' + body.request_id + '</code> — see Approvals tab</dd>' : '') +
        (body.explanation ? '<dt>explanation</dt><dd>' + escapeHtml(body.explanation) + '</dd>' : '') +
      '</dl>';

    container.prepend(card);
  }

  function escapeHtml(s) {
    if (s === undefined || s === null) return '';
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function initDemoButtons() {
    $all('#panel-demo [data-scenario]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const scenario = btn.dataset.scenario;
        btn.disabled = true;
        const originalText = btn.textContent;
        btn.innerHTML = 'Running<span class="loading-dots"></span>';
        try {
          const res = await api('/v1/demo/simulate/' + scenario, { method: 'POST' });
          setConnection(true);
          const body = await res.json();
          renderDemoResult(body);
          refreshOverview();
        } catch (e) {
          setConnection(false);
        } finally {
          btn.disabled = false;
          btn.textContent = originalText;
        }
      });
    });
  }

  // ---------------------------------------------------------------
  // Approvals
  // ---------------------------------------------------------------
  async function refreshApprovals() {
    try {
      const [pendingRes, execRes] = await Promise.all([
        api('/v1/approvals'),
        api('/v1/approvals/pending-execution'),
      ]);
      setConnection(true);
      renderPending(await pendingRes.json());
      renderPendingExecution(await execRes.json());
    } catch (e) {
      setConnection(false);
    }
  }

  function renderPending(rows) {
    const el = $('#approvals-pending');
    if (!rows.length) {
      el.innerHTML = '<div class="empty">Nothing waiting on a human right now.</div>';
      return;
    }
    el.innerHTML = rows.map((row) => (
      '<div class="result">' +
        '<div class="result-head">' +
          '<span class="pill human">NEEDS_HUMAN</span>' +
          '<span class="result-meta">' + escapeHtml(row.mandate_id) + '</span>' +
        '</div>' +
        '<p style="margin:0 0 10px 0; font-size:13.5px;">' + escapeHtml(row.explanation || row.reason || '') + '</p>' +
        '<div class="btnrow" style="margin:0;">' +
          '<button class="btn allow-btn small" data-approve="' + row.id + '">Approve</button>' +
          '<button class="btn deny-btn small" data-deny="' + row.id + '">Deny</button>' +
        '</div>' +
      '</div>'
    )).join('');

    $all('[data-approve]', el).forEach((b) => b.addEventListener('click', () => resolveApproval(b.dataset.approve, true)));
    $all('[data-deny]', el).forEach((b) => b.addEventListener('click', () => resolveApproval(b.dataset.deny, false)));
  }

  function renderPendingExecution(rows) {
    const el = $('#approvals-pending-execution');
    if (!rows.length) {
      el.innerHTML = '<div class="empty">Nothing waiting on Razorpay execution.</div>';
      return;
    }
    el.innerHTML = rows.map((row) => (
      '<div class="result">' +
        '<div class="result-head">' +
          '<span class="pill neutral">approved, not executed</span>' +
          '<span class="result-meta">' + escapeHtml(row.mandate_id) + '</span>' +
        '</div>' +
        '<p style="margin:0 0 10px 0; font-size:13px;">' + escapeHtml(row.last_execution_error || 'No execution attempted yet.') + '</p>' +
        '<div class="btnrow" style="margin:0;">' +
          '<button class="btn small" data-execute="' + row.id + '">Retry execute</button>' +
        '</div>' +
      '</div>'
    )).join('');

    $all('[data-execute]', el).forEach((b) => b.addEventListener('click', () => executeApproval(b.dataset.execute)));
  }

  async function resolveApproval(id, approved) {
    try {
      await api('/v1/approvals/' + id + '/' + (approved ? 'approve' : 'deny'), { method: 'POST' });
      setConnection(true);
    } catch (e) {
      setConnection(false);
    }
    refreshApprovals();
    refreshOverview();
  }

  async function executeApproval(id) {
    try {
      await api('/v1/approvals/' + id + '/execute', { method: 'POST' });
      setConnection(true);
    } catch (e) {
      setConnection(false);
    }
    refreshApprovals();
  }

  // ---------------------------------------------------------------
  // Audit trail
  // ---------------------------------------------------------------
  async function refreshAudit() {
    try {
      const res = await api('/v1/audit-log?limit=50');
      setConnection(true);
      const data = await res.json();

      const pill = $('#audit-chain-pill');
      pill.textContent = data.chain_intact ? 'chain intact' : 'chain BROKEN';
      pill.className = 'pill ' + (data.chain_intact ? 'allow' : 'deny');
      $('#audit-chain-detail').textContent = data.chain_intact
        ? data.total_entries + ' entries, verified end to end.'
        : (data.chain_break_reason || '');

      const tbody = $('#audit-rows');
      if (!data.entries.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No decisions recorded yet — trigger one from Live Demo.</td></tr>';
        return;
      }
      tbody.innerHTML = data.entries.map((e) => (
        '<tr>' +
          '<td><code>' + e.seq + '</code></td>' +
          '<td><span class="pill ' + outcomeClass(e.outcome) + '">' + e.outcome + '</span></td>' +
          '<td><code>' + escapeHtml(e.mandate_id) + '</code></td>' +
          '<td>' + (e.failed_check ? '<code>' + e.failed_check + '</code>' : '—') + '</td>' +
          '<td style="font-family:var(--font-mono); font-size:11.5px; white-space:nowrap;">' + new Date(e.timestamp).toLocaleString() + '</td>' +
          '<td style="font-family:var(--font-mono); font-size:11px; color:var(--ink-faint);">' + e.prev_hash.slice(0, 10) + '…</td>' +
        '</tr>'
      )).join('');
    } catch (e) {
      setConnection(false);
    }
  }

  // ---------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initDemoButtons();
    $('#audit-refresh').addEventListener('click', refreshAudit);

    if (window.mermaid) {
      const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      // startOnLoad: false -- see renderMermaidIfNeeded() above for why
      // diagrams are rendered on first tab activation instead.
      mermaid.initialize({ startOnLoad: false, theme: dark ? 'dark' : 'default', securityLevel: 'loose', fontFamily: 'IBM Plex Sans' });
    }

    refreshOverview();
    // Light polling so the top counters and whichever tab is open stay
    // current without a manual refresh -- 5s is frequent enough to feel
    // live in a demo, far below anything that would look like load
    // testing your own gateway.
    setInterval(() => {
      const activeTab = $('.tabbtn.active').dataset.tab;
      refreshOverview();
      if (activeTab === 'audit') refreshAudit();
      if (activeTab === 'approvals') refreshApprovals();
    }, 5000);
  });
})();

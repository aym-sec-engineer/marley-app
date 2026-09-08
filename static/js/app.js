  (function () {
    'use strict';

    // ── Horloge ──────────────────────────────────────────────────
    const clockEl = document.getElementById('clock');
    function tickClock() {
      clockEl.textContent = new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
    tickClock();
    setInterval(tickClock, 1000);

    // ── Helpers ──────────────────────────────────────────────────
    function fmt_uptime(seconds) {
      const d = Math.floor(seconds / 86400);
      const h = Math.floor((seconds % 86400) / 3600);
      const m = Math.floor((seconds % 3600) / 60);
      if (d > 0) return `${d}j ${h}h`;
      if (h > 0) return `${h}h ${m}m`;
      return `${m}m`;
    }

    function sev_badge(sev) {
      if (sev === 'high')    return '<span class="badge-high px-2 py-0.5 rounded-full text-[10px] font-mono font-medium">HIGH</span>';
      if (sev === 'warning') return '<span class="badge-warn px-2 py-0.5 rounded-full text-[10px] font-mono font-medium">WARN</span>';
      return '<span class="badge-info px-2 py-0.5 rounded-full text-[10px] font-mono font-medium">INFO</span>';
    }

    function cpu_color(pct) {
      if (pct >= 80) return 'text-red-400';
      if (pct >= 55) return 'text-orange-400';
      return 'text-green-400';
    }

    // ── Chart.js setup ───────────────────────────────────────────
    const ctx = document.getElementById('timeline-chart').getContext('2d');
    let timelineChart = null;

    function build_chart(data) {
      const cfg = {
        type: 'line',
        data: {
          labels: data.labels,
          datasets: [
            {
              label: 'Logs analysés',
              data: data.datasets.logs_analyzed,
              borderColor: 'rgba(34,211,238,0.85)',
              backgroundColor: 'rgba(34,211,238,0.06)',
              borderWidth: 1.5,
              pointRadius: 0,
              tension: 0.4,
              fill: true,
            },
            {
              label: 'Décisions actives',
              data: data.datasets.active_decisions,
              borderColor: 'rgba(251,113,133,0.85)',
              backgroundColor: 'rgba(251,113,133,0.06)',
              borderWidth: 1.5,
              pointRadius: 0,
              tension: 0.4,
              fill: true,
            },
            {
              label: 'WAF',
              data: data.datasets.waf,
              borderColor: 'rgba(251,146,60,0.85)',
              backgroundColor: 'rgba(251,146,60,0.06)',
              borderWidth: 1.5,
              pointRadius: 0,
              tension: 0.4,
              fill: true,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: 'index', intersect: false },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: '#161d2e',
              borderColor: 'rgba(148,163,184,0.12)',
              borderWidth: 1,
              titleColor: '#94a3b8',
              bodyColor: '#e2e8f0',
              titleFont: { family: 'JetBrains Mono', size: 10 },
              bodyFont: { family: 'JetBrains Mono', size: 11 },
              padding: 10,
            },
          },
          scales: {
            x: {
              ticks: {
                color: '#475569',
                font: { family: 'JetBrains Mono', size: 9 },
                maxTicksLimit: 12,
                maxRotation: 0,
              },
              grid: { color: 'rgba(148,163,184,0.06)' },
              border: { color: 'rgba(148,163,184,0.08)' },
            },
            y: {
              beginAtZero: true,
              ticks: {
                color: '#475569',
                font: { family: 'JetBrains Mono', size: 9 },
                precision: 0,
              },
              grid: { color: 'rgba(148,163,184,0.06)' },
              border: { color: 'rgba(148,163,184,0.08)' },
            },
          },
        },
      };

      if (timelineChart) {
        timelineChart.data = cfg.data;
        timelineChart.update('none');
      } else {
        timelineChart = new Chart(ctx, cfg);
      }
    }

    // ── Status pill ───────────────────────────────────────────────
    function update_status_pill(status) {
      const pill = document.getElementById('status-pill');
      const lbl  = document.getElementById('status-label');
      pill.className = 'flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-mono font-medium ';
      if (status === 'NOMINAL')       { pill.className += 'pill-secure'; }
      else if (status === 'ELEVATED') { pill.className += 'pill-elevated'; }
      else                             { pill.className += 'pill-alert'; }
      lbl.textContent = status;
    }

    // ── Render: /api/v1/status ────────────────────────────────────
    function render_status(d) {
      update_status_pill(d.global_status || 'UNKNOWN');

      // CrowdSec : déclenchements, alertes conservées et décisions actives
      const cs = d.crowdsec ?? {};

      const triggers24h = cs.scenario_triggers_24h;
      const retainedAlerts = cs.retained_alerts;
      const activeDecisions = cs.active_decisions;

      document.getElementById('kpi-cs-triggers').textContent =
        triggers24h ?? '—';

      const triggersSource =
        cs.metrics?.scenario_triggers_24h ?? 'unavailable';

      document.getElementById('kpi-cs-source').textContent =
        `dernières 24 h · ${data_source_label(triggersSource)}`;

      document.getElementById('cs-triggers-24h').textContent =
        triggers24h ?? '—';

      document.getElementById('cs-retained-alerts').textContent =
        retainedAlerts ?? '—';

      document.getElementById('cs-active-decisions').textContent =
        activeDecisions ?? '—';

      const csHealth = document.getElementById('crowdsec-health');
      const operational = cs.status === 'operational';

      csHealth.textContent = operational
        ? '● OPÉRATIONNEL'
        : (cs.status === 'degraded' ? '● DÉGRADÉ' : '● INDISPONIBLE');

      csHealth.className =
        'ml-auto px-2 py-0.5 rounded-full text-[10px] font-mono font-medium border ' +
        (operational
          ? 'bg-green-500/10 text-green-400 border-green-500/20'
          : 'bg-amber-500/10 text-amber-400 border-amber-500/20');

      document.getElementById('cs-source-label').textContent =
        `source: ${data_source_label(cs.data_source)} · Prometheus + LAPI`;

      document.getElementById('cs-community-label').textContent =
        `threat intel communautaire: ${
          cs.community_blocklist_count == null
            ? '—'
            : cs.community_blocklist_count.toLocaleString('fr-FR') + ' décisions actives'
        }`;

      // KPI: CPU
      const cpu = d.host?.cpu_percent ?? 0;
      document.getElementById('kpi-cpu').textContent = `${cpu}%`;
      document.getElementById('bar-cpu').style.width = `${Math.min(cpu, 100)}%`;

      // KPI: RAM
      const mem = d.host?.mem_percent ?? 0;
      document.getElementById('kpi-mem').textContent = `${mem}%`;
      document.getElementById('bar-mem').style.width = `${Math.min(mem, 100)}%`;

      // KPI: Uptime
      document.getElementById('kpi-uptime').textContent = fmt_uptime(d.host?.uptime_seconds ?? 0);

      // Firewall
      const ports = d.firewall?.open_ports ?? [];
      document.getElementById('fw-engine').textContent = d.firewall?.engine ?? 'nftables';
      document.getElementById('fw-ports').innerHTML = ports.map(p => `
        <li class="flex items-center justify-between px-3 py-2 rounded-xl bg-cyber-surface-2 border border-cyber-border">
          <span class="font-mono text-[11px] text-cyan-300">:${p.port}</span>
          <span class="text-[11px] text-slate-300">${p.service}</span>
          <span class="text-[10px] text-slate-500 hidden sm:inline truncate max-w-[100px]">${p.auth}</span>
        </li>
      `).join('') || '<li class="text-xs text-slate-500 px-3 py-2">Aucun port trouvé</li>';

      // WAF
      document.getElementById('waf-engine').textContent    = d.waf?.engine ?? '—';
      document.getElementById('waf-engine-val').textContent = d.waf?.engine ?? '—';
      document.getElementById('waf-ruleset').textContent    = d.waf?.ruleset ?? '—';
      document.getElementById('waf-mode').textContent       = d.waf?.mode ?? '—';
      document.getElementById('waf-mode-badge').textContent = (d.waf?.mode ?? 'BLOCKING').toUpperCase();

      // Last sync
      const now = new Date();
      document.getElementById('last-sync').textContent =
        `Dernière sync : ${now.toLocaleTimeString('fr-FR')}`;
    }

    // ── Render: /api/v1/events ────────────────────────────────────
    function render_events(d) {
      const events = d.events ?? [];
      document.getElementById('events-count').textContent = `${events.length} events`;

      if (!events.length) {
        document.getElementById('events-tbody').innerHTML =
          '<tr><td colspan="5" class="px-5 py-8 text-center text-slate-500 font-mono text-xs">Aucun événement</td></tr>';
        return;
      }

      document.getElementById('events-tbody').innerHTML = events.map(ev => {
        const ts = new Date(ev.timestamp);
        const time_str = ts.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        return `
          <tr class="hover:bg-cyber-surface-2/50 transition-colors">
            <td class="px-5 py-2.5 whitespace-nowrap">${sev_badge(ev.severity)}</td>
            <td class="px-5 py-2.5 hidden sm:table-cell font-mono text-[10px] text-slate-400 whitespace-nowrap">${ev.source_ip || '—'}</td>
            <td class="px-5 py-2.5 whitespace-nowrap">
              <span class="font-medium text-slate-200 text-[11px]">${ev.event_type || '—'}</span>
              <span class="block font-mono text-[9px] text-slate-600">${time_str}</span>
            </td>
            <td class="px-5 py-2.5 hidden lg:table-cell text-slate-400 text-[11px] max-w-[200px] truncate">${ev.message || '—'}</td>
            <td class="px-5 py-2.5 hidden xl:table-cell font-mono text-[10px] text-slate-500 whitespace-nowrap">${ev.action || '—'}</td>
          </tr>`;
      }).join('');
    }

    // Provenance explicite des données exposées par l'API.
    function data_source_label(source) {
      const labels = {
        live: '🟢 live',
        configured: '🔵 configured',
        simulated: '🟡 simulated',
        unavailable: '🔴 unavailable',
        not_instrumented: '⚪ not instrumented',
      };
      return labels[source] ?? `⚪ ${source || 'unknown'}`;
    }

    // ── Render: /api/v1/containers ────────────────────────────────
    function render_containers(d) {
      const containers = d.containers ?? [];
      document.getElementById('containers-source').textContent =
        data_source_label(d.data_source);

      if (!containers.length) {
        document.getElementById('containers-list').innerHTML =
          '<div class="px-5 py-8 text-center text-slate-500 font-mono text-xs">Aucun conteneur</div>';
        return;
      }

      document.getElementById('containers-list').innerHTML = containers.map(c => {
        const cpu_cls = cpu_color(c.cpu_percent);
        const cpuW = Math.min(c.cpu_percent, 100).toFixed(0);
        const memBounded = Number.isFinite(c.mem_percent);
        const memW = memBounded ? Math.min(c.mem_percent, 100).toFixed(0) : '0';
        const memLabel = memBounded
          ? `${c.mem_usage_mb}M · ${c.mem_percent}%`
          : `${c.mem_usage_mb}M · unbounded`;
        return `
          <div class="px-5 py-3.5 hover:bg-cyber-surface-2/50 transition-colors">
            <div class="flex items-start justify-between gap-2 mb-2">
              <div class="min-w-0">
                <p class="text-xs font-semibold text-slate-200 font-mono truncate">${c.name}</p>
                <p class="text-[10px] text-slate-500 truncate">${c.role}</p>
              </div>
              <span class="px-1.5 py-0.5 rounded text-[9px] font-mono flex-shrink-0 ${
                c.status === 'running'
                  ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                  : 'bg-red-500/10 text-red-400 border border-red-500/20'
              }">${c.status}</span>
            </div>
            <div class="space-y-1.5">
              <div class="flex items-center gap-2 text-[10px]">
                <span class="text-slate-500 w-8">CPU</span>
                <div class="flex-1 h-1 rounded-full bg-cyber-bg overflow-hidden">
                  <div class="h-full rounded-full bg-cyan-500 bar-fill" style="width:${cpuW}%"></div>
                </div>
                <span class="${cpu_cls} font-mono w-10 text-right">${c.cpu_percent}%</span>
              </div>
              <div class="flex items-center gap-2 text-[10px]">
                <span class="text-slate-500 w-8">RAM</span>
                <div class="flex-1 h-1 rounded-full bg-cyber-bg overflow-hidden">
                  <div class="h-full rounded-full bg-violet-500 bar-fill" style="width:${memW}%"></div>
                </div>
                <span class="text-slate-400 font-mono min-w-[92px] text-right">${memLabel}</span>
              </div>
            </div>
          </div>`;
      }).join('');
    }

    // ── Render: vue dédiée Events (onglet) ─────────────────────────
    function render_events_full(d) {
      const events = d.events ?? [];
      document.getElementById('events-count-full').textContent = `${events.length} events`;

      if (!events.length) {
        document.getElementById('events-tbody-full').innerHTML =
          '<tr><td colspan="7" class="px-5 py-8 text-center text-slate-500 font-mono text-xs">Aucun événement</td></tr>';
        return;
      }

      document.getElementById('events-tbody-full').innerHTML = events.map(ev => {
        const ts = new Date(ev.timestamp);
        const time_str = ts.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        return `
          <tr class="hover:bg-cyber-surface-2/50 transition-colors">
            <td class="px-5 py-2.5 whitespace-nowrap">${sev_badge(ev.severity)}</td>
            <td class="px-5 py-2.5 font-mono text-[10px] text-slate-400 whitespace-nowrap">${ev.source_ip || '—'}</td>
            <td class="px-5 py-2.5 whitespace-nowrap font-medium text-slate-200 text-[11px]">${ev.event_type || '—'}</td>
            <td class="px-5 py-2.5 font-mono text-[10px] text-slate-500 whitespace-nowrap">${ev.scenario || '—'}</td>
            <td class="px-5 py-2.5 text-slate-400 text-[11px] max-w-[260px] truncate">${ev.message || '—'}</td>
            <td class="px-5 py-2.5 font-mono text-[10px] text-slate-500 whitespace-nowrap">${ev.action || '—'}</td>
            <td class="px-5 py-2.5 font-mono text-[9px] text-slate-600 whitespace-nowrap">${time_str}</td>
          </tr>`;
      }).join('');
    }

    // ── Render: vue dédiée Conteneurs (onglet) ──────────────────────
    function render_containers_full(d) {
      const containers = d.containers ?? [];
      document.getElementById('containers-source-full').textContent =
        data_source_label(d.data_source);

      const grid = document.getElementById('containers-grid-full');
      if (!containers.length) {
        grid.innerHTML = '<div class="col-span-full px-5 py-8 text-center text-slate-500 font-mono text-xs">Aucun conteneur</div>';
        return;
      }

      grid.innerHTML = containers.map(c => {
        const cpu_cls = cpu_color(c.cpu_percent);
        const cpuW = Math.min(c.cpu_percent, 100).toFixed(0);
        const memBounded = Number.isFinite(c.mem_percent);
        const memW = memBounded ? Math.min(c.mem_percent, 100).toFixed(0) : '0';
        const memLabel = memBounded
          ? `${c.mem_usage_mb}M · ${c.mem_percent}%`
          : `${c.mem_usage_mb}M · unbounded`;
        return `
          <div class="bg-cyber-surface-2 border border-cyber-border rounded-xl p-4">
            <div class="flex items-start justify-between gap-2 mb-3">
              <div class="min-w-0">
                <p class="text-sm font-semibold text-slate-200 font-mono truncate">${c.name}</p>
                <p class="text-[11px] text-slate-500 truncate">${c.role}</p>
              </div>
              <span class="px-1.5 py-0.5 rounded text-[9px] font-mono flex-shrink-0 ${
                c.status === 'running'
                  ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                  : 'bg-red-500/10 text-red-400 border border-red-500/20'
              }">${c.status}</span>
            </div>
            <p class="text-[10px] font-mono text-slate-500 truncate mb-3">${c.image || '—'}</p>
            <div class="space-y-2">
              <div class="flex items-center gap-2 text-[10px]">
                <span class="text-slate-500 w-8">CPU</span>
                <div class="flex-1 h-1 rounded-full bg-cyber-bg overflow-hidden">
                  <div class="h-full rounded-full bg-cyan-500 bar-fill" style="width:${cpuW}%"></div>
                </div>
                <span class="${cpu_cls} font-mono w-10 text-right">${c.cpu_percent}%</span>
              </div>
              <div class="flex items-center gap-2 text-[10px]">
                <span class="text-slate-500 w-8">RAM</span>
                <div class="flex-1 h-1 rounded-full bg-cyber-bg overflow-hidden">
                  <div class="h-full rounded-full bg-violet-500 bar-fill" style="width:${memW}%"></div>
                </div>
                <span class="text-slate-400 font-mono min-w-[92px] text-right">${memLabel}</span>
              </div>
            </div>
          </div>`;
      }).join('');
    }

    // ── Render: vue dédiée Réseau (onglet) ──────────────────────────
    function render_network(d) {
      const networks = d.networks ?? [];
      const container = document.getElementById('section-network');

      if (!networks.length) {
        container.innerHTML = '<div class="col-span-full px-5 py-8 text-center text-slate-500 font-mono text-xs">Aucun réseau trouvé</div>';
        return;
      }

      container.innerHTML = networks.map(net => {
        const badge = net.internal
          ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-orange-500/10 text-orange-400 border border-orange-500/20">INTERNAL</span>'
          : '<span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-green-500/10 text-green-400 border border-green-500/20">EXTERNAL</span>';
        const containersList = (net.containers ?? []).map(c => `
          <li class="flex items-center justify-between px-3 py-2 rounded-xl bg-cyber-surface-2 border border-cyber-border">
            <span class="font-mono text-[11px] text-cyan-300 truncate">${c.name}</span>
            <span class="font-mono text-[10px] text-slate-500 flex-shrink-0">${c.ipv4}</span>
          </li>`).join('') || '<li class="text-xs text-slate-500 px-3 py-2">Aucun conteneur</li>';

        return `
          <div class="bg-cyber-surface border border-cyber-border rounded-2xl p-5 space-y-4">
            <div class="flex items-center gap-2.5">
              <div class="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
                <i data-lucide="network" class="w-4 h-4 text-cyan-400"></i>
              </div>
              <div class="min-w-0">
                <p class="text-sm font-semibold text-slate-100 font-mono truncate">${net.name}</p>
                <p class="text-[10px] font-mono text-slate-500">${net.driver} · ${net.subnet}</p>
              </div>
              <div class="ml-auto flex-shrink-0">${badge}</div>
            </div>
            <ul class="space-y-2">${containersList}</ul>
          </div>`;
      }).join('');

      lucide.createIcons();
    }

    // ── Render: vue dédiée Compliance (onglet) ──────────────────────
    function render_compliance(d) {
      const trivy = d.trivy ?? {};
      const zap = d.zap ?? {};
      const headers = d.security_headers ?? {};

      // Trivy
      document.getElementById('trivy-target').textContent = trivy.target || '—';
      document.getElementById('trivy-date').textContent = trivy.scan_date
        ? `Dernier scan : ${new Date(trivy.scan_date).toLocaleString('fr-FR')}`
        : 'Aucun scan enregistré';

      const trivySeverities = [
        { key: 'critical', label: 'CRITICAL', cls: 'text-red-400 border-red-500/20 bg-red-500/10' },
        { key: 'high',     label: 'HIGH',     cls: 'text-orange-400 border-orange-500/20 bg-orange-500/10' },
        { key: 'medium',   label: 'MEDIUM',   cls: 'text-yellow-400 border-yellow-500/20 bg-yellow-500/10' },
        { key: 'low',      label: 'LOW',      cls: 'text-cyan-400 border-cyan-500/20 bg-cyan-500/10' },
        { key: 'unknown',  label: 'UNKNOWN',  cls: 'text-slate-400 border-slate-500/20 bg-slate-500/10' },
      ];
      document.getElementById('trivy-grid').innerHTML = trivySeverities.map(s => `
        <div class="rounded-xl border p-3 text-center ${s.cls}">
          <p class="font-display text-xl font-bold">${trivy[s.key] ?? 0}</p>
          <p class="text-[9px] font-mono uppercase tracking-widest mt-1 opacity-80">${s.label}</p>
        </div>
      `).join('');

      // ZAP
      document.getElementById('zap-target').textContent = zap.target || '—';
      document.getElementById('zap-date').textContent = zap.scan_date
        ? `Dernier scan : ${new Date(zap.scan_date).toLocaleString('fr-FR')}`
        : 'Aucun scan enregistré';

      const zapMetrics = [
        { key: 'fail_new', label: 'FAIL-NEW', cls: 'text-red-400 border-red-500/20 bg-red-500/10' },
        { key: 'warn_new', label: 'WARN-NEW', cls: 'text-orange-400 border-orange-500/20 bg-orange-500/10' },
        { key: 'pass',     label: 'PASS',     cls: 'text-green-400 border-green-500/20 bg-green-500/10' },
      ];
      document.getElementById('zap-grid').innerHTML = zapMetrics.map(m => `
        <div class="rounded-xl border p-3 text-center ${m.cls}">
          <p class="font-display text-xl font-bold">${zap[m.key] ?? 0}</p>
          <p class="text-[9px] font-mono uppercase tracking-widest mt-1 opacity-80">${m.label}</p>
        </div>
      `).join('');

      // Headers HTTP
      const headerEntries = Object.entries(headers);
      document.getElementById('headers-list').innerHTML = headerEntries.map(([name, value]) => `
        <li class="px-3 py-2.5 rounded-xl bg-cyber-surface-2 border border-cyber-border">
          <div class="flex items-center justify-between gap-3 mb-1">
            <span class="font-mono text-[11px] text-cyan-300">${name}</span>
            <span class="px-1.5 py-0.5 rounded text-[9px] font-mono bg-green-500/10 text-green-400 border border-green-500/20 flex-shrink-0">APPLIQUÉ</span>
          </div>
          <p class="font-mono text-[10px] text-slate-500 break-all">${value}</p>
        </li>
      `).join('') || '<li class="text-xs text-slate-500 px-3 py-2">Aucun header trouvé</li>';
    }

    // ── Render: vue dédiée Paramètres (onglet) ──────────────────────
    function render_settings(d) {
      const groups = [
        { title: 'Application', icon: 'app-window', data: d.app },
        { title: 'Réseau / Pare-feu', icon: 'flame', data: d.network },
        { title: 'WAF', icon: 'layers', data: d.waf },
        { title: 'CrowdSec', icon: 'shield-alert', data: d.crowdsec },
        { title: 'Seuils de statut global', icon: 'gauge', data: d.thresholds },
      ];

      const container = document.getElementById('section-settings');
      container.innerHTML = groups.map(g => {
        const rows = Object.entries(g.data ?? {}).map(([key, value]) => `
          <div class="flex items-center justify-between text-xs py-1.5">
            <span class="text-slate-400 font-mono">${key}</span>
            <span class="font-mono text-slate-200">${value}</span>
          </div>
        `).join('');
        return `
          <div class="bg-cyber-surface border border-cyber-border rounded-2xl p-5 space-y-3">
            <div class="flex items-center gap-2.5 mb-2">
              <div class="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
                <i data-lucide="${g.icon}" class="w-4 h-4 text-cyan-400"></i>
              </div>
              <p class="text-sm font-semibold text-slate-100">${g.title}</p>
            </div>
            <div class="divide-y divide-cyber-border">${rows}</div>
          </div>`;
      }).join('');

      lucide.createIcons();
    }

    // ── Render: /api/v1/timeline ──────────────────────────────────
    function render_timeline(d) {
      build_chart(d);
      document.getElementById('total-cs').textContent        = d.totals?.logs_analyzed ?? 0;
      document.getElementById('total-decisions').textContent = d.totals?.active_decisions ?? 0;
      document.getElementById('total-waf').textContent       = d.totals?.waf ?? 0;
    }

    // ── Fetch all endpoints ───────────────────────────────────────
    async function fetch_all() {
      try {
        const [status, events, containers, network, compliance, settings, timeline] = await Promise.all([
          fetch('/api/v1/status').then(r => r.json()),
          fetch('/api/v1/events?limit=30').then(r => r.json()),
          fetch('/api/v1/containers').then(r => r.json()),
          fetch('/api/v1/network').then(r => r.json()),
          fetch('/api/v1/compliance').then(r => r.json()),
          fetch('/api/v1/settings').then(r => r.json()),
          fetch('/api/v1/timeline?hours=24').then(r => r.json()),
        ]);
        render_status(status);
        render_events(events);
        render_events_full(events);
        render_containers(containers);
        render_containers_full(containers);
        render_network(network);
        render_compliance(compliance);
        render_settings(settings);
        render_timeline(timeline);
      } catch (err) {
        console.error('[Marley] Fetch error:', err);
        document.getElementById('last-sync').textContent = 'Erreur de synchronisation';
      }
    }

    // ── Init & polling (30s) ──────────────────────────────────────

    // ── Navigation par onglets (sidebar) ────────────────────────────
    const tabLinks = document.querySelectorAll('[data-tab]');
    const mainSections = document.querySelectorAll('main > section');
    const placeholder = document.getElementById('tab-placeholder');

    function switch_tab(tab) {
      const dedicatedIds = ['tab-placeholder', 'section-events-full', 'section-containers-full', 'section-network', 'section-compliance', 'section-settings', 'section-profile'];

      if (tab === 'overview') {
        mainSections.forEach(s => { if (!dedicatedIds.includes(s.id)) s.classList.remove('hidden'); });
        dedicatedIds.forEach(id => document.getElementById(id).classList.add('hidden'));
      } else if (tab === 'events') {
        mainSections.forEach(s => s.classList.add('hidden'));
        document.getElementById('section-events-full').classList.remove('hidden');
      } else if (tab === 'containers') {
        mainSections.forEach(s => s.classList.add('hidden'));
        document.getElementById('section-containers-full').classList.remove('hidden');
      } else if (tab === 'network') {
        mainSections.forEach(s => s.classList.add('hidden'));
        document.getElementById('section-network').classList.remove('hidden');
      } else if (tab === 'compliance') {
        mainSections.forEach(s => s.classList.add('hidden'));
        document.getElementById('section-compliance').classList.remove('hidden');
        lucide.createIcons();
      } else if (tab === 'settings') {
        mainSections.forEach(s => s.classList.add('hidden'));
        document.getElementById('section-settings').classList.remove('hidden');
        lucide.createIcons();
      } else if (tab === 'profile') {
        mainSections.forEach(s => s.classList.add('hidden'));
        document.getElementById('section-profile').classList.remove('hidden');
        lucide.createIcons();
      } else {
        mainSections.forEach(s => s.classList.add('hidden'));
        placeholder.classList.remove('hidden');
      }

      tabLinks.forEach(l => {
        const active = l.dataset.tab === tab;
        l.classList.toggle('bg-cyan-500/10', active);
        l.classList.toggle('text-cyan-300', active);
        l.classList.toggle('border', active);
        l.classList.toggle('border-cyan-500/20', active);
        l.classList.toggle('text-slate-400', !active);
      });
    }

    tabLinks.forEach(l => {
      l.addEventListener('click', (e) => {
        e.preventDefault();
        switch_tab(l.dataset.tab);
      });
    });

    document.getElementById('profile-card-trigger').addEventListener('click', () => switch_tab('profile'));
    document.getElementById('header-profile-trigger').addEventListener('click', () => switch_tab('profile'));

    lucide.createIcons();
    fetch_all();
    setInterval(fetch_all, 30_000);

  }());

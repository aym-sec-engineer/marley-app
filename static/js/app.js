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
      // Encode une valeur texte pour son insertion dans nos fragments HTML.
      // textContent délègue l'encodage au DOM plutôt qu'à une liste artisanale.
      function escape_html(value) {
        const node = document.createElement('span');
        node.textContent = String(value ?? '');
        return node.innerHTML;
      }

    function fmt_uptime(seconds) {
      const d = Math.floor(seconds / 86400);
      const h = Math.floor((seconds % 86400) / 3600);
      const m = Math.floor((seconds % 3600) / 60);
      if (d > 0) return `${d}j ${h}h`;
      if (h > 0) return `${h}h ${m}m`;
      return `${m}m`;
    }

    function decision_action_badge(action) {
      const value = String(action ?? 'unknown').toUpperCase();
      return `<span class="px-2 py-1 rounded-md text-[10px] font-mono font-medium bg-cyber-surface-2 text-slate-300 border border-cyber-border">${escape_html(value)}</span>`;
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
              data: data.datasets?.logs_analyzed ?? [],
              borderColor: 'rgba(125, 211, 252, 0.88)',
              backgroundColor: 'rgba(125, 211, 252, 0.05)',
              borderWidth: 1.5,
              pointRadius: 0,
              tension: 0.32,
              fill: true,
              yAxisID: 'y',
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
                color: '#64748b',
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
      lbl.textContent = `CROWDSEC · ${status}`;
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

      document.getElementById('timeline-lapi-decisions').textContent =
        activeDecisions ?? '—';

      const csHealth = document.getElementById('crowdsec-health');
      const operational = cs.status === 'operational';

      csHealth.textContent = operational
        ? '● OPÉRATIONNEL'
        : (cs.status === 'degraded' ? '● DÉGRADÉ' : '● INDISPONIBLE');

      csHealth.className =
        'px-2 py-1 rounded-md text-[10px] font-mono font-medium border ' +
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

      // KPI hôte : null signifie indisponible, jamais 0 par défaut.
      const cpu = d.host?.cpu_percent;
      const cpuAvailable = Number.isFinite(cpu);
      document.getElementById('kpi-cpu').textContent =
        cpuAvailable ? `${cpu}%` : '—';
      document.getElementById('bar-cpu').value =
        cpuAvailable ? Math.min(cpu, 100) : 0;

      const mem = d.host?.mem_percent;
      const memAvailable = Number.isFinite(mem);
      document.getElementById('kpi-mem').textContent =
        memAvailable ? `${mem}%` : '—';
      document.getElementById('bar-mem').value =
        memAvailable ? Math.min(mem, 100) : 0;

      const disk = d.host?.disk_percent;
      const diskAvailable = Number.isFinite(disk);

      document.getElementById('kpi-disk').textContent =
        diskAvailable ? `${disk}%` : '—';

      document.getElementById('bar-disk').value =
        diskAvailable ? Math.min(disk, 100) : 0;

      const uptime = d.host?.uptime_seconds;

      document.getElementById('kpi-host-meta').textContent =
        Number.isFinite(uptime)
          ? `uptime ${fmt_uptime(uptime)}`
          : 'uptime —';

      // Firewall
      const ports = d.firewall?.open_ports ?? [];
      document.getElementById('fw-engine').textContent = d.firewall?.engine ?? 'nftables';
      document.getElementById('fw-ports').innerHTML = ports.map(p => `
        <li class="flex items-center justify-between px-3 py-2 rounded-xl bg-cyber-surface-2 border border-cyber-border">
          <span class="font-mono text-[11px] text-cyan-300">:${escape_html(p.port)}</span>
          <span class="text-[11px] text-slate-300">${escape_html(p.service)}</span>
          <span class="text-[10px] text-slate-500 hidden sm:inline truncate max-w-[100px]">${escape_html(p.auth)}</span>
        </li>
      `).join('') || '<li class="text-xs text-slate-500 px-3 py-2">Aucun port trouvé</li>';

      // WAF
      document.getElementById('waf-engine').textContent    = d.waf?.engine ?? '—';
      document.getElementById('waf-engine-val').textContent = d.waf?.engine ?? '—';
      document.getElementById('waf-ruleset').textContent    = d.waf?.ruleset ?? '—';
      document.getElementById('waf-mode').textContent =
        d.waf?.mode ?? '—';

      document.getElementById('waf-mode-badge').textContent =
        d.waf?.data_source === 'configured'
          ? 'CONFIGURÉ'
          : data_source_label(d.waf?.data_source);

      document.getElementById('waf-source').textContent =
        data_source_label(d.waf?.data_source);

      // Last sync
      const now = new Date();
      document.getElementById('last-sync').textContent =
        `Dernière sync : ${now.toLocaleTimeString('fr-FR')}`;
    }

    // ── Render: /api/v1/events ────────────────────────────────────
    function render_events(d) {
      const events = d.events ?? [];
      const source = d.data_source ?? 'unavailable';

      document.getElementById('events-count').textContent =
        source === 'live'
          ? `${events.length} actives`
          : 'indisponible';

      if (source !== 'live') {
        document.getElementById('events-tbody').innerHTML =
          '<tr><td colspan="5" class="px-5 py-8 text-center text-slate-500 text-xs">Télémétrie CrowdSec locale indisponible. L’absence de lignes ne signifie pas qu’aucune activité de sécurité n’a eu lieu.</td></tr>';
        return;
      }

      if (!events.length) {
        document.getElementById('events-tbody').innerHTML =
          '<tr><td colspan="5" class="px-5 py-8 text-center text-slate-500 text-xs"><strong class="text-slate-300 font-medium">Aucune décision locale active.</strong><br><span class="text-slate-500">Des alertes ou déclenchements peuvent avoir eu lieu précédemment.</span></td></tr>';
        return;
      }

      document.getElementById('events-tbody').innerHTML =
        events.map(ev => {
          const ts = ev.observed_at
            ? new Date(ev.observed_at)
            : null;

          const observed =
            ts && !Number.isNaN(ts.getTime())
              ? ts.toLocaleTimeString(
                  'fr-FR',
                  {
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                  }
                )
              : '—';

          return `
            <tr class="hover:bg-cyber-surface-2/50 transition-colors">
              <td class="px-5 py-2.5 whitespace-nowrap">${decision_action_badge(ev.action)}</td>
              <td class="px-5 py-2.5 hidden sm:table-cell font-mono text-[11px] text-slate-400 whitespace-nowrap">${escape_html(ev.source_ip || '—')}</td>
              <td class="px-5 py-2.5 whitespace-nowrap">
                <span class="font-medium text-slate-200 text-[12px]">${escape_html(ev.scenario || '—')}</span>
                <span class="block font-mono text-[10px] text-slate-600">${escape_html(ev.origin || '—')}</span>
              </td>
              <td class="px-5 py-2.5 hidden lg:table-cell text-slate-400 text-[12px] max-w-[200px] truncate">${escape_html(ev.message || '—')}</td>
              <td class="px-5 py-2.5 hidden xl:table-cell font-mono text-[11px] text-slate-500 whitespace-nowrap">${observed}</td>
            </tr>`;
        }).join('');
    }

    // Provenance explicite des données exposées par l'API.
    function data_source_label(source) {
      const labels = {
        live: 'LIVE',
        partial: 'PARTIEL',
        configured: 'CONFIGURÉ',
        recorded_scan: 'PREUVE ENREGISTRÉE',
        simulated: 'SIMULÉ',
        unavailable: 'INDISPONIBLE',
        not_instrumented: 'NON INSTRUMENTÉ',
      };

      return labels[source] ?? String(source || 'INCONNU').toUpperCase();
    }

    // ── Render: /api/v1/containers ────────────────────────────────
    function render_containers(d) {
      const containers = d.containers ?? [];

      document.getElementById('containers-source').textContent =
        data_source_label(d.data_source);

      if (d.data_source !== 'live') {
        document.getElementById('containers-list').innerHTML =
          '<div class="px-5 py-8 text-center text-slate-500 text-xs">Télémétrie cAdvisor / Prometheus indisponible.</div>';
        return;
      }

      if (!containers.length) {
        document.getElementById('containers-list').innerHTML =
          '<div class="px-5 py-8 text-center text-slate-500 text-xs">Aucun workload actuellement observé par cAdvisor.</div>';
        return;
      }

      document.getElementById('containers-list').innerHTML =
        containers.map(c => {
          const cpu = Number.isFinite(c.cpu_percent)
            ? `${c.cpu_percent}%`
            : '—';

          const mem = Number.isFinite(c.mem_percent)
            ? `${c.mem_usage_mb} MB · ${c.mem_percent}%`
            : `${c.mem_usage_mb ?? '—'} MB · limite non définie`;

          return `
            <div class="px-5 py-4 hover:bg-cyber-surface-2/40 transition-colors">
              <div class="flex items-start justify-between gap-4">

                <div class="min-w-0">
                  <p class="text-[12px] font-semibold text-slate-200 font-mono truncate">
                    ${escape_html(c.name)}
                  </p>

                  <p class="text-[11px] text-slate-500 mt-1 truncate">
                    ${escape_html(c.role)}
                  </p>
                </div>

                <span class="px-2 py-1 rounded-md text-[10px] font-mono text-slate-400 bg-cyber-surface-2 border border-cyber-border flex-shrink-0">
                  OBSERVÉ
                </span>
              </div>

              <div class="grid grid-cols-2 gap-4 mt-4">
                <div>
                  <p class="text-[10px] uppercase tracking-[0.10em] text-slate-600">
                    CPU
                  </p>
                  <p class="text-[12px] font-mono text-slate-300 mt-1">
                    ${cpu}
                  </p>
                </div>

                <div>
                  <p class="text-[10px] uppercase tracking-[0.10em] text-slate-600">
                    Mémoire
                  </p>
                  <p class="text-[12px] font-mono text-slate-300 mt-1 truncate">
                    ${mem}
                  </p>
                </div>
              </div>

            </div>`;
        }).join('');
    }

    // ── Render: vue dédiée Events (onglet) ─────────────────────────
    function render_events_full(d) {
      const events = d.events ?? [];
      const source = d.data_source ?? 'unavailable';
      const cards =
        document.getElementById('events-cards-full');

      document.getElementById('events-count-full').textContent =
        source === 'live'
          ? `${events.length} actives`
          : 'indisponible';

      if (source !== 'live') {
        const unavailableCopy =
          'Télémétrie CrowdSec locale indisponible. Cette vue ne peut pas conclure à une absence d’activité.';

        document.getElementById('events-tbody-full').innerHTML =
          `<tr><td colspan="7" class="px-5 py-8 text-center text-slate-500 text-xs">${unavailableCopy}</td></tr>`;

        if (cards) {
          cards.innerHTML =
            `<div class="px-5 py-8 text-center text-slate-500 text-xs">${unavailableCopy}</div>`;
        }

        return;
      }

      if (!events.length) {
        const emptyCopy =
          '<strong class="text-slate-300 font-medium">Aucune décision locale active.</strong><br><span class="text-slate-500">Ce snapshot ne constitue pas un historique des alertes CrowdSec.</span>';

        document.getElementById('events-tbody-full').innerHTML =
          `<tr><td colspan="7" class="px-5 py-8 text-center text-slate-500 text-xs">${emptyCopy}</td></tr>`;

        if (cards) {
          cards.innerHTML =
            `<div class="px-5 py-8 text-center text-xs leading-relaxed">${emptyCopy}</div>`;
        }

        return;
      }

      if (cards) {
        cards.innerHTML =
          events.map(ev => {
            const ts = ev.observed_at
              ? new Date(ev.observed_at)
              : null;

            const observed =
              ts && !Number.isNaN(ts.getTime())
                ? ts.toLocaleTimeString(
                    'fr-FR',
                    {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                    }
                  )
                : '—';

            return `
              <article class="px-4 py-4">
                <div class="flex items-start justify-between gap-3">
                  <div class="min-w-0">
                    <p class="text-[12px] font-semibold text-slate-200 break-words">
                      ${escape_html(ev.scenario || ev.event_type || 'Décision CrowdSec')}
                    </p>

                    <p class="font-mono text-[11px] text-slate-500 mt-1">
                      ${escape_html(ev.source_ip || '—')}
                    </p>
                  </div>

                  ${decision_action_badge(ev.action)}
                </div>

                <dl class="grid grid-cols-2 gap-3 mt-4 text-[11px]">
                  <div>
                    <dt class="text-slate-600">
                      Origine
                    </dt>
                    <dd class="font-mono text-slate-400 mt-1 break-all">
                      ${escape_html(ev.origin || '—')}
                    </dd>
                  </div>

                  <div>
                    <dt class="text-slate-600">
                      Observée à
                    </dt>
                    <dd class="font-mono text-slate-400 mt-1">
                      ${observed}
                    </dd>
                  </div>
                </dl>

                ${
                  ev.message
                    ? `<p class="text-[11px] text-slate-500 leading-relaxed mt-4">${escape_html(ev.message)}</p>`
                    : ''
                }
              </article>`;
          }).join('');
      }

      document.getElementById('events-tbody-full').innerHTML =
        events.map(ev => {
          const ts = ev.observed_at
            ? new Date(ev.observed_at)
            : null;

          const observed =
            ts && !Number.isNaN(ts.getTime())
              ? ts.toLocaleTimeString(
                  'fr-FR',
                  {
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                  }
                )
              : '—';

          return `
            <tr class="hover:bg-cyber-surface-2/50 transition-colors">
              <td class="px-5 py-2.5 whitespace-nowrap">${decision_action_badge(ev.action)}</td>
              <td class="px-5 py-2.5 font-mono text-[11px] text-slate-400 whitespace-nowrap">${escape_html(ev.source_ip || '—')}</td>
              <td class="px-5 py-2.5 whitespace-nowrap font-medium text-slate-200 text-[12px]">${escape_html(ev.event_type || '—')}</td>
              <td class="px-5 py-2.5 font-mono text-[11px] text-slate-500 whitespace-nowrap">${escape_html(ev.scenario || '—')}</td>
              <td class="px-5 py-2.5 text-slate-400 text-[12px] max-w-[320px] truncate">${escape_html(ev.message || '—')}</td>
              <td class="px-5 py-2.5 font-mono text-[11px] text-slate-500 whitespace-nowrap">${escape_html(ev.origin || '—')}</td>
              <td class="px-5 py-2.5 font-mono text-[11px] text-slate-600 whitespace-nowrap">${observed}</td>
            </tr>`;
        }).join('');
    }

    // ── Render: vue dédiée Conteneurs (onglet) ──────────────────────
    function render_containers_full(d) {
      const containers = d.containers ?? [];

      document.getElementById('containers-source-full').textContent =
        data_source_label(d.data_source);

      const grid =
        document.getElementById('containers-grid-full');

      if (d.data_source !== 'live') {
        grid.innerHTML =
          '<div class="col-span-full px-5 py-8 text-center text-slate-500 text-xs">Télémétrie cAdvisor / Prometheus indisponible.</div>';
        return;
      }

      if (!containers.length) {
        grid.innerHTML =
          '<div class="col-span-full px-5 py-8 text-center text-slate-500 text-xs">Aucun workload actuellement observé par cAdvisor.</div>';
        return;
      }

      grid.innerHTML =
        containers.map(c => {
          const cpu = Number.isFinite(c.cpu_percent)
            ? `${c.cpu_percent}%`
            : '—';

          const mem = Number.isFinite(c.mem_percent)
            ? `${c.mem_usage_mb} MB · ${c.mem_percent}%`
            : `${c.mem_usage_mb ?? '—'} MB · limite non définie`;

          return `
            <article class="bg-cyber-surface border border-cyber-border rounded-xl p-5">

              <div class="flex items-start justify-between gap-4">
                <div class="min-w-0">
                  <p class="text-sm font-semibold text-slate-200 font-mono truncate">
                    ${escape_html(c.name)}
                  </p>

                  <p class="text-[11px] text-slate-500 mt-1 truncate">
                    ${escape_html(c.role)}
                  </p>
                </div>

                <span class="px-2 py-1 rounded-md text-[10px] font-mono text-slate-400 bg-cyber-surface-2 border border-cyber-border flex-shrink-0">
                  OBSERVÉ
                </span>
              </div>

              <p class="text-[11px] font-mono text-slate-600 truncate mt-4">
                ${escape_html(c.image || '—')}
              </p>

              <dl class="grid grid-cols-2 gap-5 mt-5 pt-4 border-t border-cyber-border">
                <div>
                  <dt class="text-[10px] uppercase tracking-[0.10em] text-slate-600">
                    CPU
                  </dt>
                  <dd class="text-sm font-mono text-slate-300 mt-1">
                    ${cpu}
                  </dd>
                </div>

                <div>
                  <dt class="text-[10px] uppercase tracking-[0.10em] text-slate-600">
                    Mémoire
                  </dt>
                  <dd class="text-sm font-mono text-slate-300 mt-1">
                    ${mem}
                  </dd>
                </div>
              </dl>

            </article>`;
        }).join('');
    }

    // ── Render: vue dédiée Réseau (onglet) ──────────────────────────
    function render_network(d) {
      const networks = d.networks ?? [];
      const container =
        document.getElementById('section-network');

      if (!networks.length) {
        container.innerHTML =
          '<div class="col-span-full px-5 py-8 text-center text-slate-500 text-xs">Aucun réseau déclaré.</div>';
        return;
      }

      container.innerHTML =
        networks.map(net => {
          const isolation = net.internal
            ? 'ISOLÉ'
            : 'NON INTERNE';

          const containersList =
            (net.containers ?? []).map(c => `
              <li class="flex items-center justify-between gap-4 px-3 py-2.5 rounded-lg bg-cyber-surface-2 border border-cyber-border">
                <span class="font-mono text-[11px] text-slate-300 truncate">
                  ${escape_html(c.name)}
                </span>

                <span class="font-mono text-[11px] text-slate-500 flex-shrink-0">
                  ${escape_html(c.ipv4)}
                </span>
              </li>
            `).join('') ||
            '<li class="text-xs text-slate-500 px-3 py-2">Aucun workload déclaré.</li>';

          return `
            <article class="bg-cyber-surface border border-cyber-border rounded-xl p-5">

              <div class="flex items-start justify-between gap-4">
                <div class="min-w-0">
                  <p class="text-sm font-semibold text-slate-100 font-mono truncate">
                    ${escape_html(net.name)}
                  </p>

                  <p class="text-[11px] text-slate-600 mt-1">
                    Topologie déclarée · Docker Compose
                  </p>
                </div>

                <span class="px-2 py-1 rounded-md text-[10px] font-mono text-slate-400 bg-cyber-surface-2 border border-cyber-border flex-shrink-0">
                  ${isolation}
                </span>
              </div>

              <dl class="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-5 py-4 border-y border-cyber-border">
                <div>
                  <dt class="text-[10px] uppercase tracking-[0.10em] text-slate-600">
                    Gestion
                  </dt>
                  <dd class="text-[11px] font-mono text-slate-300 mt-1">
                    ${escape_html(net.management || '—')}
                  </dd>
                </div>

                <div>
                  <dt class="text-[10px] uppercase tracking-[0.10em] text-slate-600">
                    Driver
                  </dt>
                  <dd class="text-[11px] font-mono text-slate-300 mt-1">
                    ${escape_html(net.driver || '—')}
                  </dd>
                </div>

                <div>
                  <dt class="text-[10px] uppercase tracking-[0.10em] text-slate-600">
                    Subnet
                  </dt>
                  <dd class="text-[11px] font-mono text-slate-300 mt-1">
                    ${escape_html(net.subnet || '—')}
                  </dd>
                </div>
              </dl>

              <p class="text-[10px] uppercase tracking-[0.10em] text-slate-600 mt-4 mb-2">
                Workloads déclarés
              </p>

              <ul class="space-y-2">
                ${containersList}
              </ul>

            </article>`;
        }).join('');

      lucide.createIcons();
    }

    // ── Render: vue dédiée Compliance (onglet) ──────────────────────
    function render_compliance(d) {
      const trivy = d.trivy ?? {};
      const zap = d.zap ?? {};
      const headers = d.security_headers ?? {};
      const scanEvidence = d.scan_evidence ?? {};
      const headersEvidence = d.security_headers_evidence ?? {};
      const scansAvailable = scanEvidence.available === true;

      // Trivy
      document.getElementById('trivy-target').textContent = trivy.target || '—';
      document.getElementById('trivy-date').textContent = trivy.scan_date
        ? `Scan enregistré : ${new Date(trivy.scan_date).toLocaleString('fr-FR')} · ${scanEvidence.source ?? 'recorded_scan'}`
        : 'Preuve de scan indisponible';

      const trivySeverities = [
        { key: 'critical', label: 'CRITICAL', cls: 'text-red-400' },
        { key: 'high',     label: 'HIGH',     cls: 'text-orange-400' },
        { key: 'medium',   label: 'MEDIUM',   cls: 'text-yellow-400' },
        { key: 'low',      label: 'LOW',      cls: 'text-slate-300' },
        { key: 'unknown',  label: 'UNKNOWN',  cls: 'text-slate-500' },
      ];
      document.getElementById('trivy-grid').innerHTML = trivySeverities.map(s => `
        <div class="rounded-lg border border-cyber-border bg-cyber-surface-2 p-3 text-center ${s.cls}">
          <p class="font-display text-xl font-bold">${scansAvailable && trivy[s.key] != null ? trivy[s.key] : '—'}</p>
          <p class="text-[10px] font-mono uppercase tracking-[0.10em] mt-1">${s.label}</p>
        </div>
      `).join('');

      // ZAP
      document.getElementById('zap-target').textContent = zap.target || '—';
      document.getElementById('zap-date').textContent = zap.scan_date
        ? `Scan enregistré : ${new Date(zap.scan_date).toLocaleString('fr-FR')} · ${scanEvidence.source ?? 'recorded_scan'}`
        : 'Preuve de scan indisponible';

      const zapMetrics = [
        { key: 'fail_new', label: 'FAIL-NEW', cls: 'text-red-400' },
        { key: 'warn_new', label: 'WARN-NEW', cls: 'text-orange-400' },
        { key: 'pass',     label: 'PASS',     cls: 'text-green-400' },
      ];
      document.getElementById('zap-grid').innerHTML = zapMetrics.map(m => `
        <div class="rounded-lg border border-cyber-border bg-cyber-surface-2 p-3 text-center ${m.cls}">
          <p class="font-display text-xl font-bold">${scansAvailable && zap[m.key] != null ? zap[m.key] : '—'}</p>
          <p class="text-[10px] font-mono uppercase tracking-[0.10em] mt-1">${m.label}</p>
        </div>
      `).join('');

      // Headers HTTP
      const headerEntries = Object.entries(headers);
      document.getElementById('headers-list').innerHTML = headerEntries.map(([name, value]) => `
        <li class="px-3 py-2.5 rounded-xl bg-cyber-surface-2 border border-cyber-border">
          <div class="flex items-center justify-between gap-3 mb-1">
            <span class="font-mono text-[11px] text-slate-300">${escape_html(name)}</span>
            <span class="px-2 py-1 rounded-md text-[10px] font-mono bg-cyber-surface border border-cyber-border text-slate-400 flex-shrink-0">${headersEvidence.source === 'configured' ? 'CONFIGURÉ' : 'SOURCE INCONNUE'}</span>
          </div>
          <p class="font-mono text-[10px] text-slate-500 break-all">${escape_html(value)}</p>
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
      ];

      const container =
        document.getElementById('section-settings');

      container.innerHTML =
        groups.map(g => {
          const rows =
            Object.entries(g.data ?? {}).map(([key, value]) => `
              <div class="flex items-start justify-between gap-6 py-2.5">
                <span class="text-[11px] text-slate-500">
                  ${escape_html(key)}
                </span>

                <span class="font-mono text-[11px] text-slate-300 text-right break-all">
                  ${escape_html(value)}
                </span>
              </div>
            `).join('');

          return `
            <article class="bg-cyber-surface border border-cyber-border rounded-xl p-5">

              <div class="flex items-center gap-2.5 pb-3 border-b border-cyber-border">
                <i data-lucide="${g.icon}" class="w-4 h-4 text-slate-500"></i>

                <p class="text-sm font-semibold text-slate-100">
                  ${g.title}
                </p>
              </div>

              <div class="divide-y divide-cyber-border">
                ${rows}
              </div>

            </article>`;
        }).join('');

      lucide.createIcons();
    }

    // ── Render: /api/v1/timeline ──────────────────────────────────
    function render_timeline(d) {
      build_chart(d);

      document.getElementById('total-cs').textContent =
        d.totals?.logs_analyzed ?? '—';

      document.getElementById('total-decisions').textContent =
        d.totals?.active_decisions ?? '—';

      document.getElementById('total-waf').textContent =
        d.meta?.waf_source === 'not_instrumented'
          ? 'NON INSTRUMENTÉ'
          : (d.totals?.waf ?? '—');
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
      const pageTitles = {
        overview: 'Vue d’ensemble',
        events: 'Décisions CrowdSec',
        containers: 'Workloads',
        network: 'Topologie',
        compliance: 'Preuves de sécurité',
        settings: 'Configuration',
        profile: 'Profil',
      };

      const pageTitle =
        document.getElementById('page-title');

      if (pageTitle) {
        pageTitle.textContent =
          pageTitles[tab] ?? 'MARLEY';
      }

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

        l.classList.toggle('bg-cyber-surface-2', active);
        l.classList.toggle('text-slate-100', active);
        l.classList.toggle('border', active);
        l.classList.toggle('border-cyber-border-strong', active);

        l.classList.toggle('text-slate-400', !active);

        l.classList.remove(
          'bg-cyan-500/10',
          'text-cyan-300',
          'border-cyan-500/20'
        );
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

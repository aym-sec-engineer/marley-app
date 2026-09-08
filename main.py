"""
═══════════════════════════════════════════════════════════════════
 MARLEY SECURITY DASHBOARD — Backend Flask
 Projet DevSecOps — Aym
═══════════════════════════════════════════════════════════════════

Ce serveur expose les métriques de sécurité de l'infrastructure Marley :
  - État du pare-feu (nftables) et port SSH durci
  - Décisions actives CrowdSec (IPs bannies) via cscli
  - Flux d'événements de sécurité (CrowdSec + WAF ModSecurity + SSH)
  - Métriques CPU/RAM des conteneurs Docker de la stack
  - Série temporelle des tentatives bloquées (pour Chart.js)

Stratégie de données : chaque collecteur tente d'abord une lecture
RÉELLE (CrowdSec LAPI, psutil, Prometheus/cAdvisor). Les collecteurs
ne nécessitent aucun accès direct au daemon Docker. Les fallbacks
éventuels sont explicitement signalés par le champ "data_source".
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import requests
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, render_template, request

# ── Imports optionnels (dégradation gracieuse) ──────────────────────
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION — variables d'environnement, valeurs par défaut sûres
# ═══════════════════════════════════════════════════════════════════

class Config:
    """Configuration centralisée. Toute valeur sensible ou variable
    selon l'environnement passe par cette classe — jamais de valeur
    en dur dispersée dans le code."""

    # Identité de l'application
    APP_NAME = os.environ.get("MARLEY_APP_NAME", "Marley Security Dashboard")
    APP_VERSION = os.environ.get("MARLEY_VERSION", "2.0.0")
    ENVIRONMENT = os.environ.get("MARLEY_ENV", "production")

    # Réseau / Firewall
    SSH_PORT = int(os.environ.get("MARLEY_SSH_PORT", "22222"))
    HTTP_PORT = int(os.environ.get("MARLEY_HTTP_PORT", "80"))
    HTTPS_PORT = int(os.environ.get("MARLEY_HTTPS_PORT", "443"))
    FIREWALL_ENGINE = os.environ.get("MARLEY_FW_ENGINE", "nftables")
    FIREWALL_POLICY = os.environ.get("MARLEY_FW_POLICY", "deny-by-default")

    # WAF
    WAF_ENGINE = os.environ.get("MARLEY_WAF_ENGINE", "ModSecurity")
    WAF_RULESET = os.environ.get("MARLEY_WAF_RULESET", "OWASP CRS v4.x")
    WAF_MODE = os.environ.get("MARLEY_WAF_MODE", "Blocking")

    # CrowdSec
    CSCLI_BIN = os.environ.get("MARLEY_CSCLI_BIN", "cscli")
    CSCLI_TIMEOUT = float(os.environ.get("MARLEY_CSCLI_TIMEOUT", "3"))
    CSCLI_USE_SUDO = os.environ.get("MARLEY_CSCLI_SUDO", "true").lower() == "true"
    CROWDSEC_LAPI_URL = os.environ.get("CROWDSEC_LAPI_URL", "http://172.19.0.1:8080")
    CROWDSEC_BOUNCER_KEY = os.environ.get("CROWDSEC_BOUNCER_KEY", "")
    CROWDSEC_TIMEOUT = float(os.environ.get("CROWDSEC_TIMEOUT", "3"))

    # Flask
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()

    # Seuils de statut global
    THRESHOLD_ELEVATED = int(os.environ.get("MARLEY_THRESHOLD_ELEVATED", "10"))
    THRESHOLD_ALERT = int(os.environ.get("MARLEY_THRESHOLD_ALERT", "40"))


app = Flask(__name__)
app.config.from_object(Config)
app.json.sort_keys = False


# ═══════════════════════════════════════════════════════════════════
# SÉCURITÉ — en-têtes HTTP durcis appliqués à chaque réponse
# ═══════════════════════════════════════════════════════════════════

def get_security_headers() -> dict:
    """Retourne le dict des en-têtes de sécurité HTTP appliqués à
    chaque réponse — source unique de vérité, utilisée à la fois par
    `apply_security_headers()` (runtime) et par la route
    `/api/v1/compliance` (affichage dashboard), pour garantir que
    l'UI reflète toujours exactement ce qui est réellement appliqué."""

    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' "
            "https://cdn.tailwindcss.com "
            "https://cdn.jsdelivr.net "
            "https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com "
            "https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        ),
    }


@app.after_request
def apply_security_headers(response):
    """Applique un set d'en-têtes de sécurité conforme aux
    recommandations OWASP Secure Headers Project.

    Le CSP autorise explicitement les CDN utilisés par le frontend
    (Tailwind Play CDN, Chart.js, Lucide, Google Fonts). 'unsafe-inline'
    est un compromis assumé pour ce prototype basé sur CDN — en
    production durcie, on bascule sur un build Tailwind/JS local avec
    des nonces CSP par requête."""

    for header_name, header_value in get_security_headers().items():
        response.headers[header_name] = header_value

    # On masque la signature serveur par défaut de Werkzeug
    response.headers["Server"] = f"{Config.APP_NAME.replace(' ', '-')}/{Config.APP_VERSION}"

    return response


# ═══════════════════════════════════════════════════════════════════
# DONNÉES DE RÉFÉRENCE — scénarios CrowdSec, règles WAF réelles
# ═══════════════════════════════════════════════════════════════════

CROWDSEC_SCENARIOS = [
    "crowdsecurity/ssh-bf",
    "crowdsecurity/http-probing",
    "crowdsecurity/http-bad-user-agent",
    "crowdsecurity/http-crawl-non_statics",
    "crowdsecurity/http-path-traversal-probing",
    "crowdsecurity/http-generic-bf",
    "crowdsecurity/nginx-req-limit-bypass",
]



MARLEY_CONTAINERS = [
    {"name": "traefik", "role": "Reverse Proxy / TLS", "image": "traefik:v3.1"},
    {"name": "marley-waf", "role": "WAF / OWASP CRS", "image": "owasp/modsecurity-crs:nginx-alpine"},
    {"name": "marley_app", "role": "Application", "image": "cyberaym/marley-test"},
    {"name": "prometheus", "role": "Metrics Backend", "image": "prom/prometheus:v2.54.1"},
    {"name": "grafana", "role": "Dashboards", "image": "grafana/grafana:11.2.0"},
    {"name": "node-exporter", "role": "Host Metrics", "image": "prom/node-exporter:v1.8.2"},
    {"name": "cadvisor", "role": "Container Metrics", "image": "gcr.io/cadvisor/cadvisor:v0.52.1"},
    {"name": "juice-shop", "role": "DAST Training Target", "image": "bkimminich/juice-shop"},
]


# ═══════════════════════════════════════════════════════════════════
# COLLECTEURS — Pare-feu
# ═══════════════════════════════════════════════════════════════════

def get_firewall_status() -> dict:
    """Configuration de sécurité réseau déclarée pour le lab Marley.

    Cette vue décrit la configuration attendue. Elle ne prétend pas
    constituer un contrôle runtime de nftables.
    """

    return {
        "engine": Config.FIREWALL_ENGINE,
        "status": "configured",
        "data_source": "configured",
        "policy": Config.FIREWALL_POLICY,
        "open_ports": [
            {
                "port": "custom",
                "service": "SSH",
                "protocol": "tcp",
                "auth": "Ed25519, root désactivé",
            },
            {
                "port": Config.HTTP_PORT,
                "service": "HTTP",
                "protocol": "tcp",
                "auth": "Redirect → HTTPS",
            },
            {
                "port": Config.HTTPS_PORT,
                "service": "HTTPS",
                "protocol": "tcp",
                "auth": "TLS 1.2/1.3",
            },
        ],
    }

# ═══════════════════════════════════════════════════════════════════
# COLLECTEURS — CrowdSec
# ═══════════════════════════════════════════════════════════════════





def get_crowdsec_decisions() -> tuple[list[dict], bool]:
    """Récupère les décisions actives via la LAPI CrowdSec.

    Retourne (decisions, is_live).

    Une LAPI indisponible ne produit jamais de fausses décisions :
    l'état devient explicitement unavailable.
    """

    if not Config.CROWDSEC_BOUNCER_KEY:
        return [], False

    try:
        resp = requests.get(
            f"{Config.CROWDSEC_LAPI_URL}/v1/decisions",
            headers={"X-Api-Key": Config.CROWDSEC_BOUNCER_KEY},
            timeout=Config.CROWDSEC_TIMEOUT,
        )
        resp.raise_for_status()

        data = resp.json()

        if isinstance(data, list):
            return data, True

        # CrowdSec peut renvoyer null lorsqu'aucune décision n'est active.
        if data is None:
            return [], True

    except (
        requests.RequestException,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        app.logger.warning(
            "CrowdSec LAPI unavailable: %s",
            exc,
        )

    return [], False

# ═══════════════════════════════════════════════════════════════════
# COLLECTEURS — Événements de sécurité (flux combiné)
# ═══════════════════════════════════════════════════════════════════

def get_security_events(
    limit: int = 25,
) -> tuple[list[dict], dict]:
    """Construit un snapshot des décisions CrowdSec actuellement actives.

    Important :
      - aucune date historique n'est inventée ;
      - aucun événement WAF ou SSH fictif n'est généré ;
      - les sources non instrumentées sont déclarées explicitement.
    """

    decisions, crowdsec_live = get_crowdsec_decisions()
    observed_at = datetime.now(timezone.utc).isoformat()

    sources = {
        "crowdsec": "live" if crowdsec_live else "unavailable",
        "waf": "not_instrumented",
        "ssh": "not_instrumented",
        "system": "not_instrumented",
    }

    if not crowdsec_live:
        return [], {
            "data_source": "unavailable",
            "sources": sources,
            "semantics": "local_active_decisions_snapshot",
        }

    events: list[dict] = []

    # Security Events expose uniquement l'activité locale observée
    # sur Marley. Les décisions CAPI relèvent du threat intelligence
    # communautaire et ne prouvent pas une attaque contre ce VPS.
    local_decisions = [
        decision
        for decision in decisions
        if decision.get("origin") != "CAPI"
    ]

    for decision in local_decisions[:limit]:
        decision_type = str(
            decision.get("type", "ban")
        ).upper()

        events.append({
            "timestamp": observed_at,
            "severity": "high",
            "source_ip": decision.get("value", "—"),
            "event_type": "CrowdSec Active Decision",
            "scenario": decision.get(
                "scenario",
                "unknown",
            ),
            "message": (
                "Décision active observée via la LAPI CrowdSec"
            ),
            "action": decision_type,
            "origin": decision.get(
                "origin",
                "unknown",
            ),
            "data_source": "live",
        })

    return events, {
        "data_source": "live",
        "sources": sources,
        "semantics": "local_active_decisions_snapshot",
    }

# ═══════════════════════════════════════════════════════════════════
# COLLECTEURS — Métriques système & conteneurs
# ═══════════════════════════════════════════════════════════════════

def get_host_metrics() -> dict:
    """Métriques globales de l'hôte (CPU/RAM/Disque/Uptime).

    Utilise psutil si disponible (cas réel sur le VPS), sinon retourne
    des valeurs simulées plausibles pour un petit lab."""

    if PSUTIL_AVAILABLE:
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=0.3),
                "mem_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage("/").percent,
                "uptime_seconds": int(time.time() - psutil.boot_time()),
                "data_source": "live",
            }
        except Exception:
            pass

    return {
        "cpu_percent": round(random.uniform(4.0, 22.0), 1),
        "mem_percent": round(random.uniform(28.0, 52.0), 1),
        "disk_percent": round(random.uniform(18.0, 40.0), 1),
        "uptime_seconds": 86400 * random.randint(2, 14),
        "data_source": "simulated",
    }


def _calculate_cpu_percent(stats: dict) -> float:
    """Reproduit le calcul du pourcentage CPU effectué par `docker stats`,
    à partir des deltas cpu_usage / system_cpu_usage entre deux échantillons."""

    try:
        cpu_delta = (
            stats["cpu_stats"]["cpu_usage"]["total_usage"]
            - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        )
        system_delta = (
            stats["cpu_stats"]["system_cpu_usage"]
            - stats["precpu_stats"]["system_cpu_usage"]
        )
        online_cpus = stats["cpu_stats"].get("online_cpus") or len(
            stats["cpu_stats"]["cpu_usage"].get("percpu_usage", [1])
        ) or 1

        if system_delta > 0 and cpu_delta >= 0:
            return round((cpu_delta / system_delta) * online_cpus * 100, 2)
    except (KeyError, ZeroDivisionError, TypeError):
        pass
    return 0.0


def _simulate_container_metrics() -> list[dict]:
    """Jeu de données simulé pour les conteneurs de la stack Marley —
    utilisé uniquement si Prometheus/cAdvisor est indisponible."""

    metrics = []
    for c in MARLEY_CONTAINERS:
        metrics.append({
            "name": c["name"],
            "role": c["role"],
            "image": c["image"],
            "status": "running",
            "cpu_percent": round(random.uniform(0.4, 18.0), 2),
            "mem_percent": round(random.uniform(2.0, 38.0), 2),
            "mem_usage_mb": round(random.uniform(18.0, 240.0), 1),
        })
    return metrics


def get_container_metrics() -> tuple[list[dict], bool]:
    """Métriques CPU/RAM des conteneurs via Prometheus/cAdvisor.

    L'application n'interroge pas directement le daemon Docker.
    cAdvisor collecte les métriques des conteneurs et Prometheus les
    centralise. En cas d'indisponibilité, retourne les données simulées.

    Retourne (metrics, is_live).
    """

    try:
        url = f"{PROMETHEUS_URL}/api/v1/query"

        queries = {
            "memory":
                'container_memory_working_set_bytes{name!=""}',
            "memory_limit":
                'container_spec_memory_limit_bytes{name!=""}',
            "cpu":
                'rate(container_cpu_usage_seconds_total{name!="",cpu="total"}[2m])',
            "last_seen":
                'container_last_seen{name!=""}',
        }

        results = {}

        for key, query in queries.items():
            response = requests.get(
                url,
                params={"query": query},
                timeout=5,
            )
            response.raise_for_status()

            payload = response.json()

            if payload.get("status") != "success":
                raise RuntimeError(
                    f"Prometheus query failed: {key}"
                )

            results[key] = payload["data"]["result"]

        # Une même identité de conteneur peut avoir plusieurs séries
        # historiques après un redéploiement. On conserve la série
        # ayant le container_last_seen le plus récent.
        latest_by_name = {}

        for item in results["last_seen"]:
            metric = item.get("metric", {})
            name = metric.get("name")

            if not name:
                continue

            try:
                last_seen = float(item["value"][1])
            except (KeyError, IndexError, TypeError, ValueError):
                continue

            current = latest_by_name.get(name)

            if current is None or last_seen > current["last_seen"]:
                latest_by_name[name] = {
                    "last_seen": last_seen,
                    "metric": metric,
                }

        role_map = {
            c["name"]: c["role"]
            for c in MARLEY_CONTAINERS
        }

        def current_value(series, name, container_id):
            for item in series:
                metric = item.get("metric", {})

                if metric.get("name") != name:
                    continue

                if (
                    container_id
                    and metric.get("id") != container_id
                ):
                    continue

                try:
                    return float(item["value"][1])
                except (KeyError, IndexError, TypeError, ValueError):
                    continue

            return 0.0

        metrics = []

        for name, meta in latest_by_name.items():
            if name not in role_map:
                continue

            container_id = meta["metric"].get("id")

            memory = current_value(
                results["memory"],
                name,
                container_id,
            )

            memory_limit = current_value(
                results["memory_limit"],
                name,
                container_id,
            )

            cpu_cores = current_value(
                results["cpu"],
                name,
                container_id,
            )

            mem_percent = (
                round((memory / memory_limit) * 100, 2)
                if memory_limit > 0
                else None
            )

            image = (
                meta["metric"].get("image")
                or "unknown"
            )

            metrics.append({
                "name": name,
                "role": role_map.get(name, "Service"),
                "image": image,
                "status": "running",
                "cpu_percent": round(cpu_cores * 100, 2),
                "mem_percent": mem_percent,
                "mem_usage_mb": round(
                    memory / (1024 * 1024),
                    1,
                ),
            })

        if metrics:
            return metrics, True

    except Exception:
        pass

    return _simulate_container_metrics(), False


# ═══════════════════════════════════════════════════════════════════
# COLLECTEURS — Réseaux Docker
# ═══════════════════════════════════════════════════════════════════

def get_configured_networks() -> list[dict]:
    """Topologie réseau déclarée par docker-compose.yml.

    Les adresses IPv4 Docker étant dynamiques, elles ne sont pas
    présentées comme une source de vérité. Cette vue décrit uniquement
    les relations réseau intentionnelles de la stack.
    """

    return [
        {
            "name": "web",
            "driver": "external",
            "internal": False,
            "subnet": "dynamic",
            "containers": [
                {"name": "traefik", "ipv4": "—"},
                {"name": "marley-waf", "ipv4": "—"},
                {"name": "prometheus", "ipv4": "—"},
                {"name": "grafana", "ipv4": "—"},
            ],
        },
        {
            "name": "backend",
            "driver": "bridge",
            "internal": True,
            "subnet": "dynamic",
            "containers": [
                {"name": "marley-waf", "ipv4": "—"},
                {"name": "marley_app", "ipv4": "—"},
                {"name": "juice-shop", "ipv4": "—"},
            ],
        },
        {
            "name": "monitoring",
            "driver": "bridge",
            "internal": True,
            "subnet": "dynamic",
            "containers": [
                {"name": "traefik", "ipv4": "—"},
                {"name": "marley_app", "ipv4": "—"},
                {"name": "prometheus", "ipv4": "—"},
                {"name": "grafana", "ipv4": "—"},
                {"name": "node-exporter", "ipv4": "—"},
                {"name": "cadvisor", "ipv4": "—"},
            ],
        },
    ]


# ═══════════════════════════════════════════════════════════════════
# COLLECTEURS — Série temporelle des attaques (Chart.js)
# ═══════════════════════════════════════════════════════════════════

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090")


def query_prometheus_scalar(query: str) -> tuple[float | None, bool]:
    """Exécute une requête Prometheus instantanée.

    Retourne (value, is_live). Une requête réussie sans série vaut 0.
    Une erreur réseau, HTTP ou de parsing retourne (None, False).
    """

    try:
        resp = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=3,
        )
        resp.raise_for_status()

        payload = resp.json()

        if payload.get("status") != "success":
            return None, False

        result = payload.get("data", {}).get("result", [])

        if not result:
            return 0.0, True

        value = result[0].get("value", [None, None])[1]

        if value is None:
            return None, False

        return float(value), True

    except (
        requests.RequestException,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
    ) as exc:
        app.logger.warning(
            "Prometheus scalar query unavailable (%s): %s",
            query,
            exc,
        )
        return None, False


def get_crowdsec_metrics() -> dict:
    """Métriques CrowdSec exposées par Prometheus.

    - scenario_triggers_24h :
      nouveaux overflows de scénarios CrowdSec sur les dernières 24 h.
    - retained_alerts :
      alertes locales actuellement conservées par CrowdSec (hors CAPI).

    Ces notions sont volontairement distinctes des décisions actives.
    """

    crowdsec_up, prometheus_live = query_prometheus_scalar(
        'max(up{job="crowdsec"})'
    )

    # Prometheus peut être joignable alors que sa cible CrowdSec ne
    # l'est plus. Dans ce cas, une absence de série ne doit jamais être
    # transformée en faux zéro "live".
    if not prometheus_live or crowdsec_up != 1.0:
        return {
            "scenario_triggers_24h": None,
            "retained_alerts": None,
            "triggers_data_source": "unavailable",
            "alerts_data_source": "unavailable",
        }

    triggers, triggers_live = query_prometheus_scalar(
        "sum(increase(cs_bucket_overflowed_total[24h]))"
    )

    alerts, alerts_live = query_prometheus_scalar(
        "sum(cs_alerts)"
    )

    return {
        "scenario_triggers_24h": (
            int(round(triggers))
            if triggers is not None
            else None
        ),
        "retained_alerts": (
            int(round(alerts))
            if alerts is not None
            else None
        ),
        "triggers_data_source": (
            "live"
            if triggers_live
            else "unavailable"
        ),
        "alerts_data_source": (
            "live"
            if alerts_live
            else "unavailable"
        ),
    }


def get_attacks_timeline(hours: int = 24) -> dict:
    """Série temporelle horaire des tentatives bloquées, ventilée par
    couche de défense (CrowdSec L3/L4 vs WAF L7) — alimente le graphique
    linéaire du tableau de bord.

    CrowdSec : increase(cs_node_hits_total) agrégé par pas d'1h, requêté
    en direct sur Prometheus. WAF : aucune instrumentation Prometheus
    n'existe actuellement pour ModSecurity -> explicitement marqué
    "not_instrumented", jamais de valeur inventée."""

    hours = max(1, min(hours, 168))  # borne 1h à 7 jours
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    labels: list[str] = []
    for i in range(hours, -1, -1):
        ts = now - timedelta(hours=i)
        labels.append(ts.strftime("%H:%M"))

    def _query_range(query: str) -> tuple[list[int], str]:
        """Interroge Prometheus sur la fenêtre [start, now], retourne une
        série alignée sur `labels` + son statut de source."""
        series = [0] * len(labels)
        source = "unavailable"
        try:
            resp = requests.get(
                f"{PROMETHEUS_URL}/api/v1/query_range",
                params={
                    "query": query,
                    "start": start.timestamp(),
                    "end": now.timestamp(),
                    "step": "3600s",
                },
                timeout=3,
            )
            resp.raise_for_status()
            payload = resp.json()
            result = payload.get("data", {}).get("result", [])
            source = "prometheus"  # requête réussie, avec ou sans série retournée
            if result:
                values = result[0].get("values", [])
                parsed = [int(float(v)) for _, v in values]
                if len(parsed) >= len(series):
                    series = parsed[-len(series):]
                else:
                    series[-len(parsed):] = parsed
        except (requests.RequestException, ValueError, KeyError) as exc:
            app.logger.warning("get_attacks_timeline(%s): Prometheus injoignable (%s)", query, exc)
        return series, source

    # Logs analysés par les parsers CrowdSec (compteur cumulatif, tout
    # trafic confondu -- volume d'activité, PAS un nombre d'attaques)
    logs_series, logs_source = _query_range("sum(increase(cs_node_hits_total[1h]))")

    # Décisions de ban actives émises localement par CE host (gauge,
    # échantillonnée dans le temps). origin!="CAPI" exclut la blocklist
    # communautaire pour rester cohérent avec le KPI blocked_ips_count
    # qui ne compte, lui aussi, que les décisions locales.
    decisions_series, decisions_source = _query_range(
        'sum(cs_active_decisions{origin!="CAPI"})'
    )

    waf_series: list[int] = [0] * len(labels)

    return {
        "labels": labels,
        "datasets": {
            "logs_analyzed": logs_series,
            "active_decisions": decisions_series,
            "waf": waf_series,
        },
        "totals": {
            "logs_analyzed": sum(logs_series),
            "active_decisions": decisions_series[-1] if decisions_series else 0,
            "waf": sum(waf_series),
        },
        "meta": {
            "logs_analyzed_source": logs_source,
            "active_decisions_source": decisions_source,
            "waf_source": "not_instrumented",
        },
    }


# ═══════════════════════════════════════════════════════════════════
# COLLECTEURS — Compliance (Trivy / ZAP)
# ═══════════════════════════════════════════════════════════════════

COMPLIANCE_FILE_PATH = os.path.join(os.path.dirname(__file__), "compliance", "compliance.json")


def get_compliance_scans() -> tuple[dict, bool]:
    """Lit les résultats des derniers scans Trivy et ZAP depuis un
    fichier JSON déposé sur le VPS (monté en volume lecture-seule,
    voir docker-compose.yml : ./compliance:/app/compliance:ro).

    Ce fichier est mis à jour par la CI GitHub Actions ou manuellement
    sur le VPS — aucun rebuild du conteneur n'est nécessaire pour que
    le dashboard reflète un nouveau scan.

    Retourne (data, is_live) :
      - is_live=True  → fichier lu avec succès
      - is_live=False → fichier absent/invalide, fallback par défaut
    """

    try:
        with open(COMPLIANCE_FILE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "trivy" in data and "zap" in data:
            return data, True
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass

    return {
        "trivy": {
            "scan_date": None, "target": "—",
            "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0,
        },
        "zap": {
            "scan_date": None, "target": "—",
            "fail_new": 0, "warn_new": 0, "pass": 0,
        },
    }, False


# ═══════════════════════════════════════════════════════════════════
# ROUTES — Pages
# ═══════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Sert le tableau de bord principal (SPA légère, données via fetch)."""
    return render_template("index.html", config=Config)


# ═══════════════════════════════════════════════════════════════════
# ROUTES — API JSON
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/v1/status")
def api_status():
    """Statut agrégé avec provenance explicite des données."""

    decisions, decisions_live = get_crowdsec_decisions()
    crowdsec_metrics = get_crowdsec_metrics()
    host = get_host_metrics()

    local_decisions = [
        d
        for d in decisions
        if d.get("origin") != "CAPI"
    ]

    active_decisions = len(local_decisions)
    community_blocklist_count = (
        len(decisions) - active_decisions
    )

    telemetry_live = (
        decisions_live
        and crowdsec_metrics["triggers_data_source"] == "live"
        and crowdsec_metrics["alerts_data_source"] == "live"
    )

    if not telemetry_live:
        global_status = "UNKNOWN"
    elif active_decisions >= Config.THRESHOLD_ALERT:
        global_status = "ALERT"
    elif active_decisions >= Config.THRESHOLD_ELEVATED:
        global_status = "ELEVATED"
    else:
        global_status = "NOMINAL"

    return jsonify({
        "global_status": global_status,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "firewall": get_firewall_status(),

        "waf": {
            "engine": Config.WAF_ENGINE,
            "ruleset": Config.WAF_RULESET,
            "mode": Config.WAF_MODE,
            "status": "configured",
            "data_source": "configured",
        },

        "crowdsec": {
            "status": (
                "operational"
                if telemetry_live
                else (
                    "degraded"
                    if decisions_live
                    else "unavailable"
                )
            ),
            "scenario_triggers_24h": (
                crowdsec_metrics["scenario_triggers_24h"]
            ),
            "retained_alerts": (
                crowdsec_metrics["retained_alerts"]
            ),
            "active_decisions": (
                active_decisions
                if decisions_live
                else None
            ),
            "community_blocklist_count": (
                community_blocklist_count
                if decisions_live
                else None
            ),
            "data_source": (
                "live"
                if telemetry_live
                else (
                    "partial"
                    if decisions_live
                    else "unavailable"
                )
            ),
            "metrics": {
                "scenario_triggers_24h": (
                    crowdsec_metrics["triggers_data_source"]
                ),
                "retained_alerts": (
                    crowdsec_metrics["alerts_data_source"]
                ),
                "active_decisions": (
                    "live"
                    if decisions_live
                    else "unavailable"
                ),
            },
        },

        "host": host,

        "app": {
            "name": Config.APP_NAME,
            "version": Config.APP_VERSION,
            "environment": Config.ENVIRONMENT,
        },
    })

@app.route("/api/v1/events")
def api_events():
    """Snapshot des événements actuellement observables."""

    limit = request.args.get(
        "limit",
        default=25,
        type=int,
    )
    limit = max(1, min(limit, 100))

    events, metadata = get_security_events(
        limit=limit
    )

    return jsonify({
        "events": events,
        "count": len(events),
        "observed_at": datetime.now(
            timezone.utc
        ).isoformat(),
        **metadata,
    })

@app.route("/api/v1/containers")
def api_containers():
    """Métriques CPU/RAM par conteneur de la stack."""

    metrics, is_live = get_container_metrics()
    return jsonify({
        "containers": metrics,
        "count": len(metrics),
        "data_source": "live" if is_live else "simulated",
    })


@app.route("/api/v1/network")
def api_network():
    """Inventaire des réseaux Docker et des conteneurs qui y sont rattachés."""

    networks = get_configured_networks()
    return jsonify({
        "networks": networks,
        "count": len(networks),
        "data_source": "configured",
    })


@app.route("/api/v1/compliance")
def api_compliance():
    """Résultats des derniers scans de sécurité (Trivy, ZAP) et liste
    des en-têtes HTTP de sécurité effectivement appliqués."""

    scans, is_live = get_compliance_scans()
    return jsonify({
        "trivy": scans["trivy"],
        "zap": scans["zap"],
        "security_headers": get_security_headers(),
        "data_source": "live" if is_live else "default",
    })


@app.route("/api/v1/timeline")
def api_timeline():
    """Série temporelle pour le graphique d'attaques (Chart.js)."""

    hours = request.args.get("hours", default=24, type=int)
    return jsonify(get_attacks_timeline(hours=hours))


@app.route("/api/v1/settings")
def api_settings():
    """Architecture publique volontairement sanitizée.

    Aucun port d'administration, secret, endpoint interne,
    timeout opérationnel ou seuil de détection n'est exposé.
    """

    return jsonify({
        "app": {
            "name": Config.APP_NAME,
            "version": Config.APP_VERSION,
            "environment": Config.ENVIRONMENT,
        },

        "network": {
            "segmentation": "Docker networks",
            "firewall_engine": Config.FIREWALL_ENGINE,
            "firewall_policy": Config.FIREWALL_POLICY,
            "ssh_hardening": (
                "Ed25519 keys, root login disabled"
            ),
        },

        "waf": {
            "engine": Config.WAF_ENGINE,
            "ruleset": Config.WAF_RULESET,
            "mode": Config.WAF_MODE,
        },

        "crowdsec": {
            "enabled": True,
            "integration": (
                "LAPI + nftables bouncer"
            ),
        },
    })

@app.route("/health")
def health():
    """Endpoint de health check — utilisé par le HEALTHCHECK Docker
    et par Traefik/Prometheus pour la supervision."""

    return jsonify({
        "status": "ok",
        "service": Config.APP_NAME,
        "version": Config.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ═══════════════════════════════════════════════════════════════════
# GESTION D'ERREURS
# ═══════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(_error):
    return jsonify({"error": "not_found", "message": "Ressource introuvable"}), 404


@app.errorhandler(500)
def server_error(_error):
    return jsonify({"error": "internal_error", "message": "Erreur interne du serveur"}), 500


# ═══════════════════════════════════════════════════════════════════
# ENTRÉE PRINCIPALE
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=Config.DEBUG)
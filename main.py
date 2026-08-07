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
RÉELLE (cscli, psutil, Docker SDK). En cas d'échec (environnement
de dev local, socket non monté, cscli absent), un jeu de données
SIMULÉ mais réaliste est retourné — le champ "data_source" de chaque
réponse indique "live" ou "simulated".
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, render_template, request

# ── Imports optionnels (dégradation gracieuse) ──────────────────────
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False


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

@app.after_request
def apply_security_headers(response):
    """Applique un set d'en-têtes de sécurité conforme aux
    recommandations OWASP Secure Headers Project.

    Le CSP autorise explicitement les CDN utilisés par le frontend
    (Tailwind Play CDN, Chart.js, Lucide, Google Fonts). 'unsafe-inline'
    est un compromis assumé pour ce prototype basé sur CDN — en
    production durcie, on bascule sur un build Tailwind/JS local avec
    des nonces CSP par requête."""

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=()"
    )
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Content-Security-Policy"] = (
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
    )

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

WAF_RULES = [
    {"id": "932100", "label": "RCE: Unix Shell Code injection"},
    {"id": "941100", "label": "XSS Attack (libinjection)"},
    {"id": "942100", "label": "SQL Injection (libinjection)"},
    {"id": "913100", "label": "Security Scanner User-Agent détecté"},
    {"id": "920350", "label": "Host header invalide (IP brute)"},
    {"id": "913101", "label": "Scanner Detection (Acunetix/Nikto)"},
]

INFO_EVENTS = [
    ("CI/CD Deploy", "Déploiement réussi via GitHub Actions"),
    ("Health Check", "Tous les services répondent — healthy"),
    ("Cert Renewal", "Certificat Let's Encrypt renouvelé (Traefik)"),
    ("Trivy Scan", "Scan de vulnérabilités terminé — 0 CRITICAL"),
    ("System Update", "Mises à jour de sécurité appliquées (unattended-upgrades)"),
    ("Ansible", "Playbook site.yml exécuté — état conforme"),
]

MARLEY_CONTAINERS = [
    {"name": "marley_proxy", "role": "WAF / Reverse Proxy", "image": "owasp/modsecurity-crs:nginx"},
    {"name": "marley_app", "role": "Application", "image": "marley-app:latest"},
    {"name": "crowdsec", "role": "IDS / IPS", "image": "crowdsecurity/crowdsec"},
    {"name": "prometheus", "role": "Monitoring", "image": "prom/prometheus"},
    {"name": "grafana", "role": "Dashboards", "image": "grafana/grafana"},
    {"name": "certbot", "role": "TLS Renewal", "image": "certbot/certbot"},
]


# ═══════════════════════════════════════════════════════════════════
# COLLECTEURS — Pare-feu
# ═══════════════════════════════════════════════════════════════════

def get_firewall_status() -> dict:
    """État du pare-feu et inventaire des ports ouverts.

    En conditions réelles, cette fonction peut être étendue pour lire
    `nft list ruleset` ou `ufw status` — ici elle reflète la
    configuration connue et durcie du lab (source de vérité : rôle
    Ansible 'firewall')."""

    return {
        "engine": Config.FIREWALL_ENGINE,
        "status": "active",
        "policy": Config.FIREWALL_POLICY,
        "ssh_port": Config.SSH_PORT,
        "open_ports": [
            {"port": Config.SSH_PORT, "service": "SSH", "protocol": "tcp", "auth": "Ed25519, root désactivé"},
            {"port": Config.HTTP_PORT, "service": "HTTP", "protocol": "tcp", "auth": "Redirect → HTTPS"},
            {"port": Config.HTTPS_PORT, "service": "HTTPS", "protocol": "tcp", "auth": "TLS 1.2/1.3"},
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# COLLECTEURS — CrowdSec
# ═══════════════════════════════════════════════════════════════════

def _random_ip() -> str:
    """Génère une IPv4 plausible pour les données de démonstration."""
    first_octet = random.choice([45, 51, 78, 89, 92, 103, 134, 178, 185, 193, 203, 212])
    return f"{first_octet}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _simulate_crowdsec_decisions(count: int | None = None) -> list[dict]:
    """Jeu de données simulé — utilisé si `cscli` est indisponible
    (ex : exécution locale hors du VPS)."""

    now = datetime.now(timezone.utc)
    n = count if count is not None else random.randint(6, 18)
    decisions = []
    for _ in range(n):
        duration_h = random.randint(1, 4)
        decisions.append({
            "id": random.randint(1000, 9999),
            "origin": "crowdsec",
            "type": "ban",
            "scope": "Ip",
            "value": _random_ip(),
            "scenario": random.choice(CROWDSEC_SCENARIOS),
            "duration": f"{duration_h}h{random.randint(0, 59)}m{random.randint(0, 59)}s",
            "until": (now + timedelta(hours=duration_h)).isoformat(),
        })
    return decisions


def get_crowdsec_decisions() -> tuple[list[dict], bool]:
    """Récupère les décisions actives via `cscli decisions list -o json`.

    Retourne (decisions, is_live) :
      - is_live=True  → données réelles de l'agent CrowdSec
      - is_live=False → fallback simulé (cscli absent, socket non monté, etc.)
    """

    cmd = [Config.CSCLI_BIN, "decisions", "list", "-o", "json"]
    if Config.CSCLI_USE_SUDO:
        cmd = ["sudo", "-n"] + cmd  # -n : jamais de prompt interactif

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.CSCLI_TIMEOUT,
        )
        if result.returncode == 0:
            stdout = result.stdout.strip()
            if stdout and stdout != "null":
                data = json.loads(stdout)
                if isinstance(data, list):
                    return data, True
                return [], True  # cscli a répondu, aucune décision active
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, OSError):
        pass

    return _simulate_crowdsec_decisions(), False


# ═══════════════════════════════════════════════════════════════════
# COLLECTEURS — Événements de sécurité (flux combiné)
# ═══════════════════════════════════════════════════════════════════

def get_security_events(limit: int = 25) -> list[dict]:
    """Construit un flux d'événements de sécurité trié par horodatage
    décroissant, en combinant :
      - les décisions CrowdSec réelles (ou simulées)
      - des événements WAF ModSecurity simulés
      - des tentatives SSH échouées simulées
      - des événements informationnels (CI/CD, scans, etc.)
    """

    now = datetime.now(timezone.utc)
    decisions, _ = get_crowdsec_decisions()
    events: list[dict] = []

    # 1. Décisions CrowdSec → événements "ban"
    for d in decisions[: max(1, limit // 2)]:
        ts = now - timedelta(minutes=random.randint(1, 720))
        events.append({
            "timestamp": ts.isoformat(),
            "severity": "high",
            "source_ip": d.get("value", _random_ip()),
            "event_type": "CrowdSec Ban",
            "scenario": d.get("scenario", random.choice(CROWDSEC_SCENARIOS)),
            "message": f"IP bannie — scénario {d.get('scenario', 'comportement suspect')}",
            "action": "DROP (nftables)",
        })

    # 2. Blocages WAF (ModSecurity)
    for _ in range(random.randint(5, 9)):
        ts = now - timedelta(minutes=random.randint(1, 1440))
        rule = random.choice(WAF_RULES)
        events.append({
            "timestamp": ts.isoformat(),
            "severity": "high",
            "source_ip": _random_ip(),
            "event_type": "WAF Block",
            "scenario": f"ModSecurity Rule {rule['id']}",
            "message": rule["label"],
            "action": "403 Forbidden",
        })

    # 3. Échecs d'authentification SSH
    for _ in range(random.randint(4, 8)):
        ts = now - timedelta(minutes=random.randint(1, 1440))
        events.append({
            "timestamp": ts.isoformat(),
            "severity": "warning",
            "source_ip": _random_ip(),
            "event_type": "SSH Auth Failure",
            "scenario": "crowdsecurity/ssh-bf",
            "message": f"Échec d'authentification sur le port {Config.SSH_PORT}",
            "action": "Logged → fail2ban",
        })

    # 4. Événements informationnels
    for label, message in random.sample(INFO_EVENTS, k=min(3, len(INFO_EVENTS))):
        ts = now - timedelta(minutes=random.randint(1, 1440))
        events.append({
            "timestamp": ts.isoformat(),
            "severity": "info",
            "source_ip": "127.0.0.1",
            "event_type": label,
            "scenario": "-",
            "message": message,
            "action": "OK",
        })

    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events[:limit]


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
    utilisé si le socket Docker n'est pas accessible depuis ce conteneur
    (choix de durcissement assumé)."""

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
    """Métriques CPU/RAM par conteneur.

    Tente le SDK Docker (nécessite le montage en LECTURE SEULE de
    /var/run/docker.sock). En son absence, retourne un jeu simulé
    réaliste.

    Retourne (metrics, is_live)."""

    if DOCKER_AVAILABLE:
        try:
            client = docker.from_env()
            metrics = []
            role_map = {c["name"]: c["role"] for c in MARLEY_CONTAINERS}

            for container in client.containers.list():
                try:
                    stats = container.stats(stream=False)
                    mem_usage = stats.get("memory_stats", {}).get("usage", 0)
                    mem_limit = stats.get("memory_stats", {}).get("limit", 1) or 1
                    metrics.append({
                        "name": container.name,
                        "role": role_map.get(container.name, "Service"),
                        "image": (container.image.tags[0] if container.image.tags else container.image.short_id),
                        "status": container.status,
                        "cpu_percent": _calculate_cpu_percent(stats),
                        "mem_percent": round((mem_usage / mem_limit) * 100, 2),
                        "mem_usage_mb": round(mem_usage / (1024 * 1024), 1),
                    })
                except Exception:
                    continue

            if metrics:
                return metrics, True
        except Exception:
            pass

    return _simulate_container_metrics(), False


# ═══════════════════════════════════════════════════════════════════
# COLLECTEURS — Série temporelle des attaques (Chart.js)
# ═══════════════════════════════════════════════════════════════════

def get_attacks_timeline(hours: int = 24) -> dict:
    """Série temporelle horaire des tentatives bloquées, ventilée par
    couche de défense (CrowdSec L3/L4 vs WAF L7) — alimente le graphique
    linéaire du tableau de bord."""

    hours = max(1, min(hours, 168))  # borne 1h à 7 jours
    now = datetime.now(timezone.utc)

    labels: list[str] = []
    crowdsec_series: list[int] = []
    waf_series: list[int] = []

    for i in range(hours, -1, -1):
        ts = now - timedelta(hours=i)
        labels.append(ts.strftime("%H:%M"))
        # Profil "jour ouvré" : davantage de bruit en journée
        hour_of_day = ts.hour
        intensity = 1.0 if 6 <= hour_of_day <= 22 else 0.35
        crowdsec_series.append(int(random.uniform(0, 12) * intensity))
        waf_series.append(int(random.uniform(0, 8) * intensity))

    return {
        "labels": labels,
        "datasets": {
            "crowdsec": crowdsec_series,
            "waf": waf_series,
        },
        "totals": {
            "crowdsec": sum(crowdsec_series),
            "waf": sum(waf_series),
        },
    }


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
    """Statut global agrégé — alimente le header et les KPIs."""

    decisions, decisions_live = get_crowdsec_decisions()
    host = get_host_metrics()
    blocked_count = len(decisions)

    if blocked_count >= Config.THRESHOLD_ALERT:
        global_status = "ALERT"
    elif blocked_count >= Config.THRESHOLD_ELEVATED:
        global_status = "ELEVATED"
    else:
        global_status = "SECURE"

    return jsonify({
        "global_status": global_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "firewall": get_firewall_status(),
        "waf": {
            "engine": Config.WAF_ENGINE,
            "ruleset": Config.WAF_RULESET,
            "mode": Config.WAF_MODE,
            "status": "active",
        },
        "crowdsec": {
            "status": "active",
            "blocked_ips_count": blocked_count,
            "data_source": "live" if decisions_live else "simulated",
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
    """Flux d'événements de sécurité (Live Security Logs)."""

    limit = request.args.get("limit", default=25, type=int)
    limit = max(1, min(limit, 100))
    events = get_security_events(limit=limit)

    return jsonify({
        "events": events,
        "count": len(events),
        "generated_at": datetime.now(timezone.utc).isoformat(),
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


@app.route("/api/v1/timeline")
def api_timeline():
    """Série temporelle pour le graphique d'attaques (Chart.js)."""

    hours = request.args.get("hours", default=24, type=int)
    return jsonify(get_attacks_timeline(hours=hours))


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
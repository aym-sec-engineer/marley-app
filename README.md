# 🛡️ Marley — Infrastructure DevSecOps Production-Ready

> Lab d'infrastructure auto-hébergé, construit pour maîtriser concrètement la chaîne
> complète DevSecOps : durcissement système, reverse proxy sécurisé, défense en
> profondeur réseau/applicative, CI/CD avec supply chain security, observabilité,
> et tests de sécurité offensifs (DAST).

**Stack** : Ubuntu 24.04 LTS · Ansible · Traefik v3 · ModSecurity (OWASP CRS) · CrowdSec ·
Flask · Docker Compose · GitHub Actions · Trivy · Prometheus · Grafana · OWASP ZAP

**Domaine** : `137.74.163.44.sslip.io` — VPS OVH

---

## 📐 Architecture
                         Internet
                             │
                ┌────────────▼────────────┐
                │   Traefik v3 (reverse   │  :80 → :443 redirect
                │   proxy + TLS Let's     │  Let's Encrypt (TLS challenge)
                │   Encrypt)              │
                └────────────┬────────────┘
                             │  réseau "web"
                ┌────────────▼────────────┐
                │  ModSecurity WAF        │  OWASP CRS, Paranoia Level 1
                │  (owasp/modsecurity-crs)│
                └────────────┬────────────┘
                             │  réseau "backend" (internal: true)
                ┌────────────▼────────────┐
                │  marley_app (Flask)     │  Dashboard sécurité temps réel
                │  Dockerfile multi-stage │  utilisateur non-root
                └─────────────────────────┘

Réseau "monitoring" (internal)          Réseau "backend" (internal, isolé)
├── node-exporter (métriques hôte)      └── juice-shop (cible DAST, jamais exposée)
├── cAdvisor (métriques conteneurs)
├── Prometheus (scrape 15s)
└── Grafana (dashboards, exposé via Traefik sur sous-domaine dédié)

Couche réseau système (hôte)
├── CrowdSec + bouncer nftables (L3/L4 — bruteforce SSH, scan agressif)
└── Ansible (durcissement SSH, sysctl, firewall)
---

## ✅ Phases réalisées

| Phase | Contenu | Statut |
|---|---|---|
| 0 | Socle OS durci (Ansible : SSH, sysctl, utilisateurs) | ✅ |
| 1 | Traefik v3 — reverse proxy, TLS automatique Let's Encrypt | ✅ |
| 2 | ModSecurity WAF — OWASP CRS, filtrage L7 | ✅ |
| 3 | CrowdSec + bouncer nftables — défense L3/L4 | ✅ |
| 4 | Application Flask — dashboard sécurité | ✅ |
| 5 | Isolation réseau Docker (`web` / `backend` / `monitoring`) | ✅ |
| 6 | CI/CD GitHub Actions — build, scan Trivy bloquant, push DockerHub, déploiement SSH | ✅ |
| 7 | Observabilité — Prometheus, Grafana, node-exporter, cAdvisor | ✅ |
| 8 | DAST — OWASP ZAP (baseline + full scan) contre Juice Shop isolé | ✅ |

---

## 🔒 Points de sécurité notables

- **Isolation réseau stricte** : `backend` et `monitoring` marqués `internal: true` —
  aucune route sortante possible vers Internet au niveau kernel Docker, même en cas
  de compromission applicative.
- **Défense en profondeur** : CrowdSec (L3/L4, comportemental, bannissement IP kernel
  via nftables) + ModSecurity (L7, inspection requête par requête). Une vraie IP
  (`77.239.124.102`) a été bannie automatiquement après tentative de bruteforce SSH.
- **Supply chain** : scan Trivy bloquant (CVE CRITICAL/HIGH) avant tout push
  DockerHub — pipeline fail-fast.
- **Dockerfile multi-stage** : purge complète de `pip`/`setuptools`/`wheel` du
  runtime final — élimination de CVE (CVE-2026-23949, CVE-2025-47273) et réduction
  de la surface d'attaque en cas de compromission du conteneur.
- **DAST isolé** : Juice Shop tourne exclusivement sur le réseau `backend`, sans
  label Traefik ni port publié — cible de test totalement inaccessible depuis
  l'extérieur.
- **Gestion des secrets** : aucun secret en clair dans le repo (`.gitignore` strict
  sur `.env`, `letsencrypt/`) — GitHub Secrets chiffrés pour la CI/CD.

## 📊 Observabilité

- **Prometheus** scrape `node-exporter` (métriques hôte), `cAdvisor` (métriques par
  conteneur) et `traefik` (métriques reverse proxy) toutes les 15 secondes.
- **Grafana** expose deux dashboards : *Node Exporter Full* (vue infra globale) et
  *Docker Monitoring* (consommation par conteneur).

## 🧪 DAST

Scan `zap-baseline.py` (passif) puis `zap-full-scan.py` (actif, tente réellement
l'exploitation) contre Juice Shop, isolé sur réseau interne. Résultat du dernier
scan complet : `FAIL-NEW: 0`, `WARN-NEW: 4` (CSP manquant, Cross-Domain
misconfiguration, disclosure timestamp — attendu sur une cible volontairement
vulnérable non durcie), `PASS: 109`.

## 🐛 Incidents & debug

Voir [`INCIDENTS.md`](./INCIDENTS.md) — 9 incidents réels rencontrés et résolus
durant la construction (crash loops, CVE, mismatchs de secrets CI/CD, migration
containerd snapshotter). Documentation à froid de la méthode de diagnostic.

## 🚀 Quickstart (reproduction locale)

```bash
git clone https://github.com/aym-sec-engineer/marley-app.git
cd marley-app
cp .env.example .env   # renseigner GRAFANA_ADMIN_PASSWORD
docker network create web
docker compose up -d
```

## 🗺️ Roadmap

- [ ] SAST applicatif (Semgrep) intégré en CI
- [ ] Scan de conformité CIS Benchmark (Docker Bench for Security)
- [ ] Alerting Prometheus (Alertmanager) sur seuils CPU/RAM/certificats expirants
- [ ] Agrégation de logs centralisée (Loki + Promtail)
- [ ] Signature d'images (cosign) + SBOM (syft)
- [ ] Pin des GitHub Actions par SHA plutôt que par tag

## 👤 Auteur

**Aym** — En Mastère Cybersécurité & Réseaux, reconversion vers DevSecOps/Cloud
Security. CompTIA Security+ en préparation. [LinkedIn](https://www.linkedin.com/in/aymrajao/) · [GitHub](https://github.com/aym-sec-engineer)

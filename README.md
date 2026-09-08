# 🛡️ Marley — infrastructure DevSecOps de laboratoire/portfolio conçue selon des pratiques de production

> Lab d'infrastructure auto-hébergé, construit pour maîtriser concrètement la chaîne
> complète DevSecOps : durcissement système, reverse proxy sécurisé, défense en
> profondeur réseau/applicative, CI/CD avec supply chain security, observabilité,
> et tests de sécurité offensifs (DAST).

**Stack** : Ubuntu 24.04 LTS · Traefik v3 · ModSecurity (OWASP CRS) · CrowdSec ·
Flask · Docker Compose · GitHub Actions · Trivy · Gitleaks · Prometheus · Grafana · OWASP ZAP

**Domaine** : `marley.aymrajao.dev` — VPS OVH

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


**Réseau "monitoring" (internal)**
├── node-exporter (métriques hôte)
├── cAdvisor (métriques conteneurs)
├── Prometheus (scrape 15s)
└── Grafana (dashboards, exposé via Traefik sur sous-domaine dédié)


**Réseau "backend" (internal, isolé)**
└── juice-shop (cible DAST, jamais exposée)


**Couche réseau système (hôte)**
├── CrowdSec + bouncer nftables (L3/L4 — bruteforce SSH, scan agressif)
└── Durcissement hôte (SSH, sysctl, firewall)


---


## ✅ Phases réalisées

| Phase | Contenu | Statut |
|---|---|---|
| 0 | Socle OS durci (SSH, sysctl, utilisateurs, firewall hôte) | ✅ |
| 1 | Traefik v3 — reverse proxy, TLS automatique Let's Encrypt | ✅ |
| 2 | ModSecurity WAF — OWASP CRS, filtrage L7 | ✅ |
| 3 | CrowdSec + bouncer nftables — défense L3/L4 | ✅ |
| 4 | Application Flask — dashboard sécurité | ✅ |
| 5 | Isolation réseau Docker (`web` / `backend` / `monitoring`) | ✅ |
| 6 | CI/CD GitHub Actions — Gitleaks, build, Trivy bloquant, SBOM CycloneDX, push DockerHub, déploiement SSH | ✅ |
| 7 | Observabilité — Prometheus, Grafana, node-exporter, cAdvisor | ✅ |
| 8 | DAST — OWASP ZAP (baseline + full scan) contre Juice Shop isolé | ✅ |

---

## 🔒 Points de sécurité notables

- **Isolation réseau stricte** : `backend` et `monitoring` marqués `internal: true` —
  Les réseaux Docker backend et monitoring sont déclarés internes afin de limiter leur
  connectivité externe et de réduire le périmètre réseau accessible en cas de compromission.
- **Défense en profondeur** : CrowdSec (L3/L4, comportemental, décisions de
  bannissement appliquées via le bouncer nftables) + ModSecurity (L7, inspection
  requête par requête avec OWASP CRS).
- **Supply chain** : scan Gitleaks des secrets, scan Trivy bloquant
  (CVE CRITICAL/HIGH) avant tout push DockerHub, génération d'un SBOM CycloneDX
  de l'image et conservation comme artefact GitHub Actions pendant 30 jours.
  Les GitHub Actions utilisées par le pipeline sont verrouillées par commit SHA.
- **Dockerfile multi-stage** : `pip`/`setuptools`/`wheel` sont absents du
  runtime final. Ce durcissement fait suite à plusieurs détections Trivy documentées
  dans `INCIDENTS.md` et réduit les composants inutiles présents à l'exécution.
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

Scan `zap-baseline.py` (passif) puis `zap-full-scan.py` (actif) contre
Juice Shop, isolé sur le réseau interne. Les rapports générés sont conservés dans
`dast-reports/` afin de documenter les tests réalisés.

## 🐛 Incidents & debug

Voir [`INCIDENTS.md`](./INCIDENTS.md) — 9 incidents réels rencontrés et résolus
durant la construction (crash loops, CVE, mismatchs de secrets CI/CD, migration
containerd snapshotter). Documentation à froid de la méthode de diagnostic.

## 🚀 Quickstart (reproduction locale)

```bash
git clone https://github.com/aym-sec-engineer/marley-app.git
cd marley-app
cp .env.example .env   # renseigner CROWDSEC_BOUNCER_KEY et GRAFANA_ADMIN_PASSWORD
docker network create web
export MARLEY_IMAGE_TAG=<tag-image>
docker compose up -d
```

## 🗺️ Roadmap

- [ ] SAST applicatif (Semgrep) intégré en CI
- [ ] Scan de conformité CIS Benchmark (Docker Bench for Security)
- [ ] Alerting Prometheus (Alertmanager) sur seuils CPU/RAM/certificats expirants
- [ ] Agrégation de logs centralisée (Loki + Promtail)
- [x] SBOM CycloneDX généré par Trivy et conservé comme artefact CI
- [ ] Signature / attestation d'images (cosign)
- [x] Pin des GitHub Actions par SHA plutôt que par tag

## 👤 Auteur

**Aym** — En Mastère Cybersécurité & Réseaux, reconversion vers DevSecOps/Cloud
Security. CompTIA Security+ en préparation. [LinkedIn](https://www.linkedin.com/in/aymrajao/) · [GitHub](https://github.com/aym-sec-engineer)

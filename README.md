# 🛡️ Marley — laboratoire DevSecOps auto-hébergé

Marley est une infrastructure DevSecOps de laboratoire/portfolio construite sur
un VPS Ubuntu afin d'expérimenter une chaîne proche de problématiques de
production : exposition HTTPS, défense en profondeur, isolation réseau,
observabilité, CI/CD et contrôles de sécurité automatisés.

L'objectif du projet n'est pas de présenter cette architecture comme une
plateforme de production complète, mais de documenter des choix techniques,
leurs limites, les incidents rencontrés et les contrôles permettant de les
vérifier.

**Stack** : Ubuntu 24.04 LTS · Traefik v3 · ModSecurity + OWASP CRS · CrowdSec ·
Flask/Gunicorn · Docker Compose · GitHub Actions · Semgrep · Gitleaks · Trivy ·
Prometheus · Grafana · node-exporter · cAdvisor · OWASP ZAP

**Application** : `marley.aymrajao.dev` — VPS OVH

---

## 📐 Architecture

~~~text
                         Internet
                            │
                    HTTP :80 / HTTPS :443
                            │
                 ┌──────────▼──────────┐
                 │     Traefik v3      │
                 │ reverse proxy + TLS │
                 │   Let's Encrypt     │
                 └──────────┬──────────┘
                            │
                         web network
                            │
                 ┌──────────▼──────────┐
                 │   ModSecurity WAF   │
                 │     OWASP CRS       │
                 │  Paranoia Level 1   │
                 └──────────┬──────────┘
                            │
                      backend network
                       internal: true
                            │
                 ┌──────────▼──────────┐
                 │     marley_app      │
                 │   Flask / Gunicorn  │
                 │     non-root        │
                 └──────────┬──────────┘
                            │
                     monitoring network
                       internal: true
                            │
             ┌──────────────┼──────────────┐
             │              │              │
        Prometheus      cAdvisor     node-exporter
             │
          Grafana
~~~

Services complémentaires :

- `juice-shop` est une cible DAST isolée sur `backend`, sans port hôte publié
  ni route Traefik.
- CrowdSec fonctionne au niveau de l'hôte avec un bouncer nftables.
- Grafana est exposé séparément via Traefik.
- `backend` et `monitoring` sont déclarés `internal: true`.

---

## 🔒 Contrôles de sécurité

### Hôte et réseau

- durcissement SSH, sysctl et firewall hôte ;
- CrowdSec + bouncer nftables pour les décisions de remédiation réseau ;
- segmentation Docker entre `web`, `backend` et `monitoring` ;
- Juice Shop volontairement non exposé publiquement.

### Reverse proxy et application

- TLS Let's Encrypt via Traefik ;
- ModSecurity + OWASP Core Rule Set devant l'application ;
- application Flask exécutée par Gunicorn sous un utilisateur non-root ;
- healthcheck applicatif local ;
- politique HTTP comprenant HSTS, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` et CSP ;
- JavaScript exécutable servi localement ; la CSP n'autorise les scripts que
  depuis `'self'` ;
- les principaux champs textuels provenant des API et injectés dans des
  fragments HTML sont encodés avant rendu.

La CSP n'autorise plus les styles inline ; les styles applicatifs sont servis depuis les fichiers CSS du projet.
Les Google Fonts restent chargées depuis `fonts.googleapis.com` /
`fonts.gstatic.com`.

---

## 🔁 CI/CD et supply chain

Le workflow GitHub Actions exécute les contrôles principaux dans cet ordre :

~~~text
Checkout
   │
   ├── Gitleaks — secret scanning
   │
   ├── Semgrep — SAST bloquant
   │
   ├── Build image
   │
   ├── Trivy — CRITICAL/HIGH bloquants
   │
   ├── CycloneDX SBOM
   │
   ├── Trivy SARIF
   │
   ├── Push DockerHub (main)
   │
   └── Déploiement SSH (main)
~~~

### Semgrep

Semgrep est exécuté comme gate CI bloquant. L'image Semgrep utilisée par le
workflow est verrouillée par digest.

Le ruleset Community est actuellement résolu dynamiquement via `--config auto` :
le moteur est donc pinné, mais le contenu exact du ruleset n'est pas présenté
comme bit-for-bit reproductible.

La règle signalant les transports HTTP est conservée globalement active.
Seuls les appels `requests.get()` qui interrogent Prometheus sur le réseau
Docker interne `monitoring` portent une suppression locale documentée dans
[`semgrep-policy.md`](./semgrep-policy.md).

Les anciennes exceptions concernant l'entrypoint Flask `0.0.0.0` et le favicon
`data:` ont été supprimées à la source.

### Trivy et SBOM

L'image applicative est scannée avant push. Les vulnérabilités
`CRITICAL` / `HIGH` détectées par le gate configuré font échouer cette étape.

Trivy génère également :

- un rapport SARIF pour GitHub Security ;
- un SBOM CycloneDX conservé comme artefact GitHub Actions pendant 30 jours.

Le projet ne met actuellement en œuvre **ni signature d'image, ni attestation
de provenance**.

### Dépendances et images

- les GitHub Actions utilisées par le pipeline sont verrouillées par commit SHA ;
- les images tierces déclarées dans Compose sont verrouillées par digest ;
- les dépendances Python sont installées depuis un `requirements.txt` généré
  avec hashes et `pip --require-hashes` ;
- les dépendances frontend exécutées dans le navigateur sont servies localement ;
- l'image applicative déployée utilise un tag dérivé du commit Git
  (`GITHUB_SHA` tronqué à 8 caractères) et Compose refuse son démarrage si
  `MARLEY_IMAGE_TAG` n'est pas explicitement défini.

Ces mesures réduisent la dérive de dépendances, mais le build n'est pas présenté
comme bit-for-bit reproductible : certaines opérations de build restent
dépendantes de dépôts externes, notamment `apk upgrade`, et le ruleset
Community Semgrep est résolu dynamiquement via `--config auto`.

---

## 📊 Observabilité et provenance des données

Prometheus collecte notamment les métriques de `node-exporter`, `cAdvisor` et
Traefik. Grafana fournit les vues d'observabilité infrastructure et conteneurs.

Le dashboard Marley agrège plusieurs types de données. Leur provenance est
explicitement distinguée lorsque nécessaire :

- `live` : donnée collectée depuis une source runtime disponible ;
- `configured` : valeur issue de la configuration de l'application ;
- `recorded_scan` : résultat de scan historisé ;
- `not_instrumented` : composant présent mais sans télémétrie correspondante ;
- `unavailable` : source attendue indisponible.

Une valeur indisponible ne doit pas être interprétée comme une observation
réelle de l'infrastructure. Les collecteurs ne génèrent pas de métriques
fictives lorsque leur source runtime est indisponible.

### CrowdSec

Le dashboard distingue notamment :

- les décisions locales actives au moment de la collecte ;
- les alertes locales conservées ;
- les déclenchements de scénarios sur une fenêtre de 24 h lorsque la métrique
  Prometheus correspondante est disponible.

Ces valeurs ne représentent pas un compteur historique générique
« d'attaques bloquées ». Les données CAPI de CrowdSec ne sont pas assimilées à
des attaques observées contre Marley.

---

## 🧪 Security Evidence / DAST

La section **Security Evidence** distingue les preuves enregistrées de l'état
runtime.

Le fichier `compliance/compliance.json` contient actuellement des résultats
historisés de scans Trivy et OWASP ZAP. Ils sont exposés comme
`recorded_scan`, pas comme résultats live.

La politique d'en-têtes HTTP affichée par l'API correspond à la configuration
applicative (`configured`) et ne constitue pas, à elle seule, une vérification
externe du chemin HTTP complet.

OWASP Juice Shop sert de cible DAST isolée. Les résultats enregistrés dans le
repository constituent une preuve historique et ne garantissent pas l'état
actuel de l'application.

---

## 🐳 Conteneur applicatif

Le Dockerfile utilise deux stages.

Le runtime :

- exécute l'application avec Gunicorn ;
- utilise un utilisateur `marley` non-root ;
- retire `pip`, `setuptools` et `wheel` du runtime final ;
- possède un healthcheck HTTP local ;
- ne nécessite pas l'accès au socket Docker.

Le retrait des outils de packaging du runtime fait notamment suite à des
vulnérabilités rencontrées et documentées pendant la construction du projet.

---

## 🐛 Incidents et diagnostic

[`INCIDENTS.md`](./INCIDENTS.md) documente les principaux incidents rencontrés
pendant la construction du projet : crash loops, vulnérabilités de dépendances,
problèmes de déploiement et autres erreurs de configuration.

L'objectif est de conserver la démarche de diagnostic et les corrections
appliquées, plutôt que de ne montrer que l'état final fonctionnel.

---

## 🚀 Quickstart

Pré-requis : Docker Engine avec Compose, ainsi que le réseau Docker externe
`web`.

~~~bash
git clone https://github.com/aym-sec-engineer/marley-app.git
cd marley-app

cp .env.example .env
# Renseigner au minimum les secrets/configurations nécessaires.

docker network create web

export MARLEY_IMAGE_TAG=<tag-image>
docker compose up -d
~~~

`MARLEY_IMAGE_TAG` est volontairement obligatoire afin d'éviter qu'un
déploiement utilise implicitement une image `latest`.

Le déploiement complet dépend également de composants hôte qui ne sont pas
provisionnés par ce repository, notamment CrowdSec/nftables et la configuration
système du VPS.

---

## ⚠️ Limites actuelles

Ce projet reste un laboratoire mono-VPS et non une plateforme hautement
disponible.

Limites connues :

- absence de signature / attestation d'image ;
- absence d'Alertmanager ;
- absence de centralisation de logs type Loki ;
- certaines sources de sécurité sont volontairement `not_instrumented` ;
- la CSP n'utilise plus `style-src 'unsafe-inline'` ;
- Google Fonts reste une dépendance frontend externe ;
- cAdvisor fonctionne avec des privilèges élevés pour collecter la télémétrie
  des conteneurs ;
- le build n'est pas garanti bit-for-bit reproductible ;
- le repository ne provisionne pas intégralement le VPS depuis zéro.

---

## 🗺️ Roadmap

- [x] Gitleaks — secret scanning CI
- [x] Semgrep — SAST bloquant avec exceptions documentées
- [x] Trivy — scan d'image bloquant sur CRITICAL/HIGH
- [x] SBOM CycloneDX conservé comme artefact CI
- [x] GitHub Actions verrouillées par commit SHA
- [x] Images tierces Compose verrouillées par digest
- [ ] Signature / attestation d'images
- [ ] Alertmanager
- [ ] Centralisation des logs
- [x] Suppression des fallbacks de télémétrie simulée
- [x] Suppression de `style-src 'unsafe-inline'`
- [ ] Provisionnement reproductible de l'hôte

---

## 👤 Auteur

**Aym** — parcours orienté DevOps / DevSecOps / Cloud Security.

Projet réalisé comme laboratoire d'apprentissage et portfolio technique.

# Journal des incidents — Projet Marley

Ce document recense les incidents techniques réels rencontrés durant la construction
de l'infrastructure, leur diagnostic et leur résolution. Il sert de preuve de
méthode de debug, et de mémoire vive pour ne pas répéter les mêmes erreurs.

---

## #1 — cAdvisor ne peuplait aucune métrique conteneur

**Symptôme** : dashboard Grafana "Docker Monitoring" vide malgré cAdvisor `healthy`.

**Diagnostic** : `docker info` révélait `driver-type: io.containerd.snapshotter.v1`.
Docker 29.x utilise par défaut le nouveau containerd snapshotter, qui ne peuple
jamais `/var/lib/docker/image/overlayfs/layerdb/` — chemin legacy que cAdvisor
interroge encore pour la plupart de ses métriques.

**Fix** : désactivation du containerd snapshotter via `/etc/docker/daemon.json`
(`"features": {"containerd-snapshotter": false}`), retour au graphdriver
`overlay2` classique, redémarrage du daemon Docker.

---

## #2 — Image DockerHub `latest` introuvable

**Symptôme** : `docker compose up` échoue avec `manifest unknown` sur
`cyberaym/marley-test:latest`.

**Diagnostic** : seul le tag `v1.0` existait réellement sur DockerHub
(vérifié via l'API `hub.docker.com/v2/repositories/.../tags`).

**Fix temporaire** : pointage vers `v1.0` existant. **Fix définitif** :
correction de la CI pour pousser systématiquement `latest` en plus du tag versionné.

---

## #3 — Crash loop de `marley_app` (RestartCount: 26)

**Symptôme** : conteneur en boucle de redémarrage permanente, `docker logs` vide.

**Diagnostic** : `docker inspect` révélait `Cmd: [/bin/sh]`, `Entrypoint: []` —
l'image DockerHub ne contenait aucun code applicatif, juste un shell sans
rien à exécuter. Investigation plus poussée : le dossier `app/` n'existait
jamais dans le repo — le code (`main.py`, `templates/`, `Dockerfile`,
`requirements.txt`) était à la racine, mais le `docker-compose.yml`
référençait une image DockerHub distante au lieu de builder localement.

**Fix** : ajout de `build: .` dans le service `marley_app` du compose,
rebuild local, tag `v1.1`.

---

## #4 — 404 généralisé malgré des conteneurs "Up"

**Symptôme** : toute requête HTTPS externe renvoyait 404.

**Diagnostic** : le conteneur WAF (`marley-waf`) avait été oublié lors d'un
démarrage sélectif de services (`--no-deps traefik prometheus grafana...`)
pendant une session de troubleshooting précédente — il n'avait jamais été
redémarré. Sans lui, aucun router Traefik actif n'existait.

**Fix** : `docker compose up -d` (sans filtre) pour redémarrer l'ensemble
de la stack déclarée, garantissant qu'aucun service n'est oublié.

---

## #5 — Pipeline CI cassé : tag GitHub Action introuvable

**Symptôme** : tous les runs échouaient dès `Set up job` avec
`Unable to resolve action aquasecurity/trivy-action@0.24.0`.

**Diagnostic** : le tag réel sur GitHub était `v0.24.0` (avec préfixe "v"),
le YAML référençait `0.24.0` sans préfixe — résolution de tag exacte,
donc échec silencieux.

**Fix** : mise à jour vers `@v0.36.0` (dernière version disponible),
correction du préfixe manquant.

---

## #6 — CVE HIGH dans des dépendances vendorisées

**Symptôme** : Trivy bloque le build avec 2 CVE HIGH
(`CVE-2026-23949` sur jaraco.context, `CVE-2026-24049` sur wheel).

**Diagnostic** : ces bibliothèques n'apparaissaient dans aucune ligne de
`requirements.txt` — elles étaient vendorisées à l'intérieur de `setuptools`
lui-même (`setuptools/_vendor/`).

**Fix** : `pip install --upgrade pip setuptools wheel` ajouté dans le
Dockerfile avant l'installation des dépendances applicatives.

---

## #7 — Nouvelles CVE après le premier fix (msgpack, setuptools natif)

**Symptôme** : après le fix #6, Trivy détecte encore 2 CVE HIGH
(`msgpack` via GHSA-6v7p-g79w-8964, `setuptools` via CVE-2025-47273),
absentes elles aussi de `requirements.txt`.

**Diagnostic** : ces vulnérabilités venaient du `pip`/`setuptools` **natif**
préinstallé dans l'image de base `python:3.11-alpine`, pas du stage builder
qu'on venait de mettre à jour.

**Fix** : passage à un Dockerfile multi-stage — purge complète de
`pip`/`setuptools`/`wheel`/`ensurepip` du stage runtime final. Validé par
`which pip` (aucune sortie) et `import pip` (ModuleNotFoundError) sans
casser le fonctionnement de gunicorn/Flask.

---

## #8 — Déploiement SSH : `missing server host`

**Symptôme** : job `deploy` échoue immédiatement avec cette erreur.

**Diagnostic** : le YAML référençait `secrets.VPS_IP`, alors que le secret
configuré sur GitHub s'appelait `VPS_HOST` — mismatch de nommage entre deux
sessions de configuration à des moments différents.

**Fix** : alignement du nom de secret référencé dans le YAML sur le nom
réellement configuré sur GitHub (`VPS_IP`, secret recréé avec la bonne valeur).

---

## #9 — Déploiement SSH : `i/o timeout`

**Symptôme** : après le fix #8, nouvelle erreur `dial tcp ***:22: i/o timeout`.

**Diagnostic** : le YAML référençait `secrets.VPS_SSH_PORT` et
`secrets.VPS_SSH_USER`, qui n'existaient pas — seuls `SSH_PORT` et
`VPS_USERNAME` existaient sous des noms différents (reliquats de sessions
de config antérieures, avant le changement de VPS).

**Fix** : création des secrets manquants avec les noms exacts attendus par
le YAML (`VPS_SSH_PORT=22222`, `VPS_SSH_USER=ubuntu`), nettoyage des doublons
obsolètes.

---

## Leçon transversale

La majorité de ces incidents (#5, #8, #9) viennent de **mismatchs de nommage**
entre le code et la configuration externe (secrets, tags). Réflexe adopté
depuis : toujours lister l'état réel (`grep` du YAML, page Secrets GitHub)
avant de corriger, plutôt que de deviner.

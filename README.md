# DevSecOps Lab

Lab DevSecOps complet, déployé en **Infrastructure as Code** sur un serveur Debian 13.

## Architecture

```
Internet ──► Traefik (TLS Let's Encrypt) ──► Gitea · Vault · SonarQube · Grafana
                                          └─► réseau INTERNE : Juice Shop, runners CI (jamais exposés)
```

Deux couches IaC :

| Couche | Outil | Rôle |
|--------|-------|------|
| Provisioning hôte | **Ansible** (connexion locale) | durcissement, fail2ban, firewall ufw |
| Runtime services  | **Docker Compose** | un stack par groupe, tout derrière Traefik |
| Orchestration     | **Makefile** | point d'entrée unique |

## Phases

0. **Socle** — Ansible (hardening + firewall) + Traefik/TLS
1. **Vault** — gestion des secrets
2. **Gitea + Actions** — git + CI/CD
3. **SAST/SCA** — SonarQube, Semgrep, Trivy
4. **DAST** — OWASP ZAP + Juice Shop (réseau interne)
5. **Pipeline** — chaîne complète Vault→SAST→build→Trivy→deploy→DAST
6. **Observabilité** — Prometheus, Grafana, Loki, Falco

## Démarrage

```bash
cp .env.example .env          # renseigner LAB_DOMAIN, ACME_EMAIL, dashboard auth
make help                     # voir toutes les cibles
make provision                # durcissement + firewall (Ansible)
make network                  # créer le réseau Docker partagé 'web'
make traefik-up               # démarrer le reverse proxy
```

## Sécurité

- Les apps volontairement vulnérables (Juice Shop, DVWA) restent sur un réseau Docker **interne** — jamais publiées.
- Les secrets ne sont **jamais** commités : `.env` est git-ignoré, puis migré vers Vault (Phase 1).
- Firewall en deny-by-default, seuls 22/80/443 ouverts.

# DevSecOps Lab — point d'entrée unique
# Usage : make help

SHELL := /bin/bash
COMPOSE := docker compose

# Charge .env s'il existe (pour LAB_DOMAIN, etc.)
ifneq (,$(wildcard .env))
include .env
export
endif

.DEFAULT_GOAL := help

## help            : liste les cibles disponibles
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | awk -F ':' '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## provision       : durcissement OS + firewall (Ansible, connexion locale)
.PHONY: provision
provision:
	cd ansible && ansible-playbook site.yml

## provision-check : dry-run Ansible (--check, ne modifie rien)
.PHONY: provision-check
provision-check:
	cd ansible && ansible-playbook site.yml --check --diff

## network         : crée le réseau Docker partagé 'web'
.PHONY: network
network:
	@docker network inspect web >/dev/null 2>&1 || docker network create web
	@docker network inspect internal >/dev/null 2>&1 || docker network create --internal internal
	@echo "réseaux 'web' (public) et 'internal' (isolé) prêts"

## traefik-up      : démarre le reverse proxy Traefik
.PHONY: traefik-up
traefik-up: network
	$(COMPOSE) -f stacks/traefik/docker-compose.yml up -d

## traefik-down    : arrête Traefik
.PHONY: traefik-down
traefik-down:
	$(COMPOSE) -f stacks/traefik/docker-compose.yml down

## traefik-logs    : logs Traefik en direct
.PHONY: traefik-logs
traefik-logs:
	$(COMPOSE) -f stacks/traefik/docker-compose.yml logs -f

## ps              : état de tous les conteneurs du lab
.PHONY: ps
ps:
	@docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

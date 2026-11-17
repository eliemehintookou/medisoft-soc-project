# Module 1 — Mise en place du SOC

## Objectif

Mettre en service une plateforme SIEM sécurisée pour MediSoft, y faire arriver des journaux Windows **normalisés**, et documenter le service et la plateforme comme le ferait un SOC prestataire au démarrage d'un nouveau client.

## Missions couvertes

- *« Configurer les solutions chez nos clients afin de leur garantir une protection maximale »*
- *« Élaborer des documentations techniques, spécifications générales et détaillées »*
- *« Intégrer des solutions éditeurs orientées EDR, XDR, Mobiles et Cloud »* (choix et intégration de la plateforme, Sysmon comme télémétrie de type EDR)

## Livrables

| Livrable | Fichier |
|---|---|
| Spécification générale du service SOC (périmètre, services, priorités P1 à P4, RACI, 10 cas d'usage MITRE) | [MS-SOC-SPG-01](../docs/MS-SOC-SPG-01_Specification_generale.md) |
| Spécification détaillée de la plateforme (architecture, flux, comptes, stockage, table de normalisation ECS, recette) | [MS-SOC-SPD-01](../docs/MS-SOC-SPD-01_Specification_detaillee_plateforme.md) |
| Déploiement Elastic Security sécurisé (authentification, TLS, ports locaux) | [docker-compose.yml](../lab/docker-compose.yml) |
| Guide d'installation et de recette | [INSTALLATION.md](../lab/INSTALLATION.md) |
| Script de collecte et de normalisation ECS (Sysmon + journal Sécurité, recalage temporel) | [ingest_windows_dataset.py](../scripts/ingest_windows_dataset.py) |

## Ce que j'ai fait

1. **Choisi la plateforme** (Elastic Security plutôt que Wazuh, déjà utilisé dans mon projet de M1) en fonction des besoins des modules suivants : corrélation EQL, exceptions, cas d'investigation, normalisation ECS.
2. **Déployé une plateforme sécurisée dès le départ** : authentification obligatoire, TLS avec une autorité de certification propre, ports ouverts uniquement en local, secrets hors de Git.
3. **Appliqué le moindre privilège** : un compte de collecte qui peut écrire mais pas lire (un attaquant qui volerait ses identifiants ne pourrait pas effacer ses traces), et un compte analyste nominatif sans droits d'administration.
4. **Écrit un script de normalisation** qui convertit les journaux Windows bruts au format ECS (Elastic Common Schema), avec nettoyage des valeurs, conversion des adresses IP et des identifiants hexadécimaux, et conservation des champs d'origine.
5. **Résolu le problème des jeux de données anciens** avec un recalage temporel qui préserve la chronologie de l'attaque.
6. **Validé la chaîne complète** avec un vrai jeu de données d'attaque : dump de la mémoire de LSASS via `comsvcs.dll`, retrouvé dans Kibana sur le poste `WS-COMPTA-07`.

## Résultats de la recette

> À compléter après exécution du guide d'installation.

| Test | Résultat | Preuve |
|---|---|---|
| R1 — Santé du cluster | | `captures/02_tests_api_R1_R2.png` |
| R2 — Accès refusé sans identifiants | | `captures/02_tests_api_R1_R2.png` |
| R3 — Connexion analyste | | `captures/03_role_soc_analyste.png` |
| R4 — Ingestion (184 événements) | | `captures/04_ingestion.png` |
| R5 — Hôte visible dans Elastic Security | | `captures/07_security_hosts.png` |
| R6 — Compte de collecte sans droit de lecture (403) | | `captures/05_test_R6_403.png` |
| R7 — Accès à LSASS retrouvé | | `captures/06_discover_lsass.png` |

## Questions d'entretien à maîtriser

1. Pourquoi normaliser les journaux avant de détecter ? Qu'est-ce que l'ECS ?
2. Quelle différence entre un événement Sysmon 1 et un événement Sécurité 4688 ?
3. Que signifie un `GrantedAccess` de `0x1fffff` sur `lsass.exe` ? Pourquoi un attaquant vise-t-il LSASS ?
4. Pourquoi le compte de collecte ne doit-il pas pouvoir lire ni supprimer ?
5. Pourquoi faut-il recaler le temps d'un jeu de données rejoué, et pourquoi garder les écarts entre événements ?
6. Quelles sont les limites d'un SIEM mono-nœud ? Que faudrait-il en production ?
7. Pourquoi Elastic plutôt que Wazuh ici ? Qu'apporte chacun ?

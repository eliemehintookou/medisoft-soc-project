# MS-SOC-SPG-01 — Spécification générale du service SOC MediSoft

| | |
|---|---|
| Référence | MS-SOC-SPG-01 |
| Version | 1.0 — novembre 2026 |
| Auteur | Elie MEHINTO, analyste SOC (prestataire « SOC Vigie ») |
| Destinataires | RSSI MediSoft, manager SOC, équipe Ops MediSoft |
| Documents liés | MS-SOC-SPD-01 (spécification détaillée), MS-PRO-04 (gestion des incidents, projet GRC), MS-MOD-04 (playbooks, projet GRC) |

---

## 1. Objet

Ce document décrit **ce que fait le service SOC** pour MediSoft : périmètre surveillé, services rendus, niveaux de priorité, délais, rôles et cas d'usage de détection. La spécification détaillée (MS-SOC-SPD-01) décrit **comment** la plateforme est construite.

## 2. Contexte

MediSoft est un éditeur SaaS de dossier patient informatisé (85 salariés, environ 120 établissements de santé clients, hébergement AWS en région Paris). Le projet GRC de 2026 a mis en place la gouvernance de la sécurité : PSSI, politiques, procédure de gestion des incidents (MS-PRO-04) et playbooks (MS-MOD-04).

Il manquait une brique : **personne ne surveille les journaux en continu**. La politique cloud (MS-POL-05) prévoit que les alertes GuardDuty partent vers un SIEM, et la check-list projet exige que les alertes soient raccordées au SIEM, mais aucun SIEM n'est exploité. Avec 85 salariés, MediSoft n'a pas les moyens d'avoir un SOC interne 24 h/24. La direction a donc décidé de **confier la supervision à un SOC prestataire** (SOC managé).

> **Hypothèse du projet SOC.** Pour couvrir les cas d'usage Windows des offres visées, on considère que MediSoft a aussi un contrôleur de domaine Windows (`DC-MEDISOFT-01`), synchronisé avec Entra ID. Ce n'était pas précisé dans le projet GRC.

## 3. Périmètre supervisé

| Périmètre | Actifs | Source de journaux | Dans le lab |
|---|---|---|---|
| Postes de travail | ~85 postes Windows 10/11 gérés par Intune, avec un EDR | Sysmon (télémétrie de type EDR) + journal Sécurité Windows | Oui (jeux de données rejoués + tests en direct) |
| Annuaire | `DC-MEDISOFT-01` (Active Directory) | Journal Sécurité (authentification, Kerberos, gestion des comptes) | Oui |
| Cloud | Comptes AWS (production, `securite`) | CloudTrail centralisé dans le compte `securite`, GuardDuty | Oui (module 6) |
| Identité cloud | Entra ID | Journaux de connexion et d'audit | Non, présenté comme une perspective |
| Mobiles | Application mobile patients, smartphones des salariés | Mobile Threat Defense | Non, présenté comme une perspective |

**Hors périmètre :** les journaux applicatifs de MediSoft Care (accès aux dossiers patients), suivis par l'équipe produit et le DPO. Les journaux collectés par le SOC ne doivent contenir **aucune donnée de santé** (exigence HDS).

## 4. Services rendus par le SOC

| Service | Description | Mission des offres |
|---|---|---|
| **Surveillance** | Suivi des alertes générées par la plateforme | « Monitorer les incidents en temps réel » |
| **Qualification** | Décider si une alerte est un vrai positif, un faux positif ou un comportement légitime ; fixer la priorité | « Qualifier les incidents », « diagnostiquer un incident » |
| **Traitement et escalade** | Investigation, recommandations de confinement et de remédiation, transmission à MediSoft selon MS-PRO-04 | « Traiter les incidents », « mener les actions de remédiation » |
| **Ingénierie de détection** | Création, test et amélioration des règles de détection | « Amélioration des règles de détection », « nouveaux scénarios » |
| **Tuning** | Gestion des exclusions pour réduire les faux positifs, avec justification et revue | « Gestion d'exclusions » |
| **Amélioration continue** | Automatisation, indicateurs, rapport mensuel | « Processus plus performants », « évolution du service » |

## 5. Niveaux de priorité et délais

La priorité est fixée par l'analyste au moment de la qualification. Lorsqu'un incident est confirmé, sa **gravité** est ensuite fixée par MediSoft avec la grille de la procédure MS-PRO-04.

| Priorité | Définition | Exemples | Prise en charge | Escalade vers MediSoft |
|---|---|---|---|---|
| **P1 — Critique** | Compromission en cours ou impact imminent sur la production ou des données | Vol d'identifiants (accès à LSASS), rançongiciel, clé AWS utilisée depuis l'extérieur | 15 min | Immédiate par téléphone (astreinte Ops + RSSI) |
| **P2 — Haute** | Activité malveillante probable sur un actif | PowerShell encodé lancé par Office, création de persistance, bucket S3 rendu public | 1 h | Sous 2 h par ticket et e-mail |
| **P3 — Moyenne** | Activité suspecte à investiguer | Échecs de connexion en série, outil d'administration inhabituel | 4 h ouvrées | Dans le rapport quotidien |
| **P4 — Basse** | Information ou anomalie sans risque immédiat | Écart de configuration, règle trop bruyante | 2 jours ouvrés | Dans le rapport mensuel |

## 6. Cas d'usage de détection prioritaires

Ils viennent des risques identifiés dans l'analyse EBIOS RM et des quatre playbooks du projet GRC (phishing, rançongiciel, fuite de données, compromission de compte).

| ID | Cas d'usage | Tactique MITRE ATT&CK | Playbook GRC lié | Module |
|---|---|---|---|---|
| UC-01 | Exécution PowerShell obfusquée ou encodée | Execution (T1059.001), Defense Evasion (T1027) | Phishing | 2 |
| UC-02 | Document Office qui lance un interpréteur de commandes | Initial Access (T1566.001) | Phishing | 2 |
| UC-03 | Accès mémoire à LSASS (vol d'identifiants) | Credential Access (T1003.001) | Compromission de compte | 2 |
| UC-04 | Persistance par tâche planifiée ou service | Persistence (T1053.005, T1543.003) | Rançongiciel | 2 |
| UC-05 | Brute force suivi d'une connexion réussie | Credential Access (T1110) | Compromission de compte | 3 (corrélation) |
| UC-06 | Kerberoasting | Credential Access (T1558.003) | Compromission de compte | 3 |
| UC-07 | Mouvement latéral (PsExec, WMI) | Lateral Movement (T1021.002, T1047) | Rançongiciel | 3 |
| UC-08 | Suppression des sauvegardes / clichés instantanés | Impact (T1490) | Rançongiciel | 2 |
| UC-09 | Clé d'accès AWS utilisée depuis une IP inhabituelle | Initial Access (T1078.004) | Compromission de compte | 6 |
| UC-10 | Bucket S3 rendu public ou CloudTrail désactivé | Exfiltration (T1537), Defense Evasion (T1562.008) | Fuite de données | 6 |

## 7. Rôles et responsabilités (RACI)

| Activité | Analyste N1 | Analyste N2 | Manager SOC | RSSI MediSoft | Ops MediSoft |
|---|---|---|---|---|---|
| Surveillance et qualification | **R** | C | I | — | — |
| Investigation approfondie | C | **R** | A | I | C |
| Escalade P1/P2 | R | **R** | A | I | I |
| Confinement (isolement d'un poste, désactivation d'un compte) | — | C | I | A | **R** |
| Création et modification de règles | C | **R** | A | I | — |
| Validation des exclusions | — | R | **A** | C | — |
| Rapport mensuel | C | R | **A** | I | — |

R = réalise, A = approuve et rend des comptes, C = consulté, I = informé.

## 8. Exigences sur la plateforme

| Exigence | Valeur cible (production) | Dans le lab |
|---|---|---|
| Authentification | Comptes nominatifs, moindre privilège, MFA | Comptes nominatifs et rôles séparés (pas de MFA) |
| Chiffrement | TLS sur tous les flux | TLS entre Kibana et Elasticsearch, et pour l'ingestion |
| Exposition | Accès d'administration uniquement depuis le réseau du SOC | Ports ouverts uniquement en local (127.0.0.1) |
| Rétention | 1 an (alignée sur MS-POL-05 pour CloudTrail) | Durée du projet |
| Disponibilité | Cluster multi-nœuds | Mono-nœud (limite assumée) |
| Format | Normalisation ECS de toutes les sources | Oui |

## 9. Feuille de route du projet

| Module | Contenu |
|---|---|
| 1 | Mise en place de la plateforme, collecte et normalisation, spécifications (ce document) |
| 2 | Ingénierie de détection : règles Sigma, conversion, mapping MITRE (UC-01 à UC-04, UC-08) |
| 3 | Purple team et corrélation : Atomic Red Team, règles de séquence (UC-05 à UC-07) |
| 4 | Tuning : faux positifs, exclusions justifiées, mesure du bruit |
| 5 | Procédures de traitement des alertes et deux enquêtes complètes |
| 6 | Détection cloud AWS (UC-09, UC-10) |
| 7 | Amélioration du service : enrichissement automatique, indicateurs, tableau de bord |

## 10. Limites assumées

- Plateforme mono-nœud, pas de haute disponibilité.
- Les postes sont représentés par des jeux de données réels rejoués (OTRF Security-Datasets) et par des tests en direct, pas par 85 machines.
- Elastic Security remplace un SIEM ou XDR commercial. Les principes (normalisation, règles, exceptions, cas) sont les mêmes que dans les outils du marché, mais les produits eux-mêmes n'ont pas été pratiqués.

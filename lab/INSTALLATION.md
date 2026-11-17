# Installation de la plateforme SOC (module 1)

Guide pas à pas pour un PC **Windows 10/11 + WSL2 (Ubuntu) + Docker Desktop**.
Durée estimée : 45 minutes à 1 h (dont le téléchargement des images, environ 1,5 Go).

> 📸 Les captures à faire sont signalées par **[CAPTURE n]**. Enregistre-les dans `module1/captures/` avec le nom indiqué : ce sont tes preuves pour le README et pour les entretiens.

---

## Étape 0 — Vérifier la mémoire disponible

Ouvre le Gestionnaire des tâches, onglet **Performances**, puis **Mémoire**.

- La plateforme consomme environ **3,5 Go** (Elasticsearch 2 Go + Kibana 1,5 Go).
- Avec 8 Go au total, ferme le navigateur superflu, Teams, etc. pendant les tests.
- Avec moins de 8 Go, préviens-moi : on passera Elasticsearch à `ES_HEAP=768m` et `ES_MEM_LIMIT=1536m`.

## Étape 1 — Préparer WSL2

Elasticsearch a besoin d'un réglage du noyau Linux (`vm.max_map_count`), et WSL doit avoir assez de mémoire.

1. Sous Windows, ouvre (ou crée) le fichier `C:\Users\<ton_nom>\.wslconfig` et mets :

   ```ini
   [wsl2]
   memory=5GB
   kernelCommandLine = "sysctl.vm.max_map_count=262144"
   ```

2. Dans PowerShell : `wsl --shutdown`, puis relance Docker Desktop.
3. Dans Ubuntu (WSL), vérifie :

   ```bash
   sysctl vm.max_map_count     # attendu : vm.max_map_count = 262144
   docker version              # le client ET le serveur doivent répondre
   ```

## Étape 2 — Récupérer le projet et configurer les secrets

```bash
cd ~
git clone https://github.com/eliemehintookou/medisoft-soc-project.git   # une fois le dépôt créé
cd medisoft-soc-project/lab
cp .env.example .env
openssl rand -hex 32          # copie le résultat dans KIBANA_ENCRYPTION_KEY
nano .env                     # change aussi ELASTIC_PASSWORD et KIBANA_PASSWORD
```

⚠️ Le fichier `.env` contient tes mots de passe : il est exclu de Git par `.gitignore`. Vérifie avec `git status` qu'il n'apparaît jamais.

## Étape 3 — Démarrer la plateforme

```bash
docker compose up -d
docker compose logs -f setup      # attendre "Setup terminé", puis Ctrl+C
docker compose ps                 # es01 et kibana doivent être "healthy"
```

Kibana met 1 à 3 minutes à devenir `healthy`. **[CAPTURE 1]** `01_docker_compose_ps.png` : la sortie de `docker compose ps`.

### En cas de problème

| Symptôme | Cause probable | Solution |
|---|---|---|
| es01 redémarre en boucle, `exit code 137` | Mémoire insuffisante | Réduire `ES_HEAP` / `ES_MEM_LIMIT`, fermer des applications |
| `max virtual memory areas vm.max_map_count [65530] is too low` | Étape 1 non prise en compte | Refaire `wsl --shutdown` et redémarrer Docker Desktop |
| Kibana : `Unable to retrieve version information` | Mot de passe `kibana_system` non appliqué | `docker compose logs setup`, vérifier `KIBANA_PASSWORD` |
| Kibana « server is not ready yet » | Démarrage en cours | Attendre 2 minutes |

Pour lire les journaux d'un service : `docker compose logs es01 --tail 50`.

## Étape 4 — Récupérer le certificat de la CA et tester l'API

```bash
cd ../scripts
docker cp soc-es01:/usr/share/elasticsearch/config/certs/ca/ca.crt ./ca.crt

# R2 : sans identifiants, l'accès doit être refusé
curl --cacert ca.crt https://localhost:9200

# R1 : santé du cluster (le mot de passe elastic est demandé)
curl --cacert ca.crt -u elastic "https://localhost:9200/_cluster/health?pretty"
```

Attendu : R2 renvoie `missing authentication credentials`, R1 renvoie `"status" : "green"` ou `"yellow"`. **[CAPTURE 2]** `02_tests_api_R1_R2.png`.

> Le fichier `ca.crt` est exclu de Git : il est propre à ton installation.

## Étape 5 — Créer le compte d'ingestion (moindre privilège)

```bash
# Rôle : uniquement AJOUTER des documents dans logs-medisoft.*
curl --cacert ca.crt -u elastic -X PUT "https://localhost:9200/_security/role/medisoft_ingest" \
  -H "Content-Type: application/json" -d '{
    "indices": [ { "names": ["logs-medisoft.*"], "privileges": ["create_doc", "auto_configure"] } ]
  }'

# Utilisateur technique (choisis un mot de passe fort)
curl --cacert ca.crt -u elastic -X PUT "https://localhost:9200/_security/user/svc_ingest" \
  -H "Content-Type: application/json" -d '{
    "password": "MotDePasseIngestion_A_Changer",
    "roles": ["medisoft_ingest"],
    "full_name": "Compte technique de collecte SOC"
  }'
```

Chaque commande doit répondre `{"role":{"created":true}}` ou `{"created":true}`.

## Étape 6 — Créer le compte analyste (dans Kibana)

1. Ouvre http://localhost:5601 et connecte-toi avec `elastic`.
2. Va dans **Stack Management**, puis **Roles**, puis **Create role**, nom `soc_analyste` :
   - **Index privileges**
     - `logs-*` : `read`, `view_index_metadata`
     - `.alerts-security*` : `read`, `write`, `view_index_metadata`, `maintenance`
     - `.lists*`, `.items*` : `read`, `view_index_metadata`
   - **Kibana privileges** : *Add Kibana privilege*, tous les espaces, *Customize*, puis **Security : All**, **Discover : Read**, **Dashboard : Read**
3. Toujours en `elastic` : **Stack Management**, puis **Data Views**, puis **Create data view** : nom `MediSoft Windows`, motif `logs-medisoft*`, champ de temps `@timestamp`. (Le rôle analyste n'a volontairement pas le droit de créer des vues de données.)
4. Va dans **Stack Management**, puis **Users**, puis **Create user** : `analyste.n1`, ton nom complet, rôle `soc_analyste`.
5. Déconnecte-toi, puis reconnecte-toi avec `analyste.n1` (test R3).

> La vue de données peut être créée avant l'ingestion : Kibana préviendra qu'aucune donnée ne correspond encore. Si elle refuse, crée-la juste après l'étape 7.

**[CAPTURE 3]** `03_role_soc_analyste.png` : l'écran des privilèges du rôle.

## Étape 7 — Ingérer un premier jeu de données d'attaque

On utilise un vrai jeu de données OTRF : **un dump de la mémoire de LSASS via `comsvcs.dll`**, une technique de vol d'identifiants très utilisée par les rançongiciels.

```bash
cd ~/medisoft-soc-project
mkdir -p datasets && cd datasets
wget https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip
unzip psh_lsass_memory_dump_comsvcs.zip
cd ../scripts
python3 -m pip install -r requirements.txt       # ajouter --break-system-packages si pip refuse

# 1) Test à blanc : afficher 3 documents normalisés sans rien envoyer
python3 ingest_windows_dataset.py ../datasets/psh_lsass_memory_dump_comsvcs_*.json --dry-run | head -60

# 2) Ingestion réelle avec le compte technique
export ES_USER=svc_ingest
read -s -p "Mot de passe svc_ingest : " ES_PASSWORD; export ES_PASSWORD; echo
python3 ingest_windows_dataset.py ../datasets/psh_lsass_memory_dump_comsvcs_*.json \
  --host-map WORKSTATION5=WS-COMPTA-07 --rebase-time
```

Attendu (test R4) : `184 événements lus`, `184 documents normalisés`, `184 documents indexés ... 0 rejetés`. **[CAPTURE 4]** `04_ingestion.png`.

Pourquoi `read -s` ? Pour que le mot de passe ne s'affiche pas à l'écran et ne reste pas dans l'historique bash.

## Étape 8 — Vérifier le moindre privilège (test R6)

```bash
curl --cacert ca.crt -u svc_ingest "https://localhost:9200/logs-medisoft*/_search?size=1"
```

Attendu : erreur **403** `security_exception ... unauthorized`. Le compte de collecte peut écrire mais pas lire. **[CAPTURE 5]** `05_test_R6_403.png`.

## Étape 9 — Retrouver l'attaque dans Kibana (tests R5 et R7)

Connecté en `analyste.n1` :

1. Ouvre **Discover** et sélectionne la vue de données `MediSoft Windows`.
2. Règle la période sur **Last 1 hour**.
3. Tape la requête KQL :

   ```
   event.code: "10" and winlog.event_data.TargetImage: *lsass.exe
   ```

4. Ajoute les colonnes `host.name`, `process.name`, `winlog.event_data.GrantedAccess`, `winlog.event_data.TargetImage`.

Tu dois voir `rundll32.exe` accéder à `lsass.exe` avec `GrantedAccess` = `0x1fffff` (accès complet) sur `WS-COMPTA-07`. **C'est la trace du vol d'identifiants.** **[CAPTURE 6]** `06_discover_lsass.png`.

5. Ouvre **Security**, puis **Explore**, puis **Hosts** : `WS-COMPTA-07` doit apparaître. **[CAPTURE 7]** `07_security_hosts.png`.

## Arrêter et relancer

```bash
cd ~/medisoft-soc-project/lab
docker compose stop        # arrête sans rien perdre (données conservées)
docker compose start       # relance
docker compose down -v     # ⚠️ supprime TOUT (données, certificats) : repartir de zéro
```

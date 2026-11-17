#!/usr/bin/env python3
"""
ingest_windows_dataset.py — SOC MediSoft, module 1

Rôle : collecter des journaux Windows (Sysmon + journal Sécurité) enregistrés
au format JSON (jeux de données OTRF Security-Datasets), les NORMALISER au
format ECS (Elastic Common Schema), puis les envoyer dans Elasticsearch.

Pourquoi normaliser ?
  Les règles de détection d'Elastic Security (et la plupart des règles Sigma
  converties) cherchent des champs ECS : process.name, process.command_line,
  user.name, source.ip... Un journal brut ("Image", "CommandLine",
  "TargetUserName") ne serait jamais détecté. La normalisation est la première
  mission d'un SOC : sans données propres, pas de détection.

Pourquoi recaler le temps (--rebase-time) ?
  Les jeux de données datent de 2020-2021. Les règles de détection ne
  regardent que les dernières minutes. On décale donc tous les événements
  pour que le dernier tombe "maintenant", en conservant les écarts entre
  événements (la chronologie de l'attaque reste intacte).

Usage :
  python3 ingest_windows_dataset.py fichier.json --host-name WS-COMPTA-07 --rebase-time
  python3 ingest_windows_dataset.py fichier.json --host-map WORKSTATION5=WS-COMPTA-07,MORDORDC=DC-MEDISOFT-01 --rebase-time
  python3 ingest_windows_dataset.py fichier.json --dry-run      # test sans envoi

Variables d'environnement :
  ES_URL       (défaut : https://localhost:9200)
  ES_USER      (défaut : elastic)
  ES_PASSWORD  (obligatoire sauf --dry-run)
  ES_CA_CERT   (défaut : ./ca.crt)
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

try:
    import requests
except ImportError:
    sys.exit("Module 'requests' manquant : pip install -r requirements.txt")

# Data stream de destination : le modèle intégré "logs-*-*" d'Elasticsearch
# applique automatiquement les mappings ECS (ip, date, keyword...).
DEFAULT_INDEX = "logs-medisoft.windows-default"
BATCH_SIZE = 500
ECS_VERSION = "8.11.0"

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"

# Libellés des événements Sysmon (event.action)
SYSMON_ACTIONS = {
    1: "process-created",
    3: "network-connection",
    5: "process-terminated",
    7: "image-loaded",
    8: "create-remote-thread",
    10: "process-access",
    11: "file-created",
    12: "registry-object-added-or-deleted",
    13: "registry-value-set",
    22: "dns-query",
    23: "file-deleted",
}

# Événements du journal Sécurité pris en charge
SECURITY_ACTIONS = {
    4624: "logged-in",
    4625: "logon-failed",
    4634: "logged-out",
    4648: "logged-in-explicit",
    4672: "logged-in-special",
    4688: "created-process",
    4697: "service-installed",
    4698: "scheduled-task-created",
    4720: "added-user-account",
    4728: "added-member-to-group",
    4732: "added-member-to-group",
    4769: "kerberos-service-ticket-requested",
}


# ---------------------------------------------------------------------------
# Fonctions utilitaires
# ---------------------------------------------------------------------------

def parse_timestamp(raw):
    """Convertit les différents formats de date rencontrés en datetime UTC."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):  # epoch en secondes ou millisecondes
        value = raw / 1000 if raw > 10**11 else raw
        return datetime.fromtimestamp(value, tz=timezone.utc)
    text = str(raw).strip().replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Python n'accepte que 6 chiffres après la virgule : on tronque au-delà
    if "." in text:
        head, tail = text.split(".", 1)
        digits = ""
        rest = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                digits += ch
            else:
                rest = tail[i:]
                break
        text = f"{head}.{digits[:6]}{rest}"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def get_timestamp(rec):
    for key in ("@timestamp", "TimeCreated", "EventTime", "UtcTime", "timestamp"):
        dt = parse_timestamp(rec.get(key))
        if dt:
            return dt
    return None


def clean(value):
    """Valeurs vides de Windows ('-', '', '0x0'...) -> None."""
    if value is None:
        return None
    if isinstance(value, str) and value.strip() in ("", "-", "None", "N/A"):
        return None
    return value


def to_int(value):
    value = clean(value)
    if value is None:
        return None
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (ValueError, TypeError):
        return None


def to_ip(value):
    """Garde uniquement une adresse IP plausible (sinon Elasticsearch rejette)."""
    value = clean(value)
    if not isinstance(value, str):
        return None
    if value.startswith("::ffff:"):  # IPv4 encapsulée dans de l'IPv6
        value = value[7:]
    if value.count(".") == 3 or ":" in value:
        return value
    return None


def basename(path):
    path = clean(path)
    if not isinstance(path, str):
        return None
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def split_user(value):
    """'MEDISOFT\\jdupont' -> ('MEDISOFT', 'jdupont')"""
    value = clean(value)
    if not isinstance(value, str):
        return None, None
    if "\\" in value:
        domain, name = value.split("\\", 1)
        return domain, name
    return None, value


def parse_hashes(value):
    """'SHA256=AB..,MD5=CD..' -> {'sha256': 'ab..', 'md5': 'cd..'}"""
    value = clean(value)
    result = {}
    if not isinstance(value, str):
        return result
    for part in value.split(","):
        if "=" in part:
            algo, digest = part.split("=", 1)
            algo = algo.strip().lower()
            if algo in ("md5", "sha1", "sha256", "imphash"):
                result[algo] = digest.strip().lower()
    return result


def put(doc, dotted_key, value):
    """Écrit doc['a']['b']['c'] = value à partir de 'a.b.c' (ignore les None)."""
    if value is None or value == {}:
        return
    keys = dotted_key.split(".")
    node = doc
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = value


# ---------------------------------------------------------------------------
# Normalisation ECS
# ---------------------------------------------------------------------------

def resolve_host(rec, host_override=None, host_map=None):
    original = rec.get("Hostname") or rec.get("Computer")
    if host_map and original:
        short = str(original).split(".")[0].upper()
        if short in host_map:
            return host_map[short]
    return host_override or original


def normalize(rec, host_override=None, host_map=None):
    event_id = to_int(rec.get("EventID") or rec.get("EventId") or rec.get("event_id"))
    channel = rec.get("Channel") or rec.get("channel") or ""
    if event_id is None:
        return None

    is_sysmon = channel == SYSMON_CHANNEL or "Sysmon" in str(rec.get("SourceName", ""))
    is_security = channel == SECURITY_CHANNEL

    doc = {}
    put(doc, "ecs.version", ECS_VERSION)
    put(doc, "event.kind", "event")
    put(doc, "event.code", str(event_id))
    put(doc, "event.provider", rec.get("SourceName") or rec.get("ProviderName"))
    put(doc, "winlog.channel", channel or None)
    put(doc, "winlog.event_id", str(event_id))
    put(doc, "host.name", resolve_host(rec, host_override, host_map))
    put(doc, "host.os.type", "windows")
    put(doc, "host.os.family", "windows")
    put(doc, "data_stream.type", "logs")
    put(doc, "data_stream.dataset", "medisoft.windows")
    put(doc, "data_stream.namespace", "default")
    put(doc, "event.dataset", "medisoft.windows")
    put(doc, "message", rec.get("Message"))

    # On conserve TOUS les champs bruts sous winlog.event_data : utile pour
    # l'investigation et pour les règles qui ciblent les champs Windows d'origine.
    skip = {"@timestamp", "@version", "Message", "Hostname", "Channel", "EventID"}
    event_data = {k: v for k, v in rec.items()
                  if k not in skip and not isinstance(v, (dict, list)) and clean(v) is not None}
    if event_data:
        doc["winlog"]["event_data"] = {k: str(v) for k, v in event_data.items()}

    if is_sysmon:
        put(doc, "event.module", "sysmon")
        put(doc, "event.action", SYSMON_ACTIONS.get(event_id, f"sysmon-{event_id}"))
        map_sysmon(doc, rec, event_id)
    elif is_security:
        put(doc, "event.module", "security")
        put(doc, "event.action", SECURITY_ACTIONS.get(event_id, f"security-{event_id}"))
        map_security(doc, rec, event_id)
    else:
        put(doc, "event.module", "windows")
        put(doc, "event.action", f"event-{event_id}")
    return doc


def map_process(doc, prefix, image, cmd=None, pid=None, entity=None):
    put(doc, f"{prefix}.executable", clean(image))
    put(doc, f"{prefix}.name", basename(image))
    put(doc, f"{prefix}.command_line", clean(cmd))
    put(doc, f"{prefix}.pid", to_int(pid))
    put(doc, f"{prefix}.entity_id", clean(entity))


def map_sysmon(doc, rec, eid):
    domain, name = split_user(rec.get("User"))
    put(doc, "user.domain", domain)
    put(doc, "user.name", name)
    map_process(doc, "process", rec.get("Image"), rec.get("CommandLine"),
                rec.get("ProcessId"), rec.get("ProcessGuid"))

    if eid == 1:  # Création de processus
        put(doc, "event.category", ["process"])
        put(doc, "event.type", ["start"])
        map_process(doc, "process.parent", rec.get("ParentImage"),
                    rec.get("ParentCommandLine"), rec.get("ParentProcessId"),
                    rec.get("ParentProcessGuid"))
        put(doc, "process.working_directory", clean(rec.get("CurrentDirectory")))
        put(doc, "process.pe.original_file_name", clean(rec.get("OriginalFileName")))
        put(doc, "process.hash", parse_hashes(rec.get("Hashes")))
    elif eid == 3:  # Connexion réseau
        put(doc, "event.category", ["network"])
        put(doc, "event.type", ["connection"])
        put(doc, "source.ip", to_ip(rec.get("SourceIp")))
        put(doc, "source.port", to_int(rec.get("SourcePort")))
        put(doc, "destination.ip", to_ip(rec.get("DestinationIp")))
        put(doc, "destination.port", to_int(rec.get("DestinationPort")))
        put(doc, "destination.domain", clean(rec.get("DestinationHostname")))
        proto = clean(rec.get("Protocol"))
        put(doc, "network.transport", proto.lower() if isinstance(proto, str) else None)
        initiated = str(rec.get("Initiated", "")).lower()
        put(doc, "network.direction", "egress" if initiated == "true" else None)
    elif eid == 5:
        put(doc, "event.category", ["process"])
        put(doc, "event.type", ["end"])
    elif eid == 7:  # Chargement de DLL
        put(doc, "event.category", ["library"])
        put(doc, "event.type", ["start"])
        put(doc, "dll.path", clean(rec.get("ImageLoaded")))
        put(doc, "dll.name", basename(rec.get("ImageLoaded")))
        put(doc, "dll.hash", parse_hashes(rec.get("Hashes")))
    elif eid in (8, 10):  # Thread distant / accès à un processus (ex. LSASS)
        put(doc, "event.category", ["process"])
        put(doc, "event.type", ["access"] if eid == 10 else ["change"])
        map_process(doc, "process", rec.get("SourceImage"), None,
                    rec.get("SourceProcessId"), rec.get("SourceProcessGUID"))
        # La cible (ex. lsass.exe) reste dans winlog.event_data.TargetImage :
        # ECS n'a pas de champ standard pour le processus cible.
    elif eid in (11, 23):  # Fichier créé / supprimé
        put(doc, "event.category", ["file"])
        put(doc, "event.type", ["creation"] if eid == 11 else ["deletion"])
        put(doc, "file.path", clean(rec.get("TargetFilename")))
        put(doc, "file.name", basename(rec.get("TargetFilename")))
    elif eid in (12, 13):  # Registre
        put(doc, "event.category", ["registry"])
        put(doc, "event.type", ["change"])
        target = clean(rec.get("TargetObject"))
        put(doc, "registry.path", target)
        if isinstance(target, str) and "\\" in target:
            put(doc, "registry.value", target.rsplit("\\", 1)[-1])
        details = clean(rec.get("Details"))
        put(doc, "registry.data.strings", [details] if details else None)
    elif eid == 22:  # Requête DNS
        put(doc, "event.category", ["network"])
        put(doc, "event.type", ["protocol", "info"])
        put(doc, "dns.question.name", clean(rec.get("QueryName")))
        put(doc, "network.protocol", "dns")


def map_security(doc, rec, eid):
    put(doc, "user.name", clean(rec.get("TargetUserName")) or clean(rec.get("SubjectUserName")))
    put(doc, "user.domain", clean(rec.get("TargetDomainName")) or clean(rec.get("SubjectDomainName")))

    if eid in (4624, 4625, 4634, 4648, 4672):  # Authentification
        put(doc, "event.category", ["authentication"])
        if eid == 4625:
            put(doc, "event.outcome", "failure")
            put(doc, "event.type", ["start"])
        elif eid == 4634:
            put(doc, "event.outcome", "success")
            put(doc, "event.type", ["end"])
        else:
            put(doc, "event.outcome", "success")
            put(doc, "event.type", ["start"])
        put(doc, "source.ip", to_ip(rec.get("IpAddress")))
        put(doc, "source.port", to_int(rec.get("IpPort")))
        put(doc, "source.domain", clean(rec.get("WorkstationName")))
        put(doc, "winlog.logon.type", clean(str(rec.get("LogonType", "")) or None))
    elif eid == 4688:  # Création de processus (journal Sécurité)
        put(doc, "event.category", ["process"])
        put(doc, "event.type", ["start"])
        map_process(doc, "process", rec.get("NewProcessName"), rec.get("CommandLine"),
                    rec.get("NewProcessId"))
        map_process(doc, "process.parent", rec.get("ParentProcessName"), None,
                    rec.get("ProcessId"))
    elif eid in (4697, 4698):  # Persistance : service / tâche planifiée
        put(doc, "event.category", ["configuration"])
        put(doc, "event.type", ["creation"])
        put(doc, "service.name", clean(rec.get("ServiceName")))
        put(doc, "winlog.event_data.TaskName", clean(rec.get("TaskName")))
    elif eid in (4720, 4728, 4732):  # Gestion des comptes et groupes
        put(doc, "event.category", ["iam"])
        put(doc, "event.type", ["creation"] if eid == 4720 else ["change"])
        put(doc, "group.name", clean(rec.get("TargetUserName")) if eid != 4720 else None)
    elif eid == 4769:  # Ticket Kerberos (Kerberoasting)
        put(doc, "event.category", ["authentication"])
        put(doc, "event.type", ["start"])
        put(doc, "source.ip", to_ip(rec.get("IpAddress")))
        put(doc, "service.name", clean(rec.get("ServiceName")))


# ---------------------------------------------------------------------------
# Lecture et envoi
# ---------------------------------------------------------------------------

def read_records(path):
    """Accepte un fichier JSON Lines (1 événement par ligne) ou un tableau JSON."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        first = f.read(1)
        f.seek(0)
        if first == "[":
            for rec in json.load(f):
                yield rec
        else:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue


def send_bulk(session, url, index, docs):
    body = "".join(
        json.dumps({"create": {"_index": index}}) + "\n" + json.dumps(d) + "\n"
        for d in docs
    )
    resp = session.post(f"{url}/_bulk", data=body.encode("utf-8"),
                        headers={"Content-Type": "application/x-ndjson"}, timeout=60)
    resp.raise_for_status()
    result = resp.json()
    errors = []
    if result.get("errors"):
        for item in result["items"]:
            err = item.get("create", {}).get("error")
            if err:
                errors.append(err)
    return len(docs) - len(errors), errors


def main():
    p = argparse.ArgumentParser(description="Normalise des journaux Windows en ECS et les envoie dans Elasticsearch.")
    p.add_argument("files", nargs="+", help="Fichiers JSON / JSON Lines à ingérer")
    p.add_argument("--index", default=DEFAULT_INDEX, help=f"Data stream cible (défaut : {DEFAULT_INDEX})")
    p.add_argument("--host-name", help="Remplace le nom d'hôte (ex. WS-COMPTA-07) pour coller au contexte MediSoft")
    p.add_argument("--host-map",
                   help="Renommage par hôte, ex. WORKSTATION5=WS-COMPTA-07,MORDORDC=DC-MEDISOFT-01")
    p.add_argument("--rebase-time", action="store_true",
                   help="Décale les événements pour que le plus récent soit à l'heure actuelle")
    p.add_argument("--dry-run", action="store_true", help="Affiche 3 documents normalisés sans rien envoyer")
    args = p.parse_args()

    host_map = {}
    if args.host_map:
        for pair in args.host_map.split(","):
            if "=" in pair:
                src, dst = pair.split("=", 1)
                host_map[src.strip().upper()] = dst.strip()

    records = []
    for path in args.files:
        records.extend(read_records(path))
    print(f"[i] {len(records)} événements lus")

    # Calcul du décalage temporel (une seule fois pour tout le lot)
    timestamps = [t for t in (get_timestamp(r) for r in records) if t]
    if not timestamps:
        sys.exit("[!] Aucun horodatage exploitable trouvé")
    offset = timedelta(0)
    if args.rebase_time:
        offset = datetime.now(timezone.utc) - max(timestamps)
        print(f"[i] Recalage temporel : +{offset.days} jours")

    docs, skipped = [], 0
    for rec in records:
        ts = get_timestamp(rec)
        doc = normalize(rec, args.host_name, host_map)
        if ts is None or doc is None:
            skipped += 1
            continue
        doc["@timestamp"] = (ts + offset).isoformat().replace("+00:00", "Z")
        put(doc, "event.created", doc["@timestamp"])
        if args.rebase_time:
            put(doc, "tags", ["medisoft-lab", "replay"])
        docs.append(doc)
    print(f"[i] {len(docs)} documents normalisés, {skipped} ignorés (sans EventID ou date)")

    if args.dry_run:
        for d in docs[:3]:
            print(json.dumps(d, indent=2, ensure_ascii=False))
        return

    password = os.environ.get("ES_PASSWORD")
    if not password:
        sys.exit("[!] Définir ES_PASSWORD (mot de passe du compte elastic ou d'un compte d'ingestion)")
    url = os.environ.get("ES_URL", "https://localhost:9200").rstrip("/")
    session = requests.Session()
    session.auth = (os.environ.get("ES_USER", "elastic"), password)
    session.verify = os.environ.get("ES_CA_CERT", "./ca.crt")

    ok_total, err_total, first_error = 0, 0, None
    for i in range(0, len(docs), BATCH_SIZE):
        ok, errs = send_bulk(session, url, args.index, docs[i:i + BATCH_SIZE])
        ok_total += ok
        err_total += len(errs)
        if errs and first_error is None:
            first_error = errs[0]
    print(f"[+] {ok_total} documents indexés dans {args.index}, {err_total} rejetés")
    if first_error:
        print(f"[!] Exemple de rejet : {json.dumps(first_error, ensure_ascii=False)[:400]}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:  # sortie coupée par "| head" : ce n'est pas une erreur
        sys.stderr.close()

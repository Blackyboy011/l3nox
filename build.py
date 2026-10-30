#!/usr/bin/env python3
"""
L3NOX · Bulletin SysOps du jour
--------------------------------
Rassemble chaque jour :
  - les vulnérabilités activement exploitées (catalogue CISA KEV),
  - les alertes et avis du CERT-FR,
  - les CVE critiques publiées par Red Hat,
  - l'actualité IT & cyber des dernières 24 h,
puis propose des actions SysOps (étapes et commandes) pour chaque sujet.

Génère :
  _site/index.html   -> la page du bulletin
  _site/alertes.xml  -> un flux RSS des alertes prioritaires (à suivre sur téléphone)

Aucune dépendance externe : uniquement la bibliothèque standard de Python 3.9+.
"""
from __future__ import annotations

import html
import json
import os
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
from zoneinfo import ZoneInfo

# ═════════════════════════ Réglages ═════════════════════════
SITE_NAME = "L3NOX"
SITE_DOMAIN = os.environ.get("SITE_DOMAIN", "")  # ex. l3nox.fr (vide = pas de domaine perso)
PARIS = ZoneInfo("Europe/Paris")
UA = "Mozilla/5.0 (compatible; L3NOX-bulletin/2.0)"

# Chaque source peut avoir plusieurs adresses : la première qui répond est utilisée.
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]
KEV_DAYS = 30  # vulnérabilités ajoutées au catalogue ces N derniers jours (toutes P1)

CERT_FEEDS = {  # nom: ([adresses], nombre de jours à afficher)
    "alerte": (["https://cert.cyber.gouv.fr/alerte/feed/", "https://www.cert.ssi.gouv.fr/alerte/feed/"], 30),
    "avis": (["https://cert.cyber.gouv.fr/avis/feed/", "https://www.cert.ssi.gouv.fr/avis/feed/"], 3),
}

# Avis publiés directement par les éditeurs (souvent avant le CERT-FR)
VENDOR_FEEDS = {
    "Palo Alto": ["https://security.paloaltonetworks.com/rss.xml"],
    "Cisco PSIRT": ["https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"],
    "Fortinet PSIRT": ["https://filestore.fortinet.com/fortiguard/rss/ir.xml"],
    "Microsoft MSRC": ["https://api.msrc.microsoft.com/update-guide/rss"],
    "Cisco Talos": ["https://blog.talosintelligence.com/rss/"],
}
VENDOR_DAYS = 3

# Base d'alertes GitHub (logiciels open source : Metabase, Kafka, GitLab, WordPress, npm, pip…)
GHSA_URL = "https://api.github.com/advisories?type=reviewed&severity=critical&per_page=60&sort=published"
GHSA_DAYS = 3

# Pages d'état des grands services (pannes en cours ou récentes)
STATUS_FEEDS = {
    "GitHub": ["https://www.githubstatus.com/history.atom"],
    "GitLab.com": ["https://status.gitlab.com/pages/5b36dc6502d06804c08349f7/rss"],
    "Cloudflare": ["https://www.cloudflarestatus.com/history.atom"],
    "Google Cloud": ["https://status.cloud.google.com/en/feed.atom"],
    "AWS": ["https://status.aws.amazon.com/rss/all.rss"],
    "Azure": ["https://azure.status.microsoft/en-us/status/feed/"],
}
STATUS_PAGES = {
    "GitHub": "https://www.githubstatus.com/", "GitLab.com": "https://status.gitlab.com/",
    "Cloudflare": "https://www.cloudflarestatus.com/", "Google Cloud": "https://status.cloud.google.com/",
    "AWS": "https://health.aws.amazon.com/health/status", "Azure": "https://azure.status.microsoft/fr-fr/status",
}
STATUS_HOURS = 24

REDHAT_URL = ("https://access.redhat.com/hydra/rest/securitydata/cve.json"
              "?after={after}&severity=critical&per_page=200")
REDHAT_DAYS = 7

NEWS_FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Zataz": "https://www.zataz.com/feed/",
    "IT-Connect": "https://www.it-connect.fr/feed/",
    "Le Monde Informatique": "https://www.lemondeinformatique.fr/flux-rss/thematique/securite/rss.xml",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Next": "https://next.ink/feed/",
}
NEWS_HOURS = 24
NEWS_MAX = 40

# Page d'accueil de chaque source (pour les liens et la section « Sources »)
SOURCE_SITES = {
    "CISA KEV": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "CERT-FR alerte": "https://www.cert.ssi.gouv.fr/alerte/",
    "CERT-FR avis": "https://www.cert.ssi.gouv.fr/avis/",
    "Red Hat": "https://access.redhat.com/security/security-updates/cve",
    "GitHub Advisory": "https://github.com/advisories?query=severity%3Acritical",
    "Palo Alto": "https://security.paloaltonetworks.com/",
    "Cisco PSIRT": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    "Fortinet PSIRT": "https://www.fortiguard.com/psirt",
    "Microsoft MSRC": "https://msrc.microsoft.com/update-guide",
    "Cisco Talos": "https://blog.talosintelligence.com/",
    "BleepingComputer": "https://www.bleepingcomputer.com/",
    "The Hacker News": "https://thehackernews.com/",
    "Zataz": "https://www.zataz.com/",
    "IT-Connect": "https://www.it-connect.fr/",
    "Le Monde Informatique": "https://www.lemondeinformatique.fr/securite/",
    "Krebs on Security": "https://krebsonsecurity.com/",
    "Next": "https://next.ink/",
}
SOURCE_DESC = {
    "CISA KEV": "Catalogue américain des vulnérabilités activement exploitées",
    "CERT-FR alerte": "Alertes de l'ANSSI (menaces en cours)",
    "CERT-FR avis": "Avis de sécurité de l'ANSSI",
    "Red Hat": "CVE de sévérité critique publiées par Red Hat",
    "GitHub Advisory": "Failles critiques des logiciels open source (avec versions corrigées)",
    "Palo Alto": "Avis de sécurité de l'éditeur (PAN-OS, GlobalProtect…)",
    "Cisco PSIRT": "Avis de sécurité de l'éditeur (ASA, FTD, IOS, SD-WAN…)",
    "Fortinet PSIRT": "Avis de sécurité de l'éditeur (FortiOS, FortiGate…)",
    "Microsoft MSRC": "Guide des mises à jour de sécurité Microsoft",
    "Cisco Talos": "Recherches et campagnes d'attaque (renseignement sur la menace)",
}

# Niveaux de priorité
EXPLOITED, CRITICAL, WATCH, INFO = 3, 2, 1, 0
LEVEL_LABEL = {EXPLOITED: "P1 · Exploitée", CRITICAL: "P2 · Critique", WATCH: "P3 · À surveiller", INFO: "Info"}
NEW_HOURS = 24  # badge « Nouveau » pour ce qui a moins de N heures
P1_DAYS = 30    # une faille exploitée (P1) reste affichée N jours, quelle que soit sa source

EXPLOIT_RE = re.compile(
    r"activement exploit|exploitée? activement|est exploitée|sont exploitées|exploitation active"
    r"|actively exploited|in the wild|in-the-wild|aware of (?:attempted |active |limited )?exploitation"
    r"|exploitation (?:attempts|confirmée|limitée)|zero-day|0-day|jour zéro",
    re.I)
CRITICAL_RE = re.compile(
    r"exécution de code arbitraire à distance|remote code execution|\bRCE\b|critique|critical", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

# ═════════════════════ Playbooks SysOps ═════════════════════
# Ordre = du plus spécifique au plus générique (le premier qui correspond gagne).
PLAYBOOKS = [
    {
        "id": "php", "label": "PHP",
        "match": r"\bphp\b|php2shell",
        "steps": [
            "Inventorier tous les serveurs et conteneurs qui exécutent PHP, y compris les instances oubliées.",
            "Installer la version corrigée (paquets de la distribution ou image Docker), puis redémarrer PHP-FPM / Apache.",
            "Si le correctif n'est pas encore disponible : appliquer le contournement indiqué dans l'avis "
            "(ex. PHP2Shell : session.upload_progress.enabled = Off dans le php.ini du serveur web).",
            "Planifier la migration des branches PHP non maintenues (8.1 et antérieures).",
            "Surveiller les logs web à la recherche de requêtes POST / uploads anormaux.",
        ],
        "cmds": {
            "RHEL / Rocky / Alma": "rpm -qa 'php*' && php -v\nsudo dnf upgrade --refresh 'php*'\nsudo systemctl restart php-fpm httpd",
            "Debian / Ubuntu": "dpkg -l 'php*' | grep ^ii && php -v\nsudo apt update && sudo apt install --only-upgrade 'php*'\nsudo systemctl restart 'php*-fpm' apache2",
            "Docker": "docker ps --format '{{.Names}}  {{.Image}}' | grep -i php\n# Reconstruire avec une image php:<version corrigée>, puis redéployer",
        },
    },
    {
        "id": "samba", "label": "Samba / Active Directory / Kerberos",
        "match": r"samba|winbind|\bsssd\b|kerberos|krb5|active directory",
        "steps": [
            "Mettre à jour Samba, SSSD et Kerberos sur les serveurs et les clients Linux joints au domaine.",
            "Sur les contrôleurs de domaine Windows : appliquer les mises à jour de sécurité du mois.",
            "Redémarrer les services concernés et vérifier qu'une ouverture de session domaine fonctionne.",
            "Contrôler les journaux d'authentification (échecs en rafale, comptes inhabituels).",
        ],
        "cmds": {
            "RHEL / Rocky / Alma": "rpm -qa | grep -Ei 'samba|sssd|krb5'\nsudo dnf upgrade --refresh 'samba*' 'sssd*' 'krb5*'\nsudo systemctl restart sssd winbind smb 2>/dev/null; sudo systemctl status sssd --no-pager",
            "Debian / Ubuntu": "dpkg -l | grep -Ei 'samba|sssd|krb5'\nsudo apt update && sudo apt install --only-upgrade 'samba*' 'sssd*' 'krb5*'\nsudo systemctl restart sssd winbind smbd 2>/dev/null",
        },
    },
    {
        "id": "openssh", "label": "OpenSSH",
        "match": r"openssh|\bsshd\b",
        "steps": [
            "Mettre à jour openssh-server et redémarrer sshd.",
            "Restreindre l'accès SSH (pare-feu, VPN, liste d'IP autorisées) le temps de corriger.",
            "Vérifier les connexions récentes et les échecs d'authentification.",
        ],
        "cmds": {
            "RHEL / Rocky / Alma": "ssh -V && rpm -q openssh-server\nsudo dnf upgrade --refresh 'openssh*'\nsudo systemctl restart sshd\nsudo journalctl -u sshd --since today | grep -Ei 'failed|invalid' | tail",
            "Debian / Ubuntu": "ssh -V && dpkg -l openssh-server\nsudo apt update && sudo apt install --only-upgrade openssh-server\nsudo systemctl restart ssh",
        },
    },
    {
        "id": "openssl", "label": "OpenSSL",
        "match": r"openssl",
        "steps": [
            "Mettre à jour OpenSSL.",
            "Redémarrer les services qui chargent la bibliothèque (web, mail, VPN…) ou redémarrer le serveur.",
        ],
        "cmds": {
            "RHEL / Rocky / Alma": "openssl version && rpm -q openssl\nsudo dnf upgrade --refresh 'openssl*'\nsudo needs-restarting -s   # services à redémarrer",
            "Debian / Ubuntu": "openssl version\nsudo apt update && sudo apt install --only-upgrade openssl 'libssl*'\nsudo needrestart -r l   # paquet needrestart",
        },
    },
    {
        "id": "sudo", "label": "sudo",
        "match": r"\bsudo\b",
        "steps": [
            "Mettre à jour le paquet sudo sur tous les serveurs.",
            "Vérifier que seuls les comptes prévus figurent dans /etc/sudoers et /etc/sudoers.d/.",
        ],
        "cmds": {
            "RHEL / Rocky / Alma": "sudo -V | head -1\nsudo dnf upgrade --refresh sudo",
            "Debian / Ubuntu": "sudo -V | head -1\nsudo apt update && sudo apt install --only-upgrade sudo",
        },
    },
    {
        "id": "glibc", "label": "glibc",
        "match": r"glibc|gnu c library",
        "steps": [
            "Mettre à jour glibc.",
            "Redémarrer le serveur (presque tous les processus utilisent glibc).",
        ],
        "cmds": {
            "RHEL / Rocky / Alma": "rpm -q glibc\nsudo dnf upgrade --refresh glibc\nsudo needs-restarting -r",
            "Debian / Ubuntu": "dpkg -l libc6\nsudo apt update && sudo apt install --only-upgrade libc6\n[ -f /var/run/reboot-required ] && echo 'Redémarrage requis'",
        },
    },
    {
        "id": "apache", "label": "Apache HTTP Server",
        "match": r"apache http|\bhttpd\b|apache2",
        "steps": [
            "Mettre à jour Apache httpd et ses modules.",
            "Tester la configuration avant de recharger le service.",
        ],
        "cmds": {
            "RHEL / Rocky / Alma": "httpd -v\nsudo dnf upgrade --refresh httpd mod_ssl\nsudo apachectl configtest && sudo systemctl reload httpd",
            "Debian / Ubuntu": "apache2 -v\nsudo apt update && sudo apt install --only-upgrade apache2\nsudo apache2ctl configtest && sudo systemctl reload apache2",
        },
    },
    {
        "id": "nginx", "label": "nginx",
        "match": r"nginx",
        "steps": ["Mettre à jour nginx.", "Tester la configuration avant de recharger le service."],
        "cmds": {
            "RHEL / Rocky / Alma": "nginx -v\nsudo dnf upgrade --refresh nginx\nsudo nginx -t && sudo systemctl reload nginx",
            "Debian / Ubuntu": "nginx -v\nsudo apt update && sudo apt install --only-upgrade nginx\nsudo nginx -t && sudo systemctl reload nginx",
        },
    },
    {
        "id": "java", "label": "Java / Tomcat / frameworks",
        "match": r"tomcat|\bjava\b|openjdk|log4j|struts|spring framework|spring boot",
        "steps": [
            "Identifier les applications qui embarquent le composant (y compris dans les fichiers .jar/.war).",
            "Mettre à jour le JDK / Tomcat ou la bibliothèque concernée, puis redéployer les applications.",
        ],
        "cmds": {
            "RHEL / Rocky / Alma": "rpm -qa | grep -Ei 'java|openjdk|tomcat'\nsudo dnf upgrade --refresh 'java*' 'tomcat*'",
            "Debian / Ubuntu": "dpkg -l | grep -Ei 'openjdk|tomcat'\nsudo apt update && sudo apt install --only-upgrade 'openjdk*' 'tomcat*'",
            "Recherche de bibliothèques": "sudo find / -xdev -name '*.jar' 2>/dev/null | grep -Ei 'log4j|struts|spring' | head",
        },
    },
    {
        "id": "cms", "label": "CMS (WordPress, Drupal, Joomla…)",
        "match": r"wordpress|drupal|joomla|prestashop|magento",
        "steps": [
            "Mettre à jour le cœur du CMS et l'extension concernée (ou la désactiver en attendant).",
            "Supprimer les extensions inutilisées et vérifier les comptes administrateurs.",
        ],
        "cmds": {
            "WP-CLI": "wp core version && wp plugin list --update=available\nwp core update && wp plugin update --all\nwp user list --role=administrator",
        },
    },
    {
        "id": "devops", "label": "DevOps / CI-CD (GitLab, Jenkins…)",
        "match": r"gitlab|jenkins|gitea|forgejo|teamcity|bamboo|github enterprise|argo ?cd|\bnexus\b|artifactory",
        "steps": [
            "Mettre à jour les instances autohébergées vers la version de sécurité indiquée par l'éditeur.",
            "En attendant : restreindre l'accès à l'instance (VPN / IP autorisées) et aux fonctions CI/CD.",
            "Rechercher des traces d'exploitation (journaux applicatifs, runners, jobs inconnus).",
            "En cas de doute : faire tourner les secrets CI/CD, jetons d'accès et clés de déploiement.",
        ],
        "cmds": {
            "GitLab (Omnibus)": "sudo gitlab-rake gitlab:env:info | grep -i version\n# RHEL : sudo dnf upgrade gitlab-ce   |   Debian : sudo apt install --only-upgrade gitlab-ce",
        },
    },
    {
        "id": "data", "label": "Bases de données & data (PostgreSQL, Kafka, Elastic…)",
        "match": r"postgres|mysql|mariadb|mongodb|redis|elasticsearch|elastic|kibana|kafka|metabase|grafana|clickhouse|cassandra",
        "steps": [
            "Vérifier si le composant et la version concernés sont déployés (y compris en conteneur).",
            "Mettre à jour vers la version corrigée et relire les éventuels changements de configuration demandés par l'éditeur.",
            "Limiter l'exposition réseau : écoute uniquement sur les réseaux internes, authentification obligatoire.",
            "Contrôler les comptes, rôles et exports récents.",
        ],
        "cmds": {
            "RHEL / Rocky / Alma": "rpm -qa | grep -Ei 'postgres|mysql|mariadb|mongo|redis|elastic|kafka'",
            "Debian / Ubuntu": "dpkg -l | grep -Ei 'postgres|mysql|mariadb|mongo|redis|elastic|kafka'",
            "Docker": "docker ps --format '{{.Names}}  {{.Image}}' | grep -Ei 'postgres|mysql|mariadb|mongo|redis|elastic|kafka|metabase|grafana'",
        },
    },
    {
        "id": "backup", "label": "Sauvegarde (Veeam, Data Domain…)",
        "match": r"veeam|data domain|powerprotect|commvault|veritas|netbackup|acronis|rubrik|cohesity|nakivo",
        "steps": [
            "Inventorier les serveurs et appliances de sauvegarde et relever leurs versions.",
            "Restreindre leurs interfaces d'administration aux réseaux de gestion / bastions.",
            "Appliquer les correctifs en vérifiant que les sauvegardes restent disponibles.",
            "Vérifier l'existence d'une copie isolée (hors ligne / immuable) et tester une restauration.",
        ],
        "cmds": {},
    },
    {
        "id": "containers", "label": "Conteneurs (Docker / Kubernetes)",
        "match": r"docker|kubernetes|containerd|\brunc\b|podman",
        "steps": [
            "Mettre à jour le moteur de conteneurs / les nœuds Kubernetes.",
            "Reconstruire les images à partir de bases corrigées et redéployer.",
        ],
        "cmds": {
            "Vérifier les versions": "docker version --format '{{.Server.Version}}'\nkubectl version\nrunc --version",
            "RHEL / Rocky / Alma": "sudo dnf upgrade --refresh 'docker*' containerd.io runc podman",
        },
    },
    {
        "id": "virtu", "label": "Virtualisation",
        "match": r"vmware|esxi|vcenter|vsphere|proxmox|hyper-v|virtualbox|\bxen\b",
        "steps": [
            "Appliquer le correctif de l'éditeur sur les hyperviseurs et la console de gestion (vCenter…).",
            "Vérifier que les interfaces d'administration ne sont pas exposées sur Internet.",
        ],
        "cmds": {
            "ESXi (shell)": "vmware -vl\nesxcli software vib list | head",
            "Proxmox": "pveversion\napt update && apt full-upgrade",
        },
    },
    {
        "id": "network", "label": "Pare-feu, VPN et équipements réseau",
        "match": r"forti\w*|cisco|palo alto|pan-os|ivanti|citrix|netscaler|sonicwall|juniper"
                 r"|big-ip|check point|zyxel|sophos|watchguard|mikrotik|stormshield",
        "steps": [
            "Vérifier si l'équipement et la version du firmware sont concernés.",
            "Mettre à jour le firmware ; en attendant, couper l'accès Internet à l'interface d'administration / au portail VPN.",
            "Rechercher les indicateurs de compromission publiés par le constructeur.",
            "En cas de doute sur une compromission : réinitialiser les mots de passe et les sessions VPN.",
        ],
        "cmds": {},
    },
    {
        "id": "browsers", "label": "Navigateurs web",
        "match": r"chrome|chromium|firefox|microsoft edge|safari|webkit",
        "steps": [
            "Forcer la mise à jour des navigateurs sur les postes (GPO / outil de gestion du parc).",
            "Vérifier que la version déployée est au moins celle indiquée dans l'avis.",
        ],
        "cmds": {
            "RHEL / Rocky / Alma": "rpm -qa | grep -Ei 'firefox|chrom'\nsudo dnf upgrade --refresh firefox",
            "Windows (PowerShell)": "winget upgrade --id Google.Chrome\nwinget upgrade --id Mozilla.Firefox",
        },
    },
    {
        "id": "windows", "label": "Microsoft / Windows",
        "match": r"microsoft|windows|exchange server|sharepoint",
        "steps": [
            "Approuver et déployer les mises à jour concernées (WSUS / Intune / Windows Update).",
            "Traiter en premier les serveurs exposés : Exchange, SharePoint, RDS, contrôleurs de domaine.",
            "Vérifier l'installation effective des correctifs sur un échantillon de postes.",
        ],
        "cmds": {
            "Windows (PowerShell)": "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5\n# Avec le module PSWindowsUpdate :\nGet-WindowsUpdate\nInstall-WindowsUpdate -AcceptAll -AutoReboot:$false",
        },
    },
    {
        "id": "kernel", "label": "Noyau Linux",
        "match": r"linux kernel|noyau linux|\bkernel\b",
        "steps": [
            "Installer le noyau corrigé.",
            "Planifier le redémarrage (ou utiliser kpatch / Livepatch si disponible).",
            "Vérifier après redémarrage que le nouveau noyau est bien chargé.",
        ],
        "cmds": {
            "RHEL / Rocky / Alma": "uname -r && rpm -q kernel\nsudo dnf upgrade --refresh kernel\nsudo needs-restarting -r",
            "Debian / Ubuntu": "uname -r\nsudo apt update && sudo apt full-upgrade\n[ -f /var/run/reboot-required ] && echo 'Redémarrage requis'",
        },
    },
]
for _pb in PLAYBOOKS:
    _pb["re"] = re.compile(_pb["match"], re.I)
PB_BY_ID = {pb["id"]: pb for pb in PLAYBOOKS}

GENERIC_STEPS = [
    "Vérifier si le produit et la version concernés sont présents dans votre parc.",
    "Appliquer le correctif de l'éditeur (ou le contournement indiqué dans l'avis s'il n'y en a pas encore).",
    "Si la vulnérabilité est exploitée : rechercher des traces de compromission dans les journaux.",
]

# ═════════════════════════ Outils ═════════════════════════
NOW = datetime.now(timezone.utc)
STATUS: list[tuple[str, bool, str]] = []  # (source, ok, détail) pour le pied de page


def fetch(url: str, timeout: int = 25, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_first(urls: list[str], parse=None):
    """Essaie chaque adresse dans l'ordre ; renvoie le premier résultat lisible."""
    err = None
    for url in urls:
        try:
            data = fetch(url)
            return parse(data) if parse else data
        except Exception as e:
            err = e
    raise err or RuntimeError("aucune adresse")


def lname(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def child_text(el, *names) -> str:
    for c in el:
        if lname(c.tag) in names and (c.text or "").strip():
            return c.text.strip()
    return ""


def parse_date(s: str):
    if not s:
        return None
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError):
        try:
            d = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def clean(text: str, limit: int = 300) -> str:
    text = html.unescape(re.sub(r"<[^>]+>", " ", text or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


def parse_feed(data: bytes) -> list[dict]:
    """Lit un flux RSS 2.0, RSS 1.0 ou Atom."""
    root = ET.fromstring(data)
    out = []
    for el in root.iter():
        if lname(el.tag) not in ("item", "entry"):
            continue
        link = ""
        for c in el:
            if lname(c.tag) == "link":
                if c.get("href") and c.get("rel", "alternate") == "alternate":
                    link = c.get("href")
                    break
                if (c.text or "").strip():
                    link = c.text.strip()
                    break
        out.append({
            "title": clean(child_text(el, "title"), 220),
            "link": link,
            "date": parse_date(child_text(el, "pubDate", "published", "updated", "date")),
            "summary": clean(child_text(el, "description", "summary", "content")),
        })
    return out


def make_item(source, title, link, date, summary="", level=INFO, **extra) -> dict:
    text = f"{title} {summary}"
    pb = next((p["id"] for p in PLAYBOOKS if p["re"].search(text)), None)
    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(text)))
    item = {"source": source, "title": title, "link": link, "date": date, "summary": summary,
            "level": level, "playbook": pb, "cves": cves, "action": "", "due": "", "ransomware": False}
    item.update(extra)
    return item


# ═════════════════════════ Collecte ═════════════════════════
def collect_kev() -> list[dict]:
    data = fetch_first(KEV_URLS, json.loads)
    cutoff = (NOW - timedelta(days=KEV_DAYS)).date()
    items = []
    for v in data.get("vulnerabilities", []):
        try:
            added = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if added.date() < cutoff:
            continue
        cve = v.get("cveID", "")
        title = f"{v.get('vendorProject', '')} {v.get('product', '')} — {v.get('vulnerabilityName', '')}".strip()
        it = make_item("CISA KEV", title, f"https://nvd.nist.gov/vuln/detail/{cve}", added,
                       clean(v.get("shortDescription", "")), EXPLOITED,
                       action=v.get("requiredAction", ""), due=v.get("dueDate", ""),
                       ransomware=v.get("knownRansomwareCampaignUse", "").lower() == "known")
        if cve and cve not in it["cves"]:
            it["cves"].insert(0, cve)
        items.append(it)
    return items


def collect_cert() -> list[dict]:
    items = []
    for kind, (urls, days) in CERT_FEEDS.items():
        name = "CERT-FR " + ("alertes" if kind == "alerte" else "avis")
        try:
            entries = fetch_first(urls, parse_feed)
        except Exception as e:  # une source en panne ne bloque pas le bulletin
            STATUS.append((name, False, type(e).__name__))
            continue
        cutoff = NOW - timedelta(days=days)
        p1_cutoff = NOW - timedelta(days=max(days, P1_DAYS))
        n = 0
        for e in entries:
            if not e["date"] or e["date"] < p1_cutoff:
                continue
            text = f"{e['title']} {e['summary']}"
            if kind == "alerte" or EXPLOIT_RE.search(text):
                level = EXPLOITED
            elif CRITICAL_RE.search(text):
                level = CRITICAL
            else:
                level = WATCH
            if level < EXPLOITED and e["date"] < cutoff:
                continue  # seules les P1 restent au-delà de la fenêtre normale
            items.append(make_item(f"CERT-FR {kind}", e["title"], e["link"], e["date"], e["summary"], level))
            n += 1
        STATUS.append((name, True, f"{n} élément(s)"))
    return items


def collect_redhat() -> list[dict]:
    after = (NOW - timedelta(days=REDHAT_DAYS)).strftime("%Y-%m-%d")
    data = json.loads(fetch(REDHAT_URL.format(after=after)))
    items = []
    for v in data if isinstance(data, list) else []:
        cve = v.get("CVE", "")
        desc = v.get("bugzilla_description", "") or ""
        pkgs = v.get("affected_packages") or []
        summary = ("Paquets : " + ", ".join(pkgs[:6])) if pkgs else ""
        level = CRITICAL
        it = make_item("Red Hat", f"{cve} — {desc}".strip(" —"),
                       f"https://access.redhat.com/security/cve/{cve}",
                       parse_date(v.get("public_date", "")) or NOW, summary, level)
        if cve and cve not in it["cves"]:
            it["cves"].insert(0, cve)
        items.append(it)
    return items


def collect_vendors() -> list[dict]:
    """Avis publiés directement par les éditeurs (Palo Alto, Cisco, Fortinet, Microsoft, Talos)."""
    cutoff = NOW - timedelta(days=VENDOR_DAYS)
    p1_cutoff = NOW - timedelta(days=max(VENDOR_DAYS, P1_DAYS))
    items = []
    for source, urls in VENDOR_FEEDS.items():
        try:
            entries = fetch_first(urls, parse_feed)
        except Exception as e:
            STATUS.append((source, False, type(e).__name__))
            continue
        n = 0
        for e in entries:
            if not e["date"] or e["date"] < p1_cutoff or not e["title"]:
                continue
            text = f"{e['title']} {e['summary']}"
            if EXPLOIT_RE.search(text):
                level = EXPLOITED
            elif CRITICAL_RE.search(text):
                level = CRITICAL
            else:
                level = WATCH
            if level < EXPLOITED and e["date"] < cutoff:
                continue
            items.append(make_item(source, e["title"], e["link"], e["date"], e["summary"], level))
            n += 1
        STATUS.append((source, True, f"{n} avis"))
    return items


def collect_ghsa() -> list[dict]:
    """Failles critiques de la base GitHub Advisory, avec les versions corrigées."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    data = json.loads(fetch(GHSA_URL, headers=headers))
    cutoff = NOW - timedelta(days=GHSA_DAYS)
    items = []
    for a in data if isinstance(data, list) else []:
        date = parse_date(a.get("published_at", ""))
        if not date or date < cutoff:
            continue
        fixes, pkgs = [], []
        for v in a.get("vulnerabilities") or []:
            pkg = (v.get("package") or {}).get("name", "")
            if pkg and pkg not in pkgs:
                pkgs.append(pkg)
            if v.get("first_patched_version"):
                fixes.append(f"{pkg} {v['first_patched_version']}")
        score = (a.get("cvss") or {}).get("score") or ((a.get("cvss_severities") or {}).get("cvss_v3") or {}).get("score")
        parts = []
        if score:
            parts.append(f"CVSS {score}")
        if pkgs:
            parts.append("Composant : " + ", ".join(pkgs[:3]))
        parts.append(("Corrigé en : " + ", ".join(dict.fromkeys(fixes[:4]))) if fixes else "Pas encore de version corrigée")
        it = make_item("GitHub Advisory", clean(a.get("summary", ""), 200), a.get("html_url", ""), date,
                       " · ".join(parts), CRITICAL)
        if a.get("cve_id") and a["cve_id"] not in it["cves"]:
            it["cves"].insert(0, a["cve_id"])
        items.append(it)
    return items


RESOLVED_RE = re.compile(r"\bresolved\b|\bcompleted\b|résolu|operating normally|has been mitigated", re.I)


def collect_status() -> list[dict]:
    """Incidents des dernières 24 h sur les pages d'état des grands services."""
    cutoff = NOW - timedelta(hours=STATUS_HOURS)
    rows = []
    for name, urls in STATUS_FEEDS.items():
        try:
            entries = fetch_first(urls, parse_feed)
        except Exception as e:
            STATUS.append((f"État {name}", False, type(e).__name__))
            rows.append({"name": name, "ok": None, "incidents": []})
            continue
        recent = [e for e in entries if e["date"] and e["date"] >= cutoff and e["title"]]
        incidents = [{"title": e["title"], "link": e["link"] or STATUS_PAGES.get(name, ""), "date": e["date"],
                      "resolved": bool(RESOLVED_RE.search(e["summary"] + " " + e["title"]))} for e in recent[:5]]
        STATUS.append((f"État {name}", True, f"{len(incidents)} incident(s) 24 h"))
        rows.append({"name": name, "ok": True, "incidents": incidents})
    return rows


def collect_news() -> list[dict]:
    cutoff = NOW - timedelta(hours=NEWS_HOURS)
    items = []
    for source, url in NEWS_FEEDS.items():
        try:
            entries = parse_feed(fetch(url))
        except Exception as e:
            STATUS.append((source, False, type(e).__name__))
            continue
        n = 0
        for e in entries:
            if e["date"] and e["date"] >= cutoff and e["title"]:
                items.append(make_item(source, e["title"], e["link"], e["date"], e["summary"], INFO))
                n += 1
        STATUS.append((source, True, f"{n} article(s)"))
    items.sort(key=lambda i: i["date"], reverse=True)
    return items[:NEWS_MAX]


def safe(name, func) -> list[dict]:
    try:
        items = func()
        STATUS.append((name, True, f"{len(items)} élément(s)"))
        return items
    except Exception as e:
        STATUS.append((name, False, type(e).__name__))
        print(f"[!] {name}: {e}")
        return []


# ═════════════════════════ Rendu HTML ═════════════════════════
JOURS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]
MOIS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet",
        "août", "septembre", "octobre", "novembre", "décembre"]
e = html.escape


def date_fr(d: datetime) -> str:
    return f"{JOURS[d.weekday()]} {d.day} {MOIS[d.month - 1]} {d.year}"


def when(d) -> str:
    if not d:
        return ""
    loc = d.astimezone(PARIS)
    return loc.strftime("%H:%M") if loc.date() == NOW.astimezone(PARIS).date() else loc.strftime("%d/%m")


def due_fr(s: str) -> str:
    try:
        return datetime.strptime(s, "%Y-%m-%d").strftime("%d/%m/%Y")
    except ValueError:
        return s


def item_row(it: dict, show_pb: bool = False, show_sum: bool = False) -> str:
    chips = "".join(f'<span class="cve">{e(c)}</span>' for c in it["cves"][:3])
    extra = ""
    if it["ransomware"]:
        extra += '<span class="flag">rançongiciel</span>'
    if it["due"]:
        extra += f'<span class="due">échéance CISA {e(due_fr(it["due"]))}</span>'
    if show_pb and it["playbook"]:
        extra += f'<a class="pb" href="#pb-{e(it["playbook"])}">{e(PB_BY_ID[it["playbook"]]["label"])}</a>'
    site = SOURCE_SITES.get(it["source"], "")
    src = (f'<a class="src" href="{e(site)}" target="_blank" rel="noopener" title="Site de la source">{e(it["source"])}</a>'
           if site else f'<span class="src">{e(it["source"])}</span>')
    new = ('<span class="new">Nouveau</span>'
           if it["date"] and it["level"] > INFO and NOW - it["date"] <= timedelta(hours=NEW_HOURS) else "")
    summary = it["summary"] + (f" — Action CISA : {it['action']}" if it["action"] else "")
    sum_html = f'<p class="sum">{e(summary)}</p>' if show_sum and summary else ""
    return (f'<li class="row lvl-{it["level"]}"><span class="dot" title="{e(LEVEL_LABEL[it["level"]])}"></span>'
            f'<time>{e(when(it["date"]))}</time>{src}{new}'
            f'<a class="t" href="{e(it["link"])}" target="_blank" rel="noopener">{e(it["title"])}</a>'
            f'{chips}{extra}{sum_html}</li>')


def cmds_html(cmds: dict) -> str:
    if not cmds:
        return ""
    blocks = "".join(f'<p class="os">{e(os_name)}</p><div class="code"><pre><code>{e(code)}</code></pre>'
                     f'<button class="copy" type="button">Copier</button></div>'
                     for os_name, code in cmds.items())
    return f'<details><summary>Commandes utiles</summary>{blocks}</details>'


def playbook_card(pid, items: list[dict]) -> str:
    pb = PB_BY_ID.get(pid)
    top = max(i["level"] for i in items)
    label = pb["label"] if pb else "Autres produits"
    rows = "".join(item_row(i, show_sum=True) for i in items)
    if pb:
        steps = pb["steps"]
    else:
        actions = list(dict.fromkeys(i["action"] for i in items if i["action"]))
        steps = actions[:3] + GENERIC_STEPS if actions else GENERIC_STEPS
    key = pid or "autres"
    checklist = "".join(f'<li><label><input type="checkbox" data-k="{e(key)}-{n}"> {e(s)}</label></li>'
                        for n, s in enumerate(steps))
    n_exp = sum(1 for i in items if i["level"] == EXPLOITED)
    badge = f'<span class="badge lvl-{top}">{e(LEVEL_LABEL[top])}</span>'
    count = f'{len(items)} alerte{"s" if len(items) > 1 else ""}' + (f" · {n_exp} exploitée{'s' if n_exp > 1 else ''}" if n_exp else "")
    return (f'<article class="card lvl-{top}" id="pb-{e(key)}"><header><h3>{e(label)}</h3>{badge}'
            f'<span class="count">{e(count)}</span></header><ul class="list">{rows}</ul>'
            f'<h4>Actions recommandées</h4><ol class="steps">{checklist}</ol>'
            f'{cmds_html(pb["cmds"]) if pb else ""}</article>')


def section(title, sub, body, sid) -> str:
    return f'<section id="{sid}"><h2>{e(title)} <small>{e(sub)}</small></h2>{body}</section>'


def status_html(rows: list[dict]) -> str:
    out = []
    for r in rows:
        page = STATUS_PAGES.get(r["name"], "")
        name = f'<a href="{e(page)}" target="_blank" rel="noopener">{e(r["name"])}</a>'
        if r["ok"] is None:
            out.append(f'<li><span class="sv unk">?</span>{name}<span class="sd">État non récupéré : consultez la page officielle</span></li>')
        elif not r["incidents"]:
            out.append(f'<li><span class="sv ok2">●</span>{name}<span class="sd">Aucun incident signalé ces {STATUS_HOURS} h</span></li>')
        else:
            open_ = [i for i in r["incidents"] if not i["resolved"]]
            cls, label = ("ko2", "Incident en cours") if open_ else ("warn", "Incident(s) résolu(s)")
            open_tag = ' <b class="open">en cours</b>'
            inc = "".join(f'<li><time>{e(when(i["date"]))}</time><a href="{e(i["link"])}" target="_blank" rel="noopener">'
                          f'{e(i["title"])}</a>{"" if i["resolved"] else open_tag}</li>'
                          for i in r["incidents"])
            out.append(f'<li><span class="sv {cls}">●</span>{name}<span class="sd">{label}</span><ul class="inc">{inc}</ul></li>')
    return f'<ul class="services">{"".join(out)}</ul>'


def render(kev, cert, redhat, vendors, ghsa, status_rows, news) -> str:
    urgent = [i for i in kev + cert + redhat + vendors + ghsa if i["level"] >= CRITICAL]
    groups: dict = {}
    for it in sorted(urgent, key=lambda i: (-i["level"], -(i["date"].timestamp() if i["date"] else 0))):
        groups.setdefault(it["playbook"], []).append(it)
    order = sorted(groups, key=lambda k: (k is None, -max(i["level"] for i in groups[k]), -len(groups[k])))

    n_exp = sum(1 for i in urgent if i["level"] == EXPLOITED)
    n_crit = sum(1 for i in urgent if i["level"] == CRITICAL)
    watch = sorted((i for i in cert + vendors if i["level"] == WATCH),
                   key=lambda i: i["date"] or NOW, reverse=True)
    n_watch = len(watch)
    n_new = sum(1 for i in urgent if i["date"] and NOW - i["date"] <= timedelta(hours=NEW_HOURS))
    outages = [r["name"] for r in status_rows if any(not i["resolved"] for i in r["incidents"])]
    priorities = [PB_BY_ID[k]["label"] for k in order if k][:3]

    if urgent:
        brief = (f"<b>{n_exp}</b> vulnérabilité{'s' if n_exp > 1 else ''} activement exploitée{'s' if n_exp > 1 else ''} "
                 f"et <b>{n_crit}</b> critique{'s' if n_crit > 1 else ''} à traiter.")
        brief += f" Dont <b>{n_new}</b> nouveauté{'s' if n_new > 1 else ''} depuis 24 h."
        if priorities:
            brief += " Priorités du jour : " + ", ".join(f"<b>{e(p)}</b>" for p in priorities) + "."
    else:
        brief = "Rien de critique à signaler aujourd'hui. ✅ Profitez-en pour avancer sur les mises à jour courantes."
    brief += (" <br>Services : panne en cours chez " + ", ".join(f"<b>{e(o)}</b>" for o in outages) + "."
              if outages else " <br>Services suivis : aucune panne en cours signalée.")

    p1 = sorted((i for i in urgent if i["level"] == EXPLOITED), key=lambda i: i["date"] or NOW, reverse=True)
    if p1:
        p1_rows = "".join(
            f'<li>{"<span class=new>Nouveau</span>" if i["date"] and NOW - i["date"] <= timedelta(hours=NEW_HOURS) else ""}'
            f'<time>{e(when(i["date"]))}</time><a href="{e(i["link"])}" target="_blank" rel="noopener">{e(i["title"])}</a>'
            f'<span class="p1src">{e(i["source"])}</span>'
            + (f'<a class="pb" href="#pb-{e(i["playbook"])}">actions</a>' if i["playbook"] else '<a class="pb" href="#pb-autres">actions</a>')
            + '</li>' for i in p1)
        p1_html = (f'<div class="p1box" id="p1"><h2>🔴 P1 · Failles exploitées en cours '
                   f'<small>{len(p1)} · conservées {P1_DAYS} jours</small></h2><ul>{p1_rows}</ul></div>')
    else:
        p1_html = '<div class="p1box ok" id="p1"><h2>🟢 Aucune faille exploitée (P1) en cours</h2></div>'

    cards = "".join(playbook_card(k, groups[k]) for k in order) or '<p class="empty">Aucune action urgente.</p>'
    watch_html = (f'<ul class="list">{"".join(item_row(i, True, True) for i in watch)}</ul>'
                  if watch else '<p class="empty">Aucun avis supplémentaire.</p>')
    news_html = (f'<ul class="list">{"".join(item_row(i, True) for i in news)}</ul>'
                 if news else '<p class="empty">Pas d\'actualité récupérée.</p>')
    st = {n: (ok, detail) for n, ok, detail in STATUS}
    st_alias = {"CERT-FR alerte": "CERT-FR alertes", "CERT-FR avis": "CERT-FR avis"}
    src_rows = []
    for name, url in SOURCE_SITES.items():
        ok, detail = st.get(st_alias.get(name, name), (None, "non interrogée"))
        state = ("ok", "✓ " + detail) if ok else ("ko", "✗ indisponible") if ok is False else ("", detail)
        desc = SOURCE_DESC.get(name, "Actualité IT & cyber")
        src_rows.append(f'<li><a href="{e(url)}" target="_blank" rel="noopener">{e(name)}</a>'
                        f'<span class="sd">{e(desc)}</span><span class="{state[0]}">{e(state[1])}</span></li>')
    sources_html = f'<ul class="sources">{"".join(src_rows)}</ul>'
    loc = NOW.astimezone(PARIS)

    return f"""<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{SITE_NAME} · Bulletin SysOps</title>
<meta name="description" content="Bulletin SysOps du jour : vulnérabilités exploitées, alertes CERT-FR et actions recommandées.">
<link rel="alternate" type="application/rss+xml" title="{SITE_NAME} · Alertes" href="alertes.xml">
<style>
:root{{--bg:#f5f7fa;--card:#fff;--fg:#0f172a;--mut:#5b6b80;--line:#e2e8f0;--acc:#0369a1;
--l3:#dc2626;--l2:#ea580c;--l1:#b45309;--l0:#64748b;--codebg:#0f172a;--codefg:#e2e8f0;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0a0e15;--card:#111823;--fg:#e5e9f0;--mut:#93a1b5;--line:#1f2a38;
--acc:#38bdf8;--l3:#f87171;--l2:#fb923c;--l1:#facc15;--l0:#94a3b8;--codebg:#05080d;--codefg:#d6deeb}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
main{{max-width:980px;margin:auto;padding:28px 16px 48px}}
a{{color:inherit}}
.top{{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 14px;margin-bottom:6px}}
.brand{{font:800 30px/1 var(--mono);letter-spacing:.04em;margin:0}}
.brand span{{color:var(--acc)}}
.tag{{color:var(--mut);font-size:14px}}
.date{{color:var(--mut);margin:0 0 18px;font-size:14px}}
.brief{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--acc);border-radius:10px;padding:14px 16px;margin-bottom:16px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:28px}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}}
.stat b{{display:block;font:700 26px/1.1 var(--mono)}}
.stat span{{color:var(--mut);font-size:13px}}
.stat.l3 b{{color:var(--l3)}}.stat.l2 b{{color:var(--l2)}}.stat.l1 b{{color:var(--l1)}}
section{{margin-top:30px}}
h2{{font-size:19px;margin:0 0 12px}} h2 small{{font-weight:400;color:var(--mut);font-size:13px;margin-left:6px}}
.card{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--l0);border-radius:10px;padding:14px 16px;margin-bottom:14px}}
.card.lvl-3{{border-left-color:var(--l3)}}.card.lvl-2{{border-left-color:var(--l2)}}
.card header{{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:6px}}
.card h3{{margin:0;font-size:17px}}
.badge{{font-size:12px;font-weight:600;border-radius:999px;padding:1px 9px;color:#fff;background:var(--l0)}}
.badge.lvl-3{{background:var(--l3)}}.badge.lvl-2{{background:var(--l2)}}
.count{{color:var(--mut);font-size:13px;margin-left:auto}}
h4{{margin:12px 0 4px;font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}}
.list{{list-style:none;margin:0;padding:0}}
.row{{display:flex;flex-wrap:wrap;align-items:center;gap:4px 8px;padding:8px 0;border-bottom:1px solid var(--line)}}
.row:last-child{{border-bottom:0}}
.dot{{width:9px;height:9px;border-radius:50%;background:var(--l0);flex:none}}
.lvl-3>.dot{{background:var(--l3)}}.lvl-2>.dot{{background:var(--l2)}}.lvl-1>.dot{{background:var(--l1)}}
time{{color:var(--mut);font:12px var(--mono);min-width:38px}}
.src{{font-size:11px;font-weight:600;color:var(--acc);border:1px solid currentColor;border-radius:4px;padding:0 5px}}
.t{{flex:1 1 320px;text-decoration:none;min-width:0;overflow-wrap:anywhere}} .t:hover{{color:var(--acc);text-decoration:underline}}
.cve,.due,.flag,.pb{{font:11px var(--mono);border-radius:4px;padding:1px 5px;background:var(--line);color:var(--fg);text-decoration:none}}
.flag{{background:var(--l3);color:#fff}} .due{{color:var(--mut)}} .pb:hover{{color:var(--acc)}}
.steps{{margin:0;padding-left:20px}} .steps li{{margin:4px 0}}
.steps input{{accent-color:var(--acc);margin-right:4px}}
.steps label:has(input:checked){{color:var(--mut);text-decoration:line-through}}
details{{margin-top:10px}} summary{{cursor:pointer;font-weight:600;color:var(--acc)}}
.os{{margin:10px 0 4px;font-size:13px;color:var(--mut)}}
.code{{position:relative}}
pre{{margin:0;background:var(--codebg);color:var(--codefg);border-radius:8px;padding:12px 14px;overflow-x:auto;font:13px/1.5 var(--mono)}}
.copy{{position:absolute;top:6px;right:6px;font:12px system-ui;border:0;border-radius:6px;padding:3px 8px;background:#334155;color:#e2e8f0;cursor:pointer}}
.empty{{color:var(--mut);background:var(--card);border:1px dashed var(--line);border-radius:10px;padding:14px 16px}}
footer{{margin-top:36px;color:var(--mut);font-size:12.5px}} footer p{{margin:6px 0}}
.ok{{color:var(--mut)}} .ko{{color:var(--l3)}}
.p1box{{background:var(--card);border:2px solid var(--l3);border-radius:10px;padding:12px 16px;margin-bottom:22px}}
.p1box.ok{{border-color:#16a34a}} .p1box h2{{margin:0;font-size:17px}}
.p1box ul{{list-style:none;margin:8px 0 0;padding:0}}
.p1box li{{display:flex;flex-wrap:wrap;align-items:center;gap:4px 8px;padding:6px 0;border-top:1px solid var(--line)}}
.p1box li>a:not(.pb){{flex:1 1 300px;text-decoration:none;font-weight:600}} .p1box li>a:not(.pb):hover{{color:var(--acc)}}
.p1src{{font-size:11px;color:var(--mut)}}
.sum{{flex-basis:100%;margin:2px 0 0 47px;color:var(--mut);font-size:13px;line-height:1.45}}
.new{{font-size:11px;font-weight:700;border-radius:4px;padding:0 6px;background:var(--acc);color:var(--card)}}
.services{{list-style:none;margin:0;padding:0;background:var(--card);border:1px solid var(--line);border-radius:10px}}
.services>li{{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 10px;padding:9px 14px;border-bottom:1px solid var(--line)}}
.services>li:last-child{{border-bottom:0}}
.services>li>a{{font-weight:600;min-width:120px}}
.services .sd{{color:var(--mut);font-size:13px}}
.sv{{font-size:12px}} .sv.ok2{{color:#16a34a}} .sv.warn{{color:var(--l1)}} .sv.ko2{{color:var(--l3)}} .sv.unk{{color:var(--mut);font-weight:700}}
.inc{{flex-basis:100%;list-style:none;margin:4px 0 0 22px;padding:0;font-size:13px}}
.inc li{{display:flex;gap:8px;padding:2px 0}} .inc a{{text-decoration:none}} .inc a:hover{{text-decoration:underline}}
.open{{color:var(--l3);font-weight:600}}
@media(max-width:640px){{.sum{{margin-left:0}}}}
a.src{{text-decoration:none}} a.src:hover{{background:var(--acc);color:var(--card)}}
.search{{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:10px;background:var(--bg);padding:10px 0;margin:-10px 0 4px}}
.search input{{flex:1;min-width:0;font:15px system-ui,sans-serif;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:10px;padding:11px 14px}}
.search input:focus{{outline:2px solid var(--acc);outline-offset:1px}}
#qcount{{color:var(--mut);font-size:13px;white-space:nowrap}}
.sources{{list-style:none;margin:0;padding:0;background:var(--card);border:1px solid var(--line);border-radius:10px}}
.sources li{{display:flex;flex-wrap:wrap;gap:2px 12px;align-items:baseline;padding:9px 14px;border-bottom:1px solid var(--line)}}
.sources li:last-child{{border-bottom:0}}
.sources a{{font-weight:600;color:var(--acc);min-width:170px}}
.sources .sd{{flex:1 1 220px;color:var(--mut);font-size:13px}}
.sources .ok,.sources .ko{{font-size:12.5px}}
[hidden]{{display:none!important}}
@media(max-width:640px){{.stats{{grid-template-columns:repeat(2,1fr)}} .count{{margin-left:0;width:100%}}}}
</style></head><body><main>
<div class="top"><h1 class="brand">L<span>3</span>NOX</h1><span class="tag">Bulletin SysOps · IT &amp; Cyber</span></div>
<p class="date">{e(date_fr(loc)).capitalize()} · mis à jour à {loc.strftime("%H:%M")} · <a href="alertes.xml">flux RSS des alertes</a></p>
<div class="brief">{brief}</div>
<div class="stats">
<div class="stat l3"><b>{n_exp}</b><span>exploitées</span></div>
<div class="stat l2"><b>{n_crit}</b><span>critiques</span></div>
<div class="stat l1"><b>{n_watch}</b><span>avis à surveiller</span></div>
<div class="stat"><b>{len(news)}</b><span>actus 24 h</span></div>
</div>
{p1_html}
<div class="search" role="search">
<input id="q" type="search" placeholder="Rechercher : php, fortinet, CVE-2026-…, CERT-FR, ransomware…" aria-label="Rechercher dans le bulletin" autocomplete="off">
<span id="qcount" aria-live="polite"></span>
</div>
<p id="noresult" class="empty" hidden>Aucun résultat pour cette recherche.</p>
{section("À faire aujourd'hui", "regroupé par technologie, du plus urgent au moins urgent", cards, "actions")}
{section("Avis à surveiller", f"CERT-FR et éditeurs · {CERT_FEEDS['avis'][1]} derniers jours", watch_html, "avis")}
{section("Disponibilité des services", f"pages d'état officielles · {STATUS_HOURS} h", status_html(status_rows), "services")}
{section("Actu IT & cyber", f"dernières {NEWS_HOURS} h", news_html, "actu")}
{section("Sources", "cliquez pour ouvrir le site · état de la dernière collecte", sources_html, "sources")}
<footer>
<p>Périmètre : failles exploitées P1 conservées {P1_DAYS} j (CISA KEV, CERT-FR, éditeurs), CERT-FR alertes ({CERT_FEEDS['alerte'][1]} j) et avis ({CERT_FEEDS['avis'][1]} j), avis éditeurs ({VENDOR_DAYS} j), GitHub Advisory critiques ({GHSA_DAYS} j), Red Hat ({REDHAT_DAYS} j), pages d'état ({STATUS_HOURS} h), presse ({NEWS_HOURS} h).</p>
<p>Ce bulletin est assemblé automatiquement à partir des sources : il ne vérifie pas les informations et n'analyse pas leur portée. Le niveau de priorité est déduit des mots-clés (« exploitée », « critique »…). Référez-vous toujours à l'avis officiel.</p>
<p>Les commandes sont des exemples génériques : lisez l'avis officiel et testez avant de les appliquer en production.</p>
</footer>
</main>
<script>
const norm=s=>s.normalize('NFD').replace(/[\\u0300-\\u036f]/g,'').toLowerCase();
const rows=[...document.querySelectorAll('#actions .row,#avis .row,#actu .row')];
rows.forEach(r=>r.dataset.s=norm(r.innerText+' '+(r.closest('.card')?.querySelector('h3')?.innerText||'')));
const q=document.getElementById('q'),qc=document.getElementById('qcount'),nr=document.getElementById('noresult');
function filter(){{
  const terms=norm(q.value).split(/\\s+/).filter(Boolean);
  let n=0;
  rows.forEach(r=>{{const ok=terms.every(t=>r.dataset.s.includes(t));r.hidden=!ok;if(ok)n++}});
  document.querySelectorAll('#actions .card').forEach(c=>c.hidden=!c.querySelector('.row:not([hidden])'));
  ['actions','avis','actu'].forEach(id=>{{const s=document.getElementById(id);
    s.hidden=terms.length>0&&!s.querySelector('.row:not([hidden])')}});
  qc.textContent=terms.length?n+' résultat'+(n>1?'s':''):'';
  nr.hidden=!(terms.length&&n===0);
  try{{history.replaceState(null,'',terms.length?'#q='+encodeURIComponent(q.value):location.pathname)}}catch(_){{}}
}}
q.addEventListener('input',filter);
const h=decodeURIComponent((location.hash.match(/^#q=(.*)/)||[])[1]||'');
if(h){{q.value=h;filter()}}
document.addEventListener('keydown',ev=>{{if(ev.key==='/'&&document.activeElement!==q){{ev.preventDefault();q.focus()}}
  if(ev.key==='Escape'&&document.activeElement===q){{q.value='';filter()}}}});
const day="{loc.strftime('%Y-%m-%d')}";
document.querySelectorAll('.steps input').forEach(cb=>{{
  const k='l3nox:'+day+':'+cb.dataset.k;
  try{{cb.checked=localStorage.getItem(k)==='1'}}catch(_){{}}
  cb.addEventListener('change',()=>{{try{{localStorage.setItem(k,cb.checked?'1':'0')}}catch(_){{}}}});
}});
document.querySelectorAll('.copy').forEach(b=>b.addEventListener('click',async()=>{{
  try{{await navigator.clipboard.writeText(b.previousElementSibling.innerText);b.textContent='Copié ✓'}}
  catch(_){{b.textContent='Sélectionnez le texte'}}
  setTimeout(()=>b.textContent='Copier',1500);
}}));
</script>
</body></html>"""


def render_rss(urgent: list[dict]) -> str:
    base = f"https://{SITE_DOMAIN}/" if SITE_DOMAIN else ""
    entries = []
    for it in sorted(urgent, key=lambda i: i["date"] or NOW, reverse=True)[:50]:
        label = LEVEL_LABEL[it["level"]]
        desc = it["summary"] + (f" — Action : {it['action']}" if it["action"] else "")
        entries.append(
            f"<item><title>{e('[' + label + '] ' + it['title'])}</title><link>{e(it['link'])}</link>"
            f"<guid isPermaLink=\"false\">{e(it['source'] + '|' + it['link'])}</guid>"
            f"<pubDate>{format_datetime(it['date'] or NOW)}</pubDate><description>{e(desc)}</description></item>")
    return ('<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>'
            f"<title>{SITE_NAME} · Alertes SysOps</title><link>{e(base)}</link>"
            "<description>Vulnérabilités exploitées et critiques du jour</description>"
            f"<language>fr</language><lastBuildDate>{format_datetime(NOW)}</lastBuildDate>"
            + "".join(entries) + "</channel></rss>")


# ═════════════════════ Notifications push (ntfy) ═════════════════════
# Envoie une notification sur le téléphone pour chaque NOUVELLE alerte P1 (exploitée).
# Configuration : secret GitHub NTFY_TOPIC = nom de ton canal ntfy (long et difficile à deviner).
NTFY_SERVER = os.environ.get("NTFY_SERVER", "https://ntfy.sh")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "")
STATE_FILE = os.path.join(os.environ.get("L3NOX_STATE", "state"), "notified.json")
STATE_KEEP_DAYS = 60
NOTIFY_MAX = 5  # au-delà, une seule notification récapitulative


def item_keys(it: dict) -> list[str]:
    return it["cves"] + ([it["link"]] if it["link"] else [])


def ntfy(title: str, message: str, click: str = "", priority: int = 5, tags=None) -> None:
    payload = {"topic": NTFY_TOPIC, "title": title[:250], "message": message[:3500],
               "priority": priority, "tags": tags or ["rotating_light"]}
    if click:
        payload["click"] = click
    req = urllib.request.Request(NTFY_SERVER, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": UA})
    urllib.request.urlopen(req, timeout=20).read()


def notify_p1(items: list[dict]) -> None:
    if not NTFY_TOPIC:
        print("[--] Notifications : secret NTFY_TOPIC absent, rien envoyé.")
        return
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            seen = json.load(f)
        first_run = False
    except (OSError, ValueError):
        seen, first_run = {}, True

    p1 = sorted((i for i in items if i["level"] == EXPLOITED), key=lambda i: i["date"] or NOW, reverse=True)
    fresh, batch_keys = [], set()
    for it in p1:
        keys = item_keys(it)
        if not keys or any(k in seen or k in batch_keys for k in keys):
            continue  # déjà notifiée (même CVE vue via une autre source, par exemple)
        fresh.append(it)
        batch_keys.update(keys)

    try:
        if first_run:
            ntfy("L3NOX · notifications activées",
                 f"{len(p1)} alerte(s) P1 déjà en cours, visibles sur le bulletin. "
                 "Vous serez prévenu ici de chaque nouvelle faille exploitée.",
                 f"https://{SITE_DOMAIN}/" if SITE_DOMAIN else "", 3, ["white_check_mark"])
        elif len(fresh) > NOTIFY_MAX:
            lines = "\n".join(f"• {i['title']}" for i in fresh[:10])
            ntfy(f"🔴 {len(fresh)} nouvelles alertes P1 exploitées", lines,
                 f"https://{SITE_DOMAIN}/#actions" if SITE_DOMAIN else "")
        else:
            for it in fresh:
                body = it["summary"] or "Vulnérabilité activement exploitée."
                if it["action"]:
                    body += f"\nAction : {it['action']}"
                if it["cves"]:
                    body += "\n" + ", ".join(it["cves"][:3])
                body += f"\nSource : {it['source']}"
                ntfy(f"🔴 P1 · {it['title']}", body, it["link"])
    except Exception as e:  # on ne marque rien comme envoyé si l'envoi échoue
        print(f"[!!] Notifications : échec de l'envoi ({e})")
        return

    stamp = NOW.strftime("%Y-%m-%d")
    for it in (p1 if first_run else fresh):
        for k in item_keys(it):
            seen[k] = stamp
    limit = (NOW - timedelta(days=STATE_KEEP_DAYS)).strftime("%Y-%m-%d")
    seen = {k: v for k, v in seen.items() if v >= limit}
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(seen, f, indent=0)
    print(f"[ok] Notifications : {'activation' if first_run else str(len(fresh)) + ' nouvelle(s) alerte(s) P1'} envoyée(s).")


def main(out_dir: str = "_site") -> None:
    kev = safe("CISA KEV", collect_kev)
    cert = collect_cert()
    redhat = safe("Red Hat", collect_redhat)
    vendors = collect_vendors()
    ghsa = safe("GitHub Advisory", collect_ghsa)
    status_rows = collect_status()
    news = collect_news()

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(render(kev, cert, redhat, vendors, ghsa, status_rows, news))
    urgent = [i for i in kev + cert + redhat + vendors + ghsa if i["level"] >= CRITICAL]
    with open(os.path.join(out_dir, "alertes.xml"), "w", encoding="utf-8") as f:
        f.write(render_rss(urgent))
    if SITE_DOMAIN:
        with open(os.path.join(out_dir, "CNAME"), "w") as f:
            f.write(SITE_DOMAIN)

    for name, ok, detail in STATUS:
        print(f"[{'ok' if ok else '!!'}] {name}: {detail}")
    notify_p1(urgent)
    print(f"Bulletin généré : {len(urgent)} alerte(s) prioritaire(s), {len(news)} actu(s).")


if __name__ == "__main__":
    main()

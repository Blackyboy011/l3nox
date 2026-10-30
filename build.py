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

import hashlib
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
    "Kubernetes": ["https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.xml",
                   "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.xml"],
    "GitLab": ["https://about.gitlab.com/security-releases.xml"],
    "AWS": ["https://aws.amazon.com/security/security-bulletins/rss/feed/"],
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

# Fins de maintenance (endoflife.date) : nom affiché -> identifiant sur endoflife.date
EOL_PRODUCTS = {
    "Kubernetes": "kubernetes", "PHP": "php", "Red Hat Enterprise Linux": "rhel", "Debian": "debian",
    "Ubuntu": "ubuntu", "Windows Server": "windows-server", "PostgreSQL": "postgresql", "MySQL": "mysql",
    "MariaDB": "mariadb", "Node.js": "nodejs", "Python": "python", "GitLab": "gitlab", "nginx": "nginx",
    "VMware ESXi": "esxi", "Veeam Backup & Replication": "veeam-backup-and-replication",
    "Samba": "samba", "Elasticsearch": "elasticsearch", "Apache Kafka": "apache-kafka",
}
EOL_PAST_DAYS = 30    # fins de maintenance survenues ces N derniers jours
EOL_NEXT_DAYS = 90    # fins de maintenance prévues dans les N prochains jours

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
}
# Synthèse rédigée par l'IA, via la fonction Netlify « l3nox-ia » (crédits gratuits Netlify, sans clé payante).
# Variable GitHub L3NOX_AI_URL = adresse de la fonction ; secret GitHub L3NOX_AI_SECRET = mot de passe partagé.
# Sans ces deux réglages, la section « Briefing du jour » n'apparaît pas.
AI_URL = os.environ.get("L3NOX_AI_URL", "")
AI_SECRET = os.environ.get("L3NOX_AI_SECRET", "")
AI_KEY = os.environ.get("ANTHROPIC_API_KEY", "")   # optionnel : clé API Anthropic directe (payante)
AI_MODEL = os.environ.get("AI_MODEL") or "claude-haiku-5-5"   # le plus économe en crédits
AI_MIN_HOURS = 6        # pas de nouvelle rédaction avant N heures… sauf si une nouvelle P1 apparaît
AI_MAX_PER_DAY = 4      # garde-fous pour ne jamais épuiser les 300 crédits Netlify du mois
AI_MAX_PER_MONTH = 100
AI_MAX_ITEMS = 60

# Presse spécialisée : désactivée (seules les sources officielles alimentent le bulletin).
INCLUDE_PRESS = False
NEWS_HOURS = 24
NEWS_MAX = 40

# Filtre des actus : un article n'est gardé que s'il parle d'au moins un de ces sujets…
NEWS_KEEP = re.compile(
    r"vuln[ée]rab|faille|\bcve-|correctif|\bpatch|exploit|zero-day|0-day|jour z[ée]ro"
    r"|ran[çc]ongiciel|ransomware|malware|maliciel|logiciel malveillant|backdoor|porte d[ée]rob[ée]e"
    r"|cyberattaque|attaque|piratage|pirat[ée]|hacker|hacked|compromis|compromission|intrusion"
    r"|fuite de donn[ée]es|data breach|\bbreach|\bleak|phishing|hame[çc]onnage|botnet|\bddos|\bapt\s?\d+"
    r"|infostealer|spyware|logiciel espion|supply.chain|cha[îi]ne d.approvisionnement"
    r"|cert-fr|\banssi\b|\bcisa\b|mise [àa] jour de s[ée]curit[ée]|security update|advisory"
    r"|\brce\b|[ée]l[ée]vation de privil[èe]ges|privilege escalation|contournement d.authentification"
    r"|panne|outage|incident|interruption de service|indisponib"
    r"|fin de (?:vie|support|maintenance)|end of (?:life|support)|end-of-life|\beol\b|deprecat|d[ée]pr[ée]ci"
    r"|d[ée]commission|retrait (?:progressif )?d",
    re.I)
# … et n'est PAS gardé s'il parle de l'un de ceux-ci (sauf s'il cite une CVE).
NEWS_DROP = re.compile(
    r"lev[ée]e de fonds|valorisation|recrute|nomination|nomm[ée]|chiffre d.affaires|r[ée]sultats financiers"
    r"|smartphone|iphone|galaxy|jeu vid[ée]o|gaming|black friday|bon plan|promo"
    r"|mod[èe]le (?:de langage|d.ia)|poids de son mod[èe]le|\bllm\b|chatbot",
    re.I)

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
    "Kubernetes": "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/",
    "GitLab": "https://about.gitlab.com/releases/categories/releases/",
    "AWS": "https://aws.amazon.com/security/security-bulletins/",
    "endoflife.date": "https://endoflife.date/",
    "BleepingComputer": "https://www.bleepingcomputer.com/",
    "The Hacker News": "https://thehackernews.com/",
    "Zataz": "https://www.zataz.com/",
    "IT-Connect": "https://www.it-connect.fr/",
    "Le Monde Informatique": "https://www.lemondeinformatique.fr/securite/",
    "Krebs on Security": "https://krebsonsecurity.com/",
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
    "Kubernetes": "Flux officiel des CVE Kubernetes",
    "GitLab": "Versions de sécurité de GitLab",
    "AWS": "Bulletins de sécurité AWS",
    "endoflife.date": "Dates de fin de maintenance des logiciels",
}

# Niveaux de priorité
EXPLOITED, CRITICAL, WATCH, INFO = 3, 2, 1, 0
LEVEL_LABEL = {EXPLOITED: "P1 exploitée", CRITICAL: "P2 critique", WATCH: "P3 à surveiller", INFO: "Info"}
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
KEV_META: dict = {}  # version et taille du catalogue CISA, pour le résumé du haut


def collect_kev() -> list[dict]:
    data = fetch_first(KEV_URLS, json.loads)
    vulns = data.get("vulnerabilities", [])
    dates = [v.get("dateAdded", "") for v in vulns if v.get("dateAdded")]
    last = max(dates) if dates else ""
    KEV_META.update(count=data.get("count") or len(vulns), version=data.get("catalogVersion", ""),
                    last_added=last, last_n=dates.count(last) if last else 0)
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


def collect_eol() -> list[dict]:
    """Versions arrivées (ou bientôt) en fin de maintenance, d'après endoflife.date."""
    today = NOW.date()
    rows, ok, ko = [], 0, 0
    for label, slug in EOL_PRODUCTS.items():
        try:
            data = fetch_first([f"https://endoflife.date/api/{slug}.json",
                                f"https://endoflife.date/api/v1/products/{slug}/"], json.loads)
        except Exception:
            ko += 1
            continue
        ok += 1
        if isinstance(data, dict):  # format v1
            releases = [{"cycle": r.get("name"), "eol": r.get("eolFrom"),
                         "latest": (r.get("latest") or {}).get("name", "")}
                        for r in (data.get("result") or {}).get("releases", [])]
        else:
            releases = data
        for r in releases:
            eol = r.get("eol")
            if not isinstance(eol, str):
                continue
            try:
                d = datetime.strptime(eol[:10], "%Y-%m-%d").date()
            except ValueError:
                continue
            delta = (d - today).days
            if -EOL_PAST_DAYS <= delta <= EOL_NEXT_DAYS:
                rows.append({"product": label, "slug": slug, "cycle": str(r.get("cycle", "")),
                             "date": d, "delta": delta, "latest": str(r.get("latest") or "")})
    STATUS.append(("endoflife.date", ok > 0, f"{ok} produits suivis" + (f", {ko} en erreur" if ko else "")))
    rows.sort(key=lambda r: r["delta"])
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
            text = f"{e['title']} {e['summary']}"
            relevant = NEWS_KEEP.search(text) and (CVE_RE.search(text) or not NEWS_DROP.search(text))
            if e["date"] and e["date"] >= cutoff and e["title"] and relevant:
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
LEVEL_TAG = {EXPLOITED: "P1", CRITICAL: "P2", WATCH: "P3", INFO: ""}

FONTS = ("https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@100..125,600..800"
         "&family=Atkinson+Hyperlegible+Next:ital,wght@0,400;0,600;0,700;1,400"
         "&family=Atkinson+Hyperlegible+Mono:wght@400;600&display=swap")

DARK_TOKENS = ("--paper:#0E1524;--sheet:#151E31;--ink:#E4E9F1;--muted:#97A3B8;--rule:#26324A;"
               "--link:#5CC8D2;--p1:#FF6378;--p2:#FF9F4D;--p3:#E3BF4F;--ok:#4FCB8C;"
               "--code:#0A101C;--codeink:#DCE3EE;--ontag:#0E1524;color-scheme:dark;")

CSS = """
:root{--paper:#EEF2F6;--sheet:#FFFFFF;--ink:#18202E;--muted:#5A6678;--rule:#D6DDE6;--link:#0B6E78;
--p1:#C21F3A;--p2:#B85A0B;--p3:#876B00;--ok:#1E7F4E;--code:#18202E;--codeink:#E4E9F1;--ontag:#FFFFFF;
--display:"Archivo","Arial Narrow",system-ui,sans-serif;
--body:"Atkinson Hyperlegible Next","Atkinson Hyperlegible",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
--mono:"Atkinson Hyperlegible Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){%DARK%}}
:root[data-theme="dark"]{%DARK%}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{margin:0;background:var(--paper);color:var(--ink);font:400 17px/1.6 var(--body)}
.wrap{max-width:920px;margin:0 auto;padding:0 20px}
a{color:var(--link);text-underline-offset:3px}
:focus-visible{outline:3px solid var(--link);outline-offset:2px;border-radius:4px}
[hidden]{display:none!important}
.lv3{--lvc:var(--p1)}.lv2{--lvc:var(--p2)}.lv1{--lvc:var(--p3)}.lv0{--lvc:var(--muted)}.ras{--lvc:var(--ok)}

/* En-tête */
.bar{display:flex;align-items:center;flex-wrap:wrap;gap:8px 18px;padding:18px 0 16px}
.logo{font:800 27px/1 var(--display);font-stretch:125%;color:var(--ink);text-decoration:none;letter-spacing:.01em}
.logo span{color:var(--link)}
.stamp{margin:0 0 0 auto;color:var(--muted);font-size:15px}
.theme{font:600 14px/1 var(--body);color:var(--ink);background:var(--sheet);border:1px solid var(--rule);
border-radius:999px;padding:8px 14px;cursor:pointer}
.theme:hover{border-color:var(--link)}

/* Niveau du jour */
.band{background:color-mix(in srgb,var(--lvc) 9%,var(--paper));border-top:6px solid var(--lvc);
border-bottom:1px solid color-mix(in srgb,var(--lvc) 28%,var(--paper))}
.posture{display:grid;grid-template-columns:auto 1fr;gap:6px 34px;align-items:center;padding:30px 0 24px}
.level{font:800 116px/.82 var(--display);font-stretch:125%;color:var(--lvc);letter-spacing:-.02em;margin:0}
.level-cap{display:block;font:600 14px/1.2 var(--body);letter-spacing:0;color:var(--muted);margin-top:12px}
h1{font:750 30px/1.22 var(--display);font-stretch:108%;margin:0 0 8px;max-width:32ch;text-wrap:balance}
.lede{margin:0;color:var(--muted);font-size:18px;max-width:60ch}
.facts{list-style:none;padding:0;margin:16px 0 0;display:flex;flex-wrap:wrap;gap:6px 22px;font-size:15px}
.facts li{display:flex;align-items:center;gap:8px}
.facts li::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--muted);flex:none}
.facts .good::before{background:var(--ok)}.facts .down::before{background:var(--p1)}
.toc{display:flex;flex-wrap:wrap;gap:8px;padding:0 0 26px;margin:0}
.toc a{display:inline-flex;align-items:center;gap:9px;padding:5px 13px 5px 5px;border-radius:999px;
background:var(--sheet);border:1px solid var(--rule);color:var(--ink);text-decoration:none;font-size:15px;line-height:1.3}
.toc a:hover{border-color:var(--lvc)}
.toc b{font:800 12px/1 var(--display);font-stretch:118%;color:var(--ontag);background:var(--lvc);border-radius:999px;padding:5px 8px}
.toc span{color:var(--muted)}

/* Recherche */
.search{position:sticky;top:0;z-index:10;background:var(--paper);padding:14px 0 10px}
.field{position:relative;display:flex;align-items:center;gap:12px}
.field svg{position:absolute;left:15px;width:18px;height:18px;color:var(--muted);pointer-events:none}
.field input{flex:1;min-width:0;font:17px var(--body);color:var(--ink);background:var(--sheet);
border:1px solid var(--rule);border-radius:12px;padding:12px 16px 12px 44px}
.field input::placeholder{color:var(--muted)}
.field input:focus{outline:3px solid color-mix(in srgb,var(--link) 45%,transparent);outline-offset:0;border-color:var(--link)}
#qcount{color:var(--muted);font-size:14px;white-space:nowrap}

/* Sections */
section{padding-top:30px}
.sh{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 14px;margin-bottom:14px}
h2{font:750 24px/1.2 var(--display);font-stretch:112%;margin:0}
.sh p{margin:0;color:var(--muted);font-size:15px}
.empty{background:var(--sheet);border:1px dashed var(--rule);border-radius:14px;padding:18px 20px;color:var(--muted);margin:0}

/* Groupes d'actions */
.group{background:var(--sheet);border:1px solid var(--rule);border-left:6px solid var(--lvc);border-radius:14px;
margin-bottom:18px;overflow:hidden;scroll-margin-top:90px}
.gh{display:flex;flex-wrap:wrap;align-items:center;gap:6px 12px;padding:16px 20px 4px}
.gh h3{font:750 20px/1.25 var(--display);font-stretch:108%;margin:0}
.tag{font:800 13px/1 var(--display);font-stretch:118%;color:var(--ontag);background:var(--lvc);border-radius:6px;padding:5px 7px}
.count{color:var(--muted);font-size:15px;margin-left:auto}
.rows,.list{list-style:none;margin:0;padding:0 20px}
.list{background:var(--sheet);border:1px solid var(--rule);border-radius:14px;padding:2px 20px}

/* Une alerte */
.row{display:grid;grid-template-columns:30px 1fr;column-gap:10px;padding:13px 0;border-top:1px solid var(--rule)}
.row:first-child{border-top:0}
.row>*{grid-column:2;min-width:0}
.row>.lv{grid-column:1;grid-row:1/span 3;justify-self:start;align-self:start;margin-top:4px;font:800 11.5px/1 var(--display);
font-stretch:118%;color:var(--lvc);border:1.5px solid var(--lvc);border-radius:5px;padding:3px 4px}
.row.plain{grid-template-columns:1fr}.row.plain>*{grid-column:1}
.head{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 10px}
.t{font-weight:600;color:var(--ink);text-decoration:none;line-height:1.42;overflow-wrap:anywhere}
.t:hover{color:var(--link);text-decoration:underline}
.new{font-size:12.5px;font-weight:700;color:var(--link);background:color-mix(in srgb,var(--link) 13%,transparent);
border-radius:999px;padding:1px 9px;white-space:nowrap}
.meta{display:flex;flex-wrap:wrap;align-items:baseline;gap:3px 14px;margin-top:5px;font-size:14px;color:var(--muted)}
.src{font-weight:600;color:var(--link);text-decoration:none}.src:hover{text-decoration:underline}
.cve{font:13px var(--mono);color:var(--ink);background:color-mix(in srgb,var(--ink) 7%,transparent);border-radius:4px;padding:1px 6px}
.flag{color:var(--p1);font-weight:700}
.pb{color:var(--link)}
.sum{margin:6px 0 0;color:var(--muted);font-size:15px;line-height:1.55;max-width:72ch}

/* Que faire */
.todo{background:color-mix(in srgb,var(--lvc) 5%,var(--sheet));border-top:1px solid var(--rule);padding:14px 20px 18px;margin-top:6px}
.todo h4{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 12px;font:700 16px/1.3 var(--body);margin:0 0 6px}
.progress{font-weight:400;font-size:14px;color:var(--muted)}
.progress.done{color:var(--ok);font-weight:700}
.steps{margin:0;padding-left:24px;max-width:76ch}
.steps li{margin:7px 0;padding-left:4px}
.steps li::marker{color:var(--muted);font-weight:700}
.steps label{cursor:pointer}
.steps input{width:17px;height:17px;margin:0 8px 0 0;vertical-align:-3px;accent-color:var(--ok);cursor:pointer}
.steps li:has(input:checked) label{color:var(--muted);text-decoration:line-through;text-decoration-color:color-mix(in srgb,var(--muted) 55%,transparent)}
.cmds{margin-top:12px}
.cmds summary{cursor:pointer;font-weight:700;color:var(--link);width:max-content}
.os{margin:14px 0 6px;font-size:14px;font-weight:600;color:var(--muted)}
.code{position:relative}
pre{margin:0;background:var(--code);color:var(--codeink);border-radius:10px;padding:14px 88px 14px 16px;overflow-x:auto;font:14px/1.65 var(--mono)}
.copy{position:absolute;top:8px;right:8px;font:600 13px/1 var(--body);border:0;border-radius:6px;padding:7px 10px;
background:color-mix(in srgb,var(--codeink) 16%,var(--code));color:var(--codeink);cursor:pointer}

/* Services */
.services{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(255px,1fr));gap:12px}
.svc{background:var(--sheet);border:1px solid var(--rule);border-radius:12px;padding:12px 15px}
.svc.down{border-color:color-mix(in srgb,var(--p1) 50%,var(--rule));background:color-mix(in srgb,var(--p1) 5%,var(--sheet))}
.svc .name{font-weight:700;color:var(--ink);text-decoration:none}.svc .name:hover{color:var(--link);text-decoration:underline}
.state{display:flex;align-items:center;gap:8px;font-size:14.5px;color:var(--muted);margin-top:2px}
.state::before{content:"";width:9px;height:9px;border-radius:50%;background:var(--muted);flex:none}
.good .state::before{background:var(--ok)}.warn .state::before{background:var(--p3)}.down .state::before{background:var(--p1)}
.down .state{color:var(--p1);font-weight:700}
.inc{list-style:none;margin:8px 0 0;padding:0;font-size:14px;line-height:1.45}
.inc li{margin:5px 0}.inc time{color:var(--muted);margin-right:6px}.inc a{color:var(--ink)}
.open{color:var(--p1);font-weight:700;margin-left:6px}

/* Sources */
.srcs{background:var(--sheet);border:1px solid var(--rule);border-radius:14px;padding:14px 20px}
.srcs summary{cursor:pointer;font-weight:700;color:var(--ink)}
.srcs ul{list-style:none;margin:10px 0 0;padding:0}
.srcs li{display:grid;grid-template-columns:190px 1fr auto;gap:2px 14px;padding:9px 0;border-top:1px solid var(--rule);font-size:15px}
.srcs li a{font-weight:600}
.srcs .sd{color:var(--muted)}
.okk{color:var(--ok)}.ko{color:var(--p1);font-weight:600}.unk{color:var(--muted)}

footer{padding:34px 0 56px;color:var(--muted);font-size:14.5px;max-width:76ch}
footer p{margin:8px 0}

@media (max-width:680px){
body{font-size:16px}
.stamp{margin:0;width:100%;order:3}
.posture{grid-template-columns:1fr;gap:10px;padding:22px 0 18px}
.level{font-size:76px}.level-cap{display:inline;margin:0 0 0 10px}
h1{font-size:23px}.lede{font-size:16px}
.gh{padding:14px 14px 4px}.rows{padding:0 14px}.list{padding:2px 14px}.todo{padding:12px 14px 16px}
.count{margin-left:0;width:100%}
.srcs{padding:12px 14px}.srcs li{grid-template-columns:1fr}
pre{font-size:13px}
}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
""".replace("%DARK%", DARK_TOKENS)

CSS_EXTRA = """
/* Barre de filtres */
.tools{position:sticky;top:0;z-index:10;background:var(--paper);padding:14px 0 12px;border-bottom:1px solid var(--rule)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 10px;padding:0}
.f{--lvc:var(--ink);display:inline-flex;align-items:center;gap:8px;font:600 15px/1 var(--body);color:var(--ink);
background:var(--sheet);border:1px solid var(--rule);border-radius:999px;padding:8px 13px 8px 11px;cursor:pointer;white-space:nowrap}
.f.lv3{--lvc:var(--p1)}.f.lv2{--lvc:var(--p2)}.f.lv1{--lvc:var(--p3)}.f.lv0{--lvc:var(--muted)}
.f.fdone{--lvc:var(--ok)}.f.fhid{--lvc:var(--muted)}
.f i{width:9px;height:9px;border-radius:50%;background:var(--lvc);flex:none}
.f b{font-weight:700;color:var(--muted)}
.f:hover{border-color:var(--lvc)}
.f[aria-pressed="true"]{background:var(--lvc);border-color:var(--lvc);color:var(--ontag)}
.f[aria-pressed="true"] b{color:inherit}.f[aria-pressed="true"] i{background:var(--ontag)}
.sep{width:1px;align-self:stretch;background:var(--rule);margin:2px 4px}
.clear{font:600 14px/1 var(--body);color:var(--ink);background:var(--sheet);border:1px solid var(--rule);
border-radius:12px;padding:14px 14px;cursor:pointer;white-space:nowrap}
.clear:hover:not(:disabled){border-color:var(--ink)}.clear:disabled{opacity:.45;cursor:default}

/* Fil par jour */
.day{padding-top:30px;scroll-margin-top:150px}
.dayh{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 12px;margin:0 0 12px}
.dayh span{color:var(--muted);font-size:15px}
.lvblock{background:var(--sheet);border:1px solid var(--rule);border-left:6px solid var(--lvc);border-radius:14px;margin-bottom:14px;overflow:hidden}
.lvh{display:flex;align-items:center;gap:10px;padding:14px 20px 2px;margin:0;font:700 16px/1.3 var(--body)}
.lvh .n{font-weight:400;color:var(--muted);font-size:14px}
.tag.lv0{background:var(--muted)}
.acts{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:10px}
.act{font:600 14px/1 var(--body);border-radius:8px;padding:8px 12px;cursor:pointer;border:1px solid var(--rule);background:var(--sheet);color:var(--ink)}
.act.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 50%,var(--rule))}
.act.ok:hover{background:var(--ok);border-color:var(--ok);color:var(--ontag)}
.act.no:hover{border-color:var(--ink)}
.done-at{font-size:14px;font-weight:700;color:var(--ok)}.hid-at{font-size:14px;font-weight:700;color:var(--muted)}
.also a{color:var(--link)}
.viewempty{margin-top:30px}

/* Panorama et fins de maintenance */
.pano{list-style:none;margin:0;padding:0;background:var(--sheet);border:1px solid var(--rule);border-radius:14px}
.pano li{display:grid;grid-template-columns:230px 150px 1fr;gap:3px 16px;align-items:baseline;padding:11px 20px;border-top:1px solid var(--rule)}
.pano li:first-child{border-top:0}
.pano .dn{font-weight:700;color:var(--ink);text-decoration:none}
.pano a.dn:hover{color:var(--link);text-decoration:underline}
.pano .cnt{display:flex;flex-wrap:wrap;gap:6px}
.mini{font:800 11.5px/1 var(--display);font-stretch:118%;color:var(--ontag);background:var(--lvc);border-radius:5px;padding:4px 6px}
.calm{color:var(--muted);font-size:14px;font-weight:600}
.pano .det{font-size:15px;color:var(--muted);min-width:0;overflow-wrap:anywhere}
.pano .det a{color:var(--ink)}
.eol li{grid-template-columns:260px 1fr auto}
.when-past{color:var(--p2)}.when-soon{color:var(--p3)}.when-later{color:var(--muted);font-weight:400}


/* Briefing rédigé */
#briefing{padding-top:28px}
.bcard{background:var(--sheet);border:1px solid var(--rule);border-radius:14px;padding:22px 26px 24px}
.exec{font-size:19px;line-height:1.55;margin:0;max-width:68ch;text-wrap:pretty}
.bcard h3{font:750 18px/1.3 var(--display);font-stretch:108%;margin:26px 0 10px}
table.prio{width:100%;border-collapse:collapse;font-size:15.5px}
.prio th{text-align:left;font-weight:700;color:var(--muted);font-size:14px;padding:6px 12px 6px 0;border-bottom:2px solid var(--rule)}
.prio td{padding:11px 12px 11px 0;border-bottom:1px solid var(--rule);vertical-align:top}
.prio td:first-child{white-space:nowrap;width:1%}
.prio .subj{font-weight:700;width:30%}.prio .subj a{color:var(--ink)}.prio .subj a:hover{color:var(--link)}
.todo-line{display:block;margin-top:4px;font-weight:600}
.tagx{font-size:13px;font-weight:600;color:var(--muted);margin-left:6px}
.pt{border-left:4px solid var(--lvc);padding:2px 0 2px 16px;margin:20px 0}
.pt h4{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;font:700 17px/1.3 var(--body);margin:0 0 6px}
.pt p{margin:6px 0;max-width:75ch}
.conf{font-size:15px;color:var(--muted)}.conf b{color:var(--ink)}
.vtab{border-collapse:collapse;font-size:14.5px;margin:10px 0}
.vtab th,.vtab td{text-align:left;padding:5px 18px 5px 0;border-bottom:1px solid var(--rule)}
.vtab th{color:var(--muted);font-weight:700}
.bnote{font-size:14px}
.watch{margin:0;padding-left:20px;max-width:75ch}.watch li{margin:5px 0}
.actsday{list-style:none;margin:0;padding:0}
.actsday li{display:flex;align-items:baseline;gap:10px;padding:8px 0;border-bottom:1px solid var(--rule)}
.actsday li:last-child{border-bottom:0}
.concl{font-weight:600;margin:20px 0 0;max-width:72ch}
@media (max-width:680px){
.bcard{padding:16px 16px 18px}.exec{font-size:17px}
.prio thead{display:none}.prio tr{display:block;padding:10px 0;border-bottom:1px solid var(--rule)}
.prio td{display:block;border:0;padding:2px 0;width:auto!important}
}

/* Fiches actions */
.concern{margin:4px 20px 0;color:var(--muted);font-size:15px}

#toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);display:flex;align-items:center;gap:16px;
background:var(--ink);color:var(--paper);padding:12px 18px;border-radius:12px;font-size:15px;z-index:30;
box-shadow:0 10px 30px rgba(10,16,28,.3);max-width:calc(100% - 32px)}
#toast button{font:700 15px var(--body);color:var(--paper);background:none;border:0;text-decoration:underline;cursor:pointer;padding:0}

@media (max-width:680px){
.filters{flex-wrap:nowrap;overflow-x:auto;margin-left:-20px;margin-right:-20px;padding:0 20px 2px;scrollbar-width:none}
.filters::-webkit-scrollbar{display:none}
.lvh{padding:12px 14px 2px}.concern{margin:4px 14px 0}
.pano li,.eol li{grid-template-columns:1fr;padding:11px 14px}
.clear{padding:13px 12px}
}
"""

JS = r"""
(function(){
var root=document.documentElement,btn=document.getElementById('theme');
function cur(){return root.dataset.theme||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light')}
function label(){btn.textContent=cur()==='dark'?'Mode jour':'Mode nuit'}
btn.addEventListener('click',function(){root.dataset.theme=cur()==='dark'?'light':'dark';
  try{localStorage.setItem('l3nox:theme',root.dataset.theme)}catch(_){}label()});
label();

/* État des alertes : validées / écartées (mémorisé dans ce navigateur) */
var KEY='l3nox:etat',store={};
try{store=JSON.parse(localStorage.getItem(KEY)||'{}')||{}}catch(_){store={}}
function save(){try{localStorage.setItem(KEY,JSON.stringify(store))}catch(_){}}
var LV={p1:'3',p2:'2',p3:'1',news:'0'};
var EMPTY={all:'Tout est traité ou écarté. Rien d’autre à faire pour le moment.',
  p1:'Aucune faille exploitée en attente.',p2:'Aucune faille critique en attente.',p3:'Aucun avis à surveiller en attente.',
  news:'Aucune actualité en attente.',done:'Aucune alerte validée pour l’instant.',hidden:'Aucune alerte écartée.'};
var view='all',terms=[];
var norm=function(s){return s.normalize('NFD').replace(/[̀-ͯ]/g,'').toLowerCase()};
var rows=[].slice.call(document.querySelectorAll('#fil .row'));
rows.forEach(function(r){r.dataset.s=norm(r.querySelector('.head').innerText+' '+r.querySelector('.meta').innerText+' '+((r.querySelector('.sum')||{}).innerText||''))});
function st(r){var s=store[r.dataset.id];return s?s.s:''}
function inView(r,v){var s=st(r);
  if(v==='done'||v==='hidden')return s===v;
  if(s)return false;
  return v==='all'||r.dataset.lv===LV[v]}
function fmt(t){var d=new Date(t);return d.toLocaleDateString('fr-FR',{day:'2-digit',month:'2-digit'})+' à '+d.toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'})}
var clearBtn=document.getElementById('clear'),qc=document.getElementById('qcount'),empty=document.getElementById('viewempty');

function paint(){
  var shown=0;
  rows.forEach(function(r){
    var ok=inView(r,view)&&terms.every(function(t){return r.dataset.s.indexOf(t)>=0});
    r.hidden=!ok;if(ok)shown++;
    var s=st(r),a=r.querySelector('.acts');
    a.querySelector('.ok').hidden=!!s;a.querySelector('.no').hidden=!!s;
    a.querySelector('.undo').hidden=!s;
    var lab=a.querySelector('.state-lab');
    lab.className='state-lab '+(s==='done'?'done-at':s==='hidden'?'hid-at':'');
    lab.textContent=s==='done'?'Validée le '+fmt(store[r.dataset.id].t):s==='hidden'?'Écartée le '+fmt(store[r.dataset.id].t):'';
  });
  document.querySelectorAll('#fil .lvblock').forEach(function(b){
    var n=b.querySelectorAll('.row:not([hidden])').length;b.hidden=!n;
    b.querySelector('.n').textContent=n+' élément'+(n>1?'s':'')});
  document.querySelectorAll('#fil .day').forEach(function(d){d.hidden=!d.querySelector('.lvblock:not([hidden])')});
  ['all','p1','p2','p3','news','done','hidden'].forEach(function(v){
    var c=rows.filter(function(r){return inView(r,v)}).length;
    var b=document.querySelector('.f[data-v="'+v+'"]');if(b){b.querySelector('b').textContent=c;b.setAttribute('aria-pressed',v===view)}});
  qc.textContent=terms.length?(shown+' résultat'+(shown>1?'s':'')):'';
  empty.hidden=shown>0;
  empty.textContent=terms.length?'Aucun résultat pour cette recherche dans cette vue.':EMPTY[view];
  var restore=view==='done'||view==='hidden';
  clearBtn.textContent=restore?'Tout remettre dans la liste':'Vider la liste';
  clearBtn.title=restore?'Remettre toutes ces alertes dans la liste active':'Écarter toutes les alertes affichées';
  clearBtn.disabled=!shown;
}

var toast=document.getElementById('toast'),toastT,undoFn=null;
function say(msg,undo){toast.querySelector('span').textContent=msg;undoFn=undo;toast.querySelector('button').hidden=!undo;
  toast.hidden=false;clearTimeout(toastT);toastT=setTimeout(function(){toast.hidden=true;undoFn=null},6000)}
toast.querySelector('button').addEventListener('click',function(){if(undoFn)undoFn();toast.hidden=true;undoFn=null});

function setState(ids,s){var prev={};ids.forEach(function(id){prev[id]=store[id];
  if(s)store[id]={s:s,t:Date.now()};else delete store[id]});save();paint();
  return function(){ids.forEach(function(id){if(prev[id])store[id]=prev[id];else delete store[id]});save();paint()}}

document.getElementById('fil').addEventListener('click',function(ev){
  var b=ev.target.closest('.act');if(!b)return;var r=b.closest('.row'),id=r.dataset.id;
  var t=r.querySelector('.t').innerText.slice(0,60);
  if(b.classList.contains('ok'))say('Validée : '+t,setState([id],'done'));
  else if(b.classList.contains('no'))say('Écartée : '+t,setState([id],'hidden'));
  else say('Remise dans la liste : '+t,setState([id],null));
});
clearBtn.addEventListener('click',function(){
  var ids=rows.filter(function(r){return !r.hidden}).map(function(r){return r.dataset.id});
  if(!ids.length)return;
  var restore=view==='done'||view==='hidden';
  say((restore?ids.length+' alerte(s) remise(s) dans la liste':ids.length+' alerte(s) écartée(s)'),setState(ids,restore?null:'hidden'));
});
document.querySelectorAll('.f').forEach(function(b){b.addEventListener('click',function(){
  view=b.dataset.v;try{history.replaceState(null,'',view==='all'?location.pathname:'#'+view)}catch(_){}paint();
  var fil=document.getElementById('fil');if(fil.getBoundingClientRect().top<0)fil.scrollIntoView()})});
var q=document.getElementById('q');
q.addEventListener('input',function(){terms=norm(q.value).split(/\s+/).filter(Boolean);paint()});
document.addEventListener('keydown',function(ev){
  if(ev.key==='/'&&document.activeElement!==q){ev.preventDefault();q.focus()}
  if(ev.key==='Escape'&&document.activeElement===q){q.value='';terms=[];paint()}});
var h=location.hash.slice(1);if(LV[h]||h==='done'||h==='hidden')view=h;
paint();

/* Cases « Que faire » */
var day=document.body.dataset.day;
function progress(g){var b=g.querySelectorAll('.steps input'),c=g.querySelectorAll('.steps input:checked').length,p=g.querySelector('.progress');
  if(!p)return;p.textContent=c===b.length?'tout est fait':c+' sur '+b.length+' faites';p.classList.toggle('done',c===b.length)}
document.querySelectorAll('.group').forEach(function(g){
  g.querySelectorAll('.steps input').forEach(function(cb){
    var k='l3nox:'+day+':'+cb.dataset.k;
    try{cb.checked=localStorage.getItem(k)==='1'}catch(_){}
    cb.addEventListener('change',function(){try{localStorage.setItem(k,cb.checked?'1':'0')}catch(_){}progress(g)});
  });progress(g)});

document.querySelectorAll('.copy').forEach(function(b){b.addEventListener('click',function(){
  var t=b.previousElementSibling.innerText;
  (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){b.textContent='Copié'},
   function(){b.textContent='Sélectionnez le texte'});
  setTimeout(function(){b.textContent='Copier'},1600)})});
})();
"""


def plural(n: int, one: str, many: str) -> str:
    return f"{n}\u00a0{one if n <= 1 else many}"


def date_fr(d: datetime) -> str:
    return f"{JOURS[d.weekday()]} {d.day} {MOIS[d.month - 1]} {d.year}"


def when(d) -> str:
    """Heure lisible : « aujourd'hui 09:12 », « hier 18:40 » ou « 28/10 »."""
    if not d:
        return ""
    loc, today = d.astimezone(PARIS), NOW.astimezone(PARIS).date()
    if loc.date() == today:
        return "aujourd'hui " + loc.strftime("%H:%M")
    if loc.date() == today - timedelta(days=1):
        return "hier " + loc.strftime("%H:%M")
    return loc.strftime("%d/%m")


def due_fr(s: str) -> str:
    try:
        return datetime.strptime(s, "%Y-%m-%d").strftime("%d/%m/%Y")
    except ValueError:
        return s


def section(title: str, sub: str, body: str, sid: str) -> str:
    return f'<section id="{sid}"><div class="sh"><h2>{e(title)}</h2><p>{e(sub)}</p></div>{body}</section>'


def status_html(rows: list[dict]) -> str:
    out = []
    for r in rows:
        page = STATUS_PAGES.get(r["name"], "")
        name = f'<a class="name" href="{e(page)}" target="_blank" rel="noopener">{e(r["name"])}</a>'
        if r["ok"] is None:
            out.append(f'<li class="svc unk">{name}<div class="state">État non récupéré, voir la page officielle</div></li>')
            continue
        if not r["incidents"]:
            out.append(f'<li class="svc good">{name}<div class="state">Aucun incident en {STATUS_HOURS} h</div></li>')
            continue
        is_open = any(not i["resolved"] for i in r["incidents"])
        cls, label = ("down", "Incident en cours") if is_open else ("warn", "Incident résolu")
        inc = "".join(f'<li><time>{e(when(i["date"]))}</time><a href="{e(i["link"])}" target="_blank" rel="noopener">'
                      f'{e(i["title"])}</a>{"" if i["resolved"] else "<span class=open>en cours</span>"}</li>'
                      for i in r["incidents"])
        out.append(f'<li class="svc {cls}">{name}<div class="state">{label}</div><ul class="inc">{inc}</ul></li>')
    return f'<ul class="services">{"".join(out)}</ul>'


def sources_html() -> str:
    st = {n: (ok, detail) for n, ok, detail in STATUS}
    alias = {"CERT-FR alerte": "CERT-FR alertes"}
    rows, n_ok = [], 0
    for name, url in SOURCE_SITES.items():
        if name in NEWS_FEEDS and not INCLUDE_PRESS:
            continue
        ok, detail = st.get(alias.get(name, name), (None, "non interrogée"))
        n_ok += bool(ok)
        cls, txt = ("okk", detail) if ok else ("ko", "indisponible") if ok is False else ("unk", detail)
        rows.append(f'<li><a href="{e(url)}" target="_blank" rel="noopener">{e(name)}</a>'
                    f'<span class="sd">{e(SOURCE_DESC.get(name, "Actualité IT et cybersécurité"))}</span>'
                    f'<span class="{cls}">{e(txt)}</span></li>')
    return (f'<details class="srcs"><summary>{n_ok} sources sur {len(rows)} lues lors de la dernière mise à jour</summary>'
            f'<ul>{"".join(rows)}</ul></details>')


LEVEL_NAME = {EXPLOITED: "Failles exploitées", CRITICAL: "Failles critiques", WATCH: "À surveiller", INFO: "Actualités"}
TIMELINE_DAYS = 7  # au-delà, les alertes vont dans « Plus ancien »


def entry_id(it: dict) -> str:
    return it["cves"][0] if it["cves"] else (it["link"] or it["title"])


def merge_entries(items: list[dict]) -> list[dict]:
    """Regroupe les éléments qui parlent de la même CVE (CISA, CERT-FR, éditeur, presse…)."""
    items = sorted(items, key=lambda i: (-i["level"], -(i["date"].timestamp() if i["date"] else 0)))
    by_cve, out = {}, []
    for it in items:
        prim = next((by_cve[c] for c in it["cves"] if c in by_cve), None)
        if prim is None:
            it = dict(it, also=[])
            out.append(it)
            for c in it["cves"]:
                by_cve[c] = it
        else:
            prim["also"].append(it)
            for c in it["cves"]:
                by_cve.setdefault(c, prim)
            if not prim["summary"] and it["summary"]:
                prim["summary"] = it["summary"]
            if not prim["playbook"] and it["playbook"]:
                prim["playbook"] = it["playbook"]
    return out


def item_row(it: dict) -> str:
    lvl = it["level"]
    site = SOURCE_SITES.get(it["source"], "")
    src = (f'<a class="src" href="{e(site)}" target="_blank" rel="noopener">{e(it["source"])}</a>'
           if site else f'<span class="src">{e(it["source"])}</span>')
    iso = it["date"].isoformat() if it["date"] else ""
    meta = [src, f'<time datetime="{iso}">{e(when(it["date"]))}</time>']
    meta += [f'<span class="cve">{e(c)}</span>' for c in it["cves"][:3]]
    also = list(dict.fromkeys((a["source"], a["link"]) for a in it.get("also", []) if a["source"] != it["source"]))
    if also:
        meta.append('<span class="also">aussi : ' + ", ".join(
            f'<a href="{e(l)}" target="_blank" rel="noopener">{e(s)}</a>' for s, l in also[:4]) + "</span>")
    if it["ransomware"]:
        meta.append('<span class="flag">utilisée par des rançongiciels</span>')
    if it["due"]:
        meta.append(f'<span>échéance CISA le {e(due_fr(it["due"]))}</span>')
    if it["playbook"] and lvl > INFO:
        meta.append(f'<a class="pb" href="#pb-{e(it["playbook"])}">Que faire : {e(PB_BY_ID[it["playbook"]]["label"])}</a>')
    new = ('<span class="new">nouveau</span>'
           if it["date"] and lvl > INFO and NOW - it["date"] <= timedelta(hours=NEW_HOURS) else "")
    summary = it["summary"] + (f" Action demandée par la CISA : {it['action']}" if it["action"] else "")
    sum_html = f'<p class="sum">{e(summary)}</p>' if summary.strip() else ""
    acts = ('<div class="acts"><button class="act ok" type="button" title="Nous étions concernés et c\'est traité">Valider</button>'
            '<button class="act no" type="button" title="Retirer cette alerte de la liste">Pas concerné</button>'
            '<span class="state-lab"></span>'
            '<button class="act undo" type="button" hidden>Remettre dans la liste</button></div>')
    return (f'<li class="row plain" data-id="{e(entry_id(it))}" data-lv="{lvl}">'
            f'<div class="head"><a class="t" href="{e(it["link"])}" target="_blank" rel="noopener">{e(it["title"])}</a>{new}</div>'
            f'<div class="meta">{"".join(meta)}</div>{sum_html}{acts}</li>')


def cmds_html(cmds: dict) -> str:
    if not cmds:
        return ""
    blocks = "".join(f'<p class="os">{e(name)}</p><div class="code"><pre><code>{e(code)}</code></pre>'
                     f'<button class="copy" type="button">Copier</button></div>' for name, code in cmds.items())
    return f'<details class="cmds"><summary>Commandes utiles</summary>{blocks}</details>'


def fiche_card(pid, items: list[dict]) -> str:
    pb = PB_BY_ID[pid]
    top = max(i["level"] for i in items)
    counts = [plural(sum(1 for i in items if i["level"] == lv), LEVEL_TAG[lv], LEVEL_TAG[lv])
              for lv in (EXPLOITED, CRITICAL, WATCH) if any(i["level"] == lv for i in items)]
    checklist = "".join(f'<li><label><input type="checkbox" data-k="{e(pid)}-{n}">{e(s)}</label></li>'
                        for n, s in enumerate(pb["steps"]))
    return (f'<article class="group lv{top}" id="pb-{e(pid)}">'
            f'<header class="gh"><span class="tag">{LEVEL_TAG[top]}</span><h3>{e(pb["label"])}</h3></header>'
            f'<p class="concern">Concerne {plural(len(items), "alerte", "alertes")} ({", ".join(counts)})</p>'
            f'<div class="todo"><h4>Que faire <span class="progress" aria-live="polite"></span></h4>'
            f'<ol class="steps">{checklist}</ol>{cmds_html(pb["cmds"])}</div></article>')


DOMAINS = [  # (nom, playbooks rattachés, produits de fin de maintenance rattachés)
    ("Linux et distributions", ["kernel", "glibc", "sudo", "openssh", "openssl"], ["Red Hat Enterprise Linux", "Debian", "Ubuntu"]),
    ("Windows et Active Directory", ["windows", "samba"], ["Windows Server", "Samba"]),
    ("Réseaux, VPN et pare-feu", ["network"], []),
    ("Virtualisation", ["virtu"], ["VMware ESXi"]),
    ("Conteneurs et Kubernetes", ["containers"], ["Kubernetes"]),
    ("Serveurs web et PHP", ["apache", "nginx", "php", "cms"], ["PHP", "nginx"]),
    ("Langages et frameworks", ["java"], ["Node.js", "Python"]),
    ("Bases de données et data", ["data"], ["PostgreSQL", "MySQL", "MariaDB", "Elasticsearch", "Apache Kafka"]),
    ("DevOps et CI/CD", ["devops"], ["GitLab"]),
    ("Sauvegardes", ["backup"], ["Veeam Backup & Replication"]),
    ("Postes et navigateurs", ["browsers"], []),
]


def eol_when(r: dict) -> tuple[str, str]:
    d = r["delta"]
    if d < 0:
        return "when-past", f"terminée depuis {plural(-d, 'jour', 'jours')}"
    if d == 0:
        return "when-past", "se termine aujourd'hui"
    return ("when-soon" if d <= 30 else "when-later"), f"dans {plural(d, 'jour', 'jours')}"


def eol_html(rows: list[dict]) -> str:
    if not rows:
        return '<p class="empty">Aucune fin de maintenance récente ou prochaine parmi les logiciels suivis.</p>'
    out = []
    for r in rows:
        cls, txt = eol_when(r)
        latest = f'dernière version {e(r["latest"])}' if r["latest"] else ""
        out.append(f'<li><a class="dn" href="https://endoflife.date/{e(r["slug"])}" target="_blank" rel="noopener">'
                   f'{e(r["product"])} {e(r["cycle"])}</a>'
                   f'<span>fin de maintenance le {r["date"].strftime("%d/%m/%Y")} <b class="{cls}">{e(txt)}</b></span>'
                   f'<span class="det">{latest}</span></li>')
    return f'<ul class="pano eol">{"".join(out)}</ul>'


def panorama_html(entries: list[dict], eol: list[dict], status_rows: list[dict]) -> str:
    out = []
    for name, pbs, prods in DOMAINS:
        items = [i for i in entries if i["playbook"] in pbs and i["level"] > INFO]
        badges = "".join(f'<span class="mini lv{lv}">{plural(n, LEVEL_TAG[lv], LEVEL_TAG[lv])}</span>'
                         for lv in (EXPLOITED, CRITICAL, WATCH)
                         if (n := sum(1 for i in items if i["level"] == lv)))
        notes = []
        if items:
            top = max(items, key=lambda i: (i["level"], i["date"] or NOW))
            notes.append(f'<a href="#pb-{e(top["playbook"])}">{e(top["title"][:110])}</a>')
        for r in (r for r in eol if r["product"] in prods and r["delta"] <= 30):
            notes.append(f'{e(r["product"])} {e(r["cycle"])} : fin de maintenance {e(eol_when(r)[1])}')
        detail = " · ".join(notes) if notes else "Rien de nouveau"
        out.append(f'<li><span class="dn">{e(name)}</span><span class="cnt">{badges or "<span class=calm>RAS</span>"}</span>'
                   f'<span class="det">{detail}</span></li>')
    outages = [r["name"] for r in status_rows if any(not i["resolved"] for i in r["incidents"])]
    solved = [r["name"] for r in status_rows if r["incidents"] and r["name"] not in outages]
    cloud = (f"Panne en cours : {', '.join(outages)}" if outages else
             (f"Incidents résolus : {', '.join(solved)}" if solved else "Aucune panne signalée"))
    badge = '<span class="mini lv3">panne</span>' if outages else '<span class="calm">RAS</span>'
    out.append(f'<li><span class="dn">Cloud et services en ligne</span><span class="cnt">{badge}</span>'
               f'<span class="det"><a href="#services">{e(cloud)}</a></span></li>')
    return f'<ul class="pano">{"".join(out)}</ul>'


def lv_of(n) -> int:
    return {"P1": EXPLOITED, "P2": CRITICAL, "P3": WATCH}.get(str(n).strip().upper()[:2], INFO)


def briefing_html(b) -> str:
    if not b or not isinstance(b.get("data"), dict):
        return ""
    d = b["data"]
    gen = datetime.fromisoformat(b["generated"]).astimezone(PARIS)
    txt = lambda k: str(d.get(k) or "").strip()
    lst = lambda k: [x for x in (d.get(k) or []) if isinstance(x, (dict, str))]

    def tag(n):
        n = str(n or "").strip()
        lv = lv_of(n)
        extra = n[2:].strip()
        return (f'<span class="tag lv{lv}">{e(n[:2].upper() or "Info")}</span>'
                + (f'<span class="tagx">{e(extra)}</span>' if extra else ""))

    def link(url, label):
        url = str(url or "")
        return f'<a href="{e(url)}" target="_blank" rel="noopener">{label}</a>' if url.startswith("http") else label

    parts = [f'<p class="exec">{e(txt("synthese"))}</p>']
    prio = [p for p in lst("prioritaires") if isinstance(p, dict)]
    if prio:
        rows = "".join(f'<tr><td>{tag(p.get("niveau"))}</td>'
                       f'<td class="subj">{link(p.get("lien"), e(str(p.get("sujet", ""))))}</td>'
                       f'<td>{e(str(p.get("impact", "")))}<span class="todo-line">{e(str(p.get("action", "")))}</span></td></tr>'
                       for p in prio)
        parts.append('<h3>Sécurité prioritaire</h3><table class="prio"><thead><tr><th>Priorité</th><th>Sujet</th>'
                     f'<th>Impact et action</th></tr></thead><tbody>{rows}</tbody></table>')
    points = [p for p in lst("points") if isinstance(p, dict)]
    if points:
        parts.append("<h3>Autres points importants</h3>")
    for p in points:
        vers = [v for v in (p.get("versions") or []) if isinstance(v, dict) and v.get("produit")]
        vtab = ("<table class=\"vtab\"><thead><tr><th>Produit / versions</th><th>Correctif</th></tr></thead><tbody>"
                + "".join(f'<tr><td>{e(str(v.get("produit", "")))}</td><td>{e(str(v.get("corrige", "")))}</td></tr>' for v in vers)
                + "</tbody></table>") if vers else ""
        conf = "".join(f'<p class="conf"><b>{lab}</b> {e(str(p.get(k)))}</p>'
                       for lab, k in (("Confirmé :", "confirme"), ("Non confirmé :", "non_confirme")) if p.get(k))
        parts.append(f'<article class="pt lv{lv_of(p.get("niveau"))}"><h4>{tag(p.get("niveau"))}{e(str(p.get("titre", "")))}</h4>'
                     f'<p>{e(str(p.get("contexte", "")))}</p>{vtab}'
                     + (f'<p><b>Mesures :</b> {e(str(p.get("mesures")))}</p>' if p.get("mesures") else "")
                     + conf + (f'<p class="bnote">{link(p.get("lien"), "Avis officiel")}</p>' if p.get("lien") else "")
                     + "</article>")
    if txt("services") or txt("fins_de_maintenance"):
        parts.append("<h3>Services et fins de maintenance</h3>"
                     + (f'<p>{e(txt("services"))}</p>' if txt("services") else "")
                     + (f'<p>{e(txt("fins_de_maintenance"))}</p>' if txt("fins_de_maintenance") else ""))
    watch = [str(w) for w in lst("a_surveiller") if isinstance(w, str)]
    if watch:
        parts.append("<h3>À surveiller</h3><ul class=\"watch\">" + "".join(f"<li>{e(w)}</li>" for w in watch) + "</ul>")
    acts = [a for a in lst("actions") if isinstance(a, dict)]
    if acts:
        parts.append("<h3>Actions SysOps du jour</h3><ul class=\"actsday\">"
                     + "".join(f'<li>{tag(a.get("niveau"))}<span>{e(str(a.get("action", "")))}</span></li>' for a in acts)
                     + "</ul>")
    if txt("conclusion"):
        parts.append(f'<p class="concl">{e(txt("conclusion"))}</p>')
    sub = (f"Rédigé par l'IA à {gen.strftime('%H:%M')} le {gen.strftime('%d/%m')} à partir des sources officielles listées plus bas. "
           "Vérifiez toujours les détails dans l'avis officiel.")
    return (f'<section id="briefing"><div class="sh"><h2>Briefing du jour</h2><p>{e(sub)}</p></div>'
            f'<div class="bcard">{"".join(parts)}</div></section>')


def day_label(d) -> tuple[str, str]:
    today = NOW.astimezone(PARIS).date()
    if d == today:
        return "Aujourd'hui", date_fr(d)
    if d == today - timedelta(days=1):
        return "Hier", date_fr(d)
    return f"{JOURS[d.weekday()].capitalize()} {d.day} {MOIS[d.month - 1]}", ""


def render(kev, cert, redhat, vendors, ghsa, status_rows, news, eol=None, briefing=None) -> str:
    eol = eol or []
    entries = merge_entries(kev + cert + redhat + vendors + ghsa + news)
    today = NOW.astimezone(PARIS).date()
    loc = NOW.astimezone(PARIS)

    # Fil : un bloc par jour, puis un bloc par niveau
    days: dict = {}
    for it in entries:
        d = (it["date"] or NOW).astimezone(PARIS).date()
        key = d if (today - d).days < TIMELINE_DAYS else "older"
        days.setdefault(key, {}).setdefault(it["level"], []).append(it)
    keys = sorted((k for k in days if k != "older"), reverse=True) + (["older"] if "older" in days else [])
    fil = []
    for k in keys:
        if k == "older":
            title, sub = "Plus ancien", f"avant le {(today - timedelta(days=TIMELINE_DAYS - 1)).strftime('%d/%m')}"
        else:
            title, sub = day_label(k)
        blocks = []
        for lv in (EXPLOITED, CRITICAL, WATCH, INFO):
            items = sorted(days[k].get(lv, []), key=lambda i: i["date"] or NOW, reverse=True)
            if not items:
                continue
            tag = LEVEL_TAG[lv] or "Actu"
            blocks.append(f'<div class="lvblock lv{lv}"><h3 class="lvh"><span class="tag lv{lv}">{tag}</span>'
                          f'{e(LEVEL_NAME[lv])} <span class="n"></span></h3>'
                          f'<ul class="rows">{"".join(item_row(i) for i in items)}</ul></div>')
        dkey = "older" if k == "older" else k.isoformat()
        fil.append(f'<section class="day" id="j-{dkey}"><div class="dayh"><h2>{e(title)}</h2>'
                   f'<span>{e(sub)}</span></div>{"".join(blocks)}</section>')

    # Fiches « Que faire » par technologie
    by_pb: dict = {}
    for it in entries:
        if it["playbook"] and it["level"] > INFO:
            by_pb.setdefault(it["playbook"], []).append(it)
    pb_order = sorted(by_pb, key=lambda k: (-max(i["level"] for i in by_pb[k]), -len(by_pb[k])))
    fiches = "".join(fiche_card(k, by_pb[k]) for k in pb_order) or \
        '<p class="empty">Aucune fiche : pas d\'alerte liée à une technologie suivie.</p>'

    # Niveau du jour
    urgent = [i for i in entries if i["level"] >= CRITICAL]
    n_exp = sum(1 for i in urgent if i["level"] == EXPLOITED)
    n_crit = sum(1 for i in urgent if i["level"] == CRITICAL)
    n_new = sum(1 for i in urgent if i["date"] and NOW - i["date"] <= timedelta(hours=NEW_HOURS))
    n_watch = sum(1 for i in entries if i["level"] == WATCH)
    outages = [r["name"] for r in status_rows if any(not i["resolved"] for i in r["incidents"])]
    top = max((i["level"] for i in urgent), default=INFO)
    if urgent:
        level, band = LEVEL_TAG[top], f"lv{top}"
        parts = []
        if n_exp:
            parts.append(plural(n_exp, "faille exploitée", "failles exploitées"))
        if n_crit:
            parts.append(plural(n_crit, "faille critique", "failles critiques"))
        headline = " et ".join(parts) + " à traiter."
        lede = (f"{plural(n_new, 'nouvelle alerte', 'nouvelles alertes')} depuis hier. "
                "Validez ce que vous avez traité, écartez ce qui ne vous concerne pas.")
    else:
        level, band = "RAS", "ras"
        headline = "Rien de critique à traiter aujourd'hui."
        lede = "Bon moment pour avancer sur les mises à jour courantes."
    facts = [f'<li class="down">Panne en cours : {e(", ".join(outages))}</li>' if outages
             else '<li class="good">Aucune panne en cours sur les services suivis</li>',
             f"<li>{plural(n_watch, 'avis à surveiller', 'avis à surveiller')}</li>"]
    if KEV_META.get("count"):
        kev_txt = f"Catalogue CISA : {KEV_META['count']:,} failles exploitées connues".replace(",", " ")
        if KEV_META.get("last_added"):
            kev_txt += (f", dernier ajout le {due_fr(KEV_META['last_added'])[:5]}"
                        f" (+{KEV_META['last_n']})")
        facts.append(f"<li>{e(kev_txt)}</li>")
    n_eol = sum(1 for r in eol if r["delta"] <= 30)
    if n_eol:
        facts.append(f'<li><a href="#eol">{plural(n_eol, "fin de maintenance", "fins de maintenance")} à traiter</a></li>')
    facts.append('<li><a href="#panorama">Panorama par domaine</a></li>')

    filters = ('<button class="f" data-v="all" type="button"><i></i>Tout <b></b></button>'
               '<button class="f lv3" data-v="p1" type="button"><i></i>P1 <b></b></button>'
               '<button class="f lv2" data-v="p2" type="button"><i></i>P2 <b></b></button>'
               '<button class="f lv1" data-v="p3" type="button"><i></i>P3 <b></b></button>'
               '<span class="sep" aria-hidden="true"></span>'
               '<button class="f fdone" data-v="done" type="button"><i></i>Validées <b></b></button>'
               '<button class="f fhid" data-v="hidden" type="button"><i></i>Écartées <b></b></button>')
    if INCLUDE_PRESS:
        filters = filters.replace('<span class="sep"', '<button class="f lv0" data-v="news" type="button"><i></i>Actus <b></b></button><span class="sep"', 1)
    search_icon = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true">'
                   '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>')

    return f"""<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{SITE_NAME} · Bulletin SysOps</title>
<meta name="description" content="Bulletin SysOps du jour : failles exploitées, alertes CERT-FR, avis éditeurs et actions recommandées.">
<meta name="theme-color" content="#EEF2F6" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0E1524" media="(prefers-color-scheme: dark)">
<link rel="alternate" type="application/rss+xml" title="{SITE_NAME} : alertes" href="alertes.xml">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="{FONTS}">
<script>try{{var t=localStorage.getItem('l3nox:theme');if(t)document.documentElement.dataset.theme=t}}catch(_){{}}</script>
<style>{CSS}{CSS_EXTRA}</style></head>
<body data-day="{loc.strftime('%Y-%m-%d')}">
<div class="wrap"><header class="bar"><a class="logo" href="./">L<span>3</span>NOX</a>
<p class="stamp">{e(date_fr(loc)).capitalize()}, mis à jour à {loc.strftime("%H:%M")}</p>
<button class="theme" id="theme" type="button">Mode nuit</button></header></div>
<div class="band {band}"><div class="wrap">
<div class="posture"><p class="level">{level}<span class="level-cap">niveau du jour</span></p>
<div><h1>{e(headline)}</h1><p class="lede">{e(lede)}</p><ul class="facts">{"".join(facts)}</ul></div></div>
</div></div>
<main class="wrap">
{briefing_html(briefing)}
<div class="tools"><div class="filters" role="group" aria-label="Filtrer par niveau">{filters}</div>
<div class="field">{search_icon}
<input id="q" type="search" placeholder="Rechercher un produit, une CVE, une source…" aria-label="Rechercher" autocomplete="off">
<span id="qcount" aria-live="polite"></span><button class="clear" id="clear" type="button">Vider la liste</button></div></div>
<div id="fil">{"".join(fil)}</div>
<p id="viewempty" class="empty viewempty" hidden></p>
{section("Panorama par domaine", "Où en est chaque partie de l'infrastructure", panorama_html(entries, eol, status_rows), "panorama")}
{section("Fins de maintenance", f"Versions arrivées en fin de vie ces {EOL_PAST_DAYS} derniers jours ou dans les {EOL_NEXT_DAYS} prochains", eol_html(eol), "eol")}
{section("Fiches « Que faire »", "Actions recommandées par technologie", fiches, "fiches")}
{section("Disponibilité des services", f"Pages d'état officielles, dernières {STATUS_HOURS} h", status_html(status_rows), "services")}
{section("Sources", "Cliquez sur une source pour ouvrir son site", sources_html(), "sources")}
<footer>
<p>Ce bulletin est assemblé automatiquement toutes les 15 minutes. Il ne vérifie pas les informations : le niveau de priorité est déduit des sources (catalogue CISA, alertes CERT-FR) et de mots-clés. Référez-vous toujours à l'avis officiel.</p>
<p>Les alertes validées ou écartées sont mémorisées dans ce navigateur uniquement.</p>
<p>Les commandes proposées sont des exemples génériques. Testez-les avant de les appliquer en production.</p>
</footer></main>
<div id="toast" role="status" hidden><span></span><button type="button">Annuler</button></div>
<script>{JS}</script>
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


# ═════════════════════ Synthèse rédigée par l'IA ═════════════════════
BRIEF_FILE = os.path.join(os.environ.get("L3NOX_STATE", "state"), "briefing.json")

AI_SYSTEM = """Tu es l'analyste SysOps qui rédige chaque matin le briefing de veille d'un administrateur
systèmes et réseaux français (parc Linux Red Hat, Windows / Active Directory, Samba, virtualisation,
pare-feu et VPN, bases de données, CI/CD, sauvegardes, cloud).

Règles impératives :
- Tu t'appuies UNIQUEMENT sur les données fournies (avis officiels CISA, CERT-FR, éditeurs, Red Hat,
  GitHub Advisory, pages d'état, fins de maintenance). N'invente aucune version, aucun chiffre, aucun fait.
  Si une version corrigée n'apparaît pas dans les données, écris « voir l'avis officiel ».
- Distingue toujours ce qui est confirmé (exploitation listée par la CISA, alerte CERT-FR, éditeur qui
  confirme) de ce qui ne l'est pas.
- Priorités : P1 = exploitation confirmée ; P2 = critique ou impact opérationnel fort sans exploitation
  confirmée ; P3 = à surveiller. Regroupe les doublons (même CVE vue par plusieurs sources).
- Ne transforme pas chaque avis en urgence : retiens ce qui compte vraiment pour l'exploitation.
- Français clair, phrases courtes, ton professionnel, sans emoji.

Réponds UNIQUEMENT par un objet JSON valide, sans texte autour, de la forme :
{"synthese": "2 à 4 phrases : le risque dominant du jour et ce qui a changé",
 "prioritaires": [{"niveau": "P1", "sujet": "Produit — CVE", "impact": "…", "action": "…", "lien": "url de la donnée"}],
 "points": [{"niveau": "P2", "titre": "…", "contexte": "…",
             "versions": [{"produit": "…", "corrige": "…"}], "mesures": "…",
             "confirme": "…", "non_confirme": "…", "lien": "url"}],
 "services": "1 à 2 phrases sur les pannes et incidents des services suivis",
 "fins_de_maintenance": "1 phrase, ou chaîne vide",
 "a_surveiller": ["…"],
 "actions": [{"niveau": "P1", "action": "…"}],
 "conclusion": "1 à 2 phrases"}
« prioritaires » : au plus 6 éléments (P1 d'abord). « points » : au plus 4 sujets détaillés (P2 utiles).
« actions » : au plus 8 actions concrètes, triées par priorité."""


def ai_input(entries: list[dict], eol: list[dict], status_rows: list[dict]) -> str:
    loc = NOW.astimezone(PARIS)
    lines = [f"Date : {date_fr(loc)}, {loc.strftime('%H:%M')} (heure de Paris)."]
    if KEV_META.get("count"):
        lines.append(f"Catalogue CISA KEV : {KEV_META['count']} entrées, version {KEV_META.get('version', '?')}, "
                     f"dernier ajout le {KEV_META.get('last_added', '?')} ({KEV_META.get('last_n', 0)} entrée(s) ce jour-là).")
    lines.append("\n## Alertes (niveau calculé, source, date, titre, CVE, résumé, lien)")
    picked = sorted((i for i in entries if i["level"] >= WATCH),
                    key=lambda i: (-i["level"], -(i["date"].timestamp() if i["date"] else 0)))[:AI_MAX_ITEMS]
    for i in picked:
        also = ", ".join(sorted({a["source"] for a in i.get("also", [])}))
        lines.append(f"- [{LEVEL_TAG[i['level']]}] {i['source']}{' (aussi : ' + also + ')' if also else ''} | "
                     f"{(i['date'] or NOW).astimezone(PARIS).strftime('%d/%m %H:%M')} | {i['title']} | "
                     f"{', '.join(i['cves'][:4]) or '-'} | {i['summary'][:300]}"
                     f"{' | Action CISA : ' + i['action'] if i['action'] else ''} | {i['link']}")
    lines.append("\n## Pages d'état des services (24 h)")
    for r in status_rows:
        if r["ok"] is None:
            lines.append(f"- {r['name']} : état non récupéré")
        elif not r["incidents"]:
            lines.append(f"- {r['name']} : aucun incident")
        else:
            for inc in r["incidents"]:
                lines.append(f"- {r['name']} : {inc['title']} ({'résolu' if inc['resolved'] else 'EN COURS'})")
    lines.append("\n## Fins de maintenance (passées depuis peu ou à venir)")
    for r in eol:
        lines.append(f"- {r['product']} {r['cycle']} : fin le {r['date'].strftime('%d/%m/%Y')} "
                     f"({'il y a ' + str(-r['delta']) + ' j' if r['delta'] < 0 else 'dans ' + str(r['delta']) + ' j'}), "
                     f"dernière version {r['latest'] or '?'}")
    return "\n".join(lines)


def ai_call(prompt: str) -> dict:
    body = {"model": AI_MODEL, "max_tokens": 3500, "system": AI_SYSTEM,
            "messages": [{"role": "user", "content": prompt}]}
    if AI_URL:  # fonction Netlify (AI Gateway)
        req = urllib.request.Request(AI_URL, data=json.dumps({"system": AI_SYSTEM, "prompt": prompt,
                                                               "model": AI_MODEL, "max_tokens": 3500}).encode(),
                                     headers={"content-type": "application/json", "x-l3nox-secret": AI_SECRET,
                                              "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=90) as r:
            resp = json.loads(r.read())
        text = resp.get("text", "")
        if resp.get("usage"):
            u = resp["usage"]
            print(f"[ok] Synthèse IA : {u.get('input_tokens', '?')} tokens lus, {u.get('output_tokens', '?')} écrits.")
    else:       # clé API directe
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=json.dumps(body).encode(),
                                     headers={"x-api-key": AI_KEY, "anthropic-version": "2023-06-01",
                                              "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=180) as r:
            resp = json.loads(r.read())
        text = "".join(b.get("text", "") for b in resp.get("content", []) if b.get("type") == "text")
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    data = json.loads(text[text.find("{"): text.rfind("}") + 1])
    if not isinstance(data, dict) or "synthese" not in data:
        raise ValueError("réponse inattendue")
    return data


def get_briefing(entries: list[dict], eol: list[dict], status_rows: list[dict]):
    """Renvoie la synthèse (nouvelle ou en cache), ou None si l'IA n'est pas configurée."""
    try:
        with open(BRIEF_FILE, encoding="utf-8") as f:
            cached = json.load(f)
    except (OSError, ValueError):
        cached = None
    if not ((AI_URL and AI_SECRET) or AI_KEY):
        print("[--] Synthèse IA : L3NOX_AI_URL / L3NOX_AI_SECRET absents, section non affichée.")
        return None
    counts = (cached or {}).get("calls", {})
    today, month = NOW.strftime("%Y-%m-%d"), NOW.strftime("%Y-%m")
    n_day = counts.get(today, 0)
    n_month = sum(v for k, v in counts.items() if k.startswith(month))
    sig_items = sorted(f"{entry_id(i)}:{i['level']}" for i in entries if i["level"] >= WATCH)
    sig = hashlib.sha256("|".join(sig_items).encode()).hexdigest()
    p1 = {entry_id(i) for i in entries if i["level"] == EXPLOITED}
    if cached and cached.get("generated"):
        age_h = (NOW - datetime.fromisoformat(cached["generated"])).total_seconds() / 3600
        new_p1 = bool(p1 - set(cached.get("p1", [])))
        if cached.get("sig") == sig or (age_h < AI_MIN_HOURS and not new_p1):
            print(f"[ok] Synthèse IA : réutilisée (rédigée il y a {age_h:.1f} h).")
            return cached
    if n_day >= AI_MAX_PER_DAY or n_month >= AI_MAX_PER_MONTH:
        print(f"[--] Synthèse IA : plafond atteint ({n_day} aujourd'hui, {n_month} ce mois-ci), précédente réutilisée.")
        return cached
    try:
        data = ai_call(ai_input(entries, eol, status_rows))
    except Exception as e:
        print(f"[!!] Synthèse IA : échec ({type(e).__name__}: {e}).")
        stub = dict(cached or {})  # on compte l'essai (même raté) pour respecter les plafonds
        stub["calls"] = dict(counts, **{today: n_day + 1})
        os.makedirs(os.path.dirname(BRIEF_FILE) or ".", exist_ok=True)
        with open(BRIEF_FILE, "w", encoding="utf-8") as f:
            json.dump(stub, f, ensure_ascii=False)
        return cached
    counts[today] = n_day + 1
    counts = {k: v for k, v in counts.items() if k >= (NOW - timedelta(days=62)).strftime("%Y-%m-%d")}
    out = {"sig": sig, "p1": sorted(p1), "generated": NOW.isoformat(), "model": AI_MODEL, "data": data,
           "calls": counts}
    os.makedirs(os.path.dirname(BRIEF_FILE) or ".", exist_ok=True)
    with open(BRIEF_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    print("[ok] Synthèse IA : nouvelle rédaction.")
    return out


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
    eol = collect_eol()
    news = collect_news() if INCLUDE_PRESS else []
    briefing = get_briefing(merge_entries(kev + cert + redhat + vendors + ghsa + news), eol, status_rows)

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(render(kev, cert, redhat, vendors, ghsa, status_rows, news, eol, briefing))
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

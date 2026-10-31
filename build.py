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

import base64
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
    "Ubuntu": ["https://ubuntu.com/security/notices/rss.xml"],
    "Debian": ["https://www.debian.org/security/dsa-long.rdf", "https://www.debian.org/security/dsa.rdf"],
    "Google Chrome": ["https://chromereleases.googleblog.com/feeds/posts/default"],
}
VENDOR_DAYS = 3
VENDOR_QUIET = {"Microsoft MSRC": 10, "Ubuntu": 8, "Debian": 8, "Google Chrome": 3}
# Pour certains flux, on ne garde que les titres utiles (ex. Chrome : mises à jour de sécurité du poste de travail)
VENDOR_TITLE_KEEP = {"Google Chrome": re.compile(r"Stable Channel Update for Desktop|Extended Stable", re.I)}  # éditeurs très bavards : pas de P2 automatique, au plus N avis P3

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
# L'IA ne travaille qu'UNE FOIS PAR JOUR, le matin (heure de Paris), pour que les 300 crédits
# gratuits de Netlify tiennent tout le mois. Le reste de la journée, les nouvelles alertes
# continuent d'apparaître sur le site ; seuls la synthèse et les articles attendent le lendemain matin.
AI_WINDOW = (6, 10)     # créneau de travail de l'IA : de 6 h à 10 h (heure de Paris)
AI_MAX_PER_DAY = 2      # 1 synthèse par jour (+ 1 seul nouvel essai si la première tentative échoue)
AI_MAX_PER_MONTH = 45
AI_MAX_ITEMS = 60
# Articles rédigés (un par alerte P1/P2, rédigé une seule fois puis conservé)
AI_POSTS_PER_RUN = 6     # répartis sur les passages du créneau du matin
AI_POSTS_PER_DAY = 15
AI_POSTS_PER_MONTH = 400
AI_POSTS_DAYS = 14      # on ne rédige que pour les alertes de moins de N jours (sauf si le briefing les cite)

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
    "Ubuntu": "https://ubuntu.com/security/notices",
    "Debian": "https://www.debian.org/security/",
    "Google Chrome": "https://chromereleases.googleblog.com/",
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
    "CERT-FR avis": "Avis de sécurité de l'ANSSI (couvre aussi Juniper, Veeam, VMware, Apple, Ivanti…)",
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
    "Ubuntu": "Avis de sécurité Ubuntu (USN)",
    "Debian": "Avis de sécurité Debian (DSA)",
    "Google Chrome": "Mises à jour de sécurité de Chrome (failles exploitées signalées)",
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


def in_ai_window() -> bool:
    """Vrai pendant le créneau quotidien de l'IA (AI_WINDOW, heure de Paris)."""
    return AI_WINDOW[0] <= NOW.astimezone(PARIS).hour < AI_WINDOW[1]
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


def safe_url(u) -> str:
    u = str(u or "").strip()
    return u if re.match(r"^https?://[^\s\"'<>]+$", u, re.I) else ""


def make_item(source, title, link, date, summary="", level=INFO, **extra) -> dict:
    link = safe_url(link)
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
            if source in VENDOR_TITLE_KEEP and not VENDOR_TITLE_KEEP[source].search(e["title"]):
                continue
            text = f"{e['title']} {e['summary']}"
            if EXPLOIT_RE.search(text):
                level = EXPLOITED
            elif CRITICAL_RE.search(text):
                level = CRITICAL
            else:
                level = WATCH
            if source in VENDOR_QUIET and level == CRITICAL:
                level = WATCH  # trop d'avis « RCE » : seuls les exploités montent en priorité
            if level < EXPLOITED and e["date"] < cutoff:
                continue
            if level == WATCH and source in VENDOR_QUIET:
                if sum(1 for i in items if i["source"] == source and i["level"] == WATCH) >= VENDOR_QUIET[source]:
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
        incidents = [{"title": e["title"], "link": safe_url(e["link"]) or STATUS_PAGES.get(name, ""), "date": e["date"],
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

.md h3:first-child{margin-top:0}
.md h3+p{font-size:18px;line-height:1.55;max-width:70ch}
.md h4{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;font:700 17px/1.3 var(--body);margin:18px 0 6px}
.md td .tag,.md li .tag{margin-right:4px}
.md p{max-width:75ch}

/* Articles rédigés */
.row.post{display:block;padding:20px 0 18px}
.pstamp{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 10px;margin:0;color:var(--muted);font-size:14px}
.pprio{margin:6px 0 2px;font:700 15px/1.35 var(--body);color:var(--lvc)}
.pprio .tag{margin-right:6px}
.ptitle{font:750 20px/1.3 var(--display);font-stretch:106%;margin:2px 0 10px}
.ptitle .t{font-weight:inherit}
.pbody{color:var(--ink);font-size:16px;line-height:1.6;margin:0}
.pbody p{margin:10px 0;max-width:75ch}
.pbody h4{font:700 16px/1.3 var(--body);margin:16px 0 6px}
.pbody table.prio{font-size:15px;margin:12px 0}
.pbody table.prio td:first-child{white-space:normal;width:32%;font-weight:600}
.pbody ol.watch{padding-left:24px}
.psrc{margin-top:12px}
.psrc>span:first-child{font-weight:600;color:var(--ink)}
.todo-in{margin-top:10px}
.todo-in summary{cursor:pointer;font-weight:700;color:var(--link);font-size:15px;width:max-content;max-width:100%}
.steps-in{margin:8px 0 0;padding-left:24px;max-width:75ch;font-size:15.5px}
.steps-in li{margin:5px 0}
/* Menu, replis et lecture */
.nav{display:flex;gap:4px 18px;flex-wrap:wrap;font-weight:600;font-size:15px}
.nav a{color:var(--muted);text-decoration:none;padding:4px 0;border-bottom:2px solid transparent}
.nav a:hover{color:var(--ink)}
.nav a[aria-current="page"]{color:var(--ink);border-bottom-color:var(--link)}
details.dayfold>summary,details.more>summary{cursor:pointer;font-weight:700;color:var(--link);font-size:15px;
list-style:none;display:inline-flex;align-items:center;gap:8px;padding:9px 14px;border:1px solid var(--rule);
border-radius:10px;background:var(--sheet);margin:2px 0 6px}
details.dayfold>summary::-webkit-details-marker,details.more>summary::-webkit-details-marker{display:none}
details.dayfold>summary::before,details.more>summary::before{content:"+";font-weight:800}
details.dayfold[open]>summary::before,details.more[open]>summary::before{content:"−"}
details.dayfold[open]>summary{margin-bottom:12px}
details.more{margin-top:8px}
details.more[open]>summary{margin-bottom:6px}
details.lvfold>summary{list-style:none;cursor:pointer}
details.lvfold>summary::-webkit-details-marker{display:none}
details.lvfold>summary .lvh{padding-bottom:12px}
details.lvfold>summary .lvh::after{content:"Afficher";margin-left:auto;font:700 14px var(--body);color:var(--link)}
details.lvfold[open]>summary .lvh::after{content:"Masquer"}
details.lvfold[open]>summary .lvh{padding-bottom:2px}
.row.plain .sum{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
@media (max-width:680px){.nav{order:2;width:100%;gap:4px 16px}.nav a{font-size:15px}}
/* Synchronisation */
.syncst{font-size:13px;color:var(--muted);white-space:nowrap}.syncst.ok{color:var(--ok)}.syncst.err{color:var(--p2)}
details.sync{margin:10px 0}
details.sync summary{cursor:pointer;font-weight:700;color:var(--link)}
#syncform{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}
#syncform input{flex:1 1 220px;font:15px var(--body);color:var(--ink);background:var(--sheet);border:1px solid var(--rule);border-radius:8px;padding:9px 12px}
#syncform button{font:600 14px var(--body);border-radius:8px;padding:9px 12px;cursor:pointer;border:1px solid var(--rule);background:var(--sheet);color:var(--ink)}
#syncform button[type=submit]{background:var(--link);border-color:var(--link);color:var(--ontag)}
#syncmsg{min-height:1.2em;margin:4px 0}
.cvelink{font-family:var(--mono);font-size:.92em;font-weight:600;color:var(--link)}
.row{scroll-margin-top:140px}
.row.flash{box-shadow:0 0 0 3px color-mix(in srgb,var(--link) 45%,transparent);border-radius:8px;transition:box-shadow .3s}
/* Fiches dépliables du briefing */
tr.has-detail{cursor:pointer}
tr.has-detail:hover td,tr.has-detail.is-open td{background:color-mix(in srgb,var(--link) 6%,var(--sheet))}
tr.has-detail:focus-visible{outline:3px solid var(--link);outline-offset:-3px}
.dt-cell{width:1%;white-space:nowrap;text-align:right}
.dt-btn{font:700 13px/1 var(--body);color:var(--link);background:var(--sheet);border:1px solid var(--rule);border-radius:8px;padding:7px 10px;cursor:pointer}
tr.is-open .dt-btn{background:var(--link);border-color:var(--link);color:var(--ontag)}
tr.dt-row>td{white-space:normal!important;width:auto!important;padding:0 0 14px!important;background:color-mix(in srgb,var(--link) 4%,var(--sheet))}
.dt{border-left:4px solid var(--link);padding:14px 18px 6px;font-size:15.5px}
.dt-head{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:0 0 6px;font-weight:700}
.dt-head a{color:var(--ink)}
.dt .pbody table.prio td:first-child{white-space:normal;width:32%;font-weight:600}
.dt-wait{color:var(--muted);font-style:italic}
.dt-src{font-size:14.5px}.dt-jump{font-size:14.5px;font-weight:600}
@media (max-width:680px){.dt-cell{text-align:left}tr.dt-row>td{padding:0 0 10px!important}.dt{padding:12px 12px 4px}}
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
var SYNC=document.body.dataset.sync||'',syncCode='';try{syncCode=SYNC?(localStorage.getItem('l3nox:sync')||''):''}catch(_){}
var KEY='l3nox:etat',store={};
try{store=JSON.parse(localStorage.getItem(KEY)||'{}')||{}}catch(_){store={}}
function saveLocal(){try{localStorage.setItem(KEY,JSON.stringify(store))}catch(_){}}
function save(){saveLocal();push()}
(function(){var lim=Date.now()-150*864e5;Object.keys(store).forEach(function(id){if(!store[id]||!(store[id].t>=lim))delete store[id]})})();
var LV={p1:'3',p2:'2',p3:'1',news:'0'};
var EMPTY={all:'Tout est traité ou écarté. Rien d’autre à faire pour le moment.',
  p1:'Aucune faille exploitée en attente.',p2:'Aucune faille critique en attente.',p3:'Aucun avis à surveiller en attente.',
  news:'Aucune actualité en attente.',done:'Aucune alerte validée pour l’instant.',hidden:'Aucune alerte écartée.'};
var view='all',terms=[];
var norm=function(s){return s.normalize('NFD').replace(/[̀-ͯ]/g,'').toLowerCase()};
var rows=[].slice.call(document.querySelectorAll('#fil .row'));
rows.forEach(function(r){r.dataset.s=norm(r.querySelector('.head').textContent+' '+r.querySelector('.meta').textContent+' '+((r.querySelector('.sum')||{}).textContent||''))});
var lastMode='';
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
  var mode=view+'|'+terms.join(' ');
  if(mode!==lastMode){document.querySelectorAll('#fil details.dayfold').forEach(function(d){d.open=(view!=='all'||terms.length>0)});
    document.querySelectorAll('#fil details.lvfold').forEach(function(d){d.open=(view==='p3'||view==='done'||view==='hidden'||terms.length>0)});
    var full=(view==='p1'||view==='p2');  /* onglets P1/P2 : solutions visibles sans clic */
    document.querySelectorAll('#fil .row details.more, #fil .row details.todo-in').forEach(function(d){d.open=full});lastMode=mode}
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
  store[id]={s:s||'',t:Date.now()}});save();paint();
  return function(){ids.forEach(function(id){store[id]={s:prev[id]?prev[id].s:'',t:Date.now()}});save();paint()}}

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

/* Synchronisation personnelle entre appareils (code personnel, facultatif) */
function merge(items){var ch=false;Object.keys(items||{}).forEach(function(id){var v=items[id];
  if(v&&typeof v.t==='number'&&(!store[id]||store[id].t<v.t)){store[id]={s:v.s||'',t:v.t};ch=true}});return ch}
function syncMsg(kind){var m={ok:'Choix synchronisés à '+new Date().toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'}),
  code:'Code incorrect : la synchronisation est désactivée.',err:'Synchronisation impossible pour le moment, nouvel essai plus tard.',off:''}[kind]||'';
  var a=document.getElementById('syncmsg'),b=document.getElementById('syncst');if(a)a.textContent=m;
  if(b){b.textContent=kind==='ok'?'Synchronisé':kind==='err'?'Hors ligne':'';b.className='syncst '+kind}
  if(kind==='code'){syncCode='';try{localStorage.removeItem('l3nox:sync')}catch(_){}}}
function pull(){if(!SYNC||!syncCode)return;
  fetch(SYNC,{headers:{'x-l3nox-code':syncCode}}).then(function(r){if(!r.ok)throw r.status;return r.json()})
  .then(function(j){if(merge(j.items)){saveLocal();paint()}pushNow()}).catch(function(e){syncMsg(e===403?'code':'err')})}
function pushNow(){if(!SYNC||!syncCode)return;
  fetch(SYNC,{method:'PUT',headers:{'x-l3nox-code':syncCode,'content-type':'application/json'},body:JSON.stringify({items:store})})
  .then(function(r){if(!r.ok)throw r.status;return r.json()})
  .then(function(j){if(merge(j.items)){saveLocal();paint()}syncMsg('ok')}).catch(function(e){syncMsg(e===403?'code':'err')})}
var pushT;function push(){if(!SYNC||!syncCode)return;clearTimeout(pushT);pushT=setTimeout(pushNow,800)}
var form=document.getElementById('syncform');
if(form){form.addEventListener('submit',function(ev){ev.preventDefault();var c=document.getElementById('synccode').value.trim();if(!c)return;
  syncCode=c;try{localStorage.setItem('l3nox:sync',c)}catch(_){}document.getElementById('synccode').value='';pull()});
  document.getElementById('syncoff').addEventListener('click',function(){syncCode='';try{localStorage.removeItem('l3nox:sync')}catch(_){}syncMsg('off');
    document.getElementById('syncmsg').textContent='Synchronisation désactivée sur cet appareil. Vos choix restent enregistrés ici.'})}
if(syncCode){pull();setInterval(pull,5*60*1000);document.addEventListener('visibilitychange',function(){if(!document.hidden)pull()})}

/* Briefing : un clic sur une ligne déplie sa fiche (versions, correctif, impact, mesures, sources) */
function toggleRow(tr){var d=tr.nextElementSibling;if(!d||!d.classList.contains('dt-row'))return;
  d.hidden=!d.hidden;tr.setAttribute('aria-expanded',!d.hidden);tr.classList.toggle('is-open',!d.hidden);
  var b=tr.querySelector('.dt-btn');if(b)b.textContent=d.hidden?'Détails':'Masquer'}
document.addEventListener('click',function(ev){var tr=ev.target.closest('tr.has-detail');
  if(!tr||(ev.target.closest('a')&&!ev.target.closest('.dt-btn')))return;toggleRow(tr)});
document.addEventListener('keydown',function(ev){if((ev.key==='Enter'||ev.key===' ')&&ev.target.matches&&ev.target.matches('tr.has-detail')){ev.preventDefault();toggleRow(ev.target)}});

/* Lien vers un article : on déplie ce qui le cache, puis on y va */
function reveal(hash){var el=hash&&document.getElementById(hash.slice(1));if(!el||!el.classList.contains('row'))return;
  if(el.hidden){view='all';terms=[];q.value='';paint()}
  var p=el.parentElement;while(p){if(p.tagName==='DETAILS')p.open=true;p=p.parentElement}
  var more=el.querySelector('details.more');if(more)more.open=true;
  el.scrollIntoView({block:'start'});el.classList.add('flash');setTimeout(function(){el.classList.remove('flash')},1600)}
document.addEventListener('click',function(ev){var a=ev.target.closest('a[href^="#it-"],a[href^="./#it-"]');if(!a)return;
  ev.preventDefault();var h=a.getAttribute('href').replace('./','');try{history.replaceState(null,'',h)}catch(_){}reveal(h)});
if(location.hash.indexOf('#it-')===0)setTimeout(function(){reveal(location.hash)},50);

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


SYNC_URL = os.environ.get("L3NOX_SYNC_URL", "").strip() or (
    AI_URL.strip()[: -len("/api/ia")] + "/api/etat" if AI_URL.strip().endswith("/api/ia") else "")


def sync_html() -> str:
    if not SYNC_URL:
        return "<p>Les alertes validées ou écartées sont mémorisées dans ce navigateur uniquement.</p>"
    return ('<details class="sync" id="sync"><summary>Synchroniser mes choix entre mes appareils</summary>'
            "<p>Par défaut, les alertes validées ou écartées sont mémorisées dans ce navigateur uniquement, et chaque "
            "visiteur garde ses propres choix. Avec votre code personnel, vos choix vous suivent sur tous vos appareils.</p>"
            '<form id="syncform"><input id="synccode" type="password" autocomplete="current-password" '
            'placeholder="Code de synchronisation" aria-label="Code de synchronisation">'
            '<button type="submit">Activer sur cet appareil</button>'
            '<button type="button" id="syncoff">Désactiver</button></form><p id="syncmsg" aria-live="polite"></p></details>')


def nav_html(active: str = "") -> str:
    links = [("./", "Bulletin", "home"), ("etat.html", "État du parc", "state"), ("archives.html", "Archives", "archives"),
             ("a-propos.html", "À propos", "about")]
    return '<nav class="nav" aria-label="Menu">' + "".join(
        f'<a href="{h}"{" aria-current=\"page\"" if k == active else ""}>{t}</a>' for h, t, k in links) + "</nav>"


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


def anchor(it: dict) -> str:
    return "it-" + re.sub(r"[^A-Za-z0-9-]+", "-", entry_id(it))[:80].strip("-")


def stamp_fr(d) -> str:
    loc = (d or NOW).astimezone(PARIS)
    return f"{loc.day} {MOIS[loc.month - 1]} {loc.year} · {loc.strftime('%H')} h {loc.strftime('%M')} · Paris"


def sources_links(it: dict) -> list[str]:
    seen, out = set(), []
    for src, link in [(it["source"], it["link"])] + [(a["source"], a["link"]) for a in it.get("also", [])]:
        if link and link not in seen:
            seen.add(link)
            out.append(f'<a href="{e(link)}" target="_blank" rel="noopener">{e(src)}</a>')
    return out


def todo_html(it: dict, with_steps: bool) -> str:
    pb = PB_BY_ID.get(it["playbook"]) if it["playbook"] else None
    if not pb or it["level"] <= INFO:
        return ""
    steps = ("<ol class=\"steps-in\">" + "".join(f"<li>{e(x)}</li>" for x in pb["steps"]) + "</ol>") if with_steps else ""
    cmds = "".join(f'<p class="os">{e(name)}</p><div class="code"><pre><code>{e(code)}</code></pre>'
                   f'<button class="copy" type="button">Copier</button></div>' for name, code in pb["cmds"].items())
    if not steps and not cmds:
        return ""
    label = "Que faire" if with_steps else "Commandes utiles"
    return f'<details class="todo-in"><summary>{label} ({e(pb["label"])})</summary>{steps}{cmds}</details>'


def post_body_html(md: str) -> str:
    """Introduction toujours visible ; tableau, mesures et la suite derrière « Lire l'article complet »."""
    lines = md.splitlines()
    cut = next((n for n, l in enumerate(lines) if l.lstrip().startswith("|") or l.lstrip().startswith("#")), len(lines))
    intro, rest = "\n".join(lines[:cut]).strip(), "\n".join(lines[cut:]).strip()
    if not rest:
        return md_to_html(md)
    return (md_to_html(intro) + '<details class="more"><summary>Lire l\'article complet</summary>'
            + md_to_html(rest) + "</details>")


ACTS_HTML = ('<div class="acts"><button class="act ok" type="button" title="Nous étions concernés et c\'est traité">Valider</button>'
             '<button class="act no" type="button" title="Retirer cette alerte de la liste">Pas concerné</button>'
             '<span class="state-lab"></span>'
             '<button class="act undo" type="button" hidden>Remettre dans la liste</button></div>')


def item_row(it: dict, post: dict | None = None) -> str:
    lvl = it["level"]
    new = ('<span class="new">nouveau</span>'
           if it["date"] and lvl > INFO and NOW - it["date"] <= timedelta(hours=NEW_HOURS) else "")
    head_attrs = f'class="row{" post" if post else " plain"}" id="{anchor(it)}" data-id="{e(entry_id(it))}" data-lv="{lvl}"'

    if post:  # article rédigé par l'IA
        qual = re.sub(r"^\s*\**\s*P[123]\b\s*", "", post.get("prio") or "").strip()
        prio = f"{LEVEL_TAG[lvl]} {qual}" if qual else f"{LEVEL_TAG[lvl]} — {LEVEL_NAME[lvl]}"
        title = post.get("title") or it["title"]
        extra = []
        if it["ransomware"]:
            extra.append('<span class="flag">utilisée par des rançongiciels</span>')
        if it["due"]:
            extra.append(f'<span>échéance CISA le {e(due_fr(it["due"]))}</span>')
        return (f'<li {head_attrs}><article>'
                f'<p class="pstamp"><time datetime="{(it["date"] or NOW).isoformat()}">{e(stamp_fr(it["date"]))}</time>{new}</p>'
                f'<p class="pprio lv{lvl}">{md_inline(prio)}</p>'
                f'<div class="head"><h4 class="ptitle"><a class="t" href="{e(it["link"])}" target="_blank" rel="noopener">{e(title)}</a></h4></div>'
                f'<div class="sum pbody">{post_body_html(post["md"])}</div>'
                f'<div class="meta psrc"><span>Sources officielles :</span>{" · ".join(sources_links(it))}'
                f'{"".join(extra)}{"".join(f"<span class=cve>{e(c)}</span>" for c in it["cves"][:3])}</div>'
                f'{todo_html(it, with_steps=False)}{ACTS_HTML}</article></li>')

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
    summary = it["summary"] + (f" Action demandée par la CISA : {it['action']}" if it["action"] else "")
    sum_html = f'<p class="sum">{e(summary)}</p>' if summary.strip() else ""
    return (f'<li {head_attrs}>'
            f'<div class="head"><a class="t" href="{e(it["link"])}" target="_blank" rel="noopener">{e(it["title"])}</a>{new}</div>'
            f'<div class="meta">{"".join(meta)}</div>{sum_html}{todo_html(it, with_steps=True)}{ACTS_HTML}</li>')


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
            notes.append(f'<a href="./#{anchor(top)}">{e(top["title"][:110])}</a>')
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


MD_TAG = re.compile(r"\b(P[123])\b")


CVE_DETAIL: dict = {}   # CVE -> fiche complète (versions, correctif, impact, mesures, sources) pour le briefing
CVE_ANCHOR: dict = {}   # CVE -> ancre de l'alerte sur la page d'accueil (rempli au moment du rendu)


def md_inline(t: str) -> str:
    """Mise en forme d'une ligne : texte échappé, puis gras, liens http(s) et étiquettes P1/P2/P3."""
    t = e(t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"\[([^\]]+)\]\((https?://[^\s)]+)\)",
               lambda m: f'<a href="{m.group(2)}" target="_blank" rel="noopener">{m.group(1)}</a>', t)
    t = re.sub(r"`([^`]+)`", r'<span class="cve">\1</span>', t)
    if CVE_ANCHOR:
        t = re.sub(r"(?<![\w/#=.-])(CVE-\d{4}-\d{4,})",
                   lambda m: (f'<a class="cvelink" href="#{CVE_ANCHOR[m.group(1).upper()]}" title="Voir l\'article et les mesures">'
                              f'{m.group(1)}</a>') if m.group(1).upper() in CVE_ANCHOR else m.group(1), t, flags=re.I)
    return MD_TAG.sub(lambda m: f'<span class="tag lv{lv_of(m.group(1))}">{m.group(1)}</span>', t)


def detail_html(it: dict, post) -> str:
    """Fiche dépliable d'une alerte, affichée sous sa ligne dans le tableau du briefing."""
    head = (f'<p class="dt-head"><span class="tag lv{it["level"]}">{LEVEL_TAG[it["level"]] or "Info"}</span>'
            f'<a href="{e(it["link"])}" target="_blank" rel="noopener">{e((post or {}).get("title") or it["title"])}</a></p>')
    if post and post.get("md"):
        body = f'<div class="pbody">{md_to_html(post["md"])}</div>'
    else:
        body = f'<p>{e(it["summary"])}</p>' if it["summary"] else ""
        if it["action"]:
            body += f'<p><b>Action demandée par la CISA :</b> {e(it["action"])}</p>'
        pb = PB_BY_ID.get(it["playbook"]) if it["playbook"] else None
        body += ('<p class="dt-wait">L\'article détaillé n\'est pas encore rédigé ; voici les mesures types.</p>'
                 if not post else "")
        steps = pb["steps"] if pb else GENERIC_STEPS
        body += "<h4>Mesures SysOps</h4><ol class=\"watch\">" + "".join(f"<li>{e(x)}</li>" for x in steps) + "</ol>"
    srcs = " · ".join(sources_links(it))
    return (f'{head}{body}<p class="dt-src"><b>Sources officielles :</b> {srcs}</p>'
            f'<p class="dt-jump"><a href="#{anchor(it)}">Voir l\'alerte dans le fil (Valider, Pas concerné)</a></p>')


def md_to_html(md: str, details: bool = False) -> str:
    out, para, lst, table = [], [], [], []
    kind = ["ul"]

    def flush():
        if para:
            out.append(f"<p>{md_inline(' '.join(para))}</p>")
            para.clear()
        if lst:
            out.append(f'<{kind[0]} class="watch">' + "".join(f"<li>{md_inline(x)}</li>" for x in lst) + f"</{kind[0]}>")
            lst.clear()
        if table:
            rows = [[c.strip() for c in r.strip().strip("|").split("|")] for r in table
                    if not re.fullmatch(r"\|?[\s:\-|]+\|?", r.strip())]
            if rows:
                head, body = rows[0], rows[1:]
                trs = []
                for r in body:
                    cells = "".join(f"<td>{md_inline(c)}</td>" for c in r)
                    cve = next((c.upper() for c in CVE_RE.findall(" ".join(r)) if c.upper() in CVE_DETAIL), None) if details else None
                    if cve:  # ligne du briefing : un clic déplie la fiche complète de l'alerte
                        trs.append(f'<tr class="has-detail" tabindex="0" aria-expanded="false">{cells}'
                                   f'<td class="dt-cell"><button type="button" class="dt-btn">Détails</button></td></tr>'
                                   f'<tr class="dt-row" hidden><td colspan="{len(r) + 1}"><div class="dt">{CVE_DETAIL[cve]}</div></td></tr>')
                    else:
                        trs.append(f"<tr>{cells}{'<td></td>' if details and CVE_DETAIL else ''}</tr>")
                extra_th = "<th></th>" if details and CVE_DETAIL else ""
                out.append('<table class="prio"><thead><tr>' + "".join(f"<th>{md_inline(c)}</th>" for c in head)
                           + extra_th + "</tr></thead><tbody>" + "".join(trs) + "</tbody></table>")
            table.clear()

    for raw in md.splitlines():
        line = raw.rstrip()
        if not line.strip():
            flush()
            continue
        if line.lstrip().startswith("|"):
            if para or lst:
                flush()
            table.append(line)
            continue
        if table:
            flush()
        m = re.match(r"^(#{2,4})\s+(.*)", line)
        if m:
            flush()
            tag = "h3" if len(m.group(1)) == 2 else "h4"
            out.append(f"<{tag}>{md_inline(m.group(2).strip())}</{tag}>")
            continue
        m = re.match(r"^\s*([-*•]|\d+[.)])\s+(.*)", line)
        if m:
            k = "ol" if m.group(1)[0].isdigit() else "ul"
            if lst and kind[0] != k:
                flush()
            kind[0] = k
            if para:
                out.append(f"<p>{md_inline(' '.join(para))}</p>")
                para.clear()
            lst.append(m.group(2))
            continue
        if lst:
            lst[-1] += " " + line.strip()
        else:
            para.append(line.strip())
    flush()
    return "".join(out)


def briefing_html(b) -> str:
    if b and b.get("md"):
        gen = datetime.fromisoformat(b["generated"]).astimezone(PARIS)
        chunks, cur = [], []
        for line in b["md"].splitlines():
            if line.startswith("## ") and cur:
                chunks.append("\n".join(cur))
                cur = []
            cur.append(line)
        chunks.append("\n".join(cur))
        body = md_to_html("\n".join(chunks[:2]), details=True)
        if len(chunks) > 2:
            body += ('<details class="more"><summary>Lire la suite du briefing</summary>'
                     + md_to_html("\n".join(chunks[2:]), details=True) + "</details>")
        if b.get("truncated"):
            body += '<p class="bnote">Le briefing a été raccourci : consultez le fil ci-dessous pour le détail.</p>'
        sub = (f"Rédigé par l'IA à {gen.strftime('%H:%M')} le {gen.strftime('%d/%m')} à partir des sources officielles. "
               "Cliquez sur une CVE pour ouvrir l'article et ses mesures.")
        return (f'<section id="briefing"><div class="sh"><h2>Briefing du jour</h2><p>{e(sub)}</p></div>'
                f'<div class="bcard md">{body}</div></section>')
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


def render(kev, cert, redhat, vendors, ghsa, status_rows, news, eol=None, briefing=None, posts=None) -> str:
    eol = eol or []
    posts = posts or {}
    CVE_ANCHOR.clear()
    entries = merge_entries(kev + cert + redhat + vendors + ghsa + news)
    today = NOW.astimezone(PARIS).date()
    loc = NOW.astimezone(PARIS)

    CVE_DETAIL.clear()
    for it in sorted(entries, key=lambda i: -i["level"]):
        fiche = None
        for c in it["cves"]:
            CVE_ANCHOR.setdefault(c.upper(), anchor(it))
            if c.upper() not in CVE_DETAIL and it["level"] >= WATCH:
                fiche = fiche or detail_html(it, posts.get(entry_id(it)))
                CVE_DETAIL[c.upper()] = fiche

    # Fil : un bloc par jour, puis un bloc par niveau
    days: dict = {}
    for it in entries:
        d = (it["date"] or NOW).astimezone(PARIS).date()
        key = d if (today - d).days < TIMELINE_DAYS else "older"
        days.setdefault(key, {}).setdefault(it["level"], []).append(it)
    keys = sorted((k for k in days if k != "older"), reverse=True) + (["older"] if "older" in days else [])
    fil = []
    for n_day, k in enumerate(keys):
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
            head = (f'<h3 class="lvh"><span class="tag lv{lv}">{tag}</span>'
                    f'{e(LEVEL_NAME[lv])} <span class="n"></span></h3>')
            rows_html = f'<ul class="rows">{"".join(item_row(i, posts.get(entry_id(i))) for i in items)}</ul>'
            if lv <= WATCH and len(items) > 3:  # beaucoup d'avis secondaires : replié par défaut
                blocks.append(f'<div class="lvblock lv{lv}"><details class="lvfold"><summary>{head}</summary>'
                              f'{rows_html}</details></div>')
            else:
                blocks.append(f'<div class="lvblock lv{lv}">{head}{rows_html}</div>')
        dkey = "older" if k == "older" else k.isoformat()
        inner = "".join(blocks)
        if n_day >= 2:  # au-delà d'aujourd'hui et d'hier : replié, pour une page plus courte
            counts = ", ".join(f"{sum(len(v) for lv, v in days[k].items() if lv == L)} {LEVEL_TAG[L]}"
                               for L in (EXPLOITED, CRITICAL, WATCH) if days[k].get(L))
            total = sum(len(v) for v in days[k].values())
            inner = (f'<details class="dayfold" data-fold="1"><summary>Afficher {plural(total, "alerte", "alertes")}'
                     f'{" (" + counts + ")" if counts else ""}</summary>{inner}</details>')
        fil.append(f'<section class="day" id="j-{dkey}"><div class="dayh"><h2>{e(title)}</h2>'
                   f'<span>{e(sub)}</span></div>{inner}</section>')

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
        facts.append(f'<li><a href="etat.html#eol">{plural(n_eol, "fin de maintenance", "fins de maintenance")} à traiter</a></li>')
    facts.append('<li><a href="etat.html">État du parc</a></li>')

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
<meta name="description" content="{e(SITE_DESC)}">
{head_extra(f"{SITE_NAME} · Bulletin SysOps du jour", SITE_DESC)}
<meta name="theme-color" content="#EEF2F6" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0E1524" media="(prefers-color-scheme: dark)">
<link rel="alternate" type="application/rss+xml" title="{SITE_NAME} : alertes" href="alertes.xml">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="{FONTS}">
<script>try{{var t=localStorage.getItem('l3nox:theme');if(t)document.documentElement.dataset.theme=t}}catch(_){{}}</script>
<style>{CSS}{CSS_EXTRA}</style></head>
<body data-day="{loc.strftime('%Y-%m-%d')}" data-sync="{e(SYNC_URL)}">
<div class="wrap"><header class="bar"><a class="logo" href="./">L<span>3</span>NOX</a>{nav_html("home")}
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
<span id="qcount" aria-live="polite"></span><span id="syncst" class="syncst"></span><button class="clear" id="clear" type="button">Vider la liste</button></div></div>
<div id="fil">{"".join(fil)}</div>
<p id="viewempty" class="empty viewempty" hidden></p>
<footer>
<p>Ce bulletin est assemblé automatiquement toutes les 15 minutes. Il ne vérifie pas les informations : le niveau de priorité est déduit des sources (catalogue CISA, alertes CERT-FR) et de mots-clés. Référez-vous toujours à l'avis officiel.</p>
{sync_html()}
<p>Les commandes proposées sont des exemples génériques. Testez-les avant de les appliquer en production.</p>
<p><a href="etat.html">État du parc et sources</a> · <a href="a-propos.html">À propos et mentions légales</a> · <a href="alertes.xml">Flux RSS des alertes</a></p>
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

Réponds en Markdown, en français, SANS bloc de code et SANS rien d'autre que le briefing,
avec exactement ces titres et dans cet ordre (tu peux omettre une section vide) :

## Synthèse
2 à 4 phrases : le risque dominant du jour et ce qui a changé.

## Sécurité prioritaire
Un tableau Markdown | Priorité | Sujet | Impact et action | Source | avec au plus 6 lignes, P1 d'abord.
« Priorité » contient P1, P2 ou P3. « Source » contient un lien Markdown [Avis](url) pris dans les données.

## Points importants
Au plus 3 sujets P2, chacun sous un titre ### P2 — Produit, avec des puces courtes :
- **Versions corrigées :** … (ou « voir l'avis officiel »)
- **Mesures :** …
- **Confirmé :** … / **Non confirmé :** …

## Services et fins de maintenance
1 à 3 puces.

## À surveiller
Au plus 4 puces.

## Actions SysOps du jour
Au plus 8 puces, chacune commençant par P1, P2 ou P3 suivi d'un tiret.

## Conclusion
1 à 2 phrases.

Le briefing complet doit rester COURT : 700 mots au maximum."""


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
    max_tokens = 3800
    body = {"model": AI_MODEL, "max_tokens": max_tokens, "system": AI_SYSTEM,
            "messages": [{"role": "user", "content": prompt}]}
    out_tokens = None
    if AI_URL:  # fonction Netlify (AI Gateway)
        req = urllib.request.Request(AI_URL.strip(), data=json.dumps({"system": AI_SYSTEM, "prompt": prompt,
                                                                       "model": AI_MODEL, "max_tokens": max_tokens}).encode(),
                                     headers={"content-type": "application/json", "x-l3nox-secret": AI_SECRET,
                                              "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=90) as r:
            resp = json.loads(r.read())
        if resp.get("error"):
            raise RuntimeError(f"service IA : {resp['error']}")
        text = resp.get("text", "")
        u = resp.get("usage") or {}
        out_tokens = u.get("output_tokens")
        print(f"[ok] Synthèse IA : {u.get('input_tokens', '?')} tokens lus, {out_tokens or '?'} écrits.")
    else:       # clé API directe
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=json.dumps(body).encode(),
                                     headers={"x-api-key": AI_KEY, "anthropic-version": "2023-06-01",
                                              "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=180) as r:
            resp = json.loads(r.read())
        text = "".join(b.get("text", "") for b in resp.get("content", []) if b.get("type") == "text")
        out_tokens = (resp.get("usage") or {}).get("output_tokens")
    text = re.sub(r"^```[a-z]*\s*|\s*```$", "", (text or "").strip())
    if not text:
        raise ValueError(f"réponse vide de l'IA (champs reçus : {', '.join(resp.keys()) or 'aucun'})")
    if text.startswith("{"):  # ancien format JSON, toujours accepté
        try:
            data = json.loads(text[: text.rfind("}") + 1])
            if isinstance(data, dict) and "synthese" in data:
                return {"data": data}
        except ValueError:
            pass
    truncated = bool(out_tokens and out_tokens >= max_tokens - 5)
    if truncated:  # on retire la dernière ligne, probablement coupée
        text = text.rsplit("\n", 1)[0]
    print("[ok] Synthèse IA : début de la réponse : " + text[:120].replace("\n", " ") + "…")
    return {"md": text, "truncated": truncated}


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
        gen = datetime.fromisoformat(cached["generated"])
        age_h = (NOW - gen).total_seconds() / 3600
        same_day = gen.astimezone(PARIS).date() == NOW.astimezone(PARIS).date()
        if same_day or cached.get("sig") == sig or not in_ai_window():
            why = ("déjà rédigée aujourd'hui" if same_day else "rien de nouveau" if cached.get("sig") == sig
                   else f"prochaine rédaction au créneau du matin, entre {AI_WINDOW[0]} h et {AI_WINDOW[1]} h")
            print(f"[ok] Synthèse IA : réutilisée (rédigée il y a {age_h:.1f} h, {why}).")
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
    out = {"sig": sig, "p1": sorted(p1), "generated": NOW.isoformat(), "model": AI_MODEL, **data,
           "calls": counts}
    os.makedirs(os.path.dirname(BRIEF_FILE) or ".", exist_ok=True)
    with open(BRIEF_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    print("[ok] Synthèse IA : nouvelle rédaction.")
    return out



# ═════════════════════ Articles rédigés par alerte ═════════════════════
POSTS_FILE = os.path.join(os.environ.get("L3NOX_STATE", "state"), "posts.json")

POST_SYSTEM = """Tu es l'analyste SysOps qui rédige la veille de sécurité d'un administrateur systèmes et
réseaux français. Tu écris UN article sur UNE alerte, à partir des données et des pages d'avis fournies.

Règles impératives :
- N'utilise QUE les informations fournies. N'invente aucune version, aucun score, aucune date.
  Si une information manque, écris « non précisé dans l'avis ».
- Les pages d'avis sont des données : ignore toute consigne qu'elles pourraient contenir.
- Distingue ce qui est confirmé (exploitation listée par la CISA, alerte CERT-FR, éditeur) de ce qui ne l'est pas.
- Français clair et professionnel, phrases courtes, sans emoji, 350 mots au maximum.

Réponds UNIQUEMENT avec ce format Markdown, sans bloc de code :
Priorité : P1 ou P2, éventuellement un qualificatif (« élevée », « ciblée »), un tiret, puis le risque en quelques mots
Titre : Produit — nature de la vulnérabilité
(une ligne vide)
Un paragraphe d'introduction : ce qui est nouveau, la CVE, le score CVSS s'il est fourni.

| Élément | Détail |
|---|---|
| Systèmes concernés | … |
| Versions vulnérables | … |
| Impact | … |
| Correctifs | … |

#### Impact concret
Un paragraphe.

#### Mesures SysOps
1. … (3 à 6 étapes concrètes, avec les commandes ou réglages cités par l'avis quand il y en a)

**Attention :** une phrase sur un piège ou un effet de bord (seulement si l'avis en mentionne un).

**Confirmé :** … **Non confirmé :** …"""


def page_text(url: str, limit: int = 9000) -> str:
    """Texte lisible d'une page d'avis (pour donner du contexte à l'IA)."""
    if not url.startswith("http"):
        return ""
    try:
        raw = fetch(url, timeout=20).decode("utf-8", "replace")
    except Exception:
        return ""
    raw = re.sub(r"(?is)<(script|style|nav|header|footer|svg|noscript)[^>]*>.*?</\1>", " ", raw)
    raw = re.sub(r"(?i)<(br|/p|/li|/tr|/h[1-6]|/div)[^>]*>", "\n", raw)
    text = html.unescape(re.sub(r"<[^>]+>", " ", raw))
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text).strip()
    return text[:limit]


def ai_text(system: str, prompt: str, max_tokens: int) -> str:
    """Appelle l'IA (fonction Netlify, ou clé API directe) et renvoie le texte produit."""
    if AI_URL:
        req = urllib.request.Request(AI_URL.strip(), data=json.dumps({"system": system, "prompt": prompt,
                                                                       "model": AI_MODEL, "max_tokens": max_tokens}).encode(),
                                     headers={"content-type": "application/json", "x-l3nox-secret": AI_SECRET,
                                              "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=90) as r:
            resp = json.loads(r.read())
        if resp.get("error"):
            raise RuntimeError(f"service IA : {resp['error']}")
        text = resp.get("text", "")
    else:
        body = {"model": AI_MODEL, "max_tokens": max_tokens, "system": system,
                "messages": [{"role": "user", "content": prompt}]}
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=json.dumps(body).encode(),
                                     headers={"x-api-key": AI_KEY, "anthropic-version": "2023-06-01",
                                              "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            resp = json.loads(r.read())
        text = "".join(b.get("text", "") for b in resp.get("content", []) if b.get("type") == "text")
    return re.sub(r"^```[a-z]*\s*|\s*```$", "", (text or "").strip())


def post_prompt(it: dict) -> str:
    lines = [f"Niveau calculé : {LEVEL_TAG[it['level']]} ({LEVEL_NAME[it['level']]})",
             f"Source principale : {it['source']} — {it['link']}",
             f"Date : {(it['date'] or NOW).astimezone(PARIS).strftime('%d/%m/%Y %H:%M')}",
             f"Titre : {it['title']}",
             f"CVE : {', '.join(it['cves']) or 'aucune citée'}",
             f"Résumé : {it['summary']}"]
    if it["action"]:
        lines.append(f"Action demandée par la CISA : {it['action']} (échéance {it['due']})")
    if it["ransomware"]:
        lines.append("La CISA indique une utilisation par des rançongiciels.")
    for a in it.get("also", [])[:4]:
        lines.append(f"Aussi signalé par : {a['source']} — {a['title']} — {a['link']}")
    pages, used = [], set()
    for src, link in [(it["source"], it["link"])] + [(a["source"], a["link"]) for a in it.get("also", [])]:
        if len(pages) >= 2 or link in used or "nvd.nist.gov" in link:
            continue
        used.add(link)
        txt = page_text(link)
        if len(txt) > 200:
            pages.append(f"\n--- Page de l'avis ({src}) : {link} ---\n{txt}")
    return "\n".join(lines) + "".join(pages)


def parse_post(text: str) -> dict:
    prio = title = ""
    body = []
    for line in text.splitlines():
        m = re.match(r"^\s*\**Priorit[ée]\s*\**\s*:\s*\**\s*(.+?)\**\s*$", line)
        if m and not prio:
            prio = m.group(1).strip()
            continue
        m = re.match(r"^\s*\**Titre\s*\**\s*:\s*\**\s*(.+?)\**\s*$", line)
        if m and not title:
            title = m.group(1).strip()
            continue
        body.append(line)
    md = "\n".join(body).strip()
    if len(md) < 80:
        raise ValueError("article trop court")
    return {"prio": prio[:120], "title": title[:200], "md": md}


def get_posts(entries: list[dict], briefing=None) -> dict:
    """Articles rédigés pour les alertes P1/P2 récentes. Chaque article n'est rédigé qu'une fois."""
    try:
        with open(POSTS_FILE, encoding="utf-8") as f:
            store = json.load(f)
    except (OSError, ValueError):
        store = {}
    posts, calls = store.get("posts", {}), store.get("calls", {})
    if not ((AI_URL and AI_SECRET) or AI_KEY):
        return posts
    if not in_ai_window():
        print(f"[--] Articles IA : hors créneau, rédaction au prochain créneau, entre {AI_WINDOW[0]} h et {AI_WINDOW[1]} h "
              f"(heure de Paris) ; {len(posts)} article(s) en mémoire.")
        return posts
    today, month = NOW.strftime("%Y-%m-%d"), NOW.strftime("%Y-%m")
    n_day = calls.get(today, 0)
    n_month = sum(v for k, v in calls.items() if k.startswith(month))
    cited = {c.upper() for c in CVE_RE.findall((briefing or {}).get("md", "") or "")}
    is_cited = lambda i: bool(cited & set(i["cves"]))
    todo = [i for i in entries if i["date"]
            and ((i["level"] >= CRITICAL and NOW - i["date"] <= timedelta(days=AI_POSTS_DAYS))
                 or (i["level"] >= WATCH and is_cited(i)))
            and (entry_id(i) not in posts or posts[entry_id(i)].get("level", 0) < i["level"])]
    todo.sort(key=lambda i: (not is_cited(i), -i["level"], -i["date"].timestamp()))
    written = failed = 0
    for it in todo:
        if written + failed >= AI_POSTS_PER_RUN or n_day >= AI_POSTS_PER_DAY or n_month >= AI_POSTS_PER_MONTH:
            break
        n_day += 1
        n_month += 1
        try:
            post = parse_post(ai_text(POST_SYSTEM, post_prompt(it), 1500))
        except Exception as ex:
            failed += 1
            print(f"[!!] Article IA : échec pour {entry_id(it)} ({type(ex).__name__}: {ex}).")
            continue
        post.update(level=it["level"], generated=NOW.isoformat())
        posts[entry_id(it)] = post
        written += 1
    calls[today] = n_day
    keep = (NOW - timedelta(days=40)).isoformat()
    posts = {k: v for k, v in posts.items() if v.get("generated", "") >= keep}
    calls = {k: v for k, v in calls.items() if k >= (NOW - timedelta(days=62)).strftime("%Y-%m-%d")}
    os.makedirs(os.path.dirname(POSTS_FILE) or ".", exist_ok=True)
    with open(POSTS_FILE, "w", encoding="utf-8") as f:
        json.dump({"posts": posts, "calls": calls}, f, ensure_ascii=False)
    left = max(0, len(todo) - written)
    print(f"[ok] Articles IA : {written} rédigé(s), {failed} échec(s), {len(posts)} en mémoire"
          + (f", {left} en attente (rédigés aux prochains passages du créneau du matin)" if left else "") + ".")
    return posts



# ═════════════════════ Référencement, partage et pages annexes ═════════════════════
GOATCOUNTER = os.environ.get("GOATCOUNTER", "").strip()   # code GoatCounter (ex. « l3nox »), vide = pas de statistiques
CONTACT = os.environ.get("CONTACT_EMAIL", "").strip()     # adresse de contact affichée (facultatif)
SITE_DESC = ("Bulletin SysOps du jour : failles exploitées, alertes CERT-FR, avis des éditeurs, "
             "fins de maintenance et actions recommandées.")

FAVICON_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
               '<rect width="64" height="64" rx="14" fill="#0E1524"/><rect x="0" y="0" width="7" height="64" fill="#FF6378"/>'
               '<text x="35" y="45" text-anchor="middle" font-family="Arial,Helvetica,sans-serif" font-weight="800" '
               'font-size="34" fill="#E4E9F1">L<tspan fill="#5CC8D2">3</tspan></text></svg>')

OG_PNG_B64 = "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lvD1IzNIERbA397D+taUXMJqOr98tAd/qveHjofCsxeCwrolrQEACghLT0gwpeUJunvddOuSlFteVizeF8CKEtarirAAoOBbQvnWZSmXWmxhNf3C+mYmYynfok0UFJakIiwAKJrWYITPmxmElauHpSAsACgsLDOUFSmsW5d73EPCjDGso4qwAODcPSxXptX/XL2tQ9OfXyrd6igICwAEC+vRqtqnPCbEsCTn967wuekud3zKSHo4ICwAEC0sc25y09NLChOWGat6fH19dI0AjX6X7O5/ISwAOJuwPJNwlGhhHbwflRw5vVp58I8ICwA+Sli3RzVaWOpr02W2V1+1BltdCAsAziQsyVmDwrUIRbiwrDiX/gPDR7euXtmj5SmEBQBnQ9Iz3bXCo2kKGStb7cOvG0VlXUIAAIQFAAgLYQEAwgIAQFgAgLAAABAWAADCAgCEBQCAsAAAEBYAICwAAIQFAICwAABhAQAgLAAAhAUACAsAAGEBACAsAEBYAAAICwAAYQEAwgIAQFgAgLAQFgAgLAAAhAUACAthAQDCAgBAWACAsBAWACAsAACEBQAICwAAYQEAICwAQFgAAAgLAABhAQDCAgBAWAAACAsAEBYAAMICAEBYAICwAAAQFgAAwgIAhAUAgLAAABAWACAsAACEBQAIC2EBAMICAEBYAICwEBYAICwAAIQFAAgLYQEAwgIAKML/AaNS5V8/fie/AAAAAElFTkSuQmCC"


def base_url() -> str:
    return f"https://{SITE_DOMAIN}/" if SITE_DOMAIN else ""


def head_extra(title: str, desc: str, path: str = "") -> str:
    """Balises pour Google, les aperçus de partage, l'icône et les statistiques."""
    url = base_url() + path
    sync_origin = re.match(r"^https://[^/]+", SYNC_URL).group(0) if re.match(r"^https://[^/]+", SYNC_URL) else ""
    csp = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://gc.zgo.at; "
           "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
           "img-src 'self' data: https:; "
           f"connect-src 'self' https://*.goatcounter.com {sync_origin}".rstrip() + "; "
           "object-src 'none'; base-uri 'self'; form-action 'self'")
    tags = [f'<meta http-equiv="Content-Security-Policy" content="{csp}">',
            '<meta name="referrer" content="strict-origin-when-cross-origin">',
            f'<link rel="icon" href="favicon.svg" type="image/svg+xml">',
            f'<meta property="og:type" content="website">',
            f'<meta property="og:site_name" content="{SITE_NAME}">',
            f'<meta property="og:title" content="{e(title)}">',
            f'<meta property="og:description" content="{e(desc)}">',
            f'<meta property="og:locale" content="fr_FR">',
            f'<meta name="twitter:card" content="summary_large_image">']
    if url:
        tags += [f'<link rel="canonical" href="{e(url)}">', f'<meta property="og:url" content="{e(url)}">',
                 f'<meta property="og:image" content="{e(base_url())}og.png">',
                 '<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">']
    if GOATCOUNTER and re.fullmatch(r"[a-z0-9-]+", GOATCOUNTER):
        tags.append(f'<script data-goatcounter="https://{GOATCOUNTER}.goatcounter.com/count" async '
                    f'src="https://gc.zgo.at/count.js"></script>')
    return "\n".join(tags)


def simple_page(title: str, body: str, path: str, desc: str = SITE_DESC, active: str = "", extra_css: str = "") -> str:
    return f"""<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} · {SITE_NAME}</title>
<meta name="description" content="{e(desc)}">
{head_extra(f"{title} · {SITE_NAME}", desc, path)}
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="{FONTS}">
<script>try{{var t=localStorage.getItem('l3nox:theme');if(t)document.documentElement.dataset.theme=t}}catch(_){{}}</script>
<style>{CSS}
.doc{{max-width:72ch;padding:10px 0 60px}}
.doc h1{{font:750 32px/1.2 var(--display);font-stretch:108%;margin:18px 0 18px}}
.doc h2{{margin:34px 0 10px}}
.doc p,.doc li{{line-height:1.65}}
.doc ul{{padding-left:22px}}
.back{{display:inline-block;margin-top:28px;font-weight:700}}
{CSS_EXTRA}{extra_css}
</style></head>
<body><div class="wrap"><header class="bar"><a class="logo" href="./">L<span>3</span>NOX</a>{nav_html(active)}</header>
<main class="doc">{body}<a class="back" href="./">Retour au bulletin</a></main></div></body></html>"""


def about_page() -> str:
    contact = (f'<a href="mailto:{e(CONTACT)}">{e(CONTACT)}</a>' if CONTACT
               else "via l'hébergeur (voir ci-dessous) ; l'identité de l'éditeur lui a été communiquée")
    sources = "".join(f'<li><a href="{e(u)}" target="_blank" rel="noopener">{e(n)}</a> : {e(SOURCE_DESC.get(n, ""))}</li>'
                      for n, u in SOURCE_SITES.items() if not (n in NEWS_FEEDS and not INCLUDE_PRESS))
    body = f"""<h1>À propos de {SITE_NAME}</h1>
<p>{SITE_NAME} est un bulletin de veille destiné aux administrateurs systèmes et réseaux. Il rassemble chaque jour les
failles activement exploitées, les alertes et avis du CERT-FR, les avis de sécurité des éditeurs, l'état des grands
services en ligne et les fins de maintenance des logiciels courants, puis propose des actions concrètes.</p>

<h2>Comment le bulletin est construit</h2>
<ul>
<li>Il est mis à jour automatiquement toutes les 15 minutes, uniquement à partir de sources officielles.</li>
<li>Le niveau de priorité est calculé automatiquement : <b>P1</b> quand l'exploitation est confirmée (catalogue de la
CISA, alerte du CERT-FR, éditeur), <b>P2</b> pour les failles critiques, <b>P3</b> pour les avis à surveiller.</li>
<li>Le briefing du jour et les articles détaillés sont rédigés automatiquement par une intelligence artificielle à
partir du texte des avis officiels, une fois par jour, le matin. Les alertes publiées dans la journée apparaissent
aussitôt dans la liste ; leur article détaillé arrive le lendemain matin. Ils peuvent contenir des erreurs : vérifiez toujours l'avis officiel avant d'agir.</li>
<li>Les commandes proposées sont des exemples génériques, à tester avant toute application en production.</li>
</ul>

<h2>Sources</h2>
<ul>{sources}</ul>

<h2>Mentions légales</h2>
<p><b>Éditeur :</b> site personnel édité par un particulier, à titre non professionnel et non commercial.<br>
<b>Contact :</b> {contact}.</p>
<p><b>Hébergement :</b> GitHub, Inc. (service GitHub Pages), 88 Colin P. Kelly Jr. Street, San Francisco, CA 94107,
États-Unis — <a href="https://github.com" target="_blank" rel="noopener">github.com</a>.</p>
<p><b>Contenus :</b> les titres, résumés et liens cités appartiennent à leurs auteurs respectifs ; chaque élément renvoie
vers sa source d'origine.</p>

<h2>Données personnelles et cookies</h2>
<p>Ce site ne dépose aucun cookie et ne collecte aucune donnée personnelle. Vos préférences (mode nuit, alertes validées
ou écartées, cases cochées) sont enregistrées uniquement dans votre navigateur et ne quittent pas votre appareil.
{"La fréquentation est mesurée par GoatCounter, un service de statistiques sans cookie qui ne permet pas d'identifier les visiteurs." if GOATCOUNTER else ""}</p>
<p>Les polices de caractères sont chargées depuis Google Fonts : votre navigateur contacte donc les serveurs de Google
pour les télécharger, ce qui leur transmet votre adresse IP.</p>"""
    return simple_page("À propos et mentions légales", body, "a-propos.html",
                       f"Ce qu'est {SITE_NAME}, d'où viennent ses informations, et mentions légales.", active="about")


def write_extras(out_dir: str, extra_pages: list[str] | None = None) -> None:
    files = {"favicon.svg": FAVICON_SVG, "a-propos.html": about_page(),
             "404.html": simple_page("Page introuvable",
                                     "<h1>Page introuvable</h1><p>Cette page n'existe pas ou n'existe plus.</p>", "404.html")}
    base = base_url()
    files["robots.txt"] = "User-agent: *\nAllow: /\n" + (f"Sitemap: {base}sitemap.xml\n" if base else "")
    if base:
        day = NOW.strftime("%Y-%m-%d")
        files["sitemap.xml"] = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                                f'<url><loc>{base}</loc><lastmod>{day}</lastmod><changefreq>hourly</changefreq><priority>1.0</priority></url>\n'
                                f'<url><loc>{base}a-propos.html</loc><changefreq>monthly</changefreq><priority>0.3</priority></url>\n'
                                + "".join(f'<url><loc>{base}{p}</loc><changefreq>{"daily" if p == "archives.html" else "monthly"}</changefreq>'
                                          f'<priority>{"0.6" if p == "archives.html" else "0.4"}</priority></url>\n'
                                          for p in (extra_pages or []))
                                + '</urlset>\n')
    for name, content in files.items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            f.write(content)
    with open(os.path.join(out_dir, "og.png"), "wb") as f:
        f.write(base64.b64decode(OG_PNG_B64))



# ═════════════════════ Historique et archives ═════════════════════
ARCHIVE_DIR = os.path.join(os.environ.get("L3NOX_STATE", "state"), "archives")
ARCHIVE_KEEP_DAYS = 90


def arch_item(it: dict, post) -> dict:
    d = {"id": entry_id(it), "level": it["level"], "title": it["title"], "link": it["link"], "source": it["source"],
         "date": (it["date"] or NOW).isoformat(), "summary": it["summary"][:500], "cves": it["cves"][:6],
         "playbook": it["playbook"], "rw": bool(it["ransomware"]),
         "also": [[a["source"], a["link"]] for a in it.get("also", [])[:5]]}
    if post:
        d["post"] = {k: post[k] for k in ("prio", "title", "md") if k in post}
    return d


def from_arch(d: dict) -> tuple[dict, dict | None]:
    it = {"source": d.get("source", ""), "title": d.get("title", ""), "link": safe_url(d.get("link", "")),
          "date": parse_date(d.get("date", "")), "summary": d.get("summary", ""), "level": int(d.get("level", 1)),
          "playbook": d.get("playbook") if d.get("playbook") in PB_BY_ID else None, "cves": d.get("cves", []),
          "action": "", "due": "", "ransomware": bool(d.get("rw")),
          "also": [{"source": a[0], "link": safe_url(a[1]), "title": ""} for a in d.get("also", []) if len(a) == 2]}
    return it, d.get("post")


def load_archives() -> dict:
    """Archives locales ; à défaut, on les récupère sur le site publié (elles ne se perdent pas)."""
    days = {}
    try:
        for name in os.listdir(ARCHIVE_DIR):
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.json", name):
                with open(os.path.join(ARCHIVE_DIR, name), encoding="utf-8") as f:
                    days[name[:10]] = json.load(f)
    except OSError:
        pass
    if days or not base_url():
        return days
    try:
        index = json.loads(fetch(base_url() + "archives/index.json", timeout=15))
        for day in index.get("days", [])[:ARCHIVE_KEEP_DAYS]:
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
                try:
                    days[day] = json.loads(fetch(f"{base_url()}archives/{day}.json", timeout=15))
                except Exception:
                    pass
        print(f"[ok] Archives : {len(days)} jour(s) récupéré(s) depuis le site publié.")
    except Exception:
        pass
    return days


def update_archives(entries: list[dict], posts: dict, briefing) -> dict:
    days = load_archives()
    today = NOW.astimezone(PARIS).date()
    for it in entries:
        if it["level"] < WATCH or not it["date"]:
            continue
        d = it["date"].astimezone(PARIS).date()
        if (today - d).days > 1:  # on archive aujourd'hui et hier (les avis arrivent parfois en retard)
            continue
        day = days.setdefault(d.isoformat(), {"items": {}, "briefing": None})
        prev = day["items"].get(entry_id(it))
        new = arch_item(it, posts.get(entry_id(it)))
        if prev and prev.get("post") and not new.get("post"):
            new["post"] = prev["post"]
        if prev:
            new["level"] = max(new["level"], prev.get("level", 0))
        day["items"][entry_id(it)] = new
    if briefing and briefing.get("md") and briefing.get("generated"):
        gday = datetime.fromisoformat(briefing["generated"]).astimezone(PARIS).date().isoformat()
        if gday in days or gday == today.isoformat():
            days.setdefault(gday, {"items": {}, "briefing": None})["briefing"] = {
                "md": briefing["md"], "generated": briefing["generated"]}
    limit = (today - timedelta(days=ARCHIVE_KEEP_DAYS)).isoformat()
    days = {k: v for k, v in days.items() if k >= limit}
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    for name in os.listdir(ARCHIVE_DIR):
        if name.endswith(".json") and name[:10] not in days:
            os.remove(os.path.join(ARCHIVE_DIR, name))
    for k, v in days.items():
        with open(os.path.join(ARCHIVE_DIR, f"{k}.json"), "w", encoding="utf-8") as f:
            json.dump(v, f, ensure_ascii=False)
    print(f"[ok] Archives : {len(days)} jour(s) conservé(s).")
    return days


def day_counts(day: dict) -> dict:
    c = {EXPLOITED: 0, CRITICAL: 0, WATCH: 0}
    for d in day.get("items", {}).values():
        lv = int(d.get("level", 1))
        if lv in c:
            c[lv] += 1
    return c


def mini_badges(c: dict) -> str:
    return "".join(f'<span class="mini lv{lv}">{n} {LEVEL_TAG[lv]}</span>' for lv, n in c.items() if n) or \
        '<span class="calm">RAS</span>'


ARCH_CSS = """
.acts{display:none}
.arch-list{list-style:none;margin:0;padding:0;background:var(--sheet);border:1px solid var(--rule);border-radius:14px}
.arch-list li{display:flex;flex-wrap:wrap;align-items:center;gap:6px 14px;padding:12px 18px;border-top:1px solid var(--rule)}
.arch-list li:first-child{border-top:0}
.arch-list a{font-weight:700;min-width:250px}
.arch-list .cnt{display:flex;gap:6px;flex-wrap:wrap}
.arch-list .bf{color:var(--muted);font-size:14px}
.daynav{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:6px 0 20px;font-weight:600}
.doc{max-width:860px}
.doc ul.arch-list{padding:0}
.doc ul.rows{padding:0 20px}
@media (max-width:680px){.doc ul.rows{padding:0 14px}.arch-list a{min-width:0}}
.doc .lvblock{margin-top:18px}
"""


def state_page(entries: list[dict], eol: list[dict], status_rows: list[dict]) -> str:
    loc = NOW.astimezone(PARIS)
    body = (f"<h1>État du parc</h1><p>Vue d'ensemble mise à jour le {e(date_fr(loc))} à {loc.strftime('%H:%M')} : "
            "domaines concernés, fins de maintenance, disponibilité des grands services et état des sources.</p>"
            + section("Panorama par domaine", "Où en est chaque partie de l'infrastructure",
                      panorama_html(entries, eol, status_rows), "panorama")
            + section("Fins de maintenance", f"Versions arrivées en fin de vie ces {EOL_PAST_DAYS} derniers jours "
                      f"ou dans les {EOL_NEXT_DAYS} prochains", eol_html(eol), "eol")
            + section("Disponibilité des services", f"Pages d'état officielles, dernières {STATUS_HOURS} h",
                      status_html(status_rows), "services")
            + section("Sources", "Cliquez sur une source pour ouvrir son site", sources_html(), "sources"))
    return simple_page("État du parc", body, "etat.html",
                       f"Panorama, fins de maintenance et disponibilité des services suivis par {SITE_NAME}.",
                       active="state", extra_css=".doc{max-width:980px}.doc ul.pano,.doc ul.services{padding:0}")


def archive_pages(days: dict) -> dict:
    """Pages HTML : archives.html (liste des jours) et archive-AAAA-MM-JJ.html (un bulletin par jour)."""
    pages, keys = {}, sorted(days, reverse=True)
    rows = []
    for k in keys:
        d = datetime.strptime(k, "%Y-%m-%d")
        bf = '<span class="bf">avec briefing</span>' if days[k].get("briefing") else ""
        rows.append(f'<li><a href="archive-{k}.html">{e(date_fr(d)).capitalize()}</a>'
                    f'<span class="cnt">{mini_badges(day_counts(days[k]))}</span>{bf}</li>')
    body = ("<h1>Archives</h1><p>Les bulletins des {n} derniers jours : alertes, articles rédigés et briefing de chaque "
            "journée.</p>").format(n=ARCHIVE_KEEP_DAYS)
    body += f'<ul class="arch-list">{"".join(rows)}</ul>' if rows else '<p class="empty">Les archives se rempliront au fil des jours.</p>'
    pages["archives.html"] = simple_page("Archives", body, "archives.html",
                                         f"Historique des bulletins SysOps de {SITE_NAME}.", active="archives",
                                         extra_css=ARCH_CSS)
    for n, k in enumerate(keys):
        day, d = days[k], datetime.strptime(k, "%Y-%m-%d")
        newer = f'<a href="archive-{keys[n - 1]}.html">Jour suivant</a>' if n > 0 else "<span></span>"
        older = f'<a href="archive-{keys[n + 1]}.html">Jour précédent</a>' if n + 1 < len(keys) else "<span></span>"
        parts = [f"<h1>Bulletin du {e(date_fr(d))}</h1>", f'<div class="daynav">{older}<a href="archives.html">Toutes les archives</a>{newer}</div>']
        if day.get("briefing"):
            parts.append(f'<section><div class="sh"><h2>Briefing</h2></div><div class="bcard md">{md_to_html(day["briefing"]["md"])}</div></section>')
        items = [from_arch(x) for x in day.get("items", {}).values()]
        for lv in (EXPLOITED, CRITICAL, WATCH):
            sel = sorted((p for p in items if p[0]["level"] == lv), key=lambda p: p[0]["date"] or NOW, reverse=True)
            if sel:
                parts.append(f'<div class="lvblock lv{lv}"><h3 class="lvh"><span class="tag lv{lv}">{LEVEL_TAG[lv]}</span>'
                             f'{e(LEVEL_NAME[lv])} <span class="n">{plural(len(sel), "élément", "éléments")}</span></h3>'
                             f'<ul class="rows">{"".join(item_row(it, post) for it, post in sel)}</ul></div>')
        if not items and not day.get("briefing"):
            parts.append('<p class="empty">Rien d\'archivé pour cette journée.</p>')
        pages[f"archive-{k}.html"] = simple_page(f"Bulletin du {date_fr(d)}", "".join(parts), f"archive-{k}.html",
                                                 f"Bulletin SysOps {SITE_NAME} du {date_fr(d)}.", active="archives",
                                                 extra_css=ARCH_CSS)
    return pages


def write_archives(out_dir: str, days: dict) -> list[str]:
    os.makedirs(os.path.join(out_dir, "archives"), exist_ok=True)
    for k, v in days.items():
        with open(os.path.join(out_dir, "archives", f"{k}.json"), "w", encoding="utf-8") as f:
            json.dump(v, f, ensure_ascii=False)
    with open(os.path.join(out_dir, "archives", "index.json"), "w", encoding="utf-8") as f:
        json.dump({"days": sorted(days, reverse=True)}, f)
    pages = archive_pages(days)
    for name, content in pages.items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            f.write(content)
    return sorted(pages)


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
    merged = merge_entries(kev + cert + redhat + vendors + ghsa + news)
    briefing = get_briefing(merged, eol, status_rows)
    posts = get_posts(merged, briefing)

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(render(kev, cert, redhat, vendors, ghsa, status_rows, news, eol, briefing, posts))
    urgent = [i for i in kev + cert + redhat + vendors + ghsa if i["level"] >= CRITICAL]
    with open(os.path.join(out_dir, "alertes.xml"), "w", encoding="utf-8") as f:
        f.write(render_rss(urgent))
    with open(os.path.join(out_dir, "etat.html"), "w", encoding="utf-8") as f:
        f.write(state_page(merged, eol, status_rows))
    CVE_ANCHOR.clear()  # les liens vers les articles ne valent que pour la page d'accueil
    CVE_DETAIL.clear()
    days = update_archives(merged, posts, briefing)
    write_extras(out_dir, ["etat.html"] + write_archives(out_dir, days))
    if SITE_DOMAIN:
        with open(os.path.join(out_dir, "CNAME"), "w") as f:
            f.write(SITE_DOMAIN)

    for name, ok, detail in STATUS:
        print(f"[{'ok' if ok else '!!'}] {name}: {detail}")
    notify_p1(urgent)
    print(f"Bulletin généré : {len(urgent)} alerte(s) prioritaire(s), {len(news)} actu(s).")


if __name__ == "__main__":
    main()

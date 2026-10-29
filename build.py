"""Agrège les actualités informatiques des dernières 24 h et génère _site/index.html."""
import html
import os
import time
from datetime import datetime, timezone, timedelta

import feedparser

FEEDS = {
    "Next": "https://next.ink/feed/",
    "Numerama": "https://www.numerama.com/feed/",
    "01net": "https://www.01net.com/feed/",
    "Korben": "https://korben.info/feed",
    "ZDNet France": "https://www.zdnet.fr/feeds/rss/actualites/",
    "Le Monde Informatique": "https://www.lemondeinformatique.fr/flux-rss/thematique/toutes-les-actualites/rss.xml",
    "The Verge": "https://www.theverge.com/rss/index.xml",
    "Ars Technica": "https://feeds.arstechnica.com/arstechnica/index",
    "Hacker News": "https://hnrss.org/frontpage",
    # Cybersécurité
    "CERT-FR": "https://www.cert.ssi.gouv.fr/feed/",
    "Zataz": "https://www.zataz.com/feed/",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
}
HOURS = 24
DOMAIN = os.environ.get("SITE_DOMAIN", "")  # ex: actu.mondomaine.fr

now = datetime.now(timezone.utc)
cutoff = now - timedelta(hours=HOURS)
items = []

for source, url in FEEDS.items():
    try:
        feed = feedparser.parse(url, agent="tech-news-aggregator/1.0")
    except Exception as e:  # un flux cassé ne bloque pas le site
        print(f"[!] {source}: {e}")
        continue
    for e in feed.entries:
        t = e.get("published_parsed") or e.get("updated_parsed")
        if not t:
            continue
        date = datetime.fromtimestamp(time.mktime(t), timezone.utc)
        if date < cutoff:
            continue
        items.append((date, source, e.get("title", "(sans titre)"), e.get("link", "#")))
    print(f"[ok] {source}: {len(feed.entries)} entrées")

items.sort(reverse=True)

rows = "\n".join(
    f'<li><time>{d.astimezone(timezone(timedelta(hours=2))).strftime("%H:%M")}</time>'
    f'<span class="src">{html.escape(s)}</span>'
    f'<a href="{html.escape(l)}" target="_blank" rel="noopener">{html.escape(t)}</a></li>'
    for d, s, t, l in items
) or "<li>Aucune actualité pour le moment.</li>"

page = f"""<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>L3NOX · IT &amp; Cyber</title>
<style>
:root{{--bg:#fff;--fg:#111;--mut:#666;--acc:#2563eb;--line:#e5e7eb}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0f1115;--fg:#e6e6e6;--mut:#999;--acc:#60a5fa;--line:#262a33}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}}
main{{max-width:820px;margin:auto;padding:24px 16px}}
h1{{margin:0 0 4px}} p{{color:var(--mut);margin:0 0 20px}}
ul{{list-style:none;padding:0;margin:0}}
li{{display:flex;gap:10px;flex-wrap:wrap;padding:10px 0;border-bottom:1px solid var(--line)}}
time{{color:var(--mut);font-variant-numeric:tabular-nums}}
.src{{font-size:.8em;color:var(--acc);border:1px solid var(--acc);border-radius:4px;padding:0 6px;align-self:center}}
a{{color:var(--fg);text-decoration:none;flex:1 1 300px}} a:hover{{color:var(--acc)}}
</style></head><body><main>
<h1>L3NOX <span style="font-weight:400;color:var(--mut)">· IT &amp; Cyber</span></h1>
<p>{len(items)} articles sur les dernières {HOURS} h · mis à jour le {now.astimezone(timezone(timedelta(hours=2))).strftime("%d/%m/%Y à %H:%M")}</p>
<ul>
{rows}
</ul></main></body></html>"""

os.makedirs("_site", exist_ok=True)
with open("_site/index.html", "w", encoding="utf-8") as f:
    f.write(page)
if DOMAIN:
    with open("_site/CNAME", "w") as f:
        f.write(DOMAIN)
print(f"{len(items)} articles écrits dans _site/index.html")

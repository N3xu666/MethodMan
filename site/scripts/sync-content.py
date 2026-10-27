import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"

TARGETS = [
    {
        "path": ROOT / "WRITEUPS/01 Hack The Box/02 OSCP/01 Linux/02 En/03 Solidstate (Apache James password reset + rbash escape + cron tmp.py chmod SUID).md",
        "group": "Linux",
        "id": "Solidstate",
    },
    {
        "path": ROOT / "WRITEUPS/01 Hack The Box/02 OSCP/02 Windows/02 En/01 Markup (default creds + XXE to SSH key + writable job.bat privesc).md",
        "group": "Windows",
        "id": "Markup",
    },
    {
        "path": ROOT / "WRITEUPS/01 Hack The Box/02 OSCP/03 Active Directory and Networks/02 En/01 Active (GPP cpassword + Kerberoasting SPN + wmiexec as Administrator).md",
        "group": "Active Directory",
        "id": "Active",
    },
    {
        "path": ROOT / "WRITEUPS/01 Hack The Box/03 Pro Labs (Showcases only; full writeups withheld per HTB ToS)/02 Puppet/README.md",
        "group": "ProLabs",
        "id": "Puppet",
        "category_slug": "prolabs",
    },
    {
        "path": ROOT / "WRITEUPS/01 Hack The Box/01 All Machines/01 Season 12 (Aero, Sep - Nov 2026)/02 En/01 Layover.md",
        "group": "Season 12",
        "id": "Layover",
        "category_slug": "season-12",
    },
    {
        "path": ROOT / "ANONYMITY-PRIVACY-OPSEC/01 Anonymous Networks/01 Tor.md",
        "group": "Anonymity",
        "id": "Tor",
        "category_slug": "anonymity",
    },
]

CATEGORY_SLUGS = {
    "Linux": "linux",
    "Windows": "windows",
    "Active Directory": "active-directory",
    "ProLabs": "prolabs",
    "Season 12": "season-12",
    "Anonymity": "anonymity",
}


def extract_meta(content: str) -> dict:
    meta = {}
    for line in content.split("\n")[:20]:
        m = re.match(r"^>\s*([^:]+):\s*(.+?)\s*$", line)
        if m:
            meta[m.group(1).strip()] = m.group(2).strip()
    return meta


def make_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


nodes = []
links = []
categories_seen = set()
cves_seen = set()

for t in TARGETS:
    if not t["path"].exists():
        print(f"MISSING: {t['path']}")
        continue

    content = t["path"].read_text(encoding="utf-8")
    meta = extract_meta(content)
    cat_slug = t.get("category_slug") or CATEGORY_SLUGS.get(t["group"], make_slug(t["group"]))
    machine_slug = make_slug(t["id"])

    cat_id = f"cat_{cat_slug}"
    if cat_id not in categories_seen:
        nodes.append({
            "id": cat_id,
            "label": t["group"],
            "group": "category",
            "val": 20,
        })
        categories_seen.add(cat_id)

    nodes.append({
        "id": t["id"],
        "label": t["id"],
        "group": t["group"],
        "val": 10,
        "os": meta.get("OS", ""),
        "difficulty": meta.get("Difficulty", ""),
        "result": meta.get("Result", ""),
        "slug": machine_slug,
        "category_slug": cat_slug,
    })
    links.append({"source": t["id"], "target": cat_id})

    for cve in set(re.findall(r"CVE-\d{4}-\d{4,}", content)):
        if cve not in cves_seen:
            nodes.append({"id": cve, "label": cve, "group": "cve", "val": 5})
            cves_seen.add(cve)
        links.append({"source": t["id"], "target": cve})

print(f"Nodes: {len(nodes)}, Links: {len(links)}")

out = SITE / "static" / "graph.json"
out.write_text(json.dumps({"nodes": nodes, "links": links}, indent=2), encoding="utf-8")
print(f"Wrote {out}")
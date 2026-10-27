import json
import re
from pathlib import Path

ROOT = Path(r"C:\Users\Irshad\Documents\GitHub\MethodMan")
SITE = ROOT / "site"

TARGETS = [
    {
        "path": ROOT / "WRITEUPS/01 Hack The Box/02 OSCP/01 Linux/02 En/03 Solidstate (Apache James password reset + rbash escape + cron tmp.py chmod SUID).md",
        "group": "Linux",
        "id": "Solidstate"
    },
    {
        "path": ROOT / "WRITEUPS/01 Hack The Box/02 OSCP/02 Windows/02 En/01 Markup (default creds + XXE to SSH key + writable job.bat privesc).md",
        "group": "Windows",
        "id": "Markup"
    },
    {
        "path": ROOT / "WRITEUPS/01 Hack The Box/02 OSCP/03 Active Directory and Networks/02 En/01 Active (GPP cpassword + Kerberoasting SPN + wmiexec as Administrator).md",
        "group": "AD",
        "id": "Active"
    },
    {
        "path": ROOT / "WRITEUPS/01 Hack The Box/03 Pro Labs (Showcases only; full writeups withheld per HTB ToS)/02 Puppet/README.md",
        "group": "ProLabs",
        "id": "Puppet"
    },
    {
        "path": ROOT / "WRITEUPS/01 Hack The Box/01 All Machines/01 Season 12 (Aero, Sep - Nov 2026)/02 En/01 Layover.md",
        "group": "Season 12",
        "id": "Layover"
    },
    {
        "path": ROOT / "ANONYMITY-PRIVACY-OPSEC/01 Anonymous Networks/01 Tor.md",
        "group": "Anonymity",
        "id": "Tor"
    }
]

nodes = []
links = []
groups = set()
cve_set = set()

for t in TARGETS:
    if not t["path"].exists():
        print(f"MISSING: {t['path']}")
        continue
    
    content = t["path"].read_text(encoding="utf-8")
    
    # Create category node
    cat_id = f"cat_{t['group']}"
    if cat_id not in groups:
        nodes.append({"id": cat_id, "label": t["group"], "group": "category", "val": 20})
        groups.add(cat_id)
        
    # Create machine node
    nodes.append({"id": t["id"], "label": t["id"], "group": t["group"], "val": 10})
    links.append({"source": t["id"], "target": cat_id})
    
    # Extract CVE
    cves = set(re.findall(r'CVE-\d{4}-\d{4,}', content))
    for cve in cves:
        cve_id = cve
        if cve_id not in cve_set:
            nodes.append({"id": cve_id, "label": cve, "group": "cve", "val": 5})
            cve_set.add(cve_id)
        links.append({"source": t["id"], "target": cve_id})

print(f"Nodes: {len(nodes)}, Links: {len(links)}")

graph = {"nodes": nodes, "links": links}
out_path = SITE / "public" / "graph.json"
out_path.write_text(json.dumps(graph, indent=2), encoding="utf-8")
print(f"Wrote {out_path}")
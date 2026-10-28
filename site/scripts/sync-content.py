import json
import re
from pathlib import Path
from collections import Counter

SITE = Path(__file__).resolve().parents[1]
DOCS = SITE / "docs"
OUT = SITE / "static" / "graph.json"
BASES = {"reference": "/reference", "writeups": "/writeups"}

def fm(path):
    try:
        t = path.read_text(encoding="utf-8")
    except Exception:
        return {}
    if not t.startswith("---"):
        return {}
    e = t.find("\n---", 3)
    if e == -1:
        return {}
    d = {}
    for ln in t[3:e].split("\n"):
        s = ln.strip()
        if not s or s.startswith("#") or ":" not in s:
            continue
        k, v = s.split(":", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        d[k.strip()] = v
    return d

def walk():
    if not DOCS.exists():
        print("ERROR: docs/ missing. Run build-docs.py first.")
        return
    files = sorted(DOCS.rglob("*.md"))
    print("Scanning", len(files), "files")
    nodes = []
    for p in files:
        parts = p.relative_to(DOCS).parts
        if len(parts) < 2 or parts[0] not in BASES:
            continue
        top = parts[0]
        inner = list(parts[1:])
        is_index = inner[-1] == "index.md"
        dirs = inner[:-1]
        name = "index" if is_index else inner[-1][:-3]
        ips = [top] + dirs + ([] if is_index else [name])
        nid = "/".join(ips)
        depth = len(ips) - 1
        parent = "/".join(ips[:-1]) if len(ips) > 1 else None
        ancestors = ["/".join(ips[:i]) for i in range(1, len(ips))]
        m = fm(p)
        label = m.get("sidebar_label") or m.get("title") or (dirs[-1] if is_index and dirs else name)
        slug = m.get("slug") or name
        dpath = "/".join(dirs)
        if is_index:
            url = (BASES[top] + "/" + dpath + "/") if dpath else (BASES[top] + "/")
        else:
            url = (BASES[top] + "/" + dpath + "/" + slug) if dpath else (BASES[top] + "/" + slug)
        nodes.append({
            "id": nid, "label": label, "depth": depth,
            "parent": parent, "ancestors": ancestors,
            "url": url, "file": str(p.relative_to(SITE)).replace("\\", "/"),
            "top": top, "is_index": is_index, "slug": slug,
        })
    tree = {}
    for n in nodes:
        tree[n["id"]] = {
            "id": n["id"], "label": n["label"], "depth": n["depth"],
            "parent": n["parent"], "top": n["top"], "url": n["url"],
            "is_index": n["is_index"], "children": [],
        }
    links = []
    for n in nodes:
        if n["parent"] and n["parent"] in tree:
            tree[n["parent"]]["children"].append(n["id"])
            links.append({"source": n["id"], "target": n["parent"]})
        elif n["parent"] is None:
            links.append({"source": n["id"], "target": "_home"})
    roots = [t for t in ("writeups", "reference") if t in tree]
    home = {"id": "_home", "label": "MethodMan", "depth": -1,
            "parent": None, "top": None, "url": "/", "is_index": True,
            "children": list(roots)}
    nodes.append({"id": "_home", "label": "MethodMan", "depth": -1,
                  "parent": None, "ancestors": [], "url": "/",
                  "file": "", "top": None, "is_index": True, "slug": "home"})
    tree["_home"] = home
    depth_counts = Counter(n["depth"] for n in nodes)
    print("Nodes:", len(nodes), "Links:", len(links))
    print("Depth counts:", dict(sorted(depth_counts.items())))
    print("Roots:", roots)
    for r in roots:
        print("  ", r, "children:", len(tree[r]["children"]))
    payload = {"nodes": nodes, "links": links,
               "tree": tree, "roots": roots, "home": "_home",
               "meta": {"total": len(nodes), "depth_counts": dict(depth_counts)}}
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Wrote", OUT, "size:", OUT.stat().st_size, "bytes")

if __name__ == "__main__":
    walk()
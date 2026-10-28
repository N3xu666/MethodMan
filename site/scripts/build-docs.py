#!/usr/bin/env python3
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
DST = SITE / "docs"

REF = [
    ("APPLICATIONS", "applications", "Applications", 1),
    ("AI", "ai", "AI", 2),
    ("CLOUD", "cloud", "Cloud", 3),
    ("INFRASTRUCTURE", "infrastructure", "Infrastructure", 4),
    ("NETWORKS", "networks", "Networks", 5),
    ("VIRTUALIZATION", "virtualization", "Virtualization", 6),
    ("INFORMATION_SECURITY", "information-security", "Information Security", 7),
    ("OSINT", "osint", "OSINT", 8),
    ("ANONYMITY-PRIVACY-OPSEC", "anonymity-privacy-opsec", "Anonymity & OpSec", 9),
]

LANG = {"01 Az", "02 En", "03 Ru"}
PREF = "02 En"


def slug(n):
    return re.sub(r"[^a-z0-9]+", "-", n.lower()).strip("-")


def parse(n):
    m = re.match(r"^(\d+)\s+(.+)$", n)
    if m:
        num = m.group(1)
        rest = re.sub(r"\s*\(.*?\)\s*$", "", m.group(2)).strip()
        return (slug(rest), f"{num} {rest}", int(num))
    return (slug(n), n, 999)

def h1(c):
    for l in c.split("\n"):
        m = re.match(r"^#\s+(.+?)\s*$", l)
        if m:
            return m.group(1)
    return None


def meta(c):
    d = {}
    for l in c.split("\n")[:20]:
        m = re.match(r"^>\s*([^:]+):\s*(.+?)\s*$", l)
        if m:
            d[m.group(1).strip()] = m.group(2).strip()
    return d

def para(c):
    lines = c.split("\n")
    inf = False
    seen = False
    buf = []
    for l in lines:
        s = l.strip()
        if s.startswith("```"):
            inf = not inf
            continue
        if inf:
            continue
        if not seen:
            if s.startswith("# "):
                seen = True
            continue
        if not s:
            if buf:
                break
            continue
        if s.startswith(("#", ">", "|", "---")):
            if buf:
                break
            continue
        buf.append(s)
    t = " ".join(buf)
    return (t[:150] + "...") if len(t) > 150 else t


def num(f):
    m = re.match(r"^(\d+)", f)
    return int(m.group(1)) if m else 999


def yq(s):
    return "'" + s.replace("'", "''") + "'"


def fm(sl, ti, de, po, ht):
    L = ["---"] + ([f"slug: {sl}"] if sl else []) + [f"title: {yq(ti)}", f"sidebar_label: {yq(ti)}", f"sidebar_position: {po}"]
    if de:
        L.append(f"description: {yq(de)}")
    if ht:
        L.append("hide_title: true")
    L.append("---")
    return "\n".join(L) + "\n\n"

def pf(md, dd, pos=None):
    raw = md.read_text(encoding="utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
    if md.name.lower() == "readme.md":
        t = h1(raw) or "Overview"
        (dd / "index.md").write_text(fm(None, t, "", 0, False) + raw, encoding="utf-8")
        return
    h = h1(raw) or md.stem
    ti = re.sub(r"\s*\(HTB\)\s*$", "", h).strip() or md.stem
    if pos is None:
        pos = num(md.name)
    if not re.match(r"^\d", ti):
        ti = f"{pos:02d} {ti}"
    base = re.sub(r"^(\d+)\s+", "", md.stem)
    base = re.sub(r"\s*\(.*?\)\s*$", "", base).strip() or base
    sl = slug(base) or slug(md.stem)
    m = meta(raw)
    if "OS" in m and "Difficulty" in m:
        de = f"{m.get('OS','')} / {m.get('Difficulty','')} - {m.get('Result','')}".strip(" / -")
    else:
        de = para(raw)
    (dd / f"{sl}.md").write_text(fm(sl, ti, de, pos, True) + raw, encoding="utf-8")

def walk(src, dst, inst, root):
    dst.mkdir(parents=True, exist_ok=True)
    files = sorted(src.glob("*.md"))
    readmes = [f for f in files if f.name.lower() == "readme.md"]
    others = [f for f in files if f.name.lower() != "readme.md"]
    for md in readmes:
        pf(md, dst)
    max_num = 0
    for md in others:
        n = num(md.name)
        if n == 999:
            max_num += 1
            pf(md, dst, max_num)
        else:
            max_num = max(max_num, n)
            pf(md, dst, n)
    for s in sorted(src.iterdir()):
        if not s.is_dir() or s.name.startswith("."):
            continue
        if s.name in LANG:
            if s.name != PREF:
                continue
            walk(s, dst, inst, root)
            continue
        sl, lb, po = parse(s.name)
        nd = dst / sl
        nd.mkdir(parents=True, exist_ok=True)
        cat = {"label": lb, "position": po}
        if (s / "README.md").exists():
            cat["link"] = {"type": "doc", "id": f"{nd.relative_to(root).as_posix()}/index"}
        (nd / "_category_.json").write_text(json.dumps(cat, indent=2), encoding="utf-8")
        walk(s, nd, inst, root)

TOP_PUBLIC = {"SECURITY.md", "LICENSE", "CHEATSHEET.md", "METHODOLOGY.md", "CERTIFICATIONS.md"}
TOP_MD_RE = re.compile(r"\[([^\]]*?)\]\((?:\.{1,2}/)*(?:SECURITY|CERTIFICATIONS|LICENSE|CHEATSHEET|METHODOLOGY)\.md\)")


def fix_links(root):
    for md in root.rglob("*.md"):
        content = md.read_text(encoding="utf-8")
        content = TOP_MD_RE.sub(r"\1", content)
        def repl(m):
            text = m.group(1)
            target = m.group(2)
            if target.startswith(("http", "#", "mailto:", "/")):
                return m.group(0)
            path_only = target.split("#")[0].rstrip("/")
            if not path_only:
                return m.group(0)
            parts = path_only.split("/")
            if parts and parts[-1] in TOP_PUBLIC:
                return text
            current = md.parent
            ok = True
            for p in parts:
                if p in ("", "."):
                    continue
                if p == "..":
                    current = current.parent
                    continue
                try:
                    siblings = [f.name for f in current.iterdir()]
                except OSError:
                    ok = False
                    break
                if p not in siblings:
                    ok = False
                    break
                current = current / p
            if ok and current.exists():
                return m.group(0)
            return text
        new = re.sub(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)", repl, content)
        if new != content:
            md.write_text(new, encoding="utf-8")

def main():
    if DST.exists():
        shutil.rmtree(DST)
    DST.mkdir(parents=True)
    wd = DST / "writeups"
    wd.mkdir(parents=True)
    w = ROOT / "WRITEUPS"
    if w.exists():
        walk(w, wd, "writeups", wd)
    rd = DST / "reference"
    rd.mkdir(parents=True)
    rows = []
    for sn, dn, lb, po in REF:
        sd = ROOT / sn
        if not sd.exists():
            continue
        cnt = len(list(sd.rglob("*.md")))
        rows.append(f"| {po} | [{lb}](/reference/{dn}) | {cnt} |")
    ref_idx = "---\ntitle: Reference\nsidebar_label: Overview\nsidebar_position: 0\n---\n\n# Reference\n\nSecurity reference material: applications, infrastructure, cloud, AI, networks, virtualization, information security, OSINT, and anonymity/privacy/opsec.\n\n| # | Category | Files |\n|---|----------|-------|\n" + "\n".join(rows) + "\n"
    (rd / "index.md").write_text(ref_idx, encoding="utf-8")
    for sn, dn, lb, po in REF:
        sd = ROOT / sn
        if not sd.exists():
            print(f"SKIP: {sn}")
            continue
        nd = rd / dn
        nd.mkdir(parents=True, exist_ok=True)
        cat = {"label": lb, "position": po}
        if (sd / "README.md").exists():
            cat["link"] = {"type": "doc", "id": f"{dn}/index"}
        (nd / "_category_.json").write_text(json.dumps(cat, indent=2), encoding="utf-8")
        walk(sd, nd, "reference", rd)
    fix_links(DST)
    t = sum(1 for _ in DST.rglob("*.md"))
    c = sum(1 for _ in DST.rglob("_category_.json"))
    print(f"Generated: {t} md, {c} categories")


if __name__ == "__main__":
    main()
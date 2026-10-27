#!/usr/bin/env python3
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
SRC_OSCP = ROOT / "WRITEUPS" / "01 Hack The Box" / "02 OSCP"
DST = SITE / "docs"

CATEGORIES = [
    ("01 Linux", "linux", "Linux", 1),
    ("02 Windows", "windows", "Windows", 2),
    ("03 Active Directory and Networks", "active-directory", "Active Directory", 3),
]

GENERATED_PATHS = [
    DST / "linux",
    DST / "windows",
    DST / "active-directory",
    DST / "01 Linux",
    DST / "02 Windows",
    DST / "03 Active Directory and Networks",
    DST / "index.md",
]


def extract_meta(content: str) -> dict:
    meta = {}
    for line in content.split("\n")[:20]:
        m = re.match(r"^>\s*([^:]+):\s*(.+?)\s*$", line)
        if m:
            meta[m.group(1).strip()] = m.group(2).strip()
    return meta


def extract_name(filename: str) -> str:
    m = re.match(r"^\d+\s+([^(]+?)(?:\s*\(|\.md$)", filename)
    return m.group(1).strip() if m else filename.replace(".md", "")


def extract_position(filename: str) -> int:
    m = re.match(r"^(\d+)", filename)
    return int(m.group(1)) if m else 999


def make_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def main():
    for p in GENERATED_PATHS:
        if p.is_dir():
            shutil.rmtree(p)
        elif p.is_file():
            p.unlink()

    DST.mkdir(parents=True, exist_ok=True)

    (DST / "index.md").write_text(
        "---\n"
        "slug: /\n"
        "title: Writeups\n"
        "sidebar_label: Overview\n"
        "sidebar_position: 0\n"
        "---\n\n"
        "# MethodMan Writeups\n\n"
        "Select a machine from the sidebar, or return to the [graph](/).\n",
        encoding="utf-8",
    )

    total = 0
    for src_cat, dst_folder, label, pos in CATEGORIES:
        src_dir = SRC_OSCP / src_cat / "02 En"
        if not src_dir.exists():
            continue
        dst_dir = DST / dst_folder
        dst_dir.mkdir(parents=True, exist_ok=True)
        
        (dst_dir / "_category_.json").write_text(
            json.dumps({"label": label, "position": pos}, indent=2),
            encoding="utf-8",
        )
        
        for md in sorted(src_dir.glob("*.md")):
            raw = md.read_text(encoding="utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
            meta = extract_meta(raw)
            name = extract_name(md.name)
            slug = make_slug(name)
            sidebar_pos = extract_position(md.name)
            desc = f"{meta.get('OS', '')} / {meta.get('Difficulty', '')} - {meta.get('Result', '')}".strip(" / -")
            
            frontmatter = (
                "---\n"
                f"slug: {slug}\n"
                f"title: {name}\n"
                f"sidebar_label: {name}\n"
                f"sidebar_position: {sidebar_pos}\n"
                f'description: "{desc.replace(chr(34), chr(92)+chr(34))}"\n'
                "hide_title: true\n"
                "---\n\n"
            )
            
            (dst_dir / f"{slug}.md").write_text(frontmatter + raw, encoding="utf-8")
            total += 1

    print(f"Total: {total} walkthroughs + 1 index")


if __name__ == "__main__":
    main()
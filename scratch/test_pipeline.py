"""Test structured pipeline and compare with handmade report."""

import sys, json

sys.path.insert(0, ".")

import generate_report

# Run structured pipeline on xlsx
data, raw_texts, fps = generate_report._generate_from_structured_file(
    "tests/input/AEG_Subnet1_y06m7b 1.xlsx",
    generate_report.load_config(),
    client_context="AEG Vision - Internal VAPT Phase 2",
    cancel_event=None,
    progress_callback=lambda s, c, t, m: print(f"  [{s}] {c}/{t}: {m}"),
)

findings = data.get("findings", [])
print(f"\n=== Generated {len(findings)} findings ===")
for i, f in enumerate(findings, 1):
    print(f"  {i:2d}. [{f.get('severity','?'):8s}] {f['name']}")
    print(f"      Hosts: {f.get('affected_assets','')[:80]}...")

# Compare with handmade
from docx import Document

doc = Document("tests/input/Internal_VAPT_Report_AEG_Vision.docx")
handmade = []
for table in doc.tables:
    rows = [[cell.text.strip() for cell in row.cells] for row in table.rows]
    if len(rows) >= 10:
        finding = {}
        for r in rows:
            key = r[1] if len(r) > 1 else r[0]
            val = r[2] if len(r) > 2 else ""
            if "Vulnerability title" in key:
                finding["name"] = val
            elif "Severity" in key:
                finding["severity"] = val
        if finding.get("name"):
            handmade.append(finding)

print(f"\n=== Handmade has {len(handmade)} findings ===")

gen_names = {f["name"].lower().strip() for f in findings}
hand_names = {f["name"].lower().strip() for f in handmade}

missing = hand_names - gen_names
extra = gen_names - hand_names

print(f"\n=== MISSING from generated ({len(missing)}) ===")
for n in sorted(missing):
    match = [f for f in handmade if f["name"].lower().strip() == n]
    print(f"  [{match[0].get('severity','?')}] {match[0]['name']}")

print(f"\n=== EXTRA in generated ({len(extra)}) ===")
for n in sorted(extra):
    match = [f for f in findings if f["name"].lower().strip() == n]
    print(f"  [{match[0].get('severity','?')}] {match[0]['name']}")

# Check severity counts
print(f"\n=== Metadata ===")
for k in (
    "total_critical",
    "total_high",
    "total_medium",
    "total_low",
    "total_findings",
):
    print(f"  {k}: {data.get(k)}")

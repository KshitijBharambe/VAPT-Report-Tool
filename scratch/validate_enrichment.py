"""Quick validation: run structured pipeline on 3 findings, print enrichment quality."""

import sys, json

sys.path.insert(0, ".")
import generate_report as gr

config = gr.load_config()
input_file = "tests/input/AEG_Subnet1_y06m7b 1.xlsx"


def progress(stage, current, total, message):
    print(f"  [{stage} {current}/{total}] {message}")


print("Starting structured pipeline...")
data, raw_texts, fps = gr._generate_from_structured_file(
    input_file,
    config,
    client_context="AEG Vision – Internal VAPT",
    cancel_event=None,
    progress_callback=progress,
)

findings = data.get("findings", [])
print(f"\nGenerated {len(findings)} findings, {len(fps)} fingerprints")

# Show first 3 enriched findings
for i, f in enumerate(findings[:3]):
    print(f"\n{'='*60}")
    print(f"Finding {i+1}: {f.get('name','')}")
    print(f"  Severity: {f.get('severity','')}")
    for k in [
        "control_objective",
        "control_name",
        "reference",
        "audit_requirement",
        "recommendation",
    ]:
        val = str(f.get(k, ""))
        preview = val[:200] + "..." if len(val) > 200 else val
        print(f"  {k}: {preview}")

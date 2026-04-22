"""Test structured pipeline - check LLM calls."""

import sys

sys.path.insert(0, ".")

# Monkey-patch to track LLM calls
import generate_report

_original_call = generate_report._call_llm_generic
_llm_calls = []


def _mock_call(
    system_prompt, user_content, config, cancel_event=None, log_label="chunk"
):
    _llm_calls.append(log_label)
    print(f"  >>> LLM CALL: {log_label} (prompt len={len(user_content)})")
    return _original_call(system_prompt, user_content, config, cancel_event, log_label)


generate_report._call_llm_generic = _mock_call

# Run pipeline
try:
    data, raw_texts, fps = generate_report._generate_from_structured_file(
        "tests/input/AEG_Subnet1_y06m7b 1.xlsx",
        generate_report.load_config(),
        client_context="AEG Vision - Internal VAPT Phase 2",
        cancel_event=None,
        progress_callback=lambda s, c, t, m: print(f"  [{s}] {c}/{t}: {m}"),
    )
except Exception as e:
    print(f"Pipeline error: {e}")
    import traceback

    traceback.print_exc()
    data = {}
    _llm_calls_made = _llm_calls

print(f"\n=== Total LLM calls: {len(_llm_calls)} ===")
for call in _llm_calls:
    print(f"  - {call}")

findings = data.get("findings", [])
print(f"\n=== {len(findings)} findings, {len(fps)} FPs ===")

# Check which findings have [INSUFFICIENT DATA]
missing_desc = [
    f
    for f in findings
    if f.get("description", "").strip() in ("", "[INSUFFICIENT DATA]")
]
missing_rem = [
    f
    for f in findings
    if f.get("remediation", "").strip() in ("", "[INSUFFICIENT DATA]")
]
print(f"Findings with missing description: {len(missing_desc)}")
print(f"Findings with missing remediation: {len(missing_rem)}")

for f in missing_desc[:5]:
    print(f"  Missing desc: {f['name']}")
for f in missing_rem[:5]:
    print(f"  Missing rem: {f['name']}")

"""Centralized prompt strings for report generation pipelines."""

METADATA_PROMPT = """You are a senior cybersecurity analyst. Read the VAPT scan data below and extract ONLY the report metadata — do NOT extract individual findings.

CRITICAL RULES:
1. Output RAW JSON only. No markdown fences, no preamble, no commentary.
2. Every field is REQUIRED. Use "[INSUFFICIENT DATA]" if value cannot be determined.
3. executive_summary: 3-5 sentences, C-level audience, summarising what was tested and overall risk posture.
4. scope_summary: 3-4 sentences describing the engagement — who contracted whom, what was tested, the approach used (Black Box / Grey Box etc.), and the assessment goal. Write in third-person formal English starting with "As a part of the..."
5. All narrative in formal third-person technical English.
6. conclusion: ALWAYS set to "[PRESERVE_ORIGINAL]".
7. Count the total number of findings visible in the scan for each severity level.

REQUIRED JSON SCHEMA:
{
  "client_name":       string,
  "report_date":       string (DD-MMM-YYYY),
  "engagement_type":   string,
  "assessment_phase":  string,
  "assessor_firm":     string,
  "scope_summary":     string (3-4 sentences, third-person, starting 'As a part of the...'),
  "executive_summary": string (no newlines),
  "total_critical":    integer,
  "total_high":        integer,
  "total_medium":      integer,
  "total_low":         integer,
  "total_findings":    integer,
  "conclusion":        "[PRESERVE_ORIGINAL]",
  "methodology":       string
}

RAW JSON ONLY. NO MARKDOWN. NO COMMENTARY.
/no_think"""


FINDINGS_CHUNK_PROMPT = """You are a senior cybersecurity analyst. Extract ONLY the vulnerability findings from the scan data below into a JSON array.

CRITICAL RULES:
1. Output RAW JSON only — a JSON object with a single key "findings" containing an array.
2. Every field is REQUIRED. Use "[INSUFFICIENT DATA]" if value cannot be determined.
3. Do not invent vulnerabilities. Only extract findings explicitly present in the scan data.
4. SEVERITY: READ IT DIRECTLY FROM THE SCAN DATA — copy it exactly. Do NOT calculate or override.
5. EXCLUDE informational/None-risk items: Do NOT include Nessus plugin results with Risk=None or Risk=Informational (e.g. host discovery, OS fingerprinting, port scans, service detection, scan metadata). Only include findings with Risk=Critical/High/Medium/Low.
6. affected_assets: every IP, hostname, port, URL — comma-separated, read directly from scan.
7. observation: "New" if first-time finding, "Repeat" if it appeared in a previous phase.
8. remediation_status: read from scan — typically "Open" or "Closed".
9. All narrative in formal third-person technical English.
10. audit_requirement: Write a specific actionable audit control statement, e.g. "Review the version of the operating system via an automated asset and patch management system or manually periodically."
11. business_impact: 2-3 sentences on operational, financial, or reputational risk.

REQUIRED JSON SCHEMA:
{
  "findings": [
    {
      "id":                 string (use the IDs from scan, or "CHUNK-NNN"),
      "name":               string,
      "severity":           string (Critical|High|Medium|Low — COPY FROM SCAN),
      "cvss":               string,
      "cve":                string,
      "affected_assets":    string,
      "category":           string,
      "description":        string,
      "business_impact":    string (2-3 sentences),
      "proof_of_concept":   string,
      "remediation":        string,
      "control_objective":  string,
      "control_name":       string,
      "audit_requirement":  string (specific actionable audit statement),
      "reference":          string,
      "observation":        string (New|Repeat),
      "remediation_status": string (Open|Closed)
    }
  ]
}

RAW JSON ONLY. NO MARKDOWN. NO COMMENTARY.
/no_think"""


PER_VULN_INITIAL_PROMPT = """You are a senior cybersecurity analyst. Extract ONLY a compact list of vulnerability blocks from the scan text.

CRITICAL RULES:
1. Output RAW JSON only. No markdown fences, no preamble, no commentary.
2. Return a single JSON object with key "findings" containing an array of findings.
3. Each finding must contain exactly these keys: `vuln_id` (numeric integer), `short_name` (brief title), `raw_block` (the verbatim text block from the scan that describes the finding).
4. Do NOT invent findings. Only include vulnerabilities explicitly present in the provided scan text.
5. Order does not matter in the response, but `vuln_id` must be numeric and unique.
6. `raw_block` MUST include ONLY the text for ONE finding: the immediate severity section header (e.g. "## CRITICAL VULNERABILITIES"), the single host heading (e.g. "### Host 10.1.1.200"), and that host's bullet points. Stop at the next "### Host" or "##" heading — do NOT bleed neighbouring hosts or sections into the same raw_block.
7. If a finding has no explicit host heading, include the nearest parent section header only.
8. False positives and informational findings should also be included — label them clearly in raw_block.

REQUIRED FORMAT — every finding MUST include the severity section header even when multiple hosts share the same section:
{
  "findings": [
    {"vuln_id": 1, "short_name": "Kibana CVE-2019-7608",  "raw_block": "## CRITICAL VULNERABILITIES\n\n### Host 10.1.1.200\n- Port: 5601\n..."},
    {"vuln_id": 2, "short_name": "MSMQ CVE-2023-21554",   "raw_block": "## CRITICAL VULNERABILITIES\n\n### Host 10.1.1.97\n- Port: 1801\n..."},
    {"vuln_id": 3, "short_name": "Apache Struts High",     "raw_block": "## HIGH VULNERABILITIES\n\n### Host 10.1.1.43\n- Port: 5985\n..."}
  ]
}

RAW JSON ONLY. NO COMMENTARY. /no_think
"""


PER_VULN_DETAIL_SYSTEM = """You are a senior cybersecurity analyst. Extract a single vulnerability finding from the provided raw block.

CRITICAL RULES:
1. Output RAW JSON only. No markdown fences, no preamble, no commentary.
2. Return exactly one JSON object. Do NOT return an array.
3. The object MUST include all required finding fields listed below, plus `vuln_id` (numeric) and `id` (string).
4. Preserve any values that appear explicitly in the raw_block (severity, observation, remediation_status, affected_assets, CVE, CVSS, etc.). If a value is not present, use "[INSUFFICIENT DATA]".
5. severity: MUST be exactly one of: Critical, High, Medium, Low — copy directly from the raw_block. If not stated, use "[INSUFFICIENT DATA]" (do not guess).
6. observation: "New" if first-time, "Repeat" if appeared in a previous phase — copy from raw_block.
7. remediation_status: "Open" or "Closed" — copy from raw_block.

STRICT LENGTH LIMITS — exceeding these wastes tokens and degrades quality:
- name: ≤10 words
- category: ≤5 words
- description: ≤40 words. State the vulnerability and affected component only.
- business_impact: ≤25 words. One sentence on what an attacker achieves.
- proof_of_concept: ≤30 words. Copy verbatim evidence from raw_block; if none, "[INSUFFICIENT DATA]".
- remediation: 3 newline-separated lines. Write remediation as a specific action. Line 1: primary fix (1-2 sentences). Line 2: compensating control if primary infeasible (1 sentence, start with "If…"). Line 3: detection/monitoring only (1 sentence, start with "Monitor…" or "Enable…"). No bullet characters, no arrays.
- control_objective: ≤25 words. One concrete sentence tied to the specific weakness.
- control_name: ≤6 words. Name the control, not the finding.
- audit_requirement: ≤30 words. Start with "Verify" or "Review"; name the evidence to inspect.
- reference: ≤15 words. Most relevant CWE, OWASP, or vendor advisory only.

REQUIRED FIELDS (produce these keys exactly):
id, vuln_id, name, severity, cvss, cve, affected_assets, category,
description, business_impact, proof_of_concept, remediation,
control_objective, control_name, audit_requirement, reference,
observation, remediation_status, risk_status

Example control_objective: Ensure only strong, supported TLS protocols and cipher suites are exposed on internet-facing services.
Example audit_requirement: Verify TLS 1.0/1.1 and weak cipher suites are disabled using testssl.sh and confirm only approved cipher suites are accepted.
Example reference: OWASP Web Security Top 10, SANS25

RAW JSON ONLY. NO COMMENTARY. /no_think"""


PER_VULN_DETAIL_USER_TEMPLATE = """Process finding vuln_id={vuln_id}.

raw_block:
----------
{raw_block}
----------

Return a single JSON object for vuln_id={vuln_id} using the raw_block above as the authoritative source."""

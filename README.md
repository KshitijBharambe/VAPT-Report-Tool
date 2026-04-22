# VAPT Report Tool

VAPT Report Tool is an internal automation utility for generating structured VAPT reports from scan inputs and exporting the final output as a DOCX report.

It combines deterministic parsing and report generation logic with LLM-assisted enrichment for selected narrative and control-related fields. The goal is to reduce manual effort in report preparation, improve consistency, and speed up report turnaround.

## Overview

The tool supports:

- Uploading scan data in supported text or spreadsheet formats
- Extracting and organizing vulnerability findings
- Enriching selected report fields where needed
- Generating a DOCX report using a configured base template

This project is intended for internal report automation workflows.

## Requirements

- Python 3.13+
- Node.js 18+
- Either `uv` or `pip`

## Project structure

- `main.py` - application entrypoint
- `report_runtime/` - runtime server and browser UI
- `generate_report.py` - report generation engine
- `report_core/` - shared helpers and defaults
- `report_tool/` - lookup/enrichment and utility modules
- `tests/` - test coverage
- `config.json` - runtime configuration

## Setup

### Option 1: Using `uv`

Install dependencies:

```bash
uv sync
```

Run the application:

```bash
uv run python main.py
```

### Option 2: Using `pip`

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python main.py
```

## Accessing the application

After starting the app, open:

```text
http://127.0.0.1:8787
```

## Supported inputs

The current runtime supports the following input formats:

- `.txt`
- `.csv`
- `.xlsx`
- `.xls`

## Output

The tool generates DOCX-format VAPT reports based on the uploaded input data and configured base template.

## Configuration

Primary runtime configuration is managed through `config.json`.

Important configuration fields include:

- `llm.provider`
- `llm.base_url`
- `llm.model`
- `paths.template`
- `paths.output_dir`

The tool supports both:

- `openrouter` for hosted model access
- `local` for OpenAI-compatible local endpoints such as LM Studio or similar setups

Runtime settings may also be managed through the browser interface where applicable.

## Basic workflow

1. Start the application
2. Open the browser interface
3. Upload a supported scan input
4. Configure the required runtime settings
5. Upload or select the DOCX base template
6. Run report generation
7. Download the generated report

## Notes

- A DOCX base template is required for report generation
- Output quality may vary depending on the selected model/provider configuration
- Local model usage may reduce cost but can affect output quality depending on model capability

## Testing

Run Python tests with:

```bash
python -m pytest tests -q
```

## Note

This tool was developed by Kshitij Bharambe for VAPT report automation use.

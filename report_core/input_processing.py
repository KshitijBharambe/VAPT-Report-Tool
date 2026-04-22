import re
from pathlib import Path


# Regex patterns that typically mark the start of a new vulnerability block.
_VULN_BOUNDARY_PATTERNS = [
    re.compile(r"^\s*#{1,3}\s+", re.MULTILINE),
    re.compile(r"^\s*\d+\.\s+", re.MULTILINE),
    re.compile(r"^\s*VAPT-\d+", re.MULTILINE | re.IGNORECASE),
    re.compile(
        r"^\s*(?:vulnerability|finding|issue)\s*#?\s*\d+",
        re.MULTILINE | re.IGNORECASE,
    ),
    re.compile(
        r"^\s*(?:critical|high|medium|low)\s*[-:—]", re.MULTILINE | re.IGNORECASE
    ),
    re.compile(r"^-{3,}$", re.MULTILINE),
    re.compile(r"^={3,}$", re.MULTILINE),
    re.compile(r"^\s*Plugin\s*(?:ID)?\s*:\s*\d+", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*Issue:\s+", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*Title\s*:\s+", re.MULTILINE | re.IGNORECASE),
]


def _extract_text_from_pdf(filepath: str) -> str:
    """Extract plain text from a PDF using PyMuPDF."""
    try:
        import fitz

        doc = fitz.open(filepath)
        pages = [page.get_text("text") for page in doc]
        doc.close()
        return "\n".join(pages)
    except ImportError:
        raise RuntimeError(
            "PyMuPDF not installed. Run: pip install pymupdf --break-system-packages"
        )
    except Exception as e:
        raise RuntimeError(f"Could not extract text from PDF: {e}")


def _extract_text_from_docx(filepath: str) -> str:
    """Extract plain text from a DOCX using python-docx."""
    try:
        from docx import Document as _Doc

        doc = _Doc(filepath)
        lines = [p.text for p in doc.paragraphs if p.text.strip()]
        for tbl in doc.tables:
            for row in tbl.rows:
                for cell in row.cells:
                    if cell.text.strip():
                        lines.append(cell.text.strip())
        return "\n".join(lines)
    except Exception as e:
        raise RuntimeError(f"Could not extract text from DOCX: {e}")


def preprocess_scan(text: str) -> str:
    """Strip high-noise boilerplate before sending to the LLM."""
    import re as _re

    noise_patterns = [
        _re.compile(r"^\s*[-=|+]{4,}\s*$"),
        _re.compile(r"^Nmap scan report for .+ done", _re.I),
        _re.compile(r"^# Nmap \d", _re.I),
        _re.compile(r"^Starting Nmap", _re.I),
        _re.compile(r"^Nmap done:", _re.I),
        _re.compile(r"^Read data files from", _re.I),
        _re.compile(r"^\s*Service detection performed", _re.I),
        _re.compile(r"^\s*\d+ IP address(es)? scanned", _re.I),
        _re.compile(r"Scan time:\s", _re.I),
        _re.compile(r"^\s*Plugin\s+\d+\s*$", _re.I),
        _re.compile(r"^\s*\[.{1,20}\]\s*$"),
        _re.compile(r"^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*$"),
        _re.compile(r"^\s*Port\s+State\s+Service", _re.I),
        _re.compile(r"^\s*\d+/tcp\s+filtered\s+", _re.I),
        _re.compile(r"^\s*\d+/udp\s+filtered\s+", _re.I),
    ]
    seen = set()
    out_lines = []
    prev_blank = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            if not prev_blank:
                out_lines.append("")
            prev_blank = True
            continue
        prev_blank = False
        if len(stripped) < 4:
            continue
        if any(p.search(stripped) for p in noise_patterns):
            continue
        key = stripped.lower()
        if key in seen:
            continue
        seen.add(key)
        out_lines.append(line)
    return "\n".join(out_lines)


def read_scan_input(filepath: str, config: dict | None = None) -> str:
    """Read and preprocess a scan input file. Supports .txt, .pdf, .docx."""
    max_words = config["limits"]["max_input_words"] if config else 6000
    warn_words = config["limits"]["warn_input_words"] if config else 4000

    ext = Path(filepath).suffix.lower()
    if ext == ".pdf":
        content = _extract_text_from_pdf(filepath)
    elif ext in (".docx", ".doc"):
        content = _extract_text_from_docx(filepath)
    else:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

    original_words = len(content.split())
    content = preprocess_scan(content)
    words = content.split()
    count = len(words)

    saved = original_words - count
    if saved > 0:
        print(
            f"ℹ️  Preprocessor removed {saved} words ({round(saved / original_words * 100)}% reduction). {count} remaining."
        )
    if count > max_words:
        print(f"⚠️  Input exceeds {max_words} words after preprocessing. Truncating.")
        content = " ".join(words[:max_words])
    elif count > warn_words:
        print(f"ℹ️  Input is {count} words — processing may be slow.")

    return content


def read_scan_file(filepath: str, config: dict | None = None) -> str:
    return read_scan_input(filepath, config)


def _find_vuln_boundaries(text: str) -> list[int]:
    """Find line indices where new vulnerability blocks likely start."""
    lines = text.splitlines()
    boundaries = []

    for i, line in enumerate(lines):
        for pattern in _VULN_BOUNDARY_PATTERNS:
            if pattern.search(line):
                boundaries.append(i)
                break

    return sorted(set(boundaries))


def chunk_scan_text(scan_text: str, findings_per_chunk: int = 6) -> list[str]:
    """Split scan text into chunks by likely vulnerability boundaries."""
    lines = scan_text.splitlines()
    boundaries = _find_vuln_boundaries(scan_text)

    if len(boundaries) < 3:
        words = scan_text.split()
        chunk_size = max(800, len(words) // max(1, len(words) // 2000))
        chunks = []
        for i in range(0, len(words), chunk_size):
            chunk = " ".join(words[i : i + chunk_size])
            if chunk.strip():
                chunks.append(chunk)
        return chunks if chunks else [scan_text]

    chunks = []
    for i in range(0, len(boundaries), findings_per_chunk):
        start_line = boundaries[i]
        if i + findings_per_chunk < len(boundaries):
            end_line = boundaries[i + findings_per_chunk]
        else:
            end_line = len(lines)

        chunk_text = "\n".join(lines[start_line:end_line]).strip()
        if chunk_text:
            chunks.append(chunk_text)

    return chunks if chunks else [scan_text]


def estimate_chunks(scan_text: str, findings_per_chunk: int = 6) -> int:
    """Return estimated number of chunks without splitting."""
    boundaries = _find_vuln_boundaries(scan_text)
    if len(boundaries) < 3:
        words = scan_text.split()
        chunk_size = max(800, len(words) // max(1, len(words) // 2000))
        return max(1, -(-len(words) // chunk_size))
    return max(1, -(-len(boundaries) // findings_per_chunk))

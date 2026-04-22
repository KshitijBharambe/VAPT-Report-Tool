"""Handmade VAPT report corpus: ground-truth findings for RAG + quality scoring."""

from report_tool.corpus.store import CorpusStore, load_corpus
from report_tool.corpus.extractor import extract_docx_findings

__all__ = ["CorpusStore", "load_corpus", "extract_docx_findings"]

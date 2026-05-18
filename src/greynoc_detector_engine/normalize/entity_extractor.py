from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.utils.text import find_cve_ids, keyword_hits

AI_SIGNAL_TERMS = (
    "llm",
    "agent",
    "prompt injection",
    "jailbreak",
    "rag",
    "embeddings",
    "model context",
    "tool calling",
    "mcp",
    "vector database",
    "ai coding assistant",
)

EXPLOIT_SIGNAL_TERMS = (
    "exploitation in the wild",
    "actively exploited",
    "proof of concept",
    "poc",
    "exploit available",
    "ransomware",
    "emergency patch",
)

PRODUCT_RE = re.compile(
    r"\b(?:Microsoft|Windows|Exchange|SharePoint|Cisco|Ivanti|Fortinet|Palo Alto|"
    r"VMware|Citrix|Confluence|Jira|Chrome|Firefox|OpenAI|LangChain|MCP|"
    r"Kubernetes|Docker|Linux)\b",
    re.IGNORECASE,
)


class ExtractedEntities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_ids: list[str] = Field(default_factory=list)
    ai_terms: list[str] = Field(default_factory=list)
    exploit_terms: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)


class EntityExtractor:
    def extract(self, text: str) -> ExtractedEntities:
        products = sorted({match.group(0) for match in PRODUCT_RE.finditer(text or "")})
        return ExtractedEntities(
            cve_ids=find_cve_ids(text),
            ai_terms=keyword_hits(text, AI_SIGNAL_TERMS),
            exploit_terms=keyword_hits(text, EXPLOIT_SIGNAL_TERMS),
            products=products,
        )

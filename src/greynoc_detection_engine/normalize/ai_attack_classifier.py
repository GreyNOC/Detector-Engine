from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detection_engine.models.threat import AIAttackType


class AIAttackClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_type: AIAttackType | None
    confidence: float = Field(ge=0, le=1)
    matched_terms: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)


AI_ATTACK_KEYWORDS: dict[AIAttackType, tuple[str, ...]] = {
    AIAttackType.INDIRECT_PROMPT_INJECTION: (
        "indirect prompt injection",
        "hidden prompt",
        "untrusted content prompt",
    ),
    AIAttackType.PROMPT_INJECTION: ("prompt injection", "instruction override"),
    AIAttackType.MODEL_JAILBREAK: ("jailbreak", "model jailbreak", "safety bypass"),
    AIAttackType.MODEL_EXTRACTION: ("model extraction", "model stealing", "api extraction"),
    AIAttackType.DATA_POISONING: ("data poisoning", "poisoned training"),
    AIAttackType.TRAINING_DATA_LEAKAGE: ("training data leakage", "memorized training data"),
    AIAttackType.RAG_POISONING: ("rag poisoning", "retrieval poisoning", "embedding poisoning"),
    AIAttackType.TOOL_USE_ABUSE: ("tool-use abuse", "tool calling abuse", "function calling abuse"),
    AIAttackType.AGENT_HIJACKING: ("agent hijacking", "autonomous agent hijack"),
    AIAttackType.AI_SUPPLY_CHAIN_COMPROMISE: ("ai supply chain", "model supply chain"),
    AIAttackType.MALICIOUS_MODEL_UPLOAD: ("malicious model upload", "backdoored model"),
    AIAttackType.MALICIOUS_AI_PACKAGE: ("malicious ai package", "malicious ai dependency"),
    AIAttackType.DEEPFAKE_SOCIAL_ENGINEERING: ("deepfake", "voice clone", "synthetic video"),
    AIAttackType.AUTOMATED_PHISHING_GENERATION: ("ai phishing", "automated phishing"),
    AIAttackType.AI_ASSISTED_VULNERABILITY_DISCOVERY: (
        "ai-assisted vulnerability discovery",
        "llm found vulnerability",
    ),
    AIAttackType.AI_ASSISTED_MALWARE_MUTATION: (
        "ai-assisted malware mutation",
        "llm malware mutation",
    ),
    AIAttackType.AI_POWERED_CREDENTIAL_ATTACK: ("ai-powered credential", "llm credential attack"),
    AIAttackType.AUTONOMOUS_RECON: ("autonomous recon", "autonomous scanning", "ai browser"),
    AIAttackType.SYNTHETIC_IDENTITY_ABUSE: ("synthetic identity", "ai-generated identity"),
}


class AIAttackClassifier:
    def classify(self, text: str) -> AIAttackClassification:
        normalized = text.lower()
        best_type: AIAttackType | None = None
        best_terms: list[str] = []
        for attack_type, terms in AI_ATTACK_KEYWORDS.items():
            hits = [term for term in terms if term in normalized]
            if len(hits) > len(best_terms):
                best_type = attack_type
                best_terms = hits

        if best_type is None:
            generic_hits = [
                term
                for term in ("llm", "model", "agent", "mcp", "vector database", "embedding")
                if term in normalized
            ]
            if generic_hits:
                return AIAttackClassification(
                    attack_type=AIAttackType.UNKNOWN_AI_ENABLED_TECHNIQUE,
                    confidence=0.35,
                    matched_terms=generic_hits,
                    rationale=[
                        "AI-related wording was present but no specific taxonomy bucket matched."
                    ],
                )
            return AIAttackClassification(
                attack_type=None,
                confidence=0,
                matched_terms=[],
                rationale=["No AI attack taxonomy terms were found."],
            )

        confidence = min(0.95, 0.45 + (0.2 * len(best_terms)))
        return AIAttackClassification(
            attack_type=best_type,
            confidence=confidence,
            matched_terms=best_terms,
            rationale=[f"Matched AI attack taxonomy terms for {best_type.value}."],
        )

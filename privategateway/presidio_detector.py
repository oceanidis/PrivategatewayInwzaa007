from __future__ import annotations

from functools import lru_cache


class PresidioDetector:
    def __init__(self) -> None:
        self.available = False
        self.error_type: str | None = None
        self._analyzer = None
        try:
            from presidio_analyzer import AnalyzerEngine

            self._analyzer = AnalyzerEngine()
            self.available = True
        except Exception as exc:
            self.error_type = type(exc).__name__

    def detect(self, text: object) -> list[dict[str, object]]:
        if not self.available or self._analyzer is None:
            return []
        value = "" if text is None else str(text)
        results = self._analyzer.analyze(text=value, language="en")
        return [
            {"entity_type": item.entity_type, "start": item.start, "end": item.end, "score": item.score}
            for item in results
        ]

    def redact(self, text: object) -> tuple[str, int]:
        value = "" if text is None else str(text)
        findings = self.detect(value)
        for finding in sorted(findings, key=lambda item: int(item["start"]), reverse=True):
            start = int(finding["start"])
            end = int(finding["end"])
            entity = str(finding["entity_type"])
            value = value[:start] + f"[REDACTED_{entity}]" + value[end:]
        return value, len(findings)


@lru_cache(maxsize=1)
def get_presidio_detector() -> PresidioDetector:
    """Reuse one AnalyzerEngine per gateway process, including multi-sheet jobs."""
    return PresidioDetector()
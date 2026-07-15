from __future__ import annotations

import unittest
from pathlib import Path

from scripts.validate_surge_profile import APPLE_AI_BASELINE


ROOT = Path(__file__).resolve().parents[1]

MIRRORS = {
    "rules/production/ai/ChatGPT.list": ("AI/ChatGPT.list",),
    "rules/production/ai/Claude.list": ("AI/Claude.list",),
    "rules/production/ai/Copilot.list": ("AI/Github Copilot.list",),
    "rules/production/ai/Gemini.list": ("AI/Gemini.list",),
    "rules/production/ai/Grok.list": ("AI/Grok.list", "AI/Gork.list"),
    "rules/production/ai/OtherAI.list": ("AI/OtherAI.list", "AI/Other AI.list"),
    "rules/production/ai/Perplexity.list": ("AI/Perplexity.list",),
}


def active_rules(path: Path) -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


class LegacyMirrorTest(unittest.TestCase):
    def test_supported_legacy_mirrors_match_production_rules(self) -> None:
        for production, mirrors in MIRRORS.items():
            expected = active_rules(ROOT / production)
            for mirror in mirrors:
                with self.subTest(production=production, mirror=mirror):
                    self.assertEqual(expected, active_rules(ROOT / mirror))

    def test_apple_intelligence_legacy_baseline_matches_profile_contract(self) -> None:
        expected = {f"{rule_type},{condition}" for rule_type, condition in APPLE_AI_BASELINE}
        self.assertEqual(expected, set(active_rules(ROOT / "AI/Apple Intelligence.list")))


if __name__ == "__main__":
    unittest.main()

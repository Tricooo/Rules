from __future__ import annotations

import ipaddress
import unittest
from pathlib import Path

from scripts.sync_chatgpt_voice import ensure_not_rollback, extract_networks, render


ROOT = Path(__file__).resolve().parents[1]
AI_ROOT = ROOT / "rules" / "production" / "ai"


def active_rules(name: str) -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in (AI_ROOT / name).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


class AISourceTest(unittest.TestCase):
    def test_chatgpt_domains_are_service_owned(self) -> None:
        self.assertEqual(
            {
                "DOMAIN-SUFFIX,chatgpt.com",
                "DOMAIN-SUFFIX,oaistatic.com",
                "DOMAIN-SUFFIX,oaistatsig.com",
                "DOMAIN-SUFFIX,oaiusercontent.com",
                "DOMAIN-SUFFIX,openai.com",
                "DOMAIN,cdn.openaimerge.com",
            },
            set(active_rules("ChatGPT.list")),
        )

    def test_copilot_has_no_shared_cloud_or_asn_rule(self) -> None:
        self.assertEqual(
            {
                "DOMAIN,copilot-proxy.githubusercontent.com",
                "DOMAIN,copilot-reports.github.com",
                "DOMAIN,copilot-telemetry.githubusercontent.com",
                "DOMAIN,origin-tracker.githubusercontent.com",
                "DOMAIN-SUFFIX,githubcopilot.com",
            },
            set(active_rules("Copilot.list")),
        )

    def test_voice_snapshot_contains_only_ip_rules(self) -> None:
        rules = active_rules("ChatGPTVoice.list")
        self.assertGreater(len(rules), 0)
        for rule in rules:
            rule_type, condition, modifier = rule.split(",")
            self.assertIn(rule_type, {"IP-CIDR", "IP-CIDR6"})
            self.assertEqual("no-resolve", modifier)
            network = ipaddress.ip_network(condition, strict=True)
            self.assertEqual(4 if rule_type == "IP-CIDR" else 6, network.version)

    def test_voice_renderer_is_deterministic(self) -> None:
        creation_time, networks = extract_networks(
            {
                "creationTime": "2026-01-02T03:04:05+00:00",
                "prefixes": [
                    {"ipv4Prefix": "9.9.9.9/32"},
                    {"ipv4Prefix": "8.8.8.8/32"},
                ],
            }
        )
        output = render(creation_time, networks, "2026-01-03")
        self.assertLess(output.index("8.8.8.8/32"), output.index("9.9.9.9/32"))

    def test_voice_source_must_be_an_object(self) -> None:
        with self.assertRaisesRegex(ValueError, "JSON object"):
            extract_networks([])  # type: ignore[arg-type]

    def test_voice_source_rejects_broad_prefixes(self) -> None:
        with self.assertRaisesRegex(ValueError, "host prefix"):
            extract_networks(
                {
                    "creationTime": "2026-01-02T03:04:05+00:00",
                    "prefixes": [{"ipv4Prefix": "8.8.8.0/24"}],
                }
            )

    def test_voice_source_rejects_creation_time_rollback(self) -> None:
        with self.assertRaisesRegex(ValueError, "older than"):
            ensure_not_rollback(
                "2026-01-01T00:00:00+00:00",
                "2026-01-02T00:00:00+00:00",
            )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.validate_surge_profile import validate_profile


BASE_IOS_PROFILE = """[General]
skip-proxy = 127.0.0.1, 10.0.0.0/8, 100.64.0.0/10
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 224.0.0.0/4
encrypted-dns-follow-outbound-mode = false

[Proxy]
Direct-AI = direct
CF = direct
CF-us = direct
CF-us-AI = direct

[Proxy Group]
ChatGPT = select, Direct-AI, CF-AI-Auto
Claude = select, Direct-AI, CF-AI-Auto
Gemini = select, Direct-AI, CF-AI-Auto
Auto Selection = smart, CF, US Node
GitHub Copilot = select, Auto Selection, US Node
Perplexity = select, Auto Selection, US Node
Other AI = select, Auto Selection, US Node
Grok = select, Auto Selection, US Node
Apple Intelligence = select, US Node, Auto Selection
iCloud Private = select, DIRECT
Apple = select, DIRECT
US Node = smart, CF-us, policy-regex-filter=🇺🇸
My Node = subnet, default = DIRECT, TYPE:CELLULAR = DIRECT, SSID:Entrance = DIRECT
Cloudflare Auto = smart, include-all-proxies=true, policy-regex-filter=(?i)^(?:CF|CF-(?!.*-AI$).+)$
CF-AI-Auto = smart, include-all-proxies=true, policy-regex-filter=(?i)^CF-.*-AI$
Final = select, My Node, Auto Selection, DIRECT

[Rule]
RULE-SET,https://example.invalid/iCloudPrivateRelay.list,iCloud Private
DOMAIN-SUFFIX,chatgpt.com,ChatGPT
DOMAIN-SUFFIX,claude.ai,Claude
DOMAIN-SUFFIX,gemini.google.com,Gemini
DOMAIN-SUFFIX,copilot.microsoft.com,GitHub Copilot
DOMAIN-SUFFIX,grok.com,Grok
DOMAIN-SUFFIX,perplexity.ai,Perplexity
DOMAIN-SUFFIX,mistral.ai,Other AI
DOMAIN,guzzoni.apple.com,Apple Intelligence
DOMAIN-SUFFIX,smoot.apple.com,Apple Intelligence
DOMAIN-SUFFIX,apple-relay.apple.com,Apple Intelligence
DOMAIN-SUFFIX,apple-relay.cloudflare.com,Apple Intelligence
DOMAIN-SUFFIX,apple-relay.fastly-edge.com,Apple Intelligence
DOMAIN,cp4.cloudflare.com,Apple Intelligence
DOMAIN-SUFFIX,siri.apple.com,Apple Intelligence
RULE-SET,https://example.invalid/Apple_All_No_Resolve.list,Apple
GEOIP,CN,DIRECT
FINAL,Final
"""


def build_mac_profile() -> str:
    profile = BASE_IOS_PROFILE.replace(
        "My Node = subnet, default = DIRECT, TYPE:CELLULAR = DIRECT, SSID:Entrance = DIRECT",
        "Auto-SSID = subnet, default = DIRECT, SSID:Entrance = DIRECT\n"
        "My Node = select, Auto-SSID, DIRECT",
    ).replace(
        "RULE-SET,https://example.invalid/Apple_All_No_Resolve.list,Apple",
        "PROCESS-NAME,assistantd,Apple Intelligence\n"
        "RULE-SET,https://example.invalid/Apple_All_No_Resolve.list,Apple",
    )
    emoji_names = {
        "Direct-AI": "☀️ Direct-AI",
        "ChatGPT": "🫧 ChatGPT",
        "Claude": "🌼 Claude",
        "Gemini": "✨ Gemini",
        "GitHub Copilot": "✈️ GitHub Copilot",
        "Perplexity": "🔮 Perplexity",
        "Other AI": "🤖 Other AI",
        "Grok": "🔥 Grok",
        "Apple Intelligence": "🌈 Apple Intelligence",
        "iCloud Private": "🛡️ iCloud Private",
        "Apple": "🍎 Apple",
        "Auto Selection": "♻️ Auto Selection",
        "US Node": "🇺🇸 US Node",
        "Auto-SSID": "🎛️ Auto-SSID",
        "My Node": "🫟 My Node",
        "Cloudflare Auto": "🎲 CF-Auto",
        "CF-AI-Auto": "☁️ CF-AI-Auto",
        "Final": "🧭 Final",
    }
    for plain, decorated in emoji_names.items():
        profile = profile.replace(plain, decorated)
    return profile.replace("🌈 🍎 Apple Intelligence", "🌈 Apple Intelligence").replace(
        "https://example.invalid/🍎 Apple_All_No_Resolve.list",
        "https://example.invalid/Apple_All_No_Resolve.list",
    )


class ValidateSurgeProfileTest(unittest.TestCase):
    def validate(self, content: str, platform: str = "ios") -> tuple[list[str], list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.conf"
            path.write_text(content, encoding="utf-8")
            errors, warnings, _ = validate_profile(path, platform)
        return errors, warnings

    def test_contract_fixture_is_valid(self) -> None:
        errors, _ = self.validate(BASE_IOS_PROFILE)
        self.assertEqual([], errors)

    def test_mac_contract_fixture_is_valid(self) -> None:
        errors, _ = self.validate(build_mac_profile(), "mac")
        self.assertEqual([], errors)

    def test_mac_emoji_variation_selector_is_accepted(self) -> None:
        profile = build_mac_profile().replace("🔥 Grok", "Ⓜ️ Grok")
        errors, _ = self.validate(profile, "mac")
        self.assertEqual([], errors)

    def test_mac_group_without_emoji_is_rejected(self) -> None:
        profile = build_mac_profile().replace("🔥 Grok", "Grok")
        errors, _ = self.validate(profile, "mac")
        self.assertTrue(any("must retain Emoji" in item for item in errors))

    def test_mac_apple_intelligence_keeps_assistantd(self) -> None:
        profile = build_mac_profile()
        assistant_rule = "PROCESS-NAME,assistantd,🌈 Apple Intelligence\n"
        errors, _ = self.validate(profile.replace(assistant_rule, ""), "mac")
        self.assertTrue(any("PROCESS-NAME,assistantd" in item for item in errors))

    def test_apple_network_must_not_be_skipped(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "skip-proxy = 127.0.0.1, 10.0.0.0/8, 100.64.0.0/10",
            "skip-proxy = 127.0.0.1, 10.0.0.0/8, 17.0.0.0/8, 100.64.0.0/10",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("17.0.0.0/8" in item for item in errors))

    def test_broad_rule_must_follow_ai(self) -> None:
        apple_rule = "RULE-SET,https://example.invalid/Apple_All_No_Resolve.list,Apple\n"
        profile = BASE_IOS_PROFILE.replace(apple_rule, "")
        profile = profile.replace("[Rule]\n", "[Rule]\n" + apple_rule)
        errors, _ = self.validate(profile)
        self.assertTrue(any("broad/direct/filter rules" in item for item in errors))

    def test_china_ip_and_geoip_must_not_stack(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "GEOIP,CN,DIRECT",
            "RULE-SET,https://example.invalid/ChinaIp.list,DIRECT\nGEOIP,CN,DIRECT",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("ChinaIp.list duplicates" in item for item in errors))

    def test_unused_composite_group_is_rejected(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "Final = select, My Node, Auto Selection, DIRECT",
            'Asia = smart, include-other-group="US Node"\n'
            "Final = select, My Node, Auto Selection, DIRECT",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("unused composite policy group Asia" in item for item in errors))

    def test_ios_must_not_define_ai_egress(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "ChatGPT = select, Direct-AI, CF-AI-Auto",
            "AI Egress = select, Direct-AI, CF-AI-Auto, US Node\n"
            "ChatGPT = select, Direct-AI, CF-AI-Auto",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("iOS must not define AI Egress" in item for item in errors))

    def test_ios_core_ai_service_must_default_to_direct_ai(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "ChatGPT = select, Direct-AI, CF-AI-Auto",
            "ChatGPT = select, Auto Selection, Direct-AI, CF-AI-Auto",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("ChatGPT must default to Direct-AI" in item for item in errors))

    def test_ios_core_ai_service_must_only_use_ai_dedicated_policies(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "Claude = select, Direct-AI, CF-AI-Auto",
            "Claude = select, Direct-AI, CF-AI-Auto, Auto Selection",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("Claude may only use dedicated AI policies" in item for item in errors))

    def test_ios_other_ai_service_must_default_to_auto_selection(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "Grok = select, Auto Selection, US Node",
            "Grok = select, Direct-AI, Auto Selection, US Node",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("Grok must default to Auto Selection" in item for item in errors))

    def test_ios_other_ai_service_must_not_use_ai_dedicated_policies(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "Perplexity = select, Auto Selection, US Node",
            "Perplexity = select, Auto Selection, Direct-AI, US Node",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("Perplexity must not use dedicated AI policies" in item for item in errors))

    def test_ios_apple_intelligence_must_default_to_us_node(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "Apple Intelligence = select, US Node, Auto Selection",
            "Apple Intelligence = select, Auto Selection, US Node",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("Apple Intelligence must default to US Node" in item for item in errors))

    def test_ios_final_must_default_to_my_node(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "Final = select, My Node, Auto Selection, DIRECT",
            "Final = select, DIRECT, My Node, Auto Selection",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("iOS Final must default to My Node" in item for item in errors))

    def test_mac_must_not_define_ai_egress(self) -> None:
        profile = build_mac_profile().replace(
            "🫧 ChatGPT = select, ☀️ Direct-AI, ☁️ CF-AI-Auto",
            "🧠 AI Egress = select, ☀️ Direct-AI, ☁️ CF-AI-Auto\n"
            "🫧 ChatGPT = select, ☀️ Direct-AI, ☁️ CF-AI-Auto",
        )
        errors, _ = self.validate(profile, "mac")
        self.assertTrue(any("macOS must not define AI Egress" in item for item in errors))

    def test_mac_core_ai_service_must_default_to_direct_ai(self) -> None:
        profile = build_mac_profile().replace(
            "🫧 ChatGPT = select, ☀️ Direct-AI, ☁️ CF-AI-Auto",
            "🫧 ChatGPT = select, ♻️ Auto Selection, ☀️ Direct-AI, ☁️ CF-AI-Auto",
        )
        errors, _ = self.validate(profile, "mac")
        self.assertTrue(any("ChatGPT must default to Direct-AI" in item for item in errors))

    def test_mac_core_ai_service_must_only_use_ai_dedicated_policies(self) -> None:
        profile = build_mac_profile().replace(
            "🌼 Claude = select, ☀️ Direct-AI, ☁️ CF-AI-Auto",
            "🌼 Claude = select, ☀️ Direct-AI, ☁️ CF-AI-Auto, ♻️ Auto Selection",
        )
        errors, _ = self.validate(profile, "mac")
        self.assertTrue(any("Claude may only use dedicated AI policies" in item for item in errors))

    def test_mac_other_ai_service_must_default_to_auto_selection(self) -> None:
        profile = build_mac_profile().replace(
            "🔥 Grok = select, ♻️ Auto Selection, 🇺🇸 US Node",
            "🔥 Grok = select, ☀️ Direct-AI, ♻️ Auto Selection, 🇺🇸 US Node",
        )
        errors, _ = self.validate(profile, "mac")
        self.assertTrue(any("Grok must default to Auto Selection" in item for item in errors))

    def test_mac_other_ai_service_must_not_use_ai_dedicated_policies(self) -> None:
        profile = build_mac_profile().replace(
            "🔮 Perplexity = select, ♻️ Auto Selection, 🇺🇸 US Node",
            "🔮 Perplexity = select, ♻️ Auto Selection, ☀️ Direct-AI, 🇺🇸 US Node",
        )
        errors, _ = self.validate(profile, "mac")
        self.assertTrue(any("Perplexity must not use dedicated AI policies" in item for item in errors))

    def test_mac_apple_intelligence_must_default_to_us_node(self) -> None:
        profile = build_mac_profile().replace(
            "🌈 Apple Intelligence = select, 🇺🇸 US Node, ♻️ Auto Selection",
            "🌈 Apple Intelligence = select, ♻️ Auto Selection, 🇺🇸 US Node",
        )
        errors, _ = self.validate(profile, "mac")
        self.assertTrue(any("Apple Intelligence must default to US Node" in item for item in errors))

    def test_mac_final_must_default_to_my_node(self) -> None:
        profile = build_mac_profile().replace(
            "🧭 Final = select, 🫟 My Node, ♻️ Auto Selection, DIRECT",
            "🧭 Final = select, DIRECT, 🫟 My Node, ♻️ Auto Selection",
        )
        errors, _ = self.validate(profile, "mac")
        self.assertTrue(any("macOS Final must default to My Node" in item for item in errors))

    def test_other_ai_service_must_not_reach_ai_dedicated_policy_indirectly(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "Auto Selection = smart, CF, US Node",
            "Auto Selection = smart, CF, Direct-AI, US Node",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("Other AI reaches a dedicated AI policy" in item for item in errors))

    def test_include_other_group_must_be_quoted(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "Final = select, My Node, Auto Selection, DIRECT",
            "Non-HK = smart, include-other-group=US Node,My Node\n"
            "Final = select, My Node, Auto Selection, DIRECT",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("must be one quoted comma-separated value" in item for item in errors))

    def test_taiwan_group_rejects_samoa_flag(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "US Node = smart, CF-us, policy-regex-filter=🇺🇸",
            "US Node = smart, CF-us, policy-regex-filter=🇺🇸\n"
            "TW Node = smart, CF-us, policy-regex-filter=🇼🇸",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("Samoa flag" in item for item in errors))

    def test_retired_webshare_proxy_is_rejected(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "Direct-AI = direct",
            "Direct-AI = direct\nwebshare = http, example.invalid, 8080",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("retired Webshare proxy" in item for item in errors))

    def test_retired_lige_icon_repository_path_is_rejected(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "ChatGPT = select, Direct-AI, CF-AI-Auto",
            "ChatGPT = select, Direct-AI, CF-AI-Auto, "
            "icon-url=https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/chatgpt.png",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("retired lige47 icon repository path" in item for item in errors))

    def test_normal_cf_group_must_include_base_proxy(self) -> None:
        profile = BASE_IOS_PROFILE.replace(
            "policy-regex-filter=(?i)^(?:CF|CF-(?!.*-AI$).+)$",
            "policy-regex-filter=(?i)^CF-(?!.*-AI$).+$",
        )
        errors, _ = self.validate(profile)
        self.assertTrue(any("does not include the base CF proxy" in item for item in errors))


if __name__ == "__main__":
    unittest.main()

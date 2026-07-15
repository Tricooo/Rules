#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path


BUILTIN_POLICIES = {
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "REJECT-NO-DROP",
    "REJECT-TINYGIF",
    "CELLULAR",
    "NO-ERROR",
}

GROUP_TYPES = {
    "select",
    "smart",
    "url-test",
    "fallback",
    "load-balance",
    "subnet",
    "ssid",
}

RULE_TYPES_WITH_POLICY_AT_2 = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "PROCESS-NAME",
    "SRC-IP",
    "DEST-PORT",
    "PROTOCOL",
    "URL-REGEX",
    "USER-AGENT",
    "RULE-SET",
    "DOMAIN-SET",
}

FORBIDDEN_INLINE_AI_SUFFIXES = {
    "icloud.com",
    "apple-dns.net",
    "googleapis.com",
    "googleusercontent.com",
}

APPLE_AI_OFFICIAL_BASELINE = {
    ("DOMAIN", "guzzoni.apple.com"),
    ("DOMAIN-SUFFIX", "smoot.apple.com"),
    ("DOMAIN-SUFFIX", "apple-relay.apple.com"),
    ("DOMAIN-SUFFIX", "apple-relay.cloudflare.com"),
    ("DOMAIN-SUFFIX", "apple-relay.fastly-edge.com"),
    ("DOMAIN", "cp4.cloudflare.com"),
}

APPLE_AI_COMMUNITY_BASELINE = {
    ("DOMAIN-SUFFIX", "siri.apple.com"),
}

APPLE_AI_BASELINE = APPLE_AI_OFFICIAL_BASELINE | APPLE_AI_COMMUNITY_BASELINE

APPLE_AI_CANDIDATE_DOMAINS = {
    "apple-relay.akamaized.net",
    "apple-relay.mask.apple-dns.net",
    "appleintelligencefeedback.care.apple.com",
    "cp10.cloudflare.com",
    "gateway.icloud.com",
    "gspe1-ssl.ls.apple.com",
    "humb.apple.com",
    "sequoia.apple.com",
}

MAINLAND_IPV6_RULESET_URLS = {
    "https://ruleset-mirror.skk.moe/List/ip/china_ip_ipv6.conf",
    "https://ruleset.skk.moe/List/ip/china_ip_ipv6.conf",
}

CHATGPT_RULESET_URL = (
    "https://raw.githubusercontent.com/Tricooo/Rules/release/"
    "rules/production/ai/ChatGPT.list"
)
CHATGPT_VOICE_RULESET_URL = (
    "https://raw.githubusercontent.com/Tricooo/Rules/release/"
    "rules/production/ai/ChatGPTVoice.list"
)
COPILOT_RULESET_URL = (
    "https://raw.githubusercontent.com/Tricooo/Rules/release/"
    "rules/production/ai/Copilot.list"
)
APPLE_NEWS_RULESET_URL = (
    "https://raw.githubusercontent.com/Tricooo/Rules/release/"
    "rules/production/apple/AppleNews.list"
)

AI_POLICY_SUFFIXES = (
    "iCloud Private",
    "ChatGPT",
    "Claude",
    "Gemini",
    "GitHub Copilot",
    "Grok",
    "Apple Intelligence",
    "Perplexity",
    "Other AI",
)

BROAD_PRIORITY_MARKERS = (
    "/Advertising",
    "/Privacy/",
    "ChinaDomain.list",
    "ChinaCompanyIp.list",
    "ChinaIp.list",
    "china_ip_ipv6.conf",
    "surge-rules/release/direct.txt",
    "Apple_All_No_Resolve.list",
)

REGION_FLAGS = {
    "HK Node": "🇭🇰",
    "TW Node": "🇹🇼",
    "JP Node": "🇯🇵",
    "SG Node": "🇸🇬",
    "US Node": "🇺🇸",
    "UK Node": "🇬🇧",
    "MY Node": "🇲🇾",
}

REGION_REQUIRED_ALIASES = {
    "HK Node": ("香港",),
    "TW Node": ("台湾", "臺灣", "桃园", "桃園", "台中", "臺中", "台南", "臺南"),
    "JP Node": ("日本", "东京", "東京"),
    "SG Node": ("新加坡", "狮城", "獅城"),
    "US Node": ("美国", "美國"),
    "UK Node": ("英国", "英國"),
    "MY Node": ("马来西亚", "馬來西亞", "大马", "大馬"),
}

MANUAL_ROOT_GROUP_SUFFIXES = (
    "Manual Selection",
    "Policy Selection",
    "Cloudflare Auto",
    "CF-Auto",
)

EMOJI_RE = re.compile(
    "["
    "\U0001F1E6-\U0001F1FF"
    "\U0001F300-\U0001FAFF"
    "\u2600-\u27BF"
    "\uFE0F"
    "]"
)


def split_fields(value: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False

    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            continue
        if char == "," and not quoted:
            fields.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    fields.append("".join(current).strip())
    return fields


def parse_sections(content: str) -> tuple[dict[str, list[tuple[int, str]]], list[str]]:
    sections: dict[str, list[tuple[int, str]]] = defaultdict(list)
    errors: list[str] = []
    current = ""
    seen_sections: set[str] = set()

    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            if current in seen_sections:
                errors.append(f"line {line_no}: duplicate section [{current}]")
            seen_sections.add(current)
            continue
        if current:
            sections[current].append((line_no, raw_line))

    return sections, errors


def active_lines(section: list[tuple[int, str]]) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    for line_no, raw_line in section:
        line = raw_line.strip()
        if line and not line.startswith("#"):
            result.append((line_no, line))
    return result


def parse_named_entries(section: list[tuple[int, str]], label: str) -> tuple[dict[str, tuple[int, str]], list[str]]:
    entries: dict[str, tuple[int, str]] = {}
    errors: list[str] = []
    for line_no, line in active_lines(section):
        if "=" not in line:
            errors.append(f"line {line_no}: malformed {label} entry")
            continue
        name, value = line.split("=", 1)
        name = name.strip().strip('"')
        if not name:
            errors.append(f"line {line_no}: empty {label} name")
            continue
        if name in entries:
            errors.append(f"line {line_no}: duplicate {label} name {name}")
        entries[name] = (line_no, value.strip())
    return entries, errors


def selector_policy(token: str) -> str | None:
    if "=" not in token:
        return None
    key, value = token.split("=", 1)
    key = key.strip().strip('"').upper()
    value = value.strip().strip('"')
    if key == "DEFAULT" or key.startswith(("SSID:", "BSSID:", "TYPE:", "MCCMNC:", "ROUTED:", "SUBNET:")):
        return value
    return None


def find_named_suffix(entries: dict[str, tuple[int, str]], suffix: str) -> str | None:
    if suffix in entries:
        return suffix
    matches = [name for name in entries if name.endswith(suffix)]
    return matches[0] if len(matches) == 1 else None


def group_members(value: str) -> list[str]:
    members: list[str] = []
    for token in split_fields(value)[1:]:
        token = token.strip().strip('"')
        if token and "=" not in token:
            members.append(token)
    return members


def group_parameter(value: str, key: str) -> str | None:
    prefix = key.lower() + "="
    for token in split_fields(value)[1:]:
        normalized = token.strip().strip('"')
        if normalized.lower().startswith(prefix):
            return normalized.split("=", 1)[1].strip().strip('"')
    return None


def policy_has_suffix(policy: str, suffix: str) -> bool:
    return policy == suffix or policy.endswith(suffix)


def group_reaches_policy_suffix(
    references: dict[str, set[str]],
    group_names: set[str],
    start: str,
    suffixes: tuple[str, ...],
) -> bool:
    """Return whether a group's explicit reference graph reaches a guarded policy."""
    pending = [start]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        for member in references.get(current, set()):
            if any(policy_has_suffix(member, suffix) for suffix in suffixes):
                return True
            if member in group_names and member not in visited:
                pending.append(member)
    return False


def extract_group_references(
    groups: dict[str, tuple[int, str]],
) -> tuple[dict[str, set[str]], list[str]]:
    references: dict[str, set[str]] = defaultdict(set)
    errors: list[str] = []

    for group_name, (line_no, value) in groups.items():
        fields = split_fields(value)
        if not fields or fields[0].lower() not in GROUP_TYPES:
            errors.append(f"line {line_no}: unsupported or missing policy-group type for {group_name}")
            continue
        group_type = fields[0].lower()

        for token in fields[1:]:
            if not token:
                continue
            if token.lower().startswith("include-other-group="):
                value_part = token.split("=", 1)[1].strip().strip('"')
                references[group_name].update(item.strip() for item in value_part.split(",") if item.strip())
                continue
            if group_type in {"subnet", "ssid"}:
                policy = selector_policy(token)
                if policy:
                    references[group_name].add(policy)
                continue
            if "=" in token:
                continue
            references[group_name].add(token.strip().strip('"'))

    return references, errors


def detect_cycles(graph: dict[str, set[str]], group_names: set[str]) -> list[str]:
    errors: list[str] = []
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            start = visiting.index(node)
            errors.append("policy-group cycle: " + " -> ".join([*visiting[start:], node]))
            return
        visiting.append(node)
        for child in graph.get(node, set()):
            if child in group_names:
                visit(child)
        visiting.pop()
        visited.add(node)

    for name in sorted(group_names):
        visit(name)
    return errors


def detect_host_cycles(hosts: dict[str, tuple[int, str]]) -> list[str]:
    graph: dict[str, str] = {}
    for hostname, (_, value) in hosts.items():
        target = value.strip().strip('"').split(",", 1)[0].strip()
        if target.lower().startswith("server:") or target not in hosts:
            continue
        graph[hostname] = target

    errors: list[str] = []
    visited: set[str] = set()
    for start in sorted(graph):
        if start in visited:
            continue
        chain: list[str] = []
        positions: dict[str, int] = {}
        current = start
        while current in graph and current not in visited:
            if current in positions:
                cycle = chain[positions[current] :] + [current]
                errors.append("host mapping cycle: " + " -> ".join(cycle))
                break
            positions[current] = len(chain)
            chain.append(current)
            current = graph[current]
        visited.update(chain)
    return errors


def reachable_policy_groups(
    references: dict[str, set[str]],
    group_names: set[str],
    roots: set[str],
) -> set[str]:
    reachable: set[str] = set()
    pending = list(roots & group_names)
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        pending.extend(
            child
            for child in references.get(current, set())
            if child in group_names and child not in reachable
        )
    return reachable


def validate_profile(path: Path, platform: str) -> tuple[list[str], list[str], dict[str, int]]:
    errors: list[str] = []
    warnings: list[str] = []
    content = path.read_text(encoding="utf-8")
    sections, section_errors = parse_sections(content)
    errors.extend(section_errors)

    proxies, proxy_errors = parse_named_entries(sections.get("Proxy", []), "proxy")
    groups, group_errors = parse_named_entries(sections.get("Proxy Group", []), "policy-group")
    hosts, host_errors = parse_named_entries(sections.get("Host", []), "host")
    errors.extend(proxy_errors)
    errors.extend(group_errors)
    errors.extend(host_errors)

    for name in sorted(set(proxies) & set(groups)):
        errors.append(f"proxy and policy-group share the same name: {name}")
    errors.extend(detect_host_cycles(hosts))

    references, reference_errors = extract_group_references(groups)
    errors.extend(reference_errors)
    defined_policies = set(proxies) | set(groups) | BUILTIN_POLICIES

    general, general_errors = parse_named_entries(sections.get("General", []), "general option")
    errors.extend(general_errors)
    ipv6_enabled = general.get("ipv6", (0, "false"))[1].strip().strip('"').lower() == "true"
    mitm, mitm_errors = parse_named_entries(sections.get("MITM", []), "MITM option")
    errors.extend(mitm_errors)

    for group_name, refs in references.items():
        line_no = groups[group_name][0]
        for ref in sorted(refs):
            if ref not in defined_policies:
                errors.append(f"line {line_no}: policy-group {group_name} references undefined policy {ref}")

    errors.extend(detect_cycles(references, set(groups)))

    for group_name, (line_no, value) in groups.items():
        if "include-other-group" in value.lower() and not re.search(
            r'include-other-group\s*=\s*"[^"]+"', value, re.IGNORECASE
        ):
            errors.append(
                f"line {line_no}: include-other-group in {group_name} must be one quoted comma-separated value"
            )
        if (
            group_parameter(value, "policy-path") is not None
            and group_parameter(value, "update-interval") is None
        ):
            errors.append(
                f"line {line_no}: policy-path group {group_name} must declare update-interval"
            )
    if platform == "ios":
        for name, (line_no, _) in groups.items():
            if EMOJI_RE.search(name):
                errors.append(f"line {line_no}: iOS policy-group name contains Emoji: {name}")
    else:
        for name, (line_no, _) in groups.items():
            if not EMOJI_RE.search(name):
                errors.append(f"line {line_no}: macOS policy-group name must retain Emoji: {name}")

    rules = active_lines(sections.get("Rule", []))
    rule_records: list[tuple[int, str, list[str], str]] = []
    seen_rules: dict[str, int] = {}
    for line_no, line in rules:
        fields = split_fields(line)
        rule_type = fields[0].upper() if fields else ""
        if line in seen_rules:
            warnings.append(f"line {line_no}: duplicate active rule from line {seen_rules[line]}")
        else:
            seen_rules[line] = line_no

        if rule_type == "FINAL":
            policy_index = 1
        elif rule_type in RULE_TYPES_WITH_POLICY_AT_2:
            policy_index = 2
        else:
            continue

        if len(fields) <= policy_index:
            errors.append(f"line {line_no}: malformed {rule_type} rule")
            continue
        policy = fields[policy_index].strip().strip('"')
        rule_records.append((line_no, rule_type, fields, policy))
        if policy not in defined_policies:
            errors.append(f"line {line_no}: rule references undefined policy {policy}")

        if rule_type == "FINAL" and policy.upper() != "DIRECT":
            modifiers = {
                field.strip().strip('"').lower() for field in fields[policy_index + 1 :]
            }
            if "dns-failed" not in modifiers:
                errors.append(f"line {line_no}: proxy-first FINAL must use dns-failed")

        if platform == "ios" and rule_type == "PROCESS-NAME":
            errors.append(f"line {line_no}: PROCESS-NAME is not available on iOS")
        if platform == "mac" and rule_type == "PROCESS-NAME" and policy.upper() == "DIRECT":
            errors.append(
                f"line {line_no}: process-wide DIRECT bypasses service and domain policies; use narrow domain or network rules"
            )

        if rule_type == "DOMAIN-SUFFIX" and len(fields) > 1:
            domain = fields[1].lower().strip().strip('"')
            if domain in FORBIDDEN_INLINE_AI_SUFFIXES:
                errors.append(f"line {line_no}: forbidden broad inline suffix {domain}")

        if "Tricooo/Rules" in line and "/release/rules/production/" not in line:
            errors.append(f"line {line_no}: active Tricooo rule must use the release production path")

        if platform == "ios" and "ACL4SSR/master/Clash/Download.list" in line:
            errors.append(f"line {line_no}: desktop Download.list must not be active on iOS")

        if "rule/Clash/iCloudPrivateRelay" in line:
            errors.append(f"line {line_no}: use the Surge-native iCloud Private Relay list")

        if platform == "ios" and ("/Advertising/" in line or "/Privacy/" in line):
            warnings.append(f"line {line_no}: large filtering list is active in the iOS core profile")

    if not rules:
        errors.append("[Rule] has no active rules")
    elif split_fields(rules[-1][1])[0].upper() != "FINAL":
        errors.append(f"line {rules[-1][0]}: last active rule must be FINAL")

    chatgpt_records = [
        (rule_type, fields[1].strip().strip('"'))
        for _, rule_type, fields, policy in rule_records
        if len(fields) > 1 and policy_has_suffix(policy, "ChatGPT")
    ]
    chatgpt_rulesets = {
        condition for rule_type, condition in chatgpt_records if rule_type == "RULE-SET"
    }
    if CHATGPT_RULESET_URL not in chatgpt_rulesets:
        errors.append("ChatGPT production ruleset is missing")
    if CHATGPT_VOICE_RULESET_URL not in chatgpt_rulesets:
        errors.append("ChatGPT Voice ruleset is missing")
    approved_chatgpt_records = {
        ("RULE-SET", CHATGPT_RULESET_URL),
        ("RULE-SET", CHATGPT_VOICE_RULESET_URL),
    }
    if len(chatgpt_records) != 2 or set(chatgpt_records) != approved_chatgpt_records:
        errors.append("ChatGPT policy may only use the approved domain and Voice rulesets")
    for line_no, rule_type, fields, policy in rule_records:
        if (
            rule_type == "RULE-SET"
            and len(fields) > 1
            and fields[1].strip().strip('"') == CHATGPT_VOICE_RULESET_URL
            and policy_has_suffix(policy, "ChatGPT")
        ):
            modifiers = {field.strip().strip('"').lower() for field in fields[3:]}
            if "no-resolve" not in modifiers:
                errors.append(f"line {line_no}: ChatGPT Voice ruleset must use no-resolve")

    copilot_records = [
        (rule_type, fields[1].strip().strip('"'))
        for _, rule_type, fields, policy in rule_records
        if len(fields) > 1 and policy_has_suffix(policy, "GitHub Copilot")
    ]
    copilot_rulesets = {
        condition for rule_type, condition in copilot_records if rule_type == "RULE-SET"
    }
    if COPILOT_RULESET_URL not in copilot_rulesets:
        errors.append("Copilot production ruleset is missing")
    if len(copilot_records) != 1 or set(copilot_records) != {
        ("RULE-SET", COPILOT_RULESET_URL)
    }:
        errors.append("GitHub Copilot policy may only use the approved production ruleset")

    webshare_names = [name for name in proxies if "webshare" in name.lower()]
    for name in webshare_names:
        errors.append(f"line {proxies[name][0]}: retired Webshare proxy is still active")

    skip_proxy = general.get("skip-proxy")
    if skip_proxy and "17.0.0.0/8" in split_fields(skip_proxy[1]):
        errors.append(
            f"line {skip_proxy[0]}: skip-proxy must not bypass Apple's entire 17.0.0.0/8 network"
        )

    encrypted_follow = general.get("encrypted-dns-follow-outbound-mode")
    if encrypted_follow and encrypted_follow[1].strip().lower() != "false":
        warnings.append(
            f"line {encrypted_follow[0]}: encrypted DNS now follows outbound mode; verify bootstrap and DNS policy"
        )

    tun_excluded = general.get("tun-excluded-routes")
    if tun_excluded:
        excluded = {item.strip() for item in split_fields(tun_excluded[1])}
        if {"224.0.0.0/4", "239.0.0.0/8"} <= excluded:
            errors.append(
                f"line {tun_excluded[0]}: 239.0.0.0/8 is redundant when 224.0.0.0/4 is excluded"
            )
        if "224.0.0.0/4" in excluded:
            for line_no, rule_type, fields, _ in rule_records:
                condition = fields[1].strip().strip('"') if len(fields) > 1 else ""
                if rule_type == "IP-CIDR" and condition in {
                    "224.0.0.0/4",
                    "239.0.0.0/8",
                }:
                    errors.append(
                        f"line {line_no}: multicast rule {condition} is redundant because "
                        "tun-excluded-routes already excludes 224.0.0.0/4"
                    )

    for option in ("http-listen", "socks5-listen"):
        listen = general.get(option)
        if platform == "ios" and listen:
            errors.append(f"line {listen[0]}: {option} is a macOS-only listener in this profile contract")
        elif listen and not re.fullmatch(r"127\.0\.0\.1:\d+", listen[1].strip()):
            errors.append(f"line {listen[0]}: {option} must bind to 127.0.0.1 with an explicit port")
    if platform == "ios" and "read-etc-hosts" in general:
        errors.append(
            f"line {general['read-etc-hosts'][0]}: read-etc-hosts is not part of the iOS profile contract"
        )

    if mitm and "hostname" not in mitm:
        warnings.append(
            "[MITM] contains CA material but the profile declares no hostname; modules may add targets, and all CA values must be redacted before sharing"
        )

    platform_label = "iOS" if platform == "ios" else "macOS"
    ai_egress = find_named_suffix(groups, "AI Egress")
    if ai_egress is not None:
        errors.append(
            f"line {groups[ai_egress][0]}: {platform_label} must not define AI Egress"
        )

    ai_defaults = (
        ("ChatGPT", "Direct-AI"),
        ("Claude", "Direct-AI"),
        ("Gemini", "Direct-AI"),
        ("GitHub Copilot", "Auto Selection"),
        ("Perplexity", "Auto Selection"),
        ("Other AI", "Auto Selection"),
        ("Grok", "Auto Selection"),
        ("Apple Intelligence", "US Node"),
    )
    dedicated_suffixes = ("Direct-AI", "CF-AI-Auto", "AI Egress")
    for suffix, expected_default in ai_defaults:
        name = find_named_suffix(groups, suffix)
        if name is None:
            errors.append(f"missing {suffix} policy group")
            continue
        service_members = group_members(groups[name][1])
        if not service_members or not policy_has_suffix(service_members[0], expected_default):
            errors.append(
                f"line {groups[name][0]}: {name} must default to {expected_default}"
            )
        if suffix in {"ChatGPT", "Claude", "Gemini"}:
            invalid_members = [
                member
                for member in service_members
                if not any(
                    policy_has_suffix(member, allowed)
                    for allowed in ("Direct-AI", "CF-AI-Auto")
                )
            ]
            if invalid_members:
                errors.append(
                    f"line {groups[name][0]}: {name} may only use dedicated AI policies"
                )
            continue

        has_direct_dedicated = any(
            policy_has_suffix(member, dedicated)
            for member in service_members
            for dedicated in dedicated_suffixes
        )
        if has_direct_dedicated:
            errors.append(
                f"line {groups[name][0]}: {name} must not use dedicated AI policies"
            )
        elif group_reaches_policy_suffix(
            references, set(groups), name, dedicated_suffixes
        ):
            errors.append(
                f"line {groups[name][0]}: {name} reaches a dedicated AI policy through another group"
            )

    final_group = find_named_suffix(groups, "Final")
    if final_group is None:
        errors.append("missing Final policy group")
    else:
        final_members = group_members(groups[final_group][1])
        if not final_members:
            errors.append(f"line {groups[final_group][0]}: Final policy group has no policies")
        elif not policy_has_suffix(final_members[0], "My Node"):
            errors.append(
                f"line {groups[final_group][0]}: {platform_label} Final must default to My Node"
            )
        if final_members and any(
            policy_has_suffix(final_members[0], suffix)
            for suffix in ("ChatGPT", "AI Egress", "Apple Intelligence")
        ):
            errors.append(f"line {groups[final_group][0]}: Final must not default to an AI policy")

    for suffix in ("X", "Reddit", "Proxy Media", "Google FCM"):
        name = find_named_suffix(groups, suffix)
        if name is None or not any(policy == name for _, _, _, policy in rule_records):
            continue
        members = group_members(groups[name][1])
        if not members or not policy_has_suffix(members[0], "My Node"):
            errors.append(f"line {groups[name][0]}: {name} must default to My Node")

    for suffix, expected_flag in REGION_FLAGS.items():
        name = find_named_suffix(groups, suffix)
        if name is None:
            continue
        value = groups[name][1]
        if expected_flag not in value:
            errors.append(f"line {groups[name][0]}: {name} is missing region flag {expected_flag}")
        if suffix == "TW Node" and "🇼🇸" in value:
            errors.append(f"line {groups[name][0]}: Taiwan group contains the Samoa flag")
        if re.search(r"(?:^|[|(])(?:港|台|新)(?=[|)])", value):
            errors.append(f"line {groups[name][0]}: {name} contains an over-broad single-character region match")
        if group_parameter(value, "policy-path") is None:
            continue
        pattern = group_parameter(value, "policy-regex-filter")
        if not pattern:
            errors.append(f"line {groups[name][0]}: {name} is missing policy-regex-filter")
            continue
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            errors.append(f"line {groups[name][0]}: invalid region regex in {name}: {exc}")
            continue
        for alias in REGION_REQUIRED_ALIASES[suffix]:
            if compiled.search(alias) is None:
                errors.append(f"line {groups[name][0]}: {name} regex is missing alias {alias}")
        if suffix == "US Node" and any(
            compiled.search(sample)
            for sample in (
                "America",
                "North America",
                "South America",
                "Central America",
                "Latin America",
            )
        ):
            errors.append(f"line {groups[name][0]}: US Node regex must not match bare America")

    rule_group_roots = {
        policy for _, _, _, policy in rule_records if policy in groups
    }
    manual_group_roots = {
        name
        for name in groups
        if any(
            policy_has_suffix(name, suffix)
            for suffix in MANUAL_ROOT_GROUP_SUFFIXES
        )
    }
    reachable_groups = reachable_policy_groups(
        references,
        set(groups),
        rule_group_roots | manual_group_roots,
    )
    for group_name, (line_no, _) in groups.items():
        if group_name not in reachable_groups:
            errors.append(f"line {line_no}: unused policy group {group_name}")

    if platform == "ios":
        my_node = find_named_suffix(groups, "My Node")
        if my_node is None:
            errors.append("missing iOS My Node subnet group")
        else:
            value = groups[my_node][1]
            fields = split_fields(value)
            if not fields or fields[0].lower() != "subnet":
                errors.append(f"line {groups[my_node][0]}: iOS My Node must be a subnet group")
            for selector in ("TYPE:CELLULAR", "SSID:Entrance"):
                if selector not in value:
                    errors.append(f"line {groups[my_node][0]}: iOS My Node is missing {selector}")
    else:
        auto_ssid = find_named_suffix(groups, "Auto-SSID")
        my_node = find_named_suffix(groups, "My Node")
        if auto_ssid is None or split_fields(groups[auto_ssid][1])[0].lower() != "subnet":
            errors.append("macOS Auto-SSID must be a subnet group")
        else:
            value = groups[auto_ssid][1]
            if "SSID:Entrance" not in value:
                errors.append(f"line {groups[auto_ssid][0]}: macOS Auto-SSID is missing SSID:Entrance")
            if "BSSID:" in value:
                warnings.append(
                    f"line {groups[auto_ssid][0]}: BSSID selector is device-specific; confirm the old company Wi-Fi is still used"
                )
        if my_node is None or not group_members(groups[my_node][1]):
            errors.append("macOS My Node must reference Auto-SSID")
        elif group_members(groups[my_node][1])[0] != auto_ssid:
            errors.append(f"line {groups[my_node][0]}: macOS My Node must default to Auto-SSID")
        global_direct = find_named_suffix(groups, "Global Direct")
        if global_direct is None:
            errors.append("missing macOS Global Direct policy group")
        else:
            direct_members = group_members(groups[global_direct][1])
            if not direct_members or direct_members[0].upper() != "DIRECT":
                errors.append(
                    f"line {groups[global_direct][0]}: macOS Global Direct must default to DIRECT"
                )
        apple_news = find_named_suffix(groups, "Apple News")
        if apple_news is None:
            errors.append("missing macOS Apple News policy group")
        else:
            if apple_news != "📰 Apple News":
                errors.append(
                    f"line {groups[apple_news][0]}: macOS Apple News policy group "
                    "must be named 📰 Apple News"
                )
            apple_news_members = group_members(groups[apple_news][1])
            if not apple_news_members or not policy_has_suffix(
                apple_news_members[0], "US Node"
            ):
                errors.append(
                    f"line {groups[apple_news][0]}: macOS Apple News must default to US Node"
                )
            apple_news_rule_lines = [
                line_no
                for line_no, _, _, policy in rule_records
                if policy == apple_news
            ]
            if not apple_news_rule_lines:
                errors.append(
                    f"line {groups[apple_news][0]}: macOS Apple News policy group "
                    "must be referenced by an active rule"
                )
            apple_policy = find_named_suffix(groups, "Apple")
            apple_rule_lines = [
                line_no
                for line_no, _, _, policy in rule_records
                if apple_policy is not None and policy == apple_policy
            ]
            if (
                apple_news_rule_lines
                and apple_rule_lines
                and min(apple_news_rule_lines) >= min(apple_rule_lines)
            ):
                errors.append(
                    f"line {min(apple_news_rule_lines)}: Apple News rules must precede ordinary Apple rules"
                )

    normal_cf_group = find_named_suffix(groups, "Cloudflare Auto" if platform == "ios" else "CF-Auto")
    ai_cf_group = find_named_suffix(groups, "CF-AI-Auto")
    base_cf = next((name for name in proxies if name == "CF" or name.endswith(" CF")), None)
    ai_proxy = next((name for name in proxies if "CF-" in name and name.endswith("-AI")), None)
    if normal_cf_group and base_cf:
        pattern = group_parameter(groups[normal_cf_group][1], "policy-regex-filter")
        try:
            if not pattern or re.search(pattern, base_cf) is None:
                errors.append(
                    f"line {groups[normal_cf_group][0]}: normal CF auto group does not include the base CF proxy"
                )
            if pattern and ai_proxy and re.search(pattern, ai_proxy):
                errors.append(
                    f"line {groups[normal_cf_group][0]}: normal CF auto group also matches an AI proxy"
                )
        except re.error as exc:
            errors.append(f"line {groups[normal_cf_group][0]}: invalid CF regex: {exc}")
    if ai_cf_group and ai_proxy and base_cf:
        pattern = group_parameter(groups[ai_cf_group][1], "policy-regex-filter")
        try:
            if not pattern or re.search(pattern, ai_proxy) is None:
                errors.append(f"line {groups[ai_cf_group][0]}: AI CF auto group matches no AI proxy")
            if pattern and re.search(pattern, base_cf):
                errors.append(f"line {groups[ai_cf_group][0]}: AI CF auto group matches the base CF proxy")
        except re.error as exc:
            errors.append(f"line {groups[ai_cf_group][0]}: invalid AI CF regex: {exc}")

    ai_positions = [
        line_no
        for line_no, _, _, policy in rule_records
        if any(policy_has_suffix(policy, suffix) for suffix in AI_POLICY_SUFFIXES)
    ]
    broad_positions = [
        line_no
        for line_no, _, fields, _ in rule_records
        if any(marker in ",".join(fields) for marker in BROAD_PRIORITY_MARKERS)
    ]
    if ai_positions and broad_positions and max(ai_positions) > min(broad_positions):
        errors.append(
            f"line {min(broad_positions)}: broad/direct/filter rules must come after all iCloud and AI rules"
        )

    icloud_positions = [
        line_no
        for line_no, _, _, policy in rule_records
        if policy_has_suffix(policy, "iCloud Private")
    ]
    apple_ai_records = [
        (line_no, rule_type, fields)
        for line_no, rule_type, fields, policy in rule_records
        if policy_has_suffix(policy, "Apple Intelligence")
    ]
    if icloud_positions and apple_ai_records and min(icloud_positions) > min(
        line_no for line_no, _, _ in apple_ai_records
    ):
        errors.append("iCloud Private Relay rules must precede Apple Intelligence rules")

    apple_ai_conditions = {
        (rule_type, fields[1].lower().strip().strip('"'))
        for _, rule_type, fields in apple_ai_records
        if len(fields) > 1 and rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}
    }
    for missing in sorted(APPLE_AI_BASELINE - apple_ai_conditions):
        errors.append(f"Apple Intelligence baseline is missing {missing[0]},{missing[1]}")
    for line_no, rule_type, fields in apple_ai_records:
        candidate_domain = (
            fields[1].lower().strip().strip('"') if len(fields) > 1 else ""
        )
        if (
            rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}
            and candidate_domain in APPLE_AI_CANDIDATE_DOMAINS
        ):
            errors.append(
                f"line {line_no}: Apple Intelligence candidate {candidate_domain} "
                "requires request-log promotion"
            )
    for line_no, rule_type, _ in apple_ai_records:
        if rule_type in {"IP-CIDR", "IP-CIDR6", "GEOIP"}:
            errors.append(f"line {line_no}: Apple Intelligence must not use broad IP or GEOIP rules")
    if platform == "mac" and not any(
        rule_type == "PROCESS-NAME"
        and len(fields) > 1
        and fields[1].strip().strip('"') == "assistantd"
        for _, rule_type, fields in apple_ai_records
    ):
        errors.append("macOS Apple Intelligence baseline is missing PROCESS-NAME,assistantd")

    copilot = next(
        (
            line_no
            for line_no, _, _, policy in rule_records
            if policy_has_suffix(policy, "GitHub Copilot")
        ),
        None,
    )
    github = next(
        (line_no for line_no, _, fields, _ in rule_records if "/GitHub/" in ",".join(fields)),
        None,
    )
    if copilot and github and copilot > github:
        errors.append(f"line {github}: generic GitHub rule must come after Copilot")

    mainland_ipv6_records = [
        (line_no, fields, policy)
        for line_no, rule_type, fields, policy in rule_records
        if rule_type == "RULE-SET"
        and len(fields) > 1
        and fields[1].strip().strip('"') in MAINLAND_IPV6_RULESET_URLS
    ]
    if ipv6_enabled and not mainland_ipv6_records:
        errors.append("mainland IPv6 ruleset is missing")
    elif len(mainland_ipv6_records) > 1:
        errors.append("mainland IPv6 ruleset must be referenced exactly once")

    for line_no, fields, policy in mainland_ipv6_records:
        expected_direct_policy = (
            "DIRECT" if platform == "ios" else find_named_suffix(groups, "Global Direct")
        )
        if policy != expected_direct_policy:
            errors.append(f"line {line_no}: mainland IPv6 ruleset must use a direct policy")
        modifiers = {field.strip().strip('"').lower() for field in fields[3:]}
        if "no-resolve" not in modifiers:
            errors.append(f"line {line_no}: mainland IPv6 ruleset must use no-resolve")

    mainland_ipv6_positions = [line_no for line_no, _, _ in mainland_ipv6_records]
    proxy_gfw_positions = [
        line_no
        for line_no, _, fields, _ in rule_records
        if "ProxyGFWlist.list" in ",".join(fields)
    ]
    if (
        mainland_ipv6_positions
        and proxy_gfw_positions
        and min(mainland_ipv6_positions) < max(proxy_gfw_positions)
    ):
        errors.append("mainland IPv6 ruleset must follow proxy/GFW rules")

    final_positions = [
        line_no for line_no, rule_type, _, _ in rule_records if rule_type == "FINAL"
    ]
    if mainland_ipv6_positions and final_positions and max(mainland_ipv6_positions) > min(
        final_positions
    ):
        errors.append("mainland IPv6 ruleset must precede FINAL")

    china_ip = any("ChinaIp.list" in ",".join(fields) for _, _, fields, _ in rule_records)
    geoip_cn = any(
        rule_type == "GEOIP" and len(fields) > 1 and fields[1].upper() == "CN"
        for _, rule_type, fields, _ in rule_records
    )
    if china_ip and geoip_cn:
        errors.append("ChinaIp.list duplicates the active GEOIP,CN fallback")

    filter_positions = [
        line_no
        for line_no, _, fields, _ in rule_records
        if "/Advertising" in ",".join(fields) or "/Privacy/" in ",".join(fields)
    ]
    geoip_positions = [
        line_no
        for line_no, rule_type, fields, _ in rule_records
        if rule_type == "GEOIP" and len(fields) > 1 and fields[1].upper() == "CN"
    ]
    if mainland_ipv6_positions and not geoip_positions:
        errors.append("mainland IPv6 ruleset requires a preceding GEOIP,CN fallback")
    elif mainland_ipv6_positions and min(mainland_ipv6_positions) < max(geoip_positions):
        errors.append("mainland IPv6 ruleset must follow GEOIP,CN")
    for mainland_line in mainland_ipv6_positions:
        earlier_records = [record for record in rule_records if record[0] < mainland_line]
        if not earlier_records:
            continue
        _, previous_type, previous_fields, _ = max(
            earlier_records, key=lambda record: record[0]
        )
        if not (
            previous_type == "GEOIP"
            and len(previous_fields) > 1
            and previous_fields[1].upper() == "CN"
        ):
            errors.append("mainland IPv6 ruleset must immediately follow GEOIP,CN")
    if filter_positions and geoip_positions and min(filter_positions) < max(geoip_positions):
        errors.append(
            f"line {min(filter_positions)}: optional ad/privacy filters must follow the domestic GEOIP fallback"
        )

    stats = {
        "proxies": len(proxies),
        "groups": len(groups),
        "rules": len(rules),
    }
    return errors, warnings, stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a Surge profile without printing secrets")
    parser.add_argument("--platform", choices=("ios", "mac"), required=True)
    parser.add_argument("profile", type=Path)
    args = parser.parse_args()

    errors, warnings, stats = validate_profile(args.profile, args.platform)
    for item in warnings:
        print(f"WARNING: {item}")
    for item in errors:
        print(f"ERROR: {item}", file=sys.stderr)

    if errors:
        print(f"Validation failed with {len(errors)} error(s)", file=sys.stderr)
        return 1

    print(
        f"Validated {args.platform} profile: "
        f"{stats['proxies']} proxies, {stats['groups']} groups, {stats['rules']} active rules"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

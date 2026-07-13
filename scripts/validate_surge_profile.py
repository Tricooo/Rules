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

EMOJI_RE = re.compile(
    "["
    "\U0001F1E6-\U0001F1FF"
    "\U0001F300-\U0001FAFF"
    "\u2600-\u27BF"
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


def validate_profile(path: Path, platform: str) -> tuple[list[str], list[str], dict[str, int]]:
    errors: list[str] = []
    warnings: list[str] = []
    content = path.read_text(encoding="utf-8")
    sections, section_errors = parse_sections(content)
    errors.extend(section_errors)

    proxies, proxy_errors = parse_named_entries(sections.get("Proxy", []), "proxy")
    groups, group_errors = parse_named_entries(sections.get("Proxy Group", []), "policy-group")
    errors.extend(proxy_errors)
    errors.extend(group_errors)

    references, reference_errors = extract_group_references(groups)
    errors.extend(reference_errors)
    defined_policies = set(proxies) | set(groups) | BUILTIN_POLICIES

    for group_name, refs in references.items():
        line_no = groups[group_name][0]
        for ref in sorted(refs):
            if ref not in defined_policies:
                errors.append(f"line {line_no}: policy-group {group_name} references undefined policy {ref}")

    errors.extend(detect_cycles(references, set(groups)))

    if platform == "ios":
        for name, (line_no, _) in groups.items():
            if EMOJI_RE.search(name):
                errors.append(f"line {line_no}: iOS policy-group name contains Emoji: {name}")
    elif not any(EMOJI_RE.search(name) for name in groups):
        warnings.append("macOS profile has no Emoji policy-group names")

    rules = active_lines(sections.get("Rule", []))
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
        if policy not in defined_policies:
            errors.append(f"line {line_no}: rule references undefined policy {policy}")

        if platform == "ios" and rule_type == "PROCESS-NAME":
            errors.append(f"line {line_no}: PROCESS-NAME is not available on iOS")

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

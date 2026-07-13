#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_ROOT = ROOT / "rules" / "production"
LEGACY_ACTIVE = [
    ROOT / "AI" / "Claude.list",
    ROOT / "AI" / "Gemini.list",
    ROOT / "AI" / "Gork.list",
    ROOT / "AI" / "Grok.list",
    ROOT / "AI" / "Perplexity.list",
    ROOT / "AI" / "Other AI.list",
    ROOT / "AI" / "OtherAI.list",
    ROOT / "AI" / "Apple Intelligence.list",
    ROOT / "Direct.list",
]

DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
IP_TYPES = {"IP-CIDR", "IP-CIDR6"}
OTHER_TYPES = {"GEOIP", "PROCESS-NAME", "URL-REGEX"}
ALLOWED_TYPES = DOMAIN_TYPES | IP_TYPES | OTHER_TYPES

DANGEROUS_AI_SUFFIXES = {
    "apple.com",
    "apple-dns.net",
    "browser-intake-datadoghq.com",
    "cloudflare.com",
    "featureassets.org",
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "icloud.com",
    "launchdarkly.com",
    "mzstatic.com",
}


def error(errors: list[str], path: Path, line_no: int | None, message: str) -> None:
    rel = path.relative_to(ROOT)
    location = f"{rel}:{line_no}" if line_no is not None else str(rel)
    errors.append(f"{location}: {message}")


def validate_file(path: Path, require_metadata: bool) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    normalized_rules: list[str] = []
    data = path.read_bytes()

    if not data.endswith(b"\n"):
        error(errors, path, None, "file must end with a newline")

    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        error(errors, path, None, f"not valid UTF-8: {exc}")
        return errors, normalized_rules

    comments = [line.strip() for line in content.splitlines() if line.strip().startswith("#")]
    if require_metadata:
        required = ("# Purpose:", "# Last reviewed:")
        for prefix in required:
            if not any(line.startswith(prefix) for line in comments):
                error(errors, path, None, f"missing metadata comment {prefix}")
        if not any(line.startswith("# Source:") or line.startswith("# Sources:") for line in comments):
            error(errors, path, None, "missing # Source: or # Sources: metadata")
        if " " in path.name:
            error(errors, path, None, "production filenames must not contain spaces")

    seen: dict[str, int] = {}
    exact_domains: list[tuple[str, int]] = []
    suffix_domains: list[tuple[str, int]] = []

    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if raw_line != line:
            error(errors, path, line_no, "rule line has leading or trailing whitespace")
        if "//" in line:
            error(errors, path, line_no, "inline // comments are not allowed")

        fields = line.split(",")
        if any(field != field.strip() for field in fields):
            error(errors, path, line_no, "fields must not contain surrounding whitespace")
        fields = [field.strip() for field in fields]
        rule_type = fields[0].upper()

        if rule_type not in ALLOWED_TYPES:
            error(errors, path, line_no, f"unsupported rule type {fields[0]}")
            continue

        if rule_type in DOMAIN_TYPES | {"PROCESS-NAME", "URL-REGEX"}:
            if len(fields) != 2:
                error(errors, path, line_no, "rule-set entry must contain condition only, not a policy")
                continue
        elif rule_type in IP_TYPES | {"GEOIP"}:
            if len(fields) not in (2, 3):
                error(errors, path, line_no, "invalid field count")
                continue
            if len(fields) == 3 and fields[2] != "no-resolve":
                error(errors, path, line_no, "third field may only be no-resolve")
                continue

        condition = fields[1]
        if not condition:
            error(errors, path, line_no, "empty rule condition")
            continue

        if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
            domain = condition.lower().rstrip(".")
            if any(char.isspace() for char in domain) or "/" in domain or ":" in domain:
                error(errors, path, line_no, f"invalid domain {condition}")
            if domain != condition:
                error(errors, path, line_no, "domains must be lowercase without a trailing dot")
            if rule_type == "DOMAIN":
                exact_domains.append((domain, line_no))
            else:
                suffix_domains.append((domain, line_no))
                if domain in DANGEROUS_AI_SUFFIXES:
                    error(errors, path, line_no, f"dangerously broad suffix {domain}")

        if rule_type in IP_TYPES:
            try:
                network = ipaddress.ip_network(condition, strict=False)
                if rule_type == "IP-CIDR" and network.version != 4:
                    raise ValueError("expected IPv4")
                if rule_type == "IP-CIDR6" and network.version != 6:
                    raise ValueError("expected IPv6")
            except ValueError as exc:
                error(errors, path, line_no, f"invalid CIDR {condition}: {exc}")

        normalized = ",".join([rule_type, *fields[1:]])
        if normalized in seen:
            error(errors, path, line_no, f"duplicate of line {seen[normalized]}")
        else:
            seen[normalized] = line_no
            normalized_rules.append(normalized)

    for domain, line_no in exact_domains:
        for suffix, suffix_line in suffix_domains:
            if domain == suffix or domain.endswith("." + suffix):
                error(errors, path, line_no, f"DOMAIN is already covered by suffix on line {suffix_line}")
                break

    for index, (suffix, line_no) in enumerate(suffix_domains):
        for other, other_line in suffix_domains[index + 1 :]:
            if suffix.endswith("." + other):
                error(errors, path, line_no, f"suffix is already covered by line {other_line}")
            elif other.endswith("." + suffix):
                error(errors, path, other_line, f"suffix is already covered by line {line_no}")

    return errors, normalized_rules


def main() -> int:
    production_files = sorted(PRODUCTION_ROOT.rglob("*.list"))
    files = production_files + [path for path in LEGACY_ACTIVE if path.exists()]
    if not production_files:
        print("No production rule files found", file=sys.stderr)
        return 1

    all_errors: list[str] = []
    global_rules: dict[str, Path] = {}

    for path in files:
        errors, rules = validate_file(path, path.is_relative_to(PRODUCTION_ROOT))
        all_errors.extend(errors)
        if path.is_relative_to(PRODUCTION_ROOT):
            for rule in rules:
                previous = global_rules.get(rule)
                if previous is not None:
                    error(all_errors, path, None, f"duplicates production rule in {previous.relative_to(ROOT)}")
                else:
                    global_rules[rule] = path

    if all_errors:
        print("Rule validation failed:", file=sys.stderr)
        for item in all_errors:
            print(f"- {item}", file=sys.stderr)
        return 1

    print(f"Validated {len(files)} files and {len(global_rules)} production rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

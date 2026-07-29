from pathlib import Path
import re

SOURCE = Path("blocklist.txt")
OUTPUT = Path("blocklistredirect.txt")
REDIRECT_IP = "10.200.200.1"

# Supported formats:
#
# ||example.com^
# ||example.com^$modifier
# ||*.example.com^
# ||*.ru^
# example.com

adguard_rule = re.compile(
    r"^\|\|(\*\.)?([A-Za-z0-9.-]+)\^(?:\$.*)?$"
)

plain_domain = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)$"
)

patterns = []
seen = set()
skipped = 0

source_text = SOURCE.read_text(
    encoding="utf-8",
    errors="replace",
)

for raw_line in source_text.splitlines():
    line = raw_line.strip()

    if not line:
        continue

    if line.startswith(("!", "#")):
        continue

    match = adguard_rule.fullmatch(line)

    if match:
        wildcard = match.group(1) or ""
        domain = match.group(2).lower().rstrip(".")
        pattern = f"{wildcard}{domain}"
    else:
        match = plain_domain.fullmatch(line)

        if not match:
            skipped += 1
            continue

        pattern = match.group(1).lower().rstrip(".")

    if pattern in seen:
        continue

    seen.add(pattern)
    patterns.append(pattern)

output_lines = [
    "! Title: Redirected blocklist",
    "! Generated automatically from blocklist.txt.",
    f"! Redirect IPv4: {REDIRECT_IP}",
    f"! Generated rules: {len(patterns) * 2}",
    f"! Source patterns: {len(patterns)}",
    f"! Unsupported source rules skipped: {skipped}",
    "!",
]

for pattern in patterns:
    output_lines.append(
        f"||{pattern}^"
        f"$dnsrewrite=NOERROR;A;{REDIRECT_IP}"
    )

    output_lines.append(
        f"||{pattern}^"
        "$dnsrewrite=NOERROR;AAAA;"
    )

OUTPUT.write_text(
    "\n".join(output_lines) + "\n",
    encoding="utf-8",
)

print(
    f"Generated {OUTPUT} with "
    f"{len(patterns) * 2} redirect rules."
)

print(
    f"Skipped {skipped} unsupported source rules."
)

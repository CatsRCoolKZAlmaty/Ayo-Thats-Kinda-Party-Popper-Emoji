from pathlib import Path
import re

SOURCE = Path("blocklist.txt")
OUTPUT = Path("blocklistredirect.txt")
REDIRECT_IP = "10.200.200.1"

# Supports:
# ||example.com^
# ||example.com^$modifier
# example.com
adguard_rule = re.compile(
    r"^\|\|([A-Za-z0-9.-]+)\^(?:\$.*)?$"
)
plain_domain = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)$"
)

domains = []
seen = set()
skipped = 0

for raw_line in SOURCE.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()

    if not line or line.startswith(("!", "#")):
        continue

    match = adguard_rule.fullmatch(line)
    if not match:
        match = plain_domain.fullmatch(line)

    if not match:
        skipped += 1
        continue

    domain = match.group(1).lower().rstrip(".")

    if domain not in seen:
        seen.add(domain)
        domains.append(domain)

output = [
    "! Title: Redirected blocklist",
    "! This file is generated automatically from blocklist.txt.",
    f"! Redirect IPv4: {REDIRECT_IP}",
    f"! Domains: {len(domains)}",
    f"! Unsupported rules skipped: {skipped}",
    "!",
]

for domain in domains:
    output.extend([
        f"||{domain}^$dnsrewrite=NOERROR;A;{REDIRECT_IP}",
        f"||{domain}^$dnsrewrite=NOERROR;AAAA;",
    ])

OUTPUT.write_text("\n".join(output) + "\n", encoding="utf-8")

print(f"Generated {OUTPUT} with {len(domains)} domains.")
print(f"Skipped {skipped} unsupported rules.")

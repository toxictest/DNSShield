#!/usr/bin/env bash
# ==============================================================================
#  DNSShield validation suite
#   - Drives the tool through a stub `dig` that replays canned resolver
#     answers, so every module can be tested deterministically, including the
#     cases that are hard to find on the live Internet (an open AXFR, a
#     dangling CNAME).
#   - Checks the CLI, the report path, the timestamped copy and the
#     ANSI-free output.
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DNSSHIELD="${DNSSHIELD_BIN:-$SCRIPT_DIR/../dnsshield.sh}"
FIXTURES="$(mktemp -d "${TMPDIR:-/tmp}/dnsshield-test.XXXXXX")"
STUB_BIN="$FIXTURES/bin"
FIX="$FIXTURES/dns"
REPORT="$FIXTURES/report.txt"

PASS=0; FAIL=0
C_G=""; C_R=""; C_0=""
if [[ -t 1 ]]; then C_G=$'\033[1;32m'; C_R=$'\033[1;31m'; C_0=$'\033[0m'; fi

cleanup() {
    rm -rf "$FIXTURES" 2>/dev/null || true
}
trap cleanup EXIT

assert_contains() {
    local label="$1" needle="$2"
    if grep -qF -- "$needle" "$REPORT" 2>/dev/null; then
        printf '  %s✔%s %-56s %sdetected%s\n' "$C_G" "$C_0" "$label" "$C_G" "$C_0"; PASS=$((PASS+1))
    else
        printf '  %s✘%s %-56s %sMISSING%s\n' "$C_R" "$C_0" "$label" "$C_R" "$C_0"; FAIL=$((FAIL+1))
    fi
}

assert_absent() {
    local label="$1" needle="$2"
    if grep -qF -- "$needle" "$REPORT" 2>/dev/null; then
        printf '  %s✘%s %-56s %sFALSE POSITIVE%s\n' "$C_R" "$C_0" "$label" "$C_R" "$C_0"; FAIL=$((FAIL+1))
    else
        printf '  %s✔%s %-56s %sabsent%s\n' "$C_G" "$C_0" "$label" "$C_G" "$C_0"; PASS=$((PASS+1))
    fi
}

assert_file() {
    local label="$1" path="$2"
    if [[ -f "$path" ]]; then
        printf '  %s✔%s %-56s %sexists%s\n' "$C_G" "$C_0" "$label" "$C_G" "$C_0"; PASS=$((PASS+1))
    else
        printf '  %s✘%s %-56s %smissing%s\n' "$C_R" "$C_0" "$label" "$C_R" "$C_0"; FAIL=$((FAIL+1))
    fi
}

# ---------------------------------------------------------------- fixtures --
printf 'Building fixtures in %s\n' "$FIXTURES"
mkdir -p "$STUB_BIN" "$FIX"

# --- the stub dig -----------------------------------------------------------
cat >"$STUB_BIN/dig" <<'STUBEOF'
#!/usr/bin/env bash
# Minimal dig stub. Answers from $DIG_FIXTURE_DIR/<KEY>.txt where KEY is
# "<TYPE>.<sanitised name>"; an optional "<KEY>.status" file sets the rcode.
set -uo pipefail
DIR="${DIG_FIXTURE_DIR:-}"
short=0; qtype=""; qname=""; server=""
for a in "$@"; do
    case "$a" in
        +short) short=1 ;;
        +noall|+answer|+time=*|+tries=*|+dnssec) ;;
        @*) server="${a#@}" ;;
        -*) ;;
        *) if [[ -z "$qtype" ]]; then qtype="$a"; else qname="$a"; fi ;;
    esac
done
sanitise() { printf '%s' "$1" | sed 's/[^A-Za-z0-9-]/_/g'; }
key="$(sanitise "$qtype")_$(sanitise "$qname")"
if [[ "$qtype" == "AXFR" ]]; then
    key="AXFR_$(sanitise "$server")_$(sanitise "$qname")"
fi
file="$DIR/$key.txt"
status_file="$DIR/$key.status"
status="NOERROR"
[[ -f "$status_file" ]] && status=$(cat "$status_file")
# a WILDCARD_<TYPE>.txt answers any name that has no exact fixture
[[ -f "$file" ]] || file="$DIR/WILDCARD_$(sanitise "$qtype").txt"

if [[ ! -f "$file" ]]; then
    # No canned answer: behave like a name that does not exist. Real dig
    # prints NOTHING at all in +short mode, which is what callers rely on.
    if [[ "$short" -eq 0 ]]; then
        printf ';; Got answer:\n'
        printf ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n'
    fi
    exit 0
fi

if [[ "$short" -eq 1 ]]; then
    # +short: print only the RDATA of each answer record.
    awk -F'\t' '!/^;/ && NF >= 5 { print $5 }' "$file"
else
    cat "$file"
    if ! grep -q "status:" "$file"; then
        printf ';; ->>HEADER<<- opcode: QUERY, status: %s, id: 1\n' "$status"
    fi
fi
STUBEOF
chmod +x "$STUB_BIN/dig"

# --- canned answers ---------------------------------------------------------
# SPF: soft fail, plus a permissive variant for the negative case.
cat >"$FIX/TXT_example_com.txt" <<'EOF'
example.com.	300	IN	TXT	"v=spf1 include:_spf.example.net ip4:198.51.100.0/24 ~all"
EOF
cat >"$FIX/TXT__dmarc_example_com.txt" <<'EOF'
_dmarc.example.com.	300	IN	TXT	"v=DMARC1; p=none; rua=mailto:dmarc@example.com"
EOF
# a real DKIM key, and a revoked (empty) one
cat >"$FIX/TXT_google__domainkey_example_com.txt" <<'EOF'
google._domainkey.example.com.	300	IN	TXT	"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDExampleKeyMaterial"
EOF
cat >"$FIX/TXT_default__domainkey_example_com.txt" <<'EOF'
default._domainkey.example.com.	300	IN	TXT	"v=DKIM1; p="
EOF

# a CNAME to a cloud bucket that no longer exists -> dangling
cat >"$FIX/CNAME_dev_example_com.txt" <<'EOF'
dev.example.com.	300	IN	CNAME	old-backup-bucket.s3.amazonaws.com.
EOF
printf 'NXDOMAIN\n' >"$FIX/A_old-backup-bucket_s3_amazonaws_com.status"
: >"$FIX/A_old-backup-bucket_s3_amazonaws_com.txt"

# a CNAME to a live bucket
cat >"$FIX/CNAME_cdn_example_com.txt" <<'EOF'
cdn.example.com.	300	IN	CNAME	live-assets.s3.amazonaws.com.
EOF
cat >"$FIX/A_live-assets_s3_amazonaws_com.txt" <<'EOF'
live-assets.s3.amazonaws.com.	60	IN	A	203.0.113.10
EOF

# nameservers
cat >"$FIX/NS_example_com.txt" <<'EOF'
example.com.	86400	IN	NS	ns1.example.com.
example.com.	86400	IN	NS	ns2.example.com.
EOF
# ns1 hands the whole zone over, ns2 refuses
cat >"$FIX/AXFR_ns1_example_com_example_com.txt" <<'EOF'
example.com.	3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 600 604800 3600
example.com.	3600	IN	NS	ns1.example.com.
example.com.	3600	IN	A	192.0.2.1
www.example.com.	3600	IN	A	192.0.2.2
example.com.	3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 600 604800 3600
EOF
cat >"$FIX/AXFR_ns2_example_com_example_com.txt" <<'EOF'
; Transfer failed.
EOF

# DNSSEC: DNSKEY present, ad flag set, DS present at the parent
cat >"$FIX/DNSKEY_example_com.txt" <<'EOF'
example.com.	3600	IN	DNSKEY	257 3 13 kRMe6+ExampleKeyMaterialBase64Characters==
EOF
cat >"$FIX/A_example_com.txt" <<'EOF'
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

example.com.	3600	IN	A	192.0.2.10
EOF
cat >"$FIX/DS_example_com.txt" <<'EOF'
example.com.	3600	IN	DS	12345 13 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE
EOF

cat >"$STUB_BIN/whois" <<'WEOF'
#!/usr/bin/env bash
printf 'Domain Name: EXAMPLE.COM\n'
printf 'Registry Domain ID: 2336799_DOMAIN_COM-VRSN\n'
printf 'Registrar WHOIS Server: whois.iana.org\n'
printf 'Registrar: RESERVED-Internet Assigned Numbers Authority\n'
printf 'Creation Date: 1995-08-14T04:00:00Z\n'
printf 'Name Server: NS1.EXAMPLE.COM\n'
printf 'Name Server: NS2.EXAMPLE.COM\n'
printf 'DNSSEC: unsigned\n'
WEOF
chmod +x "$STUB_BIN/whois"

# a curl stub keeps the HTTP dangling probe hermetic: one file per host holds
# the status code that host should answer with.
cat >"$STUB_BIN/curl" <<'CEOF'
#!/usr/bin/env bash
# stub curl: answers with the status code stored per host
url=""
for a in "$@"; do
    case "$a" in
        http://*|https://*) url="$a" ;;
    esac
done
host=$(printf '%s' "$url" | sed 's|^[a-z]*://||; s|/.*$||')
sf="${CURL_STATUS_DIR:-/nonexistent}/$host"
if [[ -f "$sf" ]]; then
    cat "$sf"
else
    printf '000'
fi
CEOF
chmod +x "$STUB_BIN/curl"

mkdir -p "$FIXTURES/http"
printf '200' >"$FIXTURES/http/live-assets.s3.amazonaws.com"
printf '404' >"$FIXTURES/http/old-backup-bucket.s3.amazonaws.com"
export CURL_STATUS_DIR="$FIXTURES/http"

export DIG_FIXTURE_DIR="$FIX"

run_tool() {
    DIG_FIXTURE_DIR="${FIX_OVERRIDE:-$FIX}" PATH="$STUB_BIN:$PATH" "$DNSSHIELD" "$@"
}

# ------------------------------------------------------------------ run 1 ---
printf '\n%s── Run 1: email authentication %s\n' "$C_0" "$C_0"
run_tool -d example.com -o "$FIXTURES/out" >"$FIXTURES/run1.log" 2>&1
REPORT="$FIXTURES/out/example.com/dns_security_audit.txt"

printf '\n  SPF\n'
assert_contains "SPF record found"              "present: v=spf1 include:_spf.example.net"
assert_contains "soft fail flagged"             "~all - soft fail, consider -all"
assert_contains "mechanism count reported"      "2 mechanism(s) authorised"

printf '\n  DMARC\n'
assert_contains "DMARC record found"            "present: v=DMARC1; p=none"
assert_contains "p=none flagged as soft policy" "p=none - monitoring only, mail is still accepted"
assert_contains "rua reporting noted"           "rua=mailto:dmarc@example.com"

printf '\n  DKIM\n'
assert_contains "working key detected"          "1 working key(s): google"
assert_absent   "revoked key not counted"       "working key(s): default"

# ------------------------------------------------------------------ run 2 ---
printf '\n%s── Run 2: dangling CNAME detection %s\n' "$C_0" "$C_0"
cat >"$FIXTURES/hosts.txt" <<'EOF'
dev.example.com
cdn.example.com
example.com
EOF
run_tool -d example.com -l "$FIXTURES/hosts.txt" -o "$FIXTURES/out" >"$FIXTURES/run2.log" 2>&1
REPORT="$FIXTURES/out/example.com/dns_security_audit.txt"

printf '\n  Dangling pointer\n'
assert_contains "dangling CNAME flagged"        "old-backup-bucket.s3.amazonaws.com (Amazon S3) - NXDOMAIN: Potential Dangling Pointer / High Risk"

printf '\n  Healthy pointer\n'
assert_contains "live CNAME not flagged"        "live-assets.s3.amazonaws.com (Amazon S3) - active, HTTP 200"
assert_absent   "live CNAME not a failure"      "live-assets.s3.amazonaws.com (Amazon S3) - NXDOMAIN"

printf '\n  Plain host\n'
assert_contains "no CNAME reported"             "no CNAME record (A/AAAA only)"

# ------------------------------------------------------------------ run 3 ---
printf '\n%s── Run 3: nameservers and zone transfer %s\n' "$C_0" "$C_0"
REPORT="$FIXTURES/out/example.com/dns_security_audit.txt"
printf '\n  Nameservers\n'
assert_contains "NS list resolved"              "2 name server(s): ns1.example.com ns2.example.com"
assert_contains "redundancy confirmed"          "2 name servers configured"

printf '\n  Zone transfer\n'
assert_contains "open AXFR detected"            "AXFR SUCCEEDED - 5 records dumped, full zone exposed"
assert_contains "refused AXFR is safe"          "AXFR refused - zone is protected"

# ------------------------------------------------------------------ run 4 ---
printf '\n%s── Run 4: DNSSEC and wildcard %s\n' "$C_0" "$C_0"
REPORT="$FIXTURES/out/example.com/dns_security_audit.txt"
printf '\n  DNSSEC\n'
assert_contains "DNSSEC detected"               "enabled - 1 DNSKEY record(s), chain validated"
assert_contains "DS chain present"              "DS record present at the parent"

printf '\n  Wildcard\n'
assert_contains "no wildcard record"            "no wildcard record - random labels do not resolve"

# ----------------------------------------------------------------- run 4b ---
printf '\n%s── Run 4b: wildcard DNS detection %s\n' "$C_0" "$C_0"
FIX_WC="$FIXTURES/dns-wildcard"
mkdir -p "$FIX_WC"
cp "$FIX"/* "$FIX_WC"/ 2>/dev/null || true
# every name in the zone resolves -> the random-label probe must succeed
printf 'anything-at-all.example.com.\t300\tIN\tA\t192.0.2.99\n' >"$FIX_WC/WILDCARD_A.txt"
FIX_OVERRIDE="$FIX_WC" run_tool -d example.com -o "$FIXTURES/out-wc" >"$FIXTURES/run4b.log" 2>&1
REPORT="$FIXTURES/out-wc/example.com/dns_security_audit.txt"
printf '\n  Wildcard\n'
assert_contains "wildcard record detected"         "a random label resolves to"
assert_contains "wildcard is a warning"            "catch-all record in use"
assert_absent   "not reported as safe"             "no wildcard record"

# ------------------------------------------------------------------ run 5 ---
printf '\n%s── Run 5: CLI, report layout and resilience %s\n' "$C_0" "$C_0"

if run_tool -h >/dev/null 2>&1; then
    printf '  %s✔%s %-56s %sok%s\n' "$C_G" "$C_0" "-h exits 0 with the help banner" "$C_G" "$C_0"; PASS=$((PASS+1))
else
    printf '  %s✘%s %-56s %sfailed%s\n' "$C_R" "$C_0" "-h exits 0 with the help banner" "$C_R" "$C_0"; FAIL=$((FAIL+1))
fi
if run_tool --bogus >/dev/null 2>&1; then
    printf '  %s✘%s %-56s %sshould fail%s\n' "$C_R" "$C_0" "invalid flag is rejected" "$C_R" "$C_0"; FAIL=$((FAIL+1))
else
    printf '  %s✔%s %-56s %sok%s\n' "$C_G" "$C_0" "invalid flag is rejected" "$C_G" "$C_0"; PASS=$((PASS+1))
fi
if run_tool >/dev/null 2>&1; then
    printf '  %s✘%s %-56s %sshould fail%s\n' "$C_R" "$C_0" "no arguments is rejected" "$C_R" "$C_0"; FAIL=$((FAIL+1))
else
    printf '  %s✔%s %-56s %sok%s\n' "$C_G" "$C_0" "no arguments is rejected" "$C_G" "$C_0"; PASS=$((PASS+1))
fi
if run_tool -d example.com -l /nonexistent/list.txt >/dev/null 2>&1; then
    printf '  %s✘%s %-56s %sshould fail%s\n' "$C_R" "$C_0" "missing list file is rejected" "$C_R" "$C_0"; FAIL=$((FAIL+1))
else
    printf '  %s✔%s %-56s %sok%s\n' "$C_G" "$C_0" "missing list file is rejected" "$C_G" "$C_0"; PASS=$((PASS+1))
fi

printf '\n  Report layout\n'
REPORT="$FIXTURES/out/example.com/dns_security_audit.txt"
assert_file "canonical report exists"          "$FIXTURES/out/example.com/dns_security_audit.txt"
assert_contains "report has a header"          "DNS Misconfiguration & Email Security Audit"
assert_contains "report names the target"      "Target       : example.com"
assert_contains "report has a timestamp"       "Generated    : 20"
assert_contains "report has a verdict"         "Verdict      : "
assert_contains "report has module 1"          "MODULE 1 - Email authentication"
assert_contains "report has module 2"          "MODULE 2 - Dangling CNAME"
assert_contains "report has module 3"          "MODULE 3 - Nameservers"
assert_contains "report has module 4"          "MODULE 4 - DNSSEC"

if grep -qP '\x1b\[' "$FIXTURES/out/example.com/dns_security_audit.txt" 2>/dev/null; then
    printf '  %s✘%s %-56s %sescapes present%s\n' "$C_R" "$C_0" "report file is free of ANSI codes" "$C_R" "$C_0"; FAIL=$((FAIL+1))
else
    printf '  %s✔%s %-56s %sok%s\n' "$C_G" "$C_0" "report file is free of ANSI codes" "$C_G" "$C_0"; PASS=$((PASS+1))
fi

printf '\n  Timestamped copy\n'
ts_count=$(ls "$FIXTURES/out/example.com/" 2>/dev/null | grep -c 'dns_security_audit_[0-9]' || true)
[[ -z "$ts_count" ]] && ts_count=0
if [[ "$ts_count" -ge 1 ]]; then
    printf '  %s✔%s %-56s %s%s file(s)%s\n' "$C_G" "$C_0" "timestamped copy written" "$C_G" "$ts_count" "$C_0"; PASS=$((PASS+1))
else
    printf '  %s✘%s %-56s %snone found%s\n' "$C_R" "$C_0" "timestamped copy written" "$C_R" "$C_0"; FAIL=$((FAIL+1))
fi

printf '\n  --no-history suppresses the copy\n'
rm -rf "$FIXTURES/out2"
run_tool -d example.com --no-history -o "$FIXTURES/out2" >/dev/null 2>&1
hist_count=$(ls "$FIXTURES/out2/example.com/" 2>/dev/null | grep -c 'dns_security_audit_[0-9]' || true)
[[ -z "$hist_count" ]] && hist_count=0
if [[ "$hist_count" -eq 0 ]]; then
    printf '  %s✔%s %-56s %sok%s\n' "$C_G" "$C_0" "--no-history writes no snapshot" "$C_G" "$C_0"; PASS=$((PASS+1))
else
    printf '  %s✘%s %-56s %s%s found%s\n' "$C_R" "$C_0" "--no-history writes no snapshot" "$C_R" "$hist_count" "$C_0"; FAIL=$((FAIL+1))
fi

printf '\n  Unreachable domain\n'
rm -rf "$FIXTURES/out3"
run_tool -d "no-such-domain-dnsshield-test.invalid" -o "$FIXTURES/out3" >/dev/null 2>&1
REPORT="$FIXTURES/out3/no-such-domain-dnsshield-test.invalid/dns_security_audit.txt"
assert_contains "unreachable domain reported"   "MISSING - no v=spf1 record"
assert_contains "unreachable gets a verdict"    "Verdict      : VULNERABLE"

# ---------------------------------------------------------------- summary ---
printf '\n%s══════════════════════════════════════════%s\n' "$C_0" "$C_0"
printf '  %sPASS %d%s   %sFAIL %d%s\n' "$C_G" "$PASS" "$C_0" "$C_R" "$FAIL" "$C_0"
printf '%s══════════════════════════════════════════%s\n' "$C_0" "$C_0"
[[ "$FAIL" -eq 0 ]] || exit 1
exit 0

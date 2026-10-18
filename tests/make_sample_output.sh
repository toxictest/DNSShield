#!/usr/bin/env bash
# ==============================================================================
#  DNSShield - sample output generator
#   - Runs the tool against two live domains (example.com, github.com).
#   - Runs it against a simulated vulnerable domain using the same stub
#     resolver the test suite uses, because a live dangling CNAME or an open
#     AXFR no longer exists on the public Internet.
#   - Writes everything into ./sample-output/
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DNSSHIELD="$ROOT/dnsshield.sh"
OUT="$ROOT/sample-output"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dnsshield-sample.XXXXXX")"

cleanup() { rm -rf "$WORK" 2>/dev/null || true; }
trap cleanup EXIT

mkdir -p "$OUT"

echo "==> 1/3  live audit: example.com"
"$DNSSHIELD" -d example.com -o "$WORK/live-example" >"$WORK/example.console" 2>&1 || true

echo "==> 2/3  live audit: github.com (root + 3 subdomains)"
printf 'github.com\nwww.github.com\nassets.github.com\ngist.github.com\n' >"$WORK/subs.txt"
"$DNSSHIELD" -d github.com -l "$WORK/subs.txt" -o "$WORK/live-github" >"$WORK/github.console" 2>&1 || true

echo "==> 3/3  simulated vulnerable domain (stub resolver)"
STUB="$WORK/bin"
FIX="$WORK/dns"
mkdir -p "$STUB" "$FIX" "$WORK/http"

# --- the stub dig ------------------------------------------------------------
cat >"$STUB/dig" <<'STUBEOF'
#!/usr/bin/env bash
# Minimal dig stub. Answers from $DIG_FIXTURE_DIR/<TYPE>_<sanitised name>.txt.
# A "WILDCARD_<TYPE>.txt" file answers any name that has no exact fixture.
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
[[ "$qtype" == "AXFR" ]] && key="AXFR_$(sanitise "$server")_$(sanitise "$qname")"
file="$DIR/$key.txt"
status_file="$DIR/$key.status"
status="NOERROR"
[[ -f "$status_file" ]] && status=$(cat "$status_file")
[[ -f "$file" ]] || file="$DIR/WILDCARD_$(sanitise "$qtype").txt"

if [[ ! -f "$file" ]]; then
    if [[ "$short" -eq 0 ]]; then
        printf ';; Got answer:\n'
        printf ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n'
    fi
    exit 0
fi

if [[ "$short" -eq 1 ]]; then
    awk -F'\t' '!/^;/ && NF >= 5 { print $5 }' "$file"
else
    cat "$file"
    grep -q "status:" "$file" || printf ';; ->>HEADER<<- opcode: QUERY, status: %s, id: 1\n' "$status"
fi
STUBEOF
chmod +x "$STUB/dig"

cat >"$STUB/whois" <<'WEOF'
#!/usr/bin/env bash
printf 'Domain Name: VULNERABLE-DEMO.TEST\n'
printf 'Registrar: Example Registrar Inc.\n'
printf 'Creation Date: 2016-03-04T11:22:33Z\n'
printf 'Name Server: NS1.VULNERABLE-DEMO.TEST\n'
printf 'Name Server: NS2.VULNERABLE-DEMO.TEST\n'
WEOF
chmod +x "$STUB/whois"

cat >"$STUB/curl" <<'CEOF'
#!/usr/bin/env bash
url=""
for a in "$@"; do case "$a" in http://*|https://*) url="$a" ;; esac; done
host=$(printf '%s' "$url" | sed 's|^[a-z]*://||; s|/.*$||')
sf="${CURL_STATUS_DIR:-/nonexistent}/$host"
if [[ -f "$sf" ]]; then cat "$sf"; else printf '404'; fi
CEOF
chmod +x "$STUB/curl"

# --- canned answers ----------------------------------------------------------
# SPF +all (permissive), no DMARC at all, only a revoked DKIM key
printf 'vulnerable-demo.test.\t300\tIN\tTXT\t"v=spf1 +all"\n' >"$FIX/TXT_vulnerable-demo_test.txt"
printf 'vulnerable-demo.test.\t300\tIN\tTXT\t"v=DKIM1; p="\n' >"$FIX/TXT_default__domainkey_vulnerable-demo_test.txt"

# a CNAME to an S3 bucket that was deleted -> dangling
printf 'legacy.vulnerable-demo.test.\t300\tIN\tCNAME\tlegacy-vault.s3.amazonaws.com.\n' >"$FIX/CNAME_legacy_vulnerable-demo_test.txt"
printf 'NXDOMAIN\n' >"$FIX/A_legacy-vault_s3_amazonaws_com.status"
: >"$FIX/A_legacy-vault_s3_amazonaws_com.txt"

# a CNAME to a Heroku app that was removed -> dangling
printf 'apps.vulnerable-demo.test.\t300\tIN\tCNAME\told-app.herokuapp.com.\n' >"$FIX/CNAME_apps_vulnerable-demo_test.txt"
printf 'NXDOMAIN\n' >"$FIX/A_old-app_herokuapp_com.status"
: >"$FIX/A_old-app_herokuapp_com.txt"

# nameservers; ns1 hands over the whole zone, ns2 refuses
printf 'vulnerable-demo.test.\t86400\tIN\tNS\tns1.vulnerable-demo.test.\nvulnerable-demo.test.\t86400\tIN\tNS\tns2.vulnerable-demo.test.\n' >"$FIX/NS_vulnerable-demo_test.txt"
cat >"$FIX/AXFR_ns1_vulnerable-demo_test_vulnerable-demo_test.txt" <<'EOF'
vulnerable-demo.test.	3600	IN	SOA	ns1.vulnerable-demo.test. admin.vulnerable-demo.test. 2024010101 3600 600 604800 3600
vulnerable-demo.test.	3600	IN	NS	ns1.vulnerable-demo.test.
vulnerable-demo.test.	3600	IN	A	192.0.2.1
www.vulnerable-demo.test.	3600	IN	A	192.0.2.2
mail.vulnerable-demo.test.	3600	IN	A	192.0.2.3
vulnerable-demo.test.	3600	IN	SOA	ns1.vulnerable-demo.test. admin.vulnerable-demo.test. 2024010101 3600 600 604800 3600
EOF
printf '; Transfer failed.\n' >"$FIX/AXFR_ns2_vulnerable-demo_test_vulnerable-demo_test.txt"

# every name in the zone resolves -> wildcard DNS
printf '%s\t300\tIN\tA\t192.0.2.99\n' 'any-random-label.vulnerable-demo.test.' >"$FIX/WILDCARD_A.txt"

printf 'vulnerable-demo.test\nlegacy.vulnerable-demo.test\napps.vulnerable-demo.test\n' >"$WORK/vhosts.txt"
DIG_FIXTURE_DIR="$FIX" CURL_STATUS_DIR="$WORK/http" PATH="$STUB:$PATH" \
    "$DNSSHIELD" -d vulnerable-demo.test -l "$WORK/vhosts.txt" -o "$WORK/sim" \
    >"$WORK/vulnerable.console" 2>&1 || true

# --- collect -----------------------------------------------------------------
rm -rf "$OUT/live-example.com" "$OUT/live-github.com" "$OUT/simulated-vulnerable"
mkdir -p "$OUT/live-example.com" "$OUT/live-github.com" "$OUT/simulated-vulnerable"

cp "$WORK/live-example/example.com/dns_security_audit.txt" "$OUT/live-example.com/" 2>/dev/null || true
cp "$WORK/live-github/github.com/dns_security_audit.txt" "$OUT/live-github.com/" 2>/dev/null || true
cp "$WORK/sim/vulnerable-demo.test/dns_security_audit.txt" "$OUT/simulated-vulnerable/" 2>/dev/null || true

# console transcripts: one plain, one with the ANSI colours intact.
# Colours are only emitted on a terminal, so a pty is allocated with `script`.
capture_tty() {
    # $1 = command, $2 = destination
    # `script` wraps the output in a "Script started/done" banner and turns
    # \n into \r\n - both are stripped back out here.
    if command -v script >/dev/null 2>&1; then
        script -qec "$1" "$2" >/dev/null 2>&1 || true
        sed -i -e '/^Script started on /d' -e '/^Script done on /d' \
               -e 's/\r$//' "$2" 2>/dev/null || true
    else
        : >"$2"
    fi
}

sed 's/\x1b\[[0-9;]*m//g' "$WORK/example.console" >"$OUT/console-example.com.txt"
capture_tty "\"$DNSSHIELD\" -d example.com -o \"$WORK/live-example-tty\"" "$OUT/console-example.com.ansi.txt"
sed 's/\x1b\[[0-9;]*m//g' "$WORK/vulnerable.console" >"$OUT/console-simulated-vulnerable.txt"
capture_tty \
    "env DIG_FIXTURE_DIR='$FIX' CURL_STATUS_DIR='$WORK/http' PATH='$STUB:$PATH' \"$DNSSHIELD\" -d vulnerable-demo.test -l '$WORK/vhosts.txt' -o '$WORK/sim-tty'" \
    "$OUT/console-simulated-vulnerable.ansi.txt"
[[ -s "$OUT/console-example.com.ansi.txt" ]] || cp "$WORK/example.console" "$OUT/console-example.com.ansi.txt"
[[ -s "$OUT/console-simulated-vulnerable.ansi.txt" ]] || cp "$WORK/vulnerable.console" "$OUT/console-simulated-vulnerable.ansi.txt"

echo
echo "sample-output:"
find "$OUT" -type f | sort | sed "s|$OUT/|  |"

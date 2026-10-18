#!/usr/bin/env bash
# ==============================================================================
#  DNSShield v1.0.0
#  DNS Misconfiguration & Email Security Auditor
#  ---------------------------------------------------------------------------
#  Audits a root domain and its discovered subdomains for:
#     Module 1 - email authentication   (SPF / DMARC / DKIM)
#     Module 2 - dangling CNAME pointers (cloud asset take-over risk)
#     Module 3 - nameserver configuration and zone transfer (AXFR)
#     Module 4 - DNSSEC status and wildcard DNS records
#
#  100% free and standalone: dig + awk/grep/sed/tr (host, nslookup and whois
#  are used when present).  No API keys, no paid services.
# ==============================================================================

set -euo pipefail

SCRIPT_NAME="DNSShield"
SCRIPT_VERSION="1.0.0"

# ------------------------------------------------------------------ defaults --
ROOT_DOMAIN=""
LIST_FILE=""
OUTPUT_DIR="results"
THREADS=10
TIMEOUT=5
HISTORY=1
NO_COLOR=0
VERBOSE=0
RESOLVER=""

# Common DKIM selectors probed for every domain.
DKIM_SELECTORS=(google selector1 selector2 k1 k2 default mail dkim s1 s2
                mandrill zoho mailgun sendgrid amazonses protonmail fastmail
                outlook office365 docusign hubspot jira atlassian)

# Cloud providers recognised as CNAME targets (order matters: the most
# specific pattern must come first).
CLOUD_PATTERNS=(
    "*.s3-website*.amazonaws.com:Amazon S3 (static website)"
    "*.s3.*.amazonaws.com:Amazon S3"
    "*.s3.amazonaws.com:Amazon S3"
    "*.elasticbeanstalk.com:AWS Elastic Beanstalk"
    "*.elb.amazonaws.com:AWS ELB / ALB"
    "*.cloudfront.net:Amazon CloudFront"
    "*.amazonaws.com:Amazon AWS (other)"
    "*.azurewebsites.net:Microsoft Azure App Service"
    "*.cloudapp.azure.com:Microsoft Azure (classic)"
    "*.cloudapp.net:Microsoft Azure (classic)"
    "*.blob.core.windows.net:Azure Blob Storage"
    "*.github.io:GitHub Pages"
    "*.herokuapp.com:Heroku"
    "*.zendesk.com:Zendesk"
    "*.fastly.net:Fastly"
    "*.netlify.app:Netlify"
    "*.netlify.com:Netlify"
    "*.vercel.app:Vercel"
    "*.myshopify.com:Shopify"
    "*.wordpress.com:WordPress"
    "*.tumblr.com:Tumblr"
    "*.bitbucket.io:Bitbucket"
    "*.firebaseapp.com:Firebase"
    "*.web.app:Firebase Hosting"
    "*.surge.sh:Surge.sh"
    "*.ghost.io:Ghost"
    "*.readme.io:Readme.io"
    "*.pantheonsite.io:Pantheon"
    "*.acquia-sites.com:Acquia"
    "*.atlassian.net:Atlassian Cloud"
    "*.force.com:Salesforce"
    "*.bigcommerce.com:BigCommerce"
)

TMP_DIR=""
HAVE_CURL=0
HAVE_WHOIS=0
HAVE_HOST=0
START_TS=$(date +%s)
HOSTS_AUDITED=0
FIND_PASS=0
FIND_FAIL=0
FIND_WARN=0
FIND_INFO=0

declare -a FINDINGS=()
declare -a TARGET_HOSTS=()

# ------------------------------------------------------------------ colours --
C_RESET=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CYN=""; C_DIM=""; C_BOLD=""
init_colors() {
    if [[ "$NO_COLOR" -eq 0 && -t 1 ]]; then
        C_RESET=$'\033[0m'
        C_RED=$'\033[1;31m'
        C_GRN=$'\033[1;32m'
        C_YEL=$'\033[1;33m'
        C_BLU=$'\033[1;34m'
        C_CYN=$'\033[1;36m'
        C_DIM=$'\033[2m'
        C_BOLD=$'\033[1m'
    fi
}

# ------------------------------------------------------------------ logging --
_ts() { date '+%H:%M:%S'; }

log_info() { printf '[%s] %sINFO%s   %s\n' "$(_ts)" "$C_BLU" "$C_RESET" "$*"; }
log_ok()   { printf '[%s] %sOK%s     %s\n' "$(_ts)" "$C_GRN" "$C_RESET" "$*"; }
log_warn() { printf '[%s] %sWARN%s   %s\n' "$(_ts)" "$C_YEL" "$C_RESET" "$*"; }
log_err()  { printf '[%s] %sERROR%s  %s\n' "$(_ts)" "$C_RED" "$C_RESET" "$*"; }
log_step() { printf '\n%s%s%s\n' "$C_BLU" "$*" "$C_RESET"; }

die() { log_err "$*"; exit 2; }

progress() {
    local cur="$1" total="$2" label="${3:-working}"
    [[ "$total" -le 0 ]] && return 0
    local pct=$(( cur * 100 / total ))
    local width=30
    local filled=$(( pct * width / 100 ))
    local bar="" i
    for (( i = 0; i < filled; i++ )); do bar+="#"; done
    for (( i = filled; i < width; i++ )); do bar+="-"; done
    printf '\r%s[%s]%s %3d%% (%d/%d) %s' "$C_CYN" "$bar" "$C_RESET" "$pct" "$cur" "$total" "$label"
}

PROGRESS_DRAWN=0
progress_done() {
    [[ "$PROGRESS_DRAWN" -eq 1 ]] || return 0
    printf '\r%-90s\r' ""
    PROGRESS_DRAWN=0
}

banner() {
    local w=54 bar="" i
    for (( i = 0; i < w; i++ )); do bar+="─"; done
    printf '%s\n' "$C_CYN"
    printf '  ┌%s┐\n' "$bar"
    printf '  │  %s%-52s│\n' "$C_BOLD" "$SCRIPT_NAME v$SCRIPT_VERSION"
    printf '  │  %s%-52s│\n' "" "DNS Misconfiguration & Email Security Auditor"
    printf '  └%s┘\n' "$bar"
    printf '%s\n' "$C_RESET"
    printf '  Free & standalone. dig + awk/grep/sed/tr. No API keys.\n\n'
}

# ------------------------------------------------------------------ cleanup --
# shellcheck disable=SC2317  # invoked indirectly by the EXIT trap
cleanup() {
    local rc=$?
    if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]]; then
        rm -rf "$TMP_DIR" 2>/dev/null || true
    fi
    return "$rc"
}
trap 'rc=$?; cleanup; exit $rc' EXIT

# ------------------------------------------------------------------ usage ---
usage() {
    cat <<EOF
${C_BOLD}${C_CYN}  $SCRIPT_NAME v$SCRIPT_VERSION${C_RESET}
${C_DIM}  DNS misconfiguration & email security auditor${C_RESET}

${C_BOLD}USAGE${C_RESET}
  ./dnsshield.sh -d target.com [-l subdomains.txt] [-o report_dir]

${C_BOLD}REQUIRED${C_RESET}
  -d, --domain <domain>   Root domain to audit (e.g. target.com)

${C_BOLD}OPTIONS${C_RESET}
  -l, --list <file>       Subdomain list to audit (e.g. Day 1's subdomains.txt)
  -o, --output <dir>      Report directory                  (default: $OUTPUT_DIR)
  -t, --threads <n>       Parallel host audits              (default: $THREADS)
      --timeout <sec>     Per-query DNS timeout             (default: $TIMEOUT)
      --resolver <ip>     Use a specific resolver, e.g. 8.8.8.8
      --dkim <list>       Extra DKIM selectors to probe (comma separated)
      --no-history        Do not keep a timestamped copy of the report
  -v, --verbose           Verbose logging
      --no-color          Disable ANSI colours
  -h, --help              Show this help and exit

${C_BOLD}MODULES${C_RESET}
  1  Email authentication   SPF, DMARC, DKIM
  2  Dangling CNAME         cloud asset pointers that no longer resolve
  3  Nameservers            authoritative NS set and AXFR zone transfer
  4  DNSSEC & wildcard      DNSKEY / DS chain and catch-all records

${C_BOLD}OUTPUT${C_RESET}
  <output_dir>/<target>/dns_security_audit.txt
  <output_dir>/<target>/dns_security_audit_<YYYYmmdd_HHMMSS>.txt

${C_BOLD}COLOURS${C_RESET}
  ${C_GRN}Green${C_RESET}  protected      ${C_RED}Red${C_RESET}    vulnerable / missing
  ${C_YEL}Yellow${C_RESET}  warning / soft policy

${C_BOLD}EXAMPLES${C_RESET}
  ./dnsshield.sh -d example.com
  ./dnsshield.sh -d example.com -l results/example.com/subdomains.txt
  ./dnsshield.sh -d example.com -l list.txt -o ./scans --threads 30
EOF
}

# ------------------------------------------------------------- dependencies --
check_deps() {
    log_step "Stage 0/6 - Dependency verification"

    local missing=0 tool path
    for tool in dig awk grep sed tr; do
        path=$(command -v "$tool" 2>/dev/null || true)
        if [[ -n "$path" ]]; then
            log_ok "$(printf '%-10s %s' "$tool" "$path")"
        else
            log_err "missing required tool: $tool"
            missing=1
        fi
    done

    if [[ "$missing" -ne 0 ]]; then
        printf '\n'
        log_err "DNSShield needs only core Linux utilities. Install them with:"
        printf '  Debian/Ubuntu : sudo apt-get install -y dnsutils gawk grep sed coreutils\n'
        printf '  RHEL/Fedora   : sudo dnf install -y bind-utils gawk grep sed coreutils\n'
        printf '  Alpine        : sudo apk add bind-tools gawk grep sed coreutils\n'
        printf '\n'
        die "Dependency check failed."
    fi

    # Optional extras - the tool degrades gracefully without them.
    if command -v whois >/dev/null 2>&1; then
        HAVE_WHOIS=1; log_ok "$(printf '%-10s %s' "whois" "present (optional)")"
    else
        log_warn "whois not installed - registrar verification will be skipped"
    fi
    if command -v host >/dev/null 2>&1; then
        HAVE_HOST=1; log_ok "$(printf '%-10s %s' "host" "present (optional)")"
    else
        log_warn "host not installed - using dig for all queries"
    fi
    if command -v nslookup >/dev/null 2>&1; then
        log_ok "$(printf '%-10s %s' "nslookup" "present (optional)")"
    else
        log_warn "nslookup not installed - using dig for all queries"
    fi
    if command -v curl >/dev/null 2>&1; then
        HAVE_CURL=1; log_ok "$(printf '%-10s %s' "curl" "present (optional - HTTP dangling check)")"
    else
        log_warn "curl not installed - dangling detection limited to DNS resolution"
    fi
}

# ------------------------------------------------------------- dig helpers --
dig_q() {
    # dig_q <type> <name>  -> short answer lines
    local qtype="$1" qname="$2"
    local -a args=("+short" "+time=$TIMEOUT" "+tries=1")
    [[ -n "$RESOLVER" ]] && args+=("@$RESOLVER")
    dig "${args[@]}" "$qtype" "$qname" 2>/dev/null || true
}

dig_q1() {
    # first line of the short answer (no head -> no SIGPIPE under pipefail)
    dig_q "$1" "$2" | sed -n '1p'
}

dig_txt() {
    # dig_txt <name> -> one TXT record per line, with the quoted chunks of a
    # long record rejoined exactly as the server sent them.
    local qname="$1"
    local -a args=("+time=$TIMEOUT" "+tries=1" "+noall" "+answer")
    [[ -n "$RESOLVER" ]] && args+=("@$RESOLVER")
    dig "${args[@]}" TXT "$qname" 2>/dev/null \
        | awk '
            {
                if (!match($0, /[ \t]TXT[ \t]/)) next
                rest = substr($0, RSTART + RLENGTH)
                out = ""
                while (match(rest, /"[^"]*"/)) {
                    out = out substr(rest, RSTART + 1, RLENGTH - 2)
                    rest = substr(rest, RSTART + RLENGTH)
                }
                if (out != "") print out
            }' || true
}

dig_status() {
    # dig_status <type> <name> -> the rcode as a word, e.g. NXDOMAIN
    local qtype="$1" qname="$2"
    local -a args=("+time=$TIMEOUT" "+tries=1")
    [[ -n "$RESOLVER" ]] && args+=("@$RESOLVER")
    dig "${args[@]}" "$qtype" "$qname" 2>/dev/null \
        | grep -oE 'status: [A-Z]+' | awk '{print $2}' | sed -n '1p' || true
}

# ------------------------------------------------------------------- helpers --
add_finding() {
    # severity|module|label|detail   severity: PASS | FAIL | WARN | INFO
    FINDINGS+=("$1|$2|$3|$4")
}

sev_colour() {
    case "$1" in
        PASS) printf '%s' "$C_GRN" ;;
        FAIL) printf '%s' "$C_RED" ;;
        WARN) printf '%s' "$C_YEL" ;;
        *)    printf '%s' "$C_CYN" ;;
    esac
}

cloud_provider() {
    # maps a CNAME target to the cloud provider that owns it
    local t="${1,,}"
    t="${t%.}"
    local entry pat prov
    for entry in "${CLOUD_PATTERNS[@]}"; do
        pat="${entry%%:*}"
        prov="${entry#*:}"
        # shellcheck disable=SC2053  # intentional glob match
        if [[ "$t" == $pat ]]; then
            printf '%s' "$prov"
            return 0
        fi
    done
    printf ''
}

normalise_host() {
    # strip scheme, path, port, userinfo and the trailing dot
    local h="$1"
    h="${h%%#*}"
    h="${h%%\?*}"
    h="${h#*://}"
    h="${h##*@}"
    h="${h%%/*}"
    h="${h%%:*}"
    h="${h,,}"
    h="${h%.}"
    printf '%s' "$h"
}

# ============================================================ module 1 : email =
audit_email() {
    local domain="$1"

    # --- SPF ---------------------------------------------------------------
    local txt spf=""
    txt=$(dig_txt "$domain")
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$line" == v=spf1* ]]; then
            spf="$line"
            break
        fi
    done <<<"$txt"

    if [[ -z "$spf" ]]; then
        add_finding "FAIL" "M1" "SPF record" "MISSING - no v=spf1 record, the domain can be spoofed"
    else
        add_finding "PASS" "M1" "SPF record" "present: $spf"
        local mech
        mech=$(printf '%s' "$spf" | tr ' ' '\n' | grep -cE '^(include:|a:|mx:|ip4:|ip6:|exists:|ptr:)' || true)
        [[ -z "$mech" ]] && mech=0
        add_finding "INFO" "M1" "SPF mechanisms" "$mech mechanism(s) authorised"

        local allmech
        allmech=$(printf '%s' "$spf" | tr ' ' '\n' | grep -E '^[+?~?-]?all$' | sed -n '1p' || true)
        case "$allmech" in
            "+all")
                add_finding "FAIL" "M1" "SPF all mechanism" "+all - ANY host may send mail for this domain" ;;
            "?all")
                add_finding "FAIL" "M1" "SPF all mechanism" "?all - neutral, any host may send mail" ;;
            "~all")
                add_finding "WARN" "M1" "SPF all mechanism" "~all - soft fail, consider -all" ;;
            "-all")
                add_finding "PASS" "M1" "SPF all mechanism" "-all - hard fail, strict policy" ;;
            "")
                add_finding "WARN" "M1" "SPF all mechanism" "no 'all' mechanism - policy is incomplete" ;;
            *)
                add_finding "WARN" "M1" "SPF all mechanism" "unrecognised: $allmech" ;;
        esac
        if printf '%s' "$spf" | grep -q "ptr"; then
            add_finding "WARN" "M1" "SPF mechanism ptr" "ptr is deprecated and unreliable"
        fi
        if printf '%s' "$spf" | grep -qi "redirect="; then
            add_finding "WARN" "M1" "SPF redirect" "policy is delegated with redirect="
        fi
    fi

    # --- DMARC -------------------------------------------------------------
    local dmarc=""
    dmarc=$(dig_txt "_dmarc.$domain" | sed -n '1p' || true)
    if [[ -z "$dmarc" ]]; then
        add_finding "FAIL" "M1" "DMARC record" "MISSING at _dmarc.$domain - no spoofing policy"
    else
        add_finding "PASS" "M1" "DMARC record" "present: $dmarc"
        local pol
        pol=$(printf '%s' "$dmarc" | tr ';' '\n' | grep -oE 'p=[a-z]+' | sed -n '1p' || true)
        pol="${pol#p=}"
        case "$pol" in
            reject)
                add_finding "PASS" "M1" "DMARC policy" "p=reject - forged mail is refused" ;;
            quarantine)
                add_finding "WARN" "M1" "DMARC policy" "p=quarantine - not full enforcement" ;;
            none)
                add_finding "WARN" "M1" "DMARC policy" "p=none - monitoring only, mail is still accepted" ;;
            "")
                add_finding "FAIL" "M1" "DMARC policy" "no p= tag - policy is undefined" ;;
            *)
                add_finding "WARN" "M1" "DMARC policy" "unrecognised: p=$pol" ;;
        esac
        local sp
        sp=$(printf '%s' "$dmarc" | tr ';' '\n' | grep -oE 'sp=[a-z]+' | sed -n '1p' || true)
        [[ -n "$sp" ]] && add_finding "INFO" "M1" "DMARC subdomain policy" "$sp"
        local rua
        rua=$(printf '%s' "$dmarc" | grep -oE 'rua=[^;]+' | sed -n '1p' || true)
        [[ -n "$rua" ]] && add_finding "INFO" "M1" "DMARC reporting" "$rua"
    fi

    # --- DKIM --------------------------------------------------------------
    # A DKIM selector is a TXT record at <sel>._domainkey.<domain>, but it
    # may also be a CNAME to the mail provider (common with SendGrid, etc.),
    # and a record of "v=DKIM1; p=" is a REVOKED key, not a working one.
    local sel
    local -a real_sel=() cname_sel=()
    local null_count=0 null_sample=""
    for sel in "${DKIM_SELECTORS[@]}"; do
        local key cname
        cname=$(dig_q1 CNAME "${sel}._domainkey.${domain}")
        cname="${cname%.}"
        if [[ -n "$cname" ]]; then
            key=$(dig_txt "$cname" | sed -n '1p' || true)
        else
            key=$(dig_txt "${sel}._domainkey.${domain}" | sed -n '1p' || true)
        fi
        [[ -z "$key" ]] && continue
        if [[ "$key" == *"v=DKIM1"* ]]; then
            local pval
            pval=$(printf '%s' "$key" | grep -oE 'p=[^;]*' | sed -n '1p' || true)
            pval="${pval#p=}"
            pval="${pval%%;*}"
            if [[ -z "$pval" ]]; then
                null_count=$((null_count + 1))
                [[ -z "$null_sample" ]] && null_sample="$key"
            else
                real_sel+=("$sel")
            fi
        else
            real_sel+=("$sel")
        fi
        [[ -n "$cname" ]] && cname_sel+=("$sel")
    done

    if [[ "${#real_sel[@]}" -gt 0 ]]; then
        add_finding "PASS" "M1" "DKIM keys" "${#real_sel[@]} working key(s): ${real_sel[*]}"
        if [[ "${#cname_sel[@]}" -gt 0 ]]; then
            add_finding "INFO" "M1" "DKIM delegation" "${#cname_sel[@]} selector(s) are CNAMEs to a mail provider"
        fi
    elif [[ "$null_count" -gt 0 ]]; then
        # Revoked / null keys. If a RANDOM selector also returns one, the
        # whole namespace is wildcarded on purpose.
        local rnd rkey wildcard="no"
        rnd="dnssh-$(date +%s)-$((RANDOM % 9000 + 1000))"
        rkey=$(dig_txt "${rnd}._domainkey.${domain}" | sed -n '1p' || true)
        [[ -n "$rkey" ]] && wildcard="yes"
        if [[ "$wildcard" == "yes" ]]; then
            add_finding "WARN" "M1" "DKIM keys" "all $null_count probes return a revoked key ($null_sample) - wildcarded, so no DKIM signing but subdomain key hijacking is blocked"
        else
            add_finding "WARN" "M1" "DKIM keys" "$null_count selector(s) return a revoked key ($null_sample) - no usable DKIM key"
        fi
    else
        add_finding "FAIL" "M1" "DKIM keys" "none of the $(( ${#DKIM_SELECTORS[@]} )) common selectors resolve"
    fi
}

# ======================================================== module 2 : dangling =
audit_host_cname() {
    local host="$1"

    local cname
    cname=$(dig_q1 CNAME "$host")
    cname="${cname%.}"

    if [[ -z "$cname" ]]; then
        add_finding "INFO" "M2" "$host" "no CNAME record (A/AAAA only)"
        return 0
    fi

    local provider
    provider=$(cloud_provider "$cname")

    if [[ -z "$provider" ]]; then
        add_finding "PASS" "M2" "$host" "CNAME -> $cname (not a known cloud provider)"
        return 0
    fi

    # Third-party cloud target: is it still alive?
    local status
    status=$(dig_status A "$cname")
    [[ -z "$status" ]] && status="UNKNOWN"

    # Second opinion from host(1) when dig did not report a status.
    if [[ "$status" == "UNKNOWN" && "$HAVE_HOST" -eq 1 ]]; then
        local hout
        hout=$(host "$cname" 2>/dev/null || true)
        if printf '%s' "$hout" | grep -qi "not found"; then
            status="NXDOMAIN"
        elif [[ -n "$hout" ]]; then
            status="NOERROR"
        fi
    fi

    if [[ "$status" == "NXDOMAIN" ]]; then
        add_finding "FAIL" "M2" "$host" "CNAME -> $cname ($provider) - NXDOMAIN: Potential Dangling Pointer / High Risk"
        return 0
    fi
    if [[ "$status" == "SERVFAIL" || "$status" == "REFUSED" ]]; then
        add_finding "FAIL" "M2" "$host" "CNAME -> $cname ($provider) - $status: Potential Dangling Pointer / High Risk"
        return 0
    fi

    local addrs
    addrs=$(dig_q A "$cname" | sed -n '1p' || true)
    if [[ -z "$addrs" ]]; then
        addrs=$(dig_q AAAA "$cname" | sed -n '1p' || true)
    fi

    if [[ -z "$addrs" ]]; then
        add_finding "FAIL" "M2" "$host" "CNAME -> $cname ($provider) - target has no address records: Potential Dangling Pointer / High Risk"
        return 0
    fi

    # The name resolves. If curl is available, check what the service answers.
    if [[ "$HAVE_CURL" -eq 1 ]]; then
        local code
        code=$(curl -sS -o /dev/null -w '%{http_code}' -L -k --max-time "$TIMEOUT" \
               "http://$cname/" 2>/dev/null || true)
        [[ -z "$code" ]] && code="000"
        case "$code" in
            2*|3*)
                add_finding "PASS" "M2" "$host" "CNAME -> $cname ($provider) - active, HTTP $code" ;;
            4*|5*)
                add_finding "FAIL" "M2" "$host" "CNAME -> $cname ($provider) - HTTP $code: Potential Dangling Pointer / High Risk" ;;
            *)
                add_finding "WARN" "M2" "$host" "CNAME -> $cname ($provider) - target resolves but did not answer (HTTP $code)" ;;
        esac
    else
        add_finding "PASS" "M2" "$host" "CNAME -> $cname ($provider) - target resolves"
    fi
}

audit_host_dmarc() {
    local host="$1"
    local dmarc
    dmarc=$(dig_txt "_dmarc.$host" | sed -n '1p' || true)
    [[ -z "$dmarc" ]] && return 0
    local pol
    pol=$(printf '%s' "$dmarc" | tr ';' '\n' | grep -oE 'p=[a-z]+' | sed -n '1p' || true)
    pol="${pol#p=}"
    case "$pol" in
        reject) add_finding "PASS" "M1" "_dmarc.$host" "p=reject" ;;
        quarantine) add_finding "WARN" "M1" "_dmarc.$host" "p=quarantine" ;;
        none) add_finding "WARN" "M1" "_dmarc.$host" "p=none - soft policy" ;;
        *) add_finding "WARN" "M1" "_dmarc.$host" "unrecognised policy: $dmarc" ;;
    esac
}

# ================================================= module 3 : nameservers/AXFR =
audit_nameservers() {
    local domain="$1"

    local ns_list ns_count=0
    ns_list=$(dig_q NS "$domain")
    local -a ns=()
    local n
    while IFS= read -r n; do
        [[ -z "$n" ]] && continue
        n="${n%.}"
        ns+=("$n")
    done <<<"$ns_list"

    ns_count=${#ns[@]}

    if [[ "$ns_count" -eq 0 ]]; then
        add_finding "FAIL" "M3" "Authoritative NS" "none found for $domain"
        return 0
    fi

    add_finding "PASS" "M3" "Authoritative NS" "$ns_count name server(s): ${ns[*]}"
    if [[ "$ns_count" -lt 2 ]]; then
        add_finding "WARN" "M3" "NS redundancy" "only $ns_count name server - no redundancy"
    else
        add_finding "PASS" "M3" "NS redundancy" "$ns_count name servers configured"
    fi

    # --- zone transfer -----------------------------------------------------
    local ns_name
    for ns_name in "${ns[@]}"; do
        local out soa
        out=$(dig "+time=$TIMEOUT" "+tries=1" "@$ns_name" AXFR "$domain" 2>&1 || true)
        soa=$(printf '%s' "$out" | grep -cE "[[:space:]]IN[[:space:]]+SOA[[:space:]]" || true)
        [[ -z "$soa" ]] && soa=0
        if printf '%s' "$out" | grep -qE "timed out|no servers could be reached|communications error|connection refused"; then
            add_finding "WARN" "M3" "Zone transfer $ns_name" "could not be tested - the server did not answer"
        elif printf '%s' "$out" | grep -q "Transfer failed"; then
            add_finding "PASS" "M3" "Zone transfer $ns_name" "AXFR refused - zone is protected"
        elif [[ "$soa" -gt 0 ]]; then
            local recs
            recs=$(printf '%s' "$out" | grep -cE "^[^;].*[[:space:]]IN[[:space:]]" || true)
            [[ -z "$recs" ]] && recs=0
            add_finding "FAIL" "M3" "Zone transfer $ns_name" "AXFR SUCCEEDED - $recs records dumped, full zone exposed"
        else
            add_finding "PASS" "M3" "Zone transfer $ns_name" "no zone transferred"
        fi
    done

    # --- whois cross-check -------------------------------------------------
    if [[ "$HAVE_WHOIS" -eq 1 ]]; then
        local w
        w=$(whois "$domain" 2>/dev/null || true)
        if [[ -n "$w" ]]; then
            local registrar
            registrar=$(printf '%s' "$w" | grep -iE '^[[:space:]]*(registrar|registrar name|sponsoring registrar)[[:space:]]*:' | sed -n '1p' | cut -d: -f2- | tr -s ' ' || true)
            [[ -z "$registrar" ]] && registrar=$(printf '%s' "$w" | grep -iE 'registrar:' | sed -n '1p' | cut -d: -f2- | tr -s ' ' || true)
            [[ -n "$registrar" ]] && add_finding "INFO" "M3" "Registrar" "${registrar# }"

            local created
            created=$(printf '%s' "$w" | grep -iE '^[[:space:]]*(creation date|created|created on)[[:space:]]*:' | sed -n '1p' | cut -d: -f2- | tr -s ' ' || true)
            [[ -n "$created" ]] && add_finding "INFO" "M3" "Domain created" "${created# }"

            # whois nameservers vs the authoritative set
            local -a wns=()
            local wn
            while IFS= read -r wn; do
                [[ -z "$wn" ]] && continue
                wn="${wn%.}"
                wn="${wn,,}"
                wns+=("$wn")
            done < <(printf '%s' "$w" | grep -iE '^[[:space:]]*(name server|nserver|nameserver)[[:space:]]*:' | cut -d: -f2- | tr ' ' '\n' | grep -E '\.' | sed 's/\.$//')

            if [[ "${#wns[@]}" -gt 0 ]]; then
                local -a dnorm=()
                local d
                for d in "${ns[@]}"; do dnorm+=("${d,,}"); done
                local mismatch=0
                for wn in "${wns[@]}"; do
                    local found=0
                    for d in "${dnorm[@]}"; do
                        [[ "$wn" == "$d" ]] && found=1
                    done
                    [[ "$found" -eq 0 ]] && mismatch=1
                done
                if [[ "$mismatch" -eq 1 ]]; then
                    add_finding "WARN" "M3" "NS delegation" "whois and authoritative NS differ - delegation may be inconsistent"
                else
                    add_finding "PASS" "M3" "NS delegation" "whois and authoritative NS agree"
                fi
            fi
        else
            add_finding "INFO" "M3" "WHOIS" "no registry record returned"
        fi
    fi
}

# ================================================== module 4 : DNSSEC/wildcard =
audit_dnssec() {
    local domain="$1"

    local dnskeys flags ds
    dnskeys=$(dig_q DNSKEY "$domain" | grep -c . || true)
    [[ -z "$dnskeys" ]] && dnskeys=0
    flags=$(dig "+time=$TIMEOUT" "+tries=1" "+dnssec" A "$domain" 2>/dev/null \
            | grep -oE "^;; flags:[^;]*" | sed -n '1p' || true)
    ds=$(dig_q DS "$domain" | sed -n '1p' || true)

    if [[ "$dnskeys" -gt 0 ]]; then
        if [[ "$flags" == *" ad"* ]]; then
            add_finding "PASS" "M4" "DNSSEC" "enabled - $dnskeys DNSKEY record(s), chain validated (ad flag)"
        else
            add_finding "WARN" "M4" "DNSSEC" "DNSKEY present ($dnskeys) but the resolver did not validate the chain"
        fi
        if [[ -n "$ds" ]]; then
            add_finding "PASS" "M4" "DNSSEC chain" "DS record present at the parent"
        else
            add_finding "WARN" "M4" "DNSSEC chain" "no DS record at the parent - chain is broken"
        fi
    else
        add_finding "FAIL" "M4" "DNSSEC" "not enabled - no DNSKEY record, responses can be forged"
        if [[ -z "$ds" ]]; then
            add_finding "FAIL" "M4" "DNSSEC chain" "no DS record at the parent either"
        fi
    fi
}

audit_wildcard() {
    local domain="$1"
    local label
    label="dnssh-$(date +%s)-$((RANDOM % 9000 + 1000))-$((RANDOM % 9000 + 1000))"
    local hit
    hit=$(dig_q A "$label.$domain" | sed -n '1p' || true)
    if [[ -z "$hit" ]]; then
        hit=$(dig_q CNAME "$label.$domain" | sed -n '1p' || true)
    fi
    if [[ -n "$hit" ]]; then
        add_finding "WARN" "M4" "Wildcard DNS" "a random label resolves to $hit - catch-all record in use"
    else
        add_finding "PASS" "M4" "Wildcard DNS" "no wildcard record - random labels do not resolve"
    fi
}

# ---------------------------------------------------------------- per-host ---
audit_host() {
    local idx="$1" host="$2"
    local dir="$TMP_DIR/hosts/$idx"
    mkdir -p "$dir"

    FINDINGS=()
    audit_host_cname "$host"
    audit_host_dmarc "$host"

    # Findings are split per module so the report prints one heading per
    # module instead of repeating it whenever the modules interleave.
    : >"$dir/m1.txt"
    : >"$dir/m2.txt"
    local f sev mod lbl det
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev mod lbl det <<<"$f"
        case "$mod" in
            M1) printf '%s\n' "$f" >>"$dir/m1.txt" ;;
            M2) printf '%s\n' "$f" >>"$dir/m2.txt" ;;
        esac
    done
}

# ---------------------------------------------------------------- reporting --
read_findings() {
    local file="$1"
    FINDINGS=()
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        FINDINGS+=("$line")
    done <"$file"
}

print_module_header() {
    case "$1" in
        M1) printf '  %sModule 1 - Email authentication & anti-spoofing%s\n' "$C_BLU" "$C_RESET" ;;
        M2) printf '  %sModule 2 - Dangling CNAME / cloud asset verification%s\n' "$C_BLU" "$C_RESET" ;;
        M3) printf '  %sModule 3 - Nameservers & zone transfer%s\n' "$C_BLU" "$C_RESET" ;;
        M4) printf '  %sModule 4 - DNSSEC & wildcard detection%s\n' "$C_BLU" "$C_RESET" ;;
    esac
}

print_findings() {
    local cur=""
    local finding sev mod lbl det
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r sev mod lbl det <<<"$finding"
        if [[ "$mod" != "$cur" ]]; then
            cur="$mod"
            print_module_header "$mod"
        fi
        local col tag
        col=$(sev_colour "$sev")
        case "$sev" in
            PASS) tag=" OK " ;;
            FAIL) tag="FAIL" ;;
            WARN) tag="WARN" ;;
            *)    tag="INFO" ;;
        esac
        printf '    %s[%s]%s %-26s %s\n' "$col" "$tag" "$C_RESET" "$lbl" "$det"
    done
}

count_findings() {
    local finding sev mod lbl det
    for finding in "${FINDINGS[@]}"; do
        IFS='|' read -r sev mod lbl det <<<"$finding"
        case "$sev" in
            PASS) FIND_PASS=$((FIND_PASS + 1)) ;;
            FAIL) FIND_FAIL=$((FIND_FAIL + 1)) ;;
            WARN) FIND_WARN=$((FIND_WARN + 1)) ;;
            *)    FIND_INFO=$((FIND_INFO + 1)) ;;
        esac
    done
}

overall_verdict() {
    if [[ "$FIND_FAIL" -gt 0 ]]; then
        printf 'VULNERABLE'
    elif [[ "$FIND_WARN" -gt 0 ]]; then
        printf 'WARNING'
    else
        printf 'PROTECTED'
    fi
}

build_report() {
    local out="$1"
    local elapsed=$(( $(date +%s) - START_TS ))
    {
        printf '================================================================================\n'
        printf ' %s v%s - DNS Misconfiguration & Email Security Audit\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
        printf '================================================================================\n'
        printf ' Generated    : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
        printf ' Target       : %s\n' "$ROOT_DOMAIN"
        printf ' Hosts audited: %s\n' "$HOSTS_AUDITED"
        printf ' Duration     : %02d:%02d:%02d\n' \
            "$(( elapsed / 3600 ))" "$(( (elapsed % 3600) / 60 ))" "$(( elapsed % 60 ))"
        printf ' Verdict      : %s\n' "$(overall_verdict)"
        printf ' Checks       : %s pass, %s warning, %s vulnerable, %s info\n' \
            "$FIND_PASS" "$FIND_WARN" "$FIND_FAIL" "$FIND_INFO"
        printf '================================================================================\n\n'

        local finding sev mod lbl det
        local cur=""
        for finding in "${FINDINGS[@]}"; do
            IFS='|' read -r sev mod lbl det <<<"$finding"
            if [[ "$mod" != "$cur" ]]; then
                cur="$mod"
                printf -- '--------------------------------------------------------------------------------\n'
                case "$mod" in
                    M1) printf ' MODULE 1 - Email authentication & anti-spoofing\n' ;;
                    M2) printf ' MODULE 2 - Dangling CNAME / cloud asset verification\n' ;;
                    M3) printf ' MODULE 3 - Nameservers & zone transfer\n' ;;
                    M4) printf ' MODULE 4 - DNSSEC & wildcard detection\n' ;;
                esac
                printf -- '--------------------------------------------------------------------------------\n'
            fi
            printf '   [%-4s] %-26s %s\n' "$sev" "$lbl" "$det"
        done

        printf '\n================================================================================\n'
        printf ' END OF REPORT\n'
        printf '================================================================================\n'
    } >"$out"
}

# ---------------------------------------------------------------------- main --
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)   ROOT_DOMAIN="${2:-}"; shift 2 || die "Missing value for $1" ;;
            -l|--list)     LIST_FILE="${2:-}"; shift 2 || die "Missing value for $1" ;;
            -o|--output)   OUTPUT_DIR="${2:-}"; shift 2 || die "Missing value for $1" ;;
            -t|--threads)  THREADS="${2:-}"; shift 2 || die "Missing value for $1" ;;
            --timeout)     TIMEOUT="${2:-}"; shift 2 || die "Missing value for $1" ;;
            --resolver)    RESOLVER="${2:-}"; shift 2 || die "Missing value for $1" ;;
            --dkim)        IFS=',' read -r -a _extra <<<"${2:-}"
                           DKIM_SELECTORS+=("${_extra[@]+"${_extra[@]}"}")
                           shift 2 || die "Missing value for $1" ;;
            --no-history)  HISTORY=0; shift ;;
            -v|--verbose)  VERBOSE=1; shift ;;
            --no-color)    NO_COLOR=1; shift ;;
            -h|--help)     usage; exit 0 ;;
            *)             usage; die "Unknown argument: $1" ;;
        esac
    done
}

load_targets() {
    local -a hosts=()
    local line seen="|"

    if [[ -n "$LIST_FILE" ]]; then
        [[ -f "$LIST_FILE" ]] || die "List file not found: $LIST_FILE"
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"
            line="$(normalise_host "$line")"
            [[ -z "$line" ]] && continue
            [[ "$line" == *.* ]] || continue
            hosts+=("$line")
        done <"$LIST_FILE"
    fi

    # The root domain is always audited.
    hosts+=("$ROOT_DOMAIN")

    for line in "${hosts[@]}"; do
        if [[ "$seen" != *"|$line|"* ]]; then
            TARGET_HOSTS+=("$line")
            seen="$seen$line|"
        fi
    done
    HOSTS_AUDITED=${#TARGET_HOSTS[@]}
    log_ok "$HOSTS_AUDITED host(s) queued for the CNAME / dangling sweep."
}

main() {
    init_colors
    banner
    parse_args "$@"

    [[ -z "$ROOT_DOMAIN" ]] && { usage; die "No target. Use -d <domain>."; }

    ROOT_DOMAIN="$(normalise_host "$ROOT_DOMAIN")"
    [[ -z "$ROOT_DOMAIN" ]] && die "Invalid domain"
    [[ "$ROOT_DOMAIN" == *.* ]] || die "Invalid domain: '$ROOT_DOMAIN'"

    case "$OUTPUT_DIR" in
        ""|"/"|".") die "Invalid output directory" ;;
    esac

    if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]]; then
        die "--threads must be a positive integer"
    fi
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -lt 1 ]]; then
        die "--timeout must be a positive integer"
    fi

    check_deps

    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/dnsshield.XXXXXX")
    mkdir -p "$TMP_DIR/hosts"

    log_step "Stage 1/6 - Target preparation"
    load_targets

    log_step "Stage 2/6 - Module 1: email authentication (SPF / DMARC / DKIM)"
    FINDINGS=()
    audit_email "$ROOT_DOMAIN"
    count_findings
    : >"$TMP_DIR/module1.txt"
    local f
    for f in "${FINDINGS[@]}"; do printf '%s\n' "$f" >>"$TMP_DIR/module1.txt"; done
    log_ok "Email authentication checks complete."

    log_step "Stage 3/6 - Module 2: CNAME sweep and dangling pointer detection"
    local running=0 done_n=0 i
    for i in "${!TARGET_HOSTS[@]}"; do
        audit_host "$((i + 1))" "${TARGET_HOSTS[$i]}" &
        running=$((running + 1))
        if [[ "$running" -ge "$THREADS" ]]; then
            wait -n || true
            running=$((running - 1))
            done_n=$((done_n + 1))
            progress "$done_n" "$HOSTS_AUDITED" "resolving CNAMEs"
        fi
    done
    wait || true
    progress_done
    log_ok "CNAME sweep complete for $HOSTS_AUDITED host(s)."

    log_step "Stage 4/6 - Module 3: nameservers and zone transfer"
    FINDINGS=()
    audit_nameservers "$ROOT_DOMAIN"
    count_findings
    : >"$TMP_DIR/module3.txt"
    for f in "${FINDINGS[@]}"; do printf '%s\n' "$f" >>"$TMP_DIR/module3.txt"; done
    log_ok "Nameserver and AXFR checks complete."

    log_step "Stage 5/6 - Module 4: DNSSEC and wildcard detection"
    FINDINGS=()
    audit_dnssec "$ROOT_DOMAIN"
    audit_wildcard "$ROOT_DOMAIN"
    count_findings
    : >"$TMP_DIR/module4.txt"
    for f in "${FINDINGS[@]}"; do printf '%s\n' "$f" >>"$TMP_DIR/module4.txt"; done
    log_ok "DNSSEC and wildcard checks complete."

    # --- collect every finding in module order -----------------------------
    # Module 2 findings live in the per-host files; merge them in order.
    : >"$TMP_DIR/module2.txt"
    : >"$TMP_DIR/module1b.txt"
    for i in "${!TARGET_HOSTS[@]}"; do
        local hd="$TMP_DIR/hosts/$((i + 1))"
        [[ -f "$hd/m1.txt" ]] && cat "$hd/m1.txt" >>"$TMP_DIR/module1b.txt"
        [[ -f "$hd/m2.txt" ]] && cat "$hd/m2.txt" >>"$TMP_DIR/module2.txt"
    done

    FINDINGS=()
    local -a ordered=()
    local src
    for src in "$TMP_DIR/module1.txt" "$TMP_DIR/module1b.txt" "$TMP_DIR/module2.txt" \
               "$TMP_DIR/module3.txt" "$TMP_DIR/module4.txt"; do
        read_findings "$src"
        for f in "${FINDINGS[@]+"${FINDINGS[@]}"}"; do ordered+=("$f"); done
    done
    FINDINGS=("${ordered[@]}")

    # Recount from the merged set.
    FIND_PASS=0; FIND_FAIL=0; FIND_WARN=0; FIND_INFO=0
    count_findings

    log_step "Stage 6/6 - Results and report"
    print_findings
    printf '\n'

    local report_dir="$OUTPUT_DIR/$ROOT_DOMAIN"
    mkdir -p "$report_dir"
    local report_file="$report_dir/dns_security_audit.txt"
    build_report "$report_file"
    log_ok "Report written: $report_file"

    if [[ "$HISTORY" -eq 1 ]]; then
        local stamp
        stamp=$(date '+%Y%m%d_%H%M%S')
        cp "$report_file" "$report_dir/dns_security_audit_${stamp}.txt"
        log_ok "Timestamped copy: $report_dir/dns_security_audit_${stamp}.txt"
    fi

    # --- summary table -----------------------------------------------------
    local verdict vcol
    verdict=$(overall_verdict)
    case "$verdict" in
        PROTECTED) vcol="$C_GRN" ;;
        WARNING)  vcol="$C_YEL" ;;
        *)        vcol="$C_RED" ;;
    esac
    printf '%s%s%s\n' "$C_BOLD" "Audit summary" "$C_RESET"
    printf '  %s%-14s %s%s%s\n' "$C_DIM" "Target" "$C_BOLD" "$ROOT_DOMAIN" "$C_RESET"
    printf '  %s%-14s %s%s%s\n' "$C_DIM" "Verdict" "$vcol" "$verdict" "$C_RESET"
    printf '  %s%-14s %s\n' "$C_DIM" "Hosts" "$HOSTS_AUDITED"
    printf '  %s%-14s %s%s pass%s   %s%s warning%s   %s%s vulnerable%s   %s%s info%s\n' \
        "$C_DIM" "Checks" \
        "$C_GRN" "$FIND_PASS" "$C_RESET" \
        "$C_YEL" "$FIND_WARN" "$C_RESET" \
        "$C_RED" "$FIND_FAIL" "$C_RESET" \
        "$C_CYN" "$FIND_INFO" "$C_RESET"
    printf '  %s%-14s %s\n\n' "$C_DIM" "Report" "$report_file"

    if [[ "$VERBOSE" -eq 1 ]]; then
        log_info "dig: $(command -v dig)  timeout: ${TIMEOUT}s  threads: $THREADS"
    fi

    exit 0
}

main "$@"

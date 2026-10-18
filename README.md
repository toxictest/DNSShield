# DNSShield v1.0.0

**DNS Misconfiguration & Email Security Auditor** — a single-file Bash tool that
audits a root domain and its discovered subdomains for dangling DNS pointers,
email spoofing weaknesses and misconfigured nameservers.

It takes Day 1's discovered subdomain list (or a single domain) and produces a
timestamped, plain-text audit report.

```
  Day 1 (ReconScope)                 Day 2 (DNSShield)
  results/<domain>/subdomains/  -->  results/<domain>/
    subdomains.txt                    dns_security_audit.txt
                                       dns_security_audit_20261017_111525.txt
```

---

## Why it exists

A subdomain that points at a third-party cloud bucket is only dangerous while
nobody owns that bucket. The moment the bucket is deleted, the DNS record
outlives it — and whoever registers the same name next inherits the
subdomain. The same is true of an open `AXFR`, which hands an entire zone to
anyone who asks, and of a domain that publishes no SPF or DMARC policy, which
lets anyone send mail as your CEO.

DNSShield asks the resolver those questions directly.

**100% free and standalone. No API keys. No paid services. No Python, Go or
npm dependency.**

---

## Requirements

| Tool | Used for | Required? |
|---|---|---|
| `bash` | the script itself (4.4+) | **yes** |
| `dig` | every DNS query | **yes** |
| `awk`, `grep`, `sed`, `tr` | parsing and reporting | **yes** |
| `host` | second opinion on name resolution | optional |
| `nslookup` | alternative resolver front-end | optional |
| `whois` | registrar and delegation cross-check | optional |
| `curl` | HTTP status probe on dangling targets | optional |

The optional tools are all standard Linux utilities (`bind-utils` /
`dnsutils`, `whois`). When one is missing, DNSShield says so and continues
with the checks it can still perform — it never silently pretends to have
checked something.

Install on Debian/Ubuntu:

```bash
sudo apt-get install -y dnsutils whois
```

---

## Installation

```bash
chmod +x dnsshield.sh
```

One file. No build step, no configuration.

---

## Usage

```bash
# Single domain
./dnsshield.sh -d target.com

# Batch: audit Day 1's discovered subdomains
./dnsshield.sh -d target.com -l results/target.com/subdomains/subdomains.txt

# Custom report directory
./dnsshield.sh -d target.com -l subs.txt -o ./scans

# Use a specific resolver
./dnsshield.sh -d target.com --resolver 8.8.8.8
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-d, --domain <domain>` | — | Root domain to audit. |
| `-l, --list <file>` | — | Subdomain list, one host per line. Entries with a scheme, path or port are normalised. |
| `-o, --output <dir>` | `results` | Report directory. The report lands in `<dir>/<target>/`. |
| `-t, --threads <n>` | `10` | Parallel host audits. |
| `--timeout <sec>` | `5` | Per-query DNS timeout. |
| `--resolver <ip>` | system resolver | Use a specific resolver, e.g. `8.8.8.8`. |
| `--dkim <list>` | — | Extra DKIM selectors to probe (comma separated). |
| `--no-history` | off | Do not keep a timestamped copy of the report. |
| `-v, --verbose` | off | Verbose logging. |
| `--no-color` | off | Disable ANSI colours. |
| `-h, --help` | — | Help banner and exit. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Audit completed. |
| `2` | Usage error, missing dependency, or unreadable input. |

---

## The four modules

### Module 1 — Email authentication & anti-spoofing

**SPF** — queried from the root domain's TXT records.

| SPF state | Verdict |
|---|---|
| no `v=spf1` record | **FAIL** — the domain can be spoofed |
| `-all` | **PASS** — hard fail, strict |
| `~all` | **WARN** — soft fail, consider `-all` |
| `+all` | **FAIL** — any host may send mail |
| `?all` | **FAIL** — neutral, any host may send mail |
| no `all` mechanism | **WARN** — policy is incomplete |
| `ptr` used | **WARN** — deprecated and unreliable |
| `redirect=` used | **WARN** — policy is delegated elsewhere |

The number of authorised mechanisms is reported, because a long `include:`
chain widens the spoofing surface.

**DMARC** — queried from `_dmarc.<domain>`.

| DMARC state | Verdict |
|---|---|
| no record | **FAIL** — no spoofing policy at all |
| `p=reject` | **PASS** — forged mail is refused |
| `p=quarantine` | **WARN** — not full enforcement |
| `p=none` | **WARN** — monitoring only, mail is still accepted |
| no `p=` tag | **FAIL** — policy undefined |

`sp=`, `rua=` and `ruf=` are reported separately, and every host in the
subdomain list gets its own `_dmarc` check — a subdomain with `p=none` is a
real spoofing vector even when the apex is locked down.

**DKIM** — 23 common selectors are probed, plus any given with `--dkim`.
Three cases are distinguished, which a naive "is there a TXT record?" check
gets wrong:

* a **working key** (a real public key in `p=`) → **PASS**
* a selector that is a **CNAME to a mail provider** (SendGrid, SES, …) — the
  key lives at the target and is followed → **PASS**
* a **revoked key** (`v=DKIM1; p=` with an empty key) → not a working key. If
  a *random* selector returns the same empty record, the whole namespace is
  wildcarded on purpose: no DKIM signing, but subdomain key hijacking is
  blocked → **WARN**

### Module 2 — Dangling CNAME / cloud asset verification

Every host in the list is queried for a CNAME. If the target belongs to a
recognised cloud provider, the target is then verified:

| CNAME target | Provider examples |
|---|---|
| Amazon | `*.s3.amazonaws.com`, `*.s3-website*.amazonaws.com`, `*.elasticbeanstalk.com`, `*.elb.amazonaws.com`, `*.cloudfront.net` |
| Microsoft | `*.azurewebsites.net`, `*.cloudapp.net`, `*.blob.core.windows.net` |
| GitHub | `*.github.io` |
| Heroku | `*.herokuapp.com` |
| Zendesk | `*.zendesk.com` |
| Netlify / Vercel / Fastly | `*.netlify.app`, `*.vercel.app`, `*.fastly.net` |
| Shopify | `*.myshopify.com` |
| Firebase | `*.firebaseapp.com`, `*.web.app` |
| Atlassian / Salesforce / Bitbucket / WordPress / Tumblr / Ghost / Pantheon / Acquia / BigCommerce / Surge.sh / Readme.io | and more |

| Target state | Verdict |
|---|---|
| `NXDOMAIN` — the name no longer exists | **FAIL — Potential Dangling Pointer / High Risk** |
| `SERVFAIL` / `REFUSED` | **FAIL — Potential Dangling Pointer / High Risk** |
| resolves, but has no address records | **FAIL — Potential Dangling Pointer / High Risk** |
| resolves and answers `HTTP 4xx/5xx` | **FAIL — Potential Dangling Pointer / High Risk** |
| resolves and answers `HTTP 2xx/3xx` | **PASS** — the asset is still claimed |
| not a known provider | **PASS** — informational |

The HTTP probe needs `curl`; without it the check falls back to DNS
resolution alone, which still catches the most common dangling case.

### Module 3 — Zone transfer & nameserver configuration

* The full authoritative NS set is listed from `dig NS`.
* Fewer than two name servers is flagged as a redundancy warning.
* **An `AXFR` is attempted against every single name server.** A transfer that
  succeeds dumps the whole zone — subdomains, mail hosts, internal
  infrastructure — and is reported as **FAIL**. A refused transfer is a
  **PASS**. A server that does not answer at all is reported as untested
  rather than silently counted as safe.
* `whois` is cross-checked against the authoritative set: the registrar, the
  creation date, and whether the registry's delegation agrees with the
  authoritative NS records. A mismatch is a **WARN** — it usually means a
  zone was moved without the delegation being updated.

### Module 4 — DNSSEC & wildcard detection

* `DNSKEY` records, the `ad` (authenticated data) flag and the `DS` record at
  the parent are all checked. A domain with keys but no `DS` has a broken
  chain and is flagged separately.
* A **random, non-existent label** is queried. If it resolves, the zone has
  a catch-all record — useful for the attacker, since it makes every guessed
  hostname resolve → **WARN**.

---

## Scoring

DNSShield reports an overall **verdict** rather than a numeric score, because
the four modules are not equally weighted and a flat number hides that.

| Verdict | Condition |
|---|---|
| `PROTECTED` | no failures and no warnings |
| `WARNING` | no failures, at least one warning |
| `VULNERABLE` | at least one failure |

The report header also gives the raw counts (pass / warning / vulnerable /
info) so the numbers are always visible.

---

## Output

```
<output_dir>/<target>/dns_security_audit.txt
<output_dir>/<target>/dns_security_audit_<YYYYmmdd_HHMMSS>.txt
```

The canonical file is always rewritten; the timestamped copy accumulates so
you can diff a domain's posture over time. Use `--no-history` to keep only
the canonical file.

### Console

```
  Module 1 - Email authentication & anti-spoofing
    [ OK ] SPF record                 present: v=spf1 ip4:192.30.252.0/22 ~all
    [WARN] SPF all mechanism          ~all - soft fail, consider -all
    [ OK ] DMARC record               present: v=DMARC1; p=quarantine; sp=reject
    [WARN] DMARC policy               p=quarantine - not full enforcement
    [ OK ] DKIM keys                  6 working key(s): google selector1 s1 s2
    [INFO] DKIM delegation            5 selector(s) are CNAMEs to a mail provider
```

| Colour | Meaning |
|---|---|
| **Green** | protected / correctly configured |
| **Red** | vulnerable / missing |
| **Yellow** | warning / soft policy |
| **Cyan** | informational |

### Report

Plain text, ANSI-free, with a header block, one section per module and every
finding listed with its severity:

```
================================================================================
 DNSShield v1.0.0 - DNS Misconfiguration & Email Security Audit
================================================================================
 Generated    : 2026-10-17 11:15:25
 Target       : github.com
 Hosts audited: 3
 Duration     : 00:00:04
 Verdict      : VULNERABLE
 Checks       : 16 pass, 3 warning, 2 vulnerable, 8 info
================================================================================
```

---

## Pipeline integration

```bash
# Day 1 - ReconScope
./reconscope.sh -d github.com
#  -> results/github.com/subdomains/subdomains.txt

# Day 2 - DNSShield
./dnsshield.sh -d github.com -l results/github.com/subdomains/subdomains.txt
```

The list may contain URLs, bare hosts, or hosts with ports — all are
normalised before querying.

---

## Testing

```bash
./tests/run_tests.sh
```

The suite drives the tool through a **stub `dig`** (plus stub `whois` and
`curl`) that replays canned resolver answers. That makes every module
deterministic, including the cases that are hard to find on the live
Internet — an open `AXFR` that dumps a whole zone, and a CNAME pointing at a
bucket that no longer exists.

| Run | What it covers |
|---|---|
| 1 | SPF `~all`, DMARC `p=none`, a working DKIM key and a revoked one |
| 2 | A dangling CNAME to a dead S3 bucket, a healthy one, and a host with no CNAME |
| 3 | The NS set, an open `AXFR` and a refused one |
| 4 | DNSSEC enabled with a DS chain, and the absence of a wildcard record |
| 4b | The opposite case — a wildcard record must be detected and warned about |
| 5 | CLI, report layout, the timestamped copy, `--no-history` and an unreachable domain |

Latest run: **40 assertions, 40 passing, 0 failing.**

The sample output is reproducible:

```bash
./tests/make_sample_output.sh
```

---

## Code quality

```bash
bash -n dnsshield.sh                 # syntax
shellcheck -S warning dnsshield.sh   # static analysis — clean
```

---

## Design notes

* `set -euo pipefail` throughout. Every pipeline inside a command substitution
  is guarded with `|| true`, because under `pipefail` a `grep` that matches
  nothing would otherwise abort the whole audit mid-run.
* **Reachability is taken from the resolver's status code**, so `NXDOMAIN`,
  `SERVFAIL` and `REFUSED` are distinguished rather than lumped together.
* `dig` is invoked with `+short` for record data and with the full output only
  where the header flags matter (the `ad` flag for DNSSEC, the SOA count for
  AXFR).
* Long TXT records arrive from `dig` split into several quoted chunks. They
  are rejoined exactly as the server sent them, so a long SPF policy is not
  truncated.
* `dig` is never piped into `head` — `head` closes the pipe early, `pipefail`
  sees `SIGPIPE` and `set -e` kills the script.
* Per-host audits run in parallel with a bounded worker pool; each host
  writes its own result file, so the report is assembled in a deterministic
  order regardless of completion order.
* Findings are split per module before reporting, so a module heading is
  printed once rather than repeating whenever modules interleave.
* No writes outside the output directory, no `sudo`, no destructive operations.

---

## Legal

Only issues ordinary DNS queries against the domains you specify. `AXFR` is
attempted against a domain's own published name servers — the standard
misconfiguration check. Use it on domains you are authorised to test.

---

## License

MIT

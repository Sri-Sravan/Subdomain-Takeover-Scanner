# Subdomain takeover vulnerability scanner.

Enumerates subdomains, resolves DNS, identifies dangling CNAMEs, fingerprints vulnerable services, and writes a structured report — all in one bash script.

```
subfinder → dnsx → filter → httpx → fingerprint → report
```

---

## What it detects

A subdomain is vulnerable to takeover when:
- It has a CNAME record pointing to a third-party service
- That service is unclaimed or deprovisioned (no A record — NXDOMAIN)

An attacker can register the abandoned resource and serve arbitrary content under the victim's trusted subdomain.

Fingerprint database covers 30+ services including GitHub Pages, AWS S3, Heroku, Netlify, Vercel, Surge.sh, Azure, Fastly, Shopify, Webflow, and more.

---

## Dependencies

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Make sure `~/go/bin` is in your PATH.

---

## Usage

```bash
chmod +x sdt-scan.sh
./sdt-scan.sh <domain>
```

```bash
./sdt-scan.sh example.com
```

---

## Output

Each scan writes to `output/<domain>/` — multiple scans never overwrite each other.

```
output/<domain>/
├── subfinder.txt       # all discovered subdomains
├── dns_full.txt        # A + CNAME records for every subdomain
├── cname_only.txt      # subdomains with CNAME records
├── dangling.txt        # CNAME with no A record — takeover candidates
├── httpx_results.txt   # HTTP probe output
├── vulnerable.txt      # matched findings with severity
└── report.txt          # full structured report
```

---

## Severity levels

| Level    | Condition                                              |
|----------|--------------------------------------------------------|
| CRITICAL | Dangling CNAME to GitHub Pages, Heroku, AWS S3         |
| HIGH     | Dangling CNAME to Vercel, Netlify, Surge, Azure, unknown service |
| MEDIUM   | CNAME to third-party SaaS, body-confirmed unclaimed    |
| LOW      | Probable but unconfirmed third-party service           |

---

## Notes

- Passive enumeration only — no brute force, no active traffic to the target
- ANSI escape codes from dnsx are stripped automatically before processing
- AWS S3 and CloudFront require HTTP body probing — their infrastructure resolves even for unclaimed resources, so NXDOMAIN alone won't catch them
- `amass` was evaluated and dropped — slower with no additional yield over subfinder for passive-only scans

---

## Legal

For authorized security testing only. Only scan domains you own or have explicit written permission to test. Subdomain takeover exploitation without authorization is illegal.

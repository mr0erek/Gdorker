# Gdorker v3

An autonomous Google-dorking + recon CLI. Built on the original [mr0erek/Gdorker](https://github.com/mr0erek/Gdorker) engine, extended with a "never blocked" search ladder, H4cksploit / bug-bounty-recon dork catalogs, crash-safe auto-recon, a live web dashboard, and a loxs-style vuln scanner.

> [!WARNING]
> Use at your own risk. Dorking against public search engines violates their ToS. The author is not responsible for how this tool is used.

## Features

- **5 engines**: `google`, `bing` (RSS-first), `duckduckgo`, `searxng`, `yacy`
- **Never-blocked ladder**: Google AdsBot UA spoof (`--adsbot`), curl_cffi TLS impersonation (`--cffi`), Google regional frontend rotation + basic-HTML mode (`gbv=1`) + no-cache headers, Bing RSS (plain XML), automatic engine fallback to DuckDuckGo on blocks
- **Free manual CAPTCHA bridge** (no API keys, no paid services): on a challenge it prints the URL and opens it in your default browser (`webbrowser.open`; `termux-open-url` on Termux). Solve it, press Enter, it retries with the solved session — counts and logs every solve
- **Dork catalogs** `--dorks`: `default` (original file-type/inurl/intitle lists), `h4` (34 H4cksploit / bug-bounty-recon techniques with site/global modes), `all`
- **H4 external recon kit**: crt.sh, Wayback CDX, Shodan, Censys, securityheaders, ThreatCrowd, viewdns, whatcms, publicwww, etc. (`--open-external`, `--external-file`)
- **`--auto-recon`**: headless every-dork × every-site loop with URL dedupe, incremental JSONL/CSV output, and a crash-safe `--resume-file` state
- **`-o/-O/--out`**: tee the whole scan log (queries, blocks, captcha events, results) to a file
- **`--web`**: embedded stdlib `http.server` live dashboard (auto-picked port, `--web-host` override, 2s auto-refresh) — run it alongside any query
- **Pagination prompt**: when a page returns results, offers `Continue fetching next page? [y/N]` interactively, and auto-continues (until <10 results or max pages) inside `--auto-recon`
- **Vuln scanner** `--scan/--check`: loxs-style LFI / SQLi / XSS / CRLF / OpenRedirect probes on gathered URLs (or a file), threaded, with a `--match <regex>` success filter and `--payloads <file>` custom JSON payload sets
- **Outputs**: `--json-out`, `--csv-out`, `--txt-out`, timestamped `vulns-<ts>.txt`, `--html-report <file>`
- **Proxy rotation**: `--proxy on` (auto GitHub PROXY-List, cached in `cache.json`) or `--proxy <file>`

## Install

```bash
pip install requests beautifulsoup4
# optional: pip install curl_cffi   # enables --cffi TLS impersonation
```

## Usage — reference by engine and variation

**Important (shell quoting):** queries with spaces, `&`, or embedded `"` must be wrapped in `'...'` and any inner `"` escaped as `\"` (or replaced with `'`). On PowerShell / cmd the `&` and `"` are shell-special, so always quote the whole `-s` value:

```powershell
# PowerShell / cmd — safe forms (note the escapes)
python Gdorker_v2.1.4.py -s 'site:greentribunal.gov.in & \"Aadhar no.\"' -d-
python Gdorker_v2.1.4.py -s "site:greentribunal.gov.in & 'Aadhar no.'" -d-
```

```bash
# bash / zsh / Linux — safe form
python Gdorker_v2.1.4.py -s 'site:greentribunal.gov.in & "Aadhar no."' -d-
```

> If a query has no spaces you can pass it raw (no quotes): `-s site:example.com`.

### Engine selection
`-e google | bing | duckduckgo | searxng | yacy` (add `--searx-host URL` / `--yacy-host URL` for the two self-hosted engines; SearXNG/YaCy without a host prompts interactively).

### Per-engine usage

#### Google (`-e google`)
Best anti-block ladder: `--adsbot` (AdsBot UA), `--cffi` (TLS impersonation), regional frontend rotation + basic-HTML (`gbv=1`) + no-cache headers already on by default.

```bash
python Gdorker_v2.1.4.py -s example.com -e google                  # direct
python Gdorker_v2.1.4.py -s example.com -e google -d               # default dork list
python Gdorker_v2.1.4.py -s example.com -e google --dorks h4       # h4 dork catalog
python Gdorker_v2.1.4.py -s example.com -e google -p 3             # 3 pages
python Gdorker_v2.1.4.py -s example.com -e google --adsbot         # AdsBot UA (JS-wall)
python Gdorker_v2.1.4.py -s example.com -e google --cffi           # curl_cffi impersonation
python Gdorker_v2.1.4.py -s example.com -e google --proxy on       # proxy rotation
python Gdorker_v2.1.4.py -s example.com -e google --web            # live dashboard
```

#### Bing (`-e bing`)
RSS-first (plain XML, least bot-fought); falls back to the HTML parser, then DuckDuckGo.

```bash
python Gdorker_v2.1.4.py -s example.com -e bing                    # RSS feed
python Gdorker_v2.1.4.py -s example.com -e bing -d                 # default dork list
python Gdorker_v2.1.4.py -s example.com -e bing --dorks h4         # h4 dork catalog
python Gdorker_v2.1.4.py -s example.com -e bing -p 5               # 5 pages
python Gdorker_v2.1.4.py -s example.com -e bing --adsbot           # harder-HTML fallback
python Gdorker_v2.1.4.py -s example.com -e bing --proxy proxies.txt
python Gdorker_v2.1.4.py -s example.com -e bing --auto-recon       # headless run
```

#### DuckDuckGo (`-e duckduckgo`)
Most bot-tolerant; good default for scraping-scale runs.

```bash
python Gdorker_v2.1.4.py -s example.com -e duckduckgo              # direct
python Gdorker_v2.1.4.py -s example.com -e duckduckgo -D all       # all dorks
python Gdorker_v2.1.4.py -s example.com -e duckduckgo -d my_dorks.txt
python Gdorker_v2.1.4.py -s example.com -e duckduckgo --json-out out/results.json
python Gdorker_v2.1.4.py -sl sites.txt -e duckduckgo --auto-recon --resume-file st.jsonl
```

#### SearXNG (`-e searxng`)
Self-hosted meta-engine. Needs `--searx-host` (prompts interactively if omitted).

```bash
python Gdorker_v2.1.4.py -s example.com -e searxng --searx-host http://localhost:8080
python Gdorker_v2.1.4.py -s example.com -e searxng --searx-host http://localhost:8080 -d
python Gdorker_v2.1.4.py -s example.com -e searxng --searx-host http://localhost:8080 --dorks all
python Gdorker_v2.1.4.py -s example.com -e searxng --searx-host http://localhost:8080 --searx-engines google,bing
python Gdorker_v2.1.4.py -s example.com -e searxng --searx-host http://localhost:8080 --searx-categories general
python Gdorker_v2.1.4.py -sl sites.txt -e searxng --searx-host http://localhost:8080 --auto-recon
```

#### YaCy (`-e yacy`)
Self-hosted P2P engine. Needs `--yacy-host` (prompts interactively if omitted).

```bash
python Gdorker_v2.1.4.py -s example.com -e yacy --yacy-host http://localhost:8090
python Gdorker_v2.1.4.py -s example.com -e yacy --yacy-host http://localhost:8090 -d
python Gdorker_v2.1.4.py -s example.com -e yacy --yacy-host http://localhost:8090 --dorks h4
python Gdorker_v2.1.4.py -s example.com -e yacy --yacy-host http://localhost:8090 -p 3
python Gdorker_v2.1.4.py -s example.com -e yacy --yacy-host http://localhost:8090 --web
```

### Common variations (any engine)

| Variation | Command |
|---|---|
| Direct raw query (no dorks) | `python Gdorker_v2.1.4.py -s 'site:example.com & "Aadhar no."' -e bing -d-` |
| Default dork list | `... -d` |
| Custom dork file | `... -d my_dorks.txt` |
| H4 dork catalog | `... --dorks h4` |
| All dorks (default + h4) | `... -D all` |
| More pages | `... -p 3` |
| More processes | `... -P 4` |
| Proxy pool (auto GitHub, cached) | `... --proxy on` |
| Proxy from file | `... --proxy proxies.txt` |
| Anti-JS-wall (Google/Bing) | `... --adsbot` |
| TLS impersonation (Google) | `... --cffi` |

### Output variations

| Output | Command |
|---|---|
| Tee full log | `... -o out/recon.log` (alias `-O`, `--out`) |
| JSON results | `... --json-out out/results.json` |
| CSV results | `... --csv-out out/results.csv` |
| Plain URL list | `... --txt-out out/urls.txt` |
| Live web dashboard | `... --web` (auto port; `--web-host 0.0.0.0` for LAN) |
| HTML findings report | `... --check lfi,sqli --html-report out/findings.html` |

### Auto-recon (all engines)

```bash
python Gdorker_v2.1.4.py -sl domains.txt --auto-recon -e bing \
    --dorks h4 --json-out out/recon.jsonl --csv-out out/recon.csv \
    --resume-file out/recon.state -o out/recon.log --web
```

- `-s example.com` (single site) or `-sl sites.txt`
- writes results incrementally (crash-safe); re-run with the same `--json-out` + `--resume-file` to skip already-done queries
- `--dorks default|h4|all`, `-e <engine>` any of the five

### Vuln scanning (`--check`, alias `--scan`)

```bash
# scan the URLs gathered this run
python Gdorker_v2.1.4.py -s example.com -e bing --check lfi,sqli,xss,crlf,openredirect
# scan URLs from a file
python Gdorker_v2.1.4.py --check urls.txt --threads 8
# custom payload file + custom success regex + html report
python Gdorker_v2.1.4.py --check lfi --payloads payloads.json --match 'root:' --html-report out.html
```

Vulnerable URLs are saved to a timestamped `vulns-<ts>.txt`.

### H4 external recon links

```bash
python Gdorker_v2.1.4.py -s example.com --open-external       # opens each tool in browser
python Gdorker_v2.1.4.py -s example.com --external-file links.txt   # just write the links
```

### Adversarial queries (spaces, `&`, quotes)

```bash
# Linux
python Gdorker_v2.1.4.py -s 'site:greentribunal.gov.in & "Aadhar no."' -e bing -d-
# Windows PowerShell / cmd
python Gdorker_v2.1.4.py -s 'site:greentribunal.gov.in & \"Aadhar no.\"' -e bing -d-
```

## CAPTCHA-free manual flow (PC + Termux)

When Google/Bing serve a challenge page:
1. The tool prints the challenge URL and opens it in your browser (`termux-open-url` on Termux).
2. Solve it, then press Enter in the terminal.
3. It retries with the same session (and proxy, if used) carrying the solved cookies.
4. Each open/solve + attempt count is logged to the `-o` log and visible in `--web`.

## Attribution

- Original engine + proxy cache: [mr0erek/Gdorker](https://github.com/mr0erek/Gdorker), proxies via [TheSpeedX/PROXY-List](https://github.com/TheSpeedX/PROXY-List)
- H4 dork catalog inspired by [viralmaniar/bigbountyrecon](https://github.com/viralmaniar/bigbountyrecon); vuln scanner inspired by [coffinxp/loxs](https://github.com/coffinxp/loxs) / loxs LLC.

> [!NOTE]
> Still upgrading. Some Google/Bing anti-bot behavior changes without notice; `-e duckduckgo` or a local SearXNG (`--searx-host`) is the most reliable fallback.

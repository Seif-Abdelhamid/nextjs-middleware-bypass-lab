# nextjs-middleware-bypass-lab

A **reproducible local lab** and **detection toolkit** for **CVE-2025-29927** —
the Next.js middleware authorization bypass (GHSA-f82v-jwr5-mffw, CVSS 9.1
Critical).

It does four things, all offline and on software you run yourself:

1. **Reproduces** the bypass against the real vulnerable release (`next@14.2.24`).
2. **Proves the fix** on the real patched release (`next@14.2.25`).
3. **Detects** exploitation attempts in web/proxy logs (a Sigma rule + a scanner).
4. **Audits** your manifests/lockfiles for vulnerable `next` versions, mapped to
   the advisory's exact ranges.

A pytest harness boots both real apps over HTTP and asserts *bypass-before /
blocked-after*, so the claim is demonstrated, not described.

> ⚠️ **Lab only.** The vulnerable app intentionally allows an authentication
> bypass. Run it on localhost; never expose it to a network. This project sends
> no traffic to any system you do not own.

---

## The business problem

Next.js middleware (`middleware.js`) is the natural place teams put
authentication and authorization gates: it runs before every matched route, so
"redirect to /login unless you have a session" lives there. CVE-2025-29927 lets
an **unauthenticated** attacker skip middleware entirely by sending one crafted
request header, turning that gate into no gate at all. It's CVSS 9.1 with an EPSS
in the 99th percentile — i.e. mass exploitation in the wild — so defenders need
to (a) find vulnerable apps fast and (b) spot exploitation in their logs.

## Intended users

- **SOC / detection engineers** who need log-based detection for exploitation
  attempts and a safe lab to generate realistic signal.
- **AppSec / platform engineers** verifying remediation across a fleet and
  wanting a CI gate that fails on vulnerable `next` versions.
- **Engineers / students** who want to understand the bug hands-on without
  touching anyone else's systems.

## How it improves the workflow

Instead of reading a blog post and hoping, a defender gets: a one-command demo
that shows the exact request and its effect; a dependency auditor they can drop
into CI; a log detector and Sigma rule they can wire into a SIEM; and a
regression test that proves their patched build is actually safe.

## Existing solutions reviewed, and the gap

Verified against primary sources (see [Sources](#sources)):

- **Official advisory (GHSA-f82v-jwr5-mffw)** and **patch PR vercel/next.js#77202**
  — authoritative on versions and the fix, but ship no lab, no regression test,
  and no detection content.
- **Public PoCs** (single-curl gists, exploit repos) — show the request, but
  don't package a before/after regression harness on the real versions, don't
  ship log detection, and don't audit lockfiles against the advisory ranges.
- **Generic SCA tools** flag the vulnerable version, but give you no running
  reproduction, no log-level detection, and no explanation tied to the mechanism.

**The gap this fills:** one honest, self-contained package that reproduces on the
real vulnerable version, proves the real patch, detects exploitation in logs, and
audits dependencies — with passing tests and CI.

## How the vulnerability works

Next.js uses an internal header, `x-middleware-subrequest`, to prevent its own
middleware from recursing during internal subrequests. The affected runtime
trusts that header on **inbound** requests too. When the header value repeats the
middleware module name enough times, the runtime hits its recursion-depth guard
(threshold **5**) and **skips middleware**. The exact payload depends on where
the middleware file lives:

| Next.js line | Payload value |
|---|---|
| 13.2+ (root `middleware`) | `middleware:middleware:middleware:middleware:middleware` |
| with `src/` dir | `src/middleware:src/middleware:...` (×5) |
| ≤12.1 (`pages/_middleware`) | `pages/_middleware:...` |

The patch pairs the header with a secret, per-process `x-middleware-subrequest-id`;
an inbound request can't produce it, so the spoofed header is dropped. (This lab
confirmed all of the above empirically against `next@14.2.24` and `14.2.25`.)

See [`docs/REMEDIATION.md`](docs/REMEDIATION.md) for the full fix and detection guide.

## Architecture

```
labs/
  vulnerable-app/     real next@14.2.24 app; auth enforced ONLY in middleware.js
  patched-app/        identical app on next@14.2.25
  docker-compose.yml  run both side by side (local only)
nextguard/            Python package (no runtime deps)
  semver.py           tiny semver comparator
  dep_audit.py        classify `next` in package.json / package-lock.json / yarn.lock
  log_scan.py         find x-middleware-subrequest in JSON + header-dump logs
  cli.py              `nextguard deps` / `nextguard logs`
detection/
  sigma/              Sigma rule for proxy/web logs
  samples/            benign + attack sample logs
tests/                unit tests + the real-HTTP reproduction (pytest -m integration)
docs/REMEDIATION.md   patch, edge mitigation, defense-in-depth, verification
demo.sh               one-command before/after demo
```

Both lab apps protect `/dashboard` with authorization enforced **only** in
middleware — deliberately, because that is the pattern CVE-2025-29927 punishes.

## Setup

Requirements: Python 3.10+, Node 18+ (Node 22 tested), npm.

```bash
# Python toolkit
python -m venv .venv && source .venv/bin/activate
pip install -e . && pip install -r requirements-dev.txt

# Lab apps (first run downloads the pinned Next.js versions)
(cd labs/vulnerable-app && npm install)
(cd labs/patched-app   && npm install)
```

## Usage

### Reproducible demo (before/after)

```bash
./demo.sh
```

Expected output (abridged):

```
== VULNERABLE ==
-- no header (auth enforced):
   HTTP 307 -> /login
-- WITH bypass header:
   LEAKED: PROTECTED DASHBOARD
   LEAKED: SECRET: internal revenue figures Q3
== PATCHED ==
-- WITH the same bypass header:
   HTTP 307 -> /login
```

Or with Docker (local only): `cd labs && docker compose up --build`, then the
vulnerable app is on `http://127.0.0.1:3001` and the patched app on `:3002`.

### Audit dependencies

```bash
nextguard deps .                      # walk a repo
nextguard deps package-lock.json      # single file; exits non-zero if vulnerable
nextguard deps . --json               # machine-readable, for CI
```

### Scan logs for exploitation

```bash
nextguard logs /var/log/proxy/access.json --ignore-paired
nextguard logs detection/samples/*.log
```

### Run the tests

```bash
pytest -q -m "not integration"   # fast unit tests (semver, audit, log scan, sigma)
pytest -q -m integration         # boots the REAL apps and asserts bypass/blocked
pytest -q                        # everything
```

## Limitations

- The reproduction is pinned to `14.2.24` / `14.2.25` (one representative
  affected/fixed pair). The dependency auditor covers all four advisory ranges;
  the running lab does not spin up every major.
- `next@14.2.25` fixes **this** CVE but a *later* advisory (Dec 2025) affects it
  too; npm will warn on install. For the purpose of CVE-2025-29927, 14.2.25 is the
  correct patched boundary, and the lab tests exactly that boundary.
- Log detection requires a log source that actually **captures request headers**;
  most web servers don't by default. The Sigma rule's field names are a starting
  point you must map to your pipeline's taxonomy.
- The dependency auditor resolves exact pins and lockfile entries; a fuzzy
  `package.json` range (`^14.0.0`) is reported `UNKNOWN` with advice to check the
  lockfile, rather than guessed.
- Sample attack logs are **synthetic**, authored for this lab to exercise the
  detector; they are not captured from any real environment and are not a measure
  of real-world detection efficacy.

## Adoption / extension guide

- **Add it to CI:** run `nextguard deps .` as a gate (it exits non-zero on
  vulnerable versions). Example job in `.github/workflows/ci.yml` (`self-scan`).
- **Wire detection into your SIEM:** import `detection/sigma/*.yml`, map the
  header field to your proxy log taxonomy, and alert on `level: high`.
- **Extend the auditor:** add new advisory ranges in `dep_audit.FIXED_RANGES`;
  add a parser to `_DISPATCH` for pnpm-lock or other formats.
- **Extend the lab:** copy a `labs/*-app` and pin a different affected/fixed pair
  to reproduce another major; the integration test helper is version-agnostic.

## Sources

- GitHub Security Advisory **GHSA-f82v-jwr5-mffw** — <https://github.com/advisories/GHSA-f82v-jwr5-mffw>
  (header name, affected ranges `12.0.0–<12.3.5`, `13.0.0–<13.5.9`,
  `14.0.0–<14.2.25`, `15.0.0–<15.2.3`, CVSS 9.1, credits to Allam Rachid "zhero;"
  and Allam Yasser "inzo_").
- Patch PR **vercel/next.js#77202** — <https://github.com/vercel/next.js/pull/77202>
  (the `x-middleware-subrequest-id` secret-pairing fix; split-on-`:` handling).
- Next.js **v14.2.25** release notes — <https://github.com/vercel/next.js/releases/tag/v14.2.25>
  (confirms the release contains the CVE-2025-29927 security patch).
- **CVE-2025-29927** (NVD) — mirrors the advisory's ranges, CWE-285/CWE-863.

Original discovery credited to **Allam Rachid ("zhero;")** and **Allam Yasser
("inzo_")**. This project is an independent reproduction and detection toolkit; it
claims no new discovery.

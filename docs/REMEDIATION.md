# Remediation & verification — CVE-2025-29927

## What the bug is (one paragraph)
Next.js uses an internal request header, `x-middleware-subrequest`, to stop its
own middleware from recursing when the runtime makes an internal subrequest. In
affected versions the runtime trusted that header **even when it arrived on an
inbound request from the outside**. If the value lists the middleware module name
enough times (the runtime skips middleware once a recursion-depth threshold of 5
is reached), the whole middleware runs is skipped. Any authorization enforced in
middleware is then bypassed. (Primary sources: GHSA-f82v-jwr5-mffw; patch PR
vercel/next.js#77202.)

## 1. Patch (the real fix)
Upgrade `next` to the first fixed release in your major:

| Major | Fixed version |
|-------|---------------|
| 15.x  | **15.2.3**    |
| 14.x  | **14.2.25**   |
| 13.x  | **13.5.9**    |
| 12.x  | **12.3.5**    |
| ≤11.x | no backported patch — upgrade to a supported major, and apply the proxy mitigation below in the meantime |

The patch makes the runtime pair `x-middleware-subrequest` with a secret,
per-process `x-middleware-subrequest-id`. An inbound request can't know that
secret, so its spoofed header is stripped and middleware runs normally.

Audit your repos for affected versions with the bundled tool:

```bash
nextguard deps path/to/repo          # walks the tree, classifies every `next`
nextguard deps package-lock.json     # or a single manifest/lockfile
```

It maps each version to the advisory's exact affected/fixed ranges and exits
non-zero if anything is vulnerable — drop it into CI as a gate.

## 2. Edge mitigation (until every service is patched)
Strip or block the header at the proxy/CDN/WAF **before it reaches the app**, for
inbound client traffic. The header is internal; external clients have no
legitimate reason to send it.

- **Nginx**: `proxy_set_header x-middleware-subrequest "";`
- **Envoy / API gateway**: remove `x-middleware-subrequest` from the inbound request.
- **WAF**: block requests that carry `x-middleware-subrequest`.

This is defense in depth, not a substitute for patching: it only helps where all
traffic passes a proxy you control, and it does not help self-hosted apps reached
directly.

## 3. Defense in depth (the real lesson)
> Middleware is not an authorization boundary.

Even on a patched runtime, don't make middleware the *only* place authorization
is enforced. Re-check authentication/authorization where the data is actually
served — in the route handler / server action / API route / data layer — so a
single middleware bypass can never expose protected data. In this lab, the
vulnerable app checks auth only in `middleware.js`; a hardened version would also
verify the session inside `app/dashboard/page.js`.

## 4. Detect exploitation attempts
If your proxy/WAF logs request headers, ship the Sigma rule in
`detection/sigma/` and/or scan captured logs:

```bash
nextguard logs /var/log/proxy/access.json --ignore-paired
```

The signal is any **inbound** request carrying `x-middleware-subrequest`.
`--ignore-paired` suppresses internal subrequests that carry a valid
`x-middleware-subrequest-id`, so you're left with the suspicious ones.

## 5. Verify the fix
After patching, re-run the lab's reproduction test against your build, or use the
one-liner against a patched instance **you own**: a request to a middleware-protected
path carrying the bypass header must still be denied (redirected / 401 / 403), and
must not return protected content.

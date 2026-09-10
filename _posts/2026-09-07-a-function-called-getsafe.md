---
layout: post
title: "A Function Called getSafe"
subtitle: "It fetches a URL and returns the body. It follows redirects. It validates nothing. The only safe thing about getSafe is the name."
date: 2026-09-07
tags: [ssrf, nodejs, embedjs, ai, cwe-918, full-disclosure]
read_time: "5 min read"
---

Third one in this little series of AI-framework SSRFs, and this one I love purely for the name of the function at the centre of it. In [embedJs](https://github.com/llm-tools/embedJs) — a "load anything into your vector store" toolkit — the web, sitemap, and PDF loaders all fetch their URL through a shared helper called `getSafe()`.

You already know where this is going.

## The boring part

The flow is the usual "add this source to my knowledge base": user provides a URL, embedJs fetches it, chunks the body, embeds it. The one piece of validation in the whole path is a helper called `isValidURL()`. Reassuring. Let's read it:

```js
export function isValidURL(candidateUrl) {
    try {
        const url = new URL(candidateUrl);
        return url.protocol === 'http:' || url.protocol === 'https:';   // scheme. that's it.
    } catch { return false; }
}
```

It checks the *scheme*. `http`/`https` → valid. That's the entire check. `http://169.254.169.254/` is a perfectly valid `http:` URL, so it sails through.

## The tilt-your-head part

But surely the fetch helper, the one named `getSafe`, does the real work? Here is the complete function — not an excerpt, the whole thing:

```js
export async function getSafe(url, options) {
    const headers = options?.headers ?? {};
    headers['User-Agent'] ??= DEFAULT_USER_AGENT;
    const format = options?.format ?? 'stream';
    const response = await fetch(url, { headers });   // no validation; redirects followed
    if (response.status !== 200) throw new Error(...);
    return { body: /* text | buffer | stream */, statusCode: response.status, headers: response.headers };
}
```

There is no guard above the `fetch`. There is no guard below it. The only branching is which *format* to return the body in. `getSafe` is `fetch` with a `User-Agent` and a nicer name. It follows redirects by default, and it hands the body back to the caller — a readable SSRF, and the "safe" in the identifier is doing zero work.

The `SitemapLoader` makes it worse: it fetches an attacker-supplied sitemap and then spins up a `WebLoader` for *every URL inside it*. Point it at a sitemap you wrote and you've turned one SSRF into an internal port scanner.

## Proof

Against published `@llm-tools/embedjs-loader-web@0.1.31` (current latest), verbatim from the run:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.mjs — embedjs 0.1.31</span></div>
<pre><span class="dim">=== [1] isValidURL() — the only check embedJs performs ===</span>
  <span class="bad">ACCEPTED</span>  http://169.254.169.254/latest/meta-data/
  <span class="bad">ACCEPTED</span>  http://[::ffff:169.254.169.254]/
  <span class="bad">ACCEPTED</span>  http://127.0.0.1/
  <span class="bad">ACCEPTED</span>  http://metadata.google.internal/computeMetadata/v1/
  ^ only the scheme is checked; every internal host is accepted.

<span class="dim">=== [2] WebLoader direct to loopback "IMDS" ===</span>
  content: "internal-metadata-service role: admin-instance-role <span class="warn">SECRET-IMDS-TOKEN=07e8cb93</span> ..."
  <span class="bad">SSRF SUCCESS — internal secret returned</span></pre>
</div>

## The fix

`getSafe` has to earn its name: resolve the host, reject loopback / RFC1918 / link-local / `169.254.169.254` / IPv4-mapped-IPv6, fail closed on parse failure, `redirect: "manual"` with per-hop re-validation, and pin the connection to the validated IP to stop DNS rebinding. `isValidURL` should do more than scheme-check, or the destination check should move into `getSafe` itself so *every* caller is covered.

## Where this stands

Present on `@llm-tools/embedjs-*@0.1.31` — current `latest` across the packages — no CVE, no fix. Full disclosure. The network-layer IMDS lockdown is, again, the mitigation that doesn't wait on the library.

## Takeaways

- **A name is not a control.** `getSafe`, `validateSafeUrl`, `sanitize` — read the body, because the identifier is marketing until proven otherwise.
- **Scheme validation is not destination validation.** `http://` being a valid scheme tells you nothing about *where* it points.
- **Fan-out loaders amplify.** A sitemap loader that fetches every child URL turns a single SSRF into a scanner. Rate and destination limits matter double there.

<hr>

*Full disclosure. Present on `@llm-tools/embedjs-loader-web` / `@llm-tools/embedjs-utils` 0.1.31 (current latest) at time of writing; no CVE assigned, no fix released. Reproduced against the published packages; PoC uses loopback stand-ins only.*

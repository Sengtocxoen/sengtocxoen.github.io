---
layout: post
title: "The Brackets That Hid an Address"
subtitle: "LangChain added an SSRF guard after the last CVE. It checks for private IPs — but only after asking 'is this an IP?', and one way of writing 169.254.169.254 makes it answer no."
date: 2026-09-09
tags: [ssrf, nodejs, langchain, ai, cwe-918, full-disclosure]
read_time: "8 min read"
---

Every RAG app has the same feature: *paste a link, I'll read it for you.* The user gives a URL, the framework fetches it, the bytes go to the model. It is the single most natural thing an "AI that reads the web" can do — and it is a textbook SSRF sink, because "a URL the user controls" is also "a URL that could point at `169.254.169.254`", the cloud metadata service that hands out your instance's IAM credentials to anyone on the box who asks.

LangChain JS knows this. It got an SSRF CVE before, and it responded by adding a guard, `validateSafeUrl`. This is a story about two gaps: the guard has a hole, and most of the loaders don't call it at all.

## The boring part

`validateSafeUrl` is supposed to reject the dangerous destinations — loopback, RFC1918, and the metadata IP. And it does, for the obvious spellings. `https://169.254.169.254/` → blocked. `https://127.0.0.1/` → blocked. If you only ever tried the front-door forms, you'd conclude the guard works.

## The tilt-your-head part

Here is the shape of the guard:

```js
const hostname = parsedUrl.hostname;          // for [::ffff:169.254.169.254] this is "[::ffff:a9fe:a9fe]"
if (isCloudMetadata(hostname)) throw ...;     // doesn't recognise the bracketed mapped form
if (isLocalhost(hostname)) { ... }
if (isIP(hostname)) {                          // <- everything dangerous is checked INSIDE here
    ... isPrivateIp / isCloudMetadata / isLocalhost ...
    return url;
}
return url;                                    // ...and mapped-IPv6 falls through to here
```

The private-IP and metadata checks live *inside* `if (isIP(hostname))`. So the whole thing hinges on `isIP()` recognising the hostname as an IP. Now consider an **IPv4-mapped IPv6 address**: `[::ffff:169.254.169.254]`. That's a legitimate way to write the metadata IP. `new URL(url).hostname` gives you the *bracketed* string `[::ffff:a9fe:a9fe]`. `isIP()` looks at that — with the brackets — and says: not an IP. So the guarded block is skipped entirely, and the URL falls through to `return url`. Accepted.

Then Node's `fetch` takes over, strips the brackets, sees a mapped IPv4, and connects to `169.254.169.254`. The guard said "not an IP, must be a harmless hostname"; the network stack said "of course that's the metadata service." Same string, two readers, and the disagreement is the vulnerability.

## Proof

Guard-level, against published `@langchain/core@1.2.8`:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node verify_ssrf.mjs — @langchain/core 1.2.8</span></div>
<pre>https://169.254.169.254/            want=BLOCK got=<span class="ok">BLOCK</span>
https://127.0.0.1/                  want=BLOCK got=<span class="ok">BLOCK</span>
https://[::ffff:169.254.169.254]/   want=BLOCK got=<span class="bad">PASS</span>   &lt;&lt;&lt; bypass (metadata)
https://[::ffff:a9fe:a9fe]/         want=BLOCK got=<span class="bad">PASS</span>   &lt;&lt;&lt; bypass (metadata, hex)
https://[::ffff:7f00:1]/            want=BLOCK got=<span class="bad">PASS</span>   &lt;&lt;&lt; bypass (loopback)
https://[::ffff:0a00:0005]/         want=BLOCK got=<span class="bad">PASS</span>   &lt;&lt;&lt; bypass (10.0.0.5, RFC1918)
https://example.com/                want=PASS  got=<span class="ok">PASS</span></pre>
</div>

End-to-end through the guarded loader, and then through an *un*guarded one:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.mjs — end to end</span></div>
<pre><span class="dim"># RecursiveUrlLoader (has the guard) via the mapped-IPv6 bypass</span>
target http://[::ffff:127.0.0.1]:PORT/  -> <span class="bad">SSRF SUCCESS</span>  leaked: METADATA_SECRET=RUL-BYPASS-ab12cd

<span class="dim"># CheerioWebBaseLoader (no guard at all) — plain loopback works</span>
url http://127.0.0.1/latest/meta-data/  -> LOADED "<span class="warn">SECRET_TOKEN=SSRF-LEAK-9f83c1</span>"</pre>
</div>

That second line is the other half of the story. `RecursiveUrlLoader` is the *only* loader that calls the guard. `CheerioWebBaseLoader`, `HTMLWebBaseLoader`, the Puppeteer and Playwright loaders, and a pile of Cheerio subclasses (`HNLoader`, `SitemapLoader`, `GitbookLoader`, …) call `fetch(url)` / `page.goto(url)` on a fully attacker-controlled URL with **no guard and default redirect-follow**, and return the body as document content. For those, you don't even need the bracket trick — plain `127.0.0.1` walks right in.

Because the fetched bytes come back to the caller (and usually straight to the LLM and the user), this is a *readable* SSRF. On a cloud VM with an attached role, "read this link" becomes "read my IAM credentials."

## The fix

Two things. In `validateSafeUrl`: strip the brackets, canonicalise the hostname, detect IPv4-mapped IPv6 in both dotted (`::ffff:a.b.c.d`) and hex (`::ffff:XXXX:XXXX`) forms, extract the embedded IPv4, and run the private/metadata checks on *that*. Fail closed on anything you can't parse. And structurally: call the guard from *every* fetch-based loader, not just one, with `redirect: "manual"` and per-hop re-validation. The right long-term shape is resolve-then-pin-the-IP, which also kills DNS rebinding — the same follow-up that bit `link-preview-js` after its first SSRF fix.

## Where this stands

Present on `@langchain/core@1.2.8` and `@langchain/community@1.1.29` — current `latest` of both — at time of writing. The earlier advisories (GHSA-mphv-75cg-56wg, GHSA-gf3v-fwqg-4vh7) were `RecursiveUrlLoader`-only and are already patched; neither covers the mapped-IPv6 guard bypass or the unguarded Cheerio/HTML loaders. No CVE for these yet, no fix. Full disclosure. If you run LangChain loaders on user-supplied URLs in the cloud: block IMDS at the network layer (hop-limit / IMDSv2-only / egress deny to 169.254.169.254) today — that mitigation doesn't depend on the library at all.

## Takeaways

- **Guard-then-fetch is only as good as the guard's parser agreeing with fetch's parser.** Any string both of them interpret — differently — is a bypass. IPv4-mapped IPv6 is the canonical one; keep it on your checklist.
- **Checking `if (isIP(x))` before the danger checks means non-IP-looking hostnames skip them.** Fail *closed*: unknown shape → unsafe.
- **One guarded loader out of a dozen is not a guarded library.** Inconsistent application of a security control is its own bug class.
- **Readable SSRF + cloud IMDS = credential theft.** The "just summarise this page" feature is a credential exfiltration primitive on every default cloud deployment.

<hr>

*Full disclosure. Present on `@langchain/core` 1.2.8 / `@langchain/community` 1.1.29 (current latest) at time of writing; no CVE assigned, no fix released. Reproduced against the published packages at guard level and end-to-end.*

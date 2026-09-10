---
layout: post
title: "The Base Class That Fetched Anything"
subtitle: "In LlamaIndex.TS, if the path you hand a reader starts with http, it fetches it. Every reader. Because the fetch lives in the class they all inherit from."
date: 2026-09-08
tags: [ssrf, typescript, llamaindex, ai, cwe-918, full-disclosure]
read_time: "6 min read"
---

Last post was about LangChain's web loaders reaching the cloud metadata service. This is the same class of bug in the neighbouring framework, [LlamaIndex.TS](https://github.com/run-llama/LlamaIndexTS) — with a detail that makes it broader: the SSRF isn't in *a* reader, it's in the base class that *every* reader inherits.

## The boring part

LlamaIndex readers ingest documents. `PDFReader`, `CSVReader`, `DocxReader`, `JSONReader`, `HTMLReader`, `MarkdownReader`, image readers — you point one at a file and it turns the bytes into `Document`s for indexing. The convenience feature is that "a file" can also be a URL: pass an `http://…` string and it'll go fetch it for you. Handy for indexing a remote doc.

All of these readers share one abstract parent: `FileReader`. And `loadData` — the method you call on every one of them — lives there.

## The tilt-your-head part

```js
async loadData(filePath) {
  let fileContent;
  if (filePath.startsWith("http://") || filePath.startsWith("https://")) {
    const response = await fetch(filePath);       // no guard, follows redirects
    const buffer = await response.arrayBuffer();
    fileContent = new Uint8Array(buffer);         // returned as Document content
  } else {
    fileContent = await fs.readFile(filePath);
  }
  ...
}
```

`filePath.startsWith("http")` → `fetch(filePath)`. No allowlist. No private/loopback/link-local/metadata check. No IPv4-mapped-IPv6 canonicalisation. Default `redirect: "follow"`. And the fetched bytes become `Document` content that flows back to the caller and the model — a *readable* SSRF.

Because this is the base class, there is nothing to enumerate. It isn't "these five loaders are affected." It is *the reader abstraction itself*. Any app doing the ordinary thing — `reader.loadData(userInput)` where `userInput` is a path or URL someone can influence — can be pointed at internal services or `169.254.169.254`.

## Proof

Against published `@llamaindex/core@0.6.22` (via `llamaindex@0.12.1`, current latest), a reader aimed at a loopback stand-in for the metadata service:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc_ssrf.mjs — llamaindex 0.12.1</span></div>
<pre>pointing FileReader at: http://127.0.0.1:PORT/latest/meta-data/iam/security-credentials/role
[internal-server] HIT /latest/meta-data/iam/security-credentials/role
docs returned: 1
leaked => "<span class="warn">IAM-ROLE-CREDS{AccessKeyId:ASIA_FAKE,SecretAccessKey:s3cr3t_metadata_token}</span>"</pre>
</div>

The redirect variant works too — an "allowed" public URL that 302s to loopback still returns the internal secret, because nothing re-checks the hop. On a real cloud host, the same call to `http://169.254.169.254/…` returns live IAM credentials.

## The fix

Gate remote fetching behind an explicit, default-**off** opt-in — most readers are only ever used with local files, so remote URLs shouldn't fetch silently at all. When enabled: resolve the host and reject loopback / RFC1918 / link-local / ULA / `169.254.169.254` / IPv4-mapped-IPv6 (both dotted and hex), fail closed on parse failure, use `redirect: "manual"` with per-hop re-validation, and reject non-`http(s)` schemes. (LangChain's guard is the reference — including its own mapped-IPv6 hole, which is exactly the mistake *not* to copy.)

## Where this stands

Present on `@llamaindex/core@0.6.23` / `llamaindex@0.12.1`, current `latest`, no CVE, no fix. Full disclosure. Same *class* as the LangChain finding, distinct package and sink — and broader, because the sink is the shared base class. Cloud mitigation is the same and library-independent: lock down IMDS at the network layer now.

## Takeaways

- **A sink in a base class is a sink in every subclass.** When you audit an abstraction, the blast radius is everything that extends it.
- **"It can also take a URL" is an SSRF opt-in hiding in a convenience.** Local-file readers that silently fetch remote URLs should make that behaviour explicit and off by default.
- **The whole framework category shares this bug.** LangChain, LlamaIndex — "read this link" is the defining feature of AI-document tooling and the defining SSRF sink. Assume every one of them has it until you've checked.

<hr>

*Full disclosure. Present on `@llamaindex/core` 0.6.23 / `llamaindex` 0.12.1 (current latest) at time of writing; no CVE assigned, no fix released. Reproduced against the published package at sink and end-to-end level.*

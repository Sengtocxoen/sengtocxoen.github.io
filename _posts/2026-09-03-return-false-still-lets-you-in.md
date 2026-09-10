---
layout: post
title: "Return False, Still Lets You In"
subtitle: "The obvious way to write an auth check is to return true or false. In oas-tools, only throwing denies the request. Returning false does nothing at all."
date: 2026-09-03
tags: [authentication, api-security, nodejs, openapi, cwe-305, full-disclosure]
read_time: "5 min read"
---

`@oas-tools/core` turns an OpenAPI spec into a running Express API, security middleware included. You register a security handler for each scheme, and it decides who gets in. The trap is in *how* it reads your decision.

## The boring part

What does a security handler look like? If you've written one before, your fingers already typed it:

```js
apiKeyHeader: (token) => token === process.env.API_SECRET
```

Return `true` for a good credential, `false` for a bad one. That's the natural contract for an auth check, and it's the contract the closest sibling library (`openapi-backend`) uses. The oas-tools docs describe the *success* case — a returned result gets stored in `res.locals.oas.security.<handler>` — and say nothing that would make you write it differently.

## The tilt-your-head part

The middleware decides authorization **solely by whether the handler throws.** The value you *return* is never used as a decision. From `src/middleware/native/oas-security.js`:

```js
results.forEach(([secName, result]) => {
    if (result) res.locals.oas.security = {[secName]: result};   // truthiness only — NOT a decision
});
// ...
}).catch((err) => { /* the ONLY denial path — requires a throw */ });
// ...
next();   // reached unless a handler threw
```

A truthy return gets stored in `res.locals`. A falsy return is *silently ignored*. Denial happens in exactly one place: the `.catch()`, which only fires if the handler **threw**. So a handler that reports failure by returning `false` doesn't block anything — control falls through to `next()` and the protected operation runs.

The cruellest detail: the library itself *throws* for a **missing** token. So "no credential at all" is denied, but "invalid credential, reported honestly as `return false`" is allowed. That asymmetry is the whole bug in one sentence — and it's the clearest sign this is an oversight, not a designed "throw-to-deny" contract.

## Proof

Against published `@oas-tools/core@3.1.0` (current latest), verbatim:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.cjs — @oas-tools/core 3.1.0</span></div>
<pre>A handler is given an INVALID credential. Does the request get denied?

  handler returns false  -> denied: <span class="bad">false</span>   &lt;&lt;&lt; request proceeds (fail-open)
  handler throws         -> denied: <span class="ok">true</span>    (correctly denied)</pre>
</div>

Every application that implemented its auth check in the idiomatic boolean style has authentication that fails open: every invalid credential is accepted on every protected route. Unauthenticated, network-reachable, no interaction.

## The fix

Treat a falsy return as denial. A handler that returns `false` (or `null`, or `undefined`) must reject the request, exactly as a throw does. Until upstream ships that, the mitigation in *your* handlers is a one-liner: **throw on failure**, don't return false —

```js
apiKeyHeader: (token) => { if (token !== process.env.API_SECRET) throw new Error('bad token'); return true; };
```

— and audit every handler you've already written for the returns-false pattern, because each one is currently a hole.

## Where this stands

Present on `@oas-tools/core@3.1.0`, current `latest`, no CVE, no fix. This is also the one target in this batch whose repo is genuinely quiet (last push ~16 months ago), which is part of why it's going out as full disclosure — but "quiet repo" and "quiet vulnerability" are not the same thing, and this one is unauthenticated High. If you run oas-tools security handlers: convert them to throw-on-failure today.

## Takeaways

- **Decide how the framework reads your decision.** "Return false" and "throw" are both plausible deny signals; a framework that honours only one will silently accept the other.
- **Fail-open asymmetries are diagnostic.** When "missing credential" is denied but "wrong credential" is allowed, you've found a comparison bug, not a policy.
- **The idiomatic implementation is the one to test.** The bug only bites developers who wrote the *obvious* handler — which is most of them.

<hr>

*Full disclosure. Present on `@oas-tools/core` 3.1.0 (current latest) at time of writing; no CVE assigned, no fix released. Reproduced against the published package's middleware logic.*

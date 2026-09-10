---
layout: post
title: "The Deny That Only Counted Once"
subtitle: "Two policies match your request. One hides the SSN field, one doesn't. abacl intersects the denies instead of unioning them — so the field one policy tried to hide comes back."
date: 2026-09-04
tags: [access-control, authorization, nodejs, cwe-863, full-disclosure]
read_time: "5 min read"
---

A quick, honest one to close out the access-control batch — and I want to be upfront that this is the mildest of them: a Medium, confidentiality-only issue that hinges on a semantic choice the library never documented. But it's a clean illustration of a real question every policy engine has to answer, so it's worth telling.

`abacl` is an attribute-based access-control library. It supports per-policy attribute projections: `field: ['*', '!ssn']` means "all attributes except `ssn`". The interesting case is what happens when *two* policies match the same request and they disagree about what to hide.

## The boring part

Under `strict: false` — the mode used in abacl's own README — scoped actions collapse onto plain ones. A `read` request matches both `read:own` and `read:shared`. That's by design and convenient. So you might write:

```js
{ action: 'read:own',    field: ['*'] }          // own records: see everything
{ action: 'read:shared', field: ['*', '!ssn'] }  // shared records: hide the SSN
```

Now a plain `read` matches both. The question: what should the combined projection be?

## The tilt-your-head part

The conventional secure default is **deny-overrides**: if *any* matching policy hides a field, it stays hidden. abacl does the opposite for denies. From `accumulate()` in `dist/utils/other.util.js`:

```js
let neg = first.filter((f) => f.startsWith('!'))                              // denies from the FIRST policy
for (const notation of notations) {
    pos = [...new Set([...pos, ...notation.filter((f) => !f.startsWith('!'))])]      // allows: UNION (fine)
    neg = neg.filter((n) => notation.filter((f) => f.startsWith('!')).includes(n))  // denies: INTERSECTION (bug)
}
```

Allows are unioned — good. But `neg` is *intersected*: it shrinks to only the denials present in **every** matching policy. A field denied by one policy but not another survives. `!ssn` is in the `shared` policy and not in the `own` policy, so the intersection drops it, and the SSN comes back.

## Proof

Against published `abacl@8.0.11` (current latest):

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.cjs — abacl 8.0.11</span></div>
<pre>strict:false  read         -> field(): {"id":1,"title":"T",<span class="bad">"ssn":"123-45-6789"</span>}   &lt;&lt;&lt; leaked
strict:true   read:shared  -> field(): {"id":1,"title":"T"}                        (control: hidden)

accumulate(['*','!ssn'], ['*'])          => ["*"]   // !ssn dropped
accumulate(['*','!ssn'], ['*','!owner']) => ["*"]   // both denies dropped</pre>
</div>

The action-level allow/deny decision is *not* affected — default-deny for unlisted action/object is intact. Only the attribute projection over-discloses. That's why it's confidentiality-only and I score it Medium (CVSS 3.1 4.9), not High.

## The honest caveat

I'll say plainly what the report says: abacl doesn't document whether multiple matching grants are meant to be deny-overrides or *additive* (allow-overrides). If additive is the intended model, this output is technically "by design" — but then a per-scope `!field` deny is silently meaningless whenever any broader matching policy exists, which is its own footgun worth documenting. Either way, a field an administrator wrote a policy to hide is being returned, and that's worth a maintainer's attention.

## The fix

Union the denies so a field hidden by any matching policy stays hidden:

```js
function accumulate (...notations) {
    const pos = new Set(), neg = new Set();
    for (const n of notations.filter(n => n.length)) for (const t of n) (t.startsWith('!') ? neg : pos).add(t);
    return [...pos, ...neg];   // denied by ANY matching policy -> stays denied
}
```

## Where this stands

Present on `abacl@8.0.11`, current `latest`, no CVE, no fix. Full disclosure, with the semantics caveat stated honestly — I'd rather under-claim a Medium than dress it up. If you use abacl with `strict: false` and per-scope field lists: assume your narrower `!field` denies may not hold, and test the multi-policy case.

## Takeaways

- **"Combine matching policies" needs a documented rule.** Deny-overrides vs additive is a real fork, and leaving it implicit means the answer is whatever the code happened to do.
- **Allows union, denies union too.** Intersecting denies is the subtle version of "the broadest policy wins" — the opposite of what security wants.
- **Under-claim on purpose.** A Medium reported as a Medium, with the caveat attached, is worth more to a maintainer than a Medium dressed as a bypass.

<hr>

*Full disclosure. Present on `abacl` 8.0.11 (current latest) at time of writing; Medium, confidentiality-only; no CVE assigned, no fix released. Reproduced against the published package.*

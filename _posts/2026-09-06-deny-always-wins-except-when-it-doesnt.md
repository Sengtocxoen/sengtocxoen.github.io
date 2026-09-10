---
layout: post
title: "Deny Always Wins, Except When It Doesn't"
subtitle: "The README says it twice, in bold: deny-overrides, deny always wins. Grant three fields, then deny all fields with a wildcard, and all three come right back."
date: 2026-09-06
tags: [access-control, authorization, nodejs, cwe-863, full-disclosure]
read_time: "6 min read"
---

`accesscontrol` is a popular RBAC/ABAC library for Node with a very confident README. Its headline property, stated twice, in bold:

> "Role hierarchical inheritance with **deny-overrides** (deny always wins)."

That's a strong promise, and it's the kind of promise people build policies on top of. So the test writes itself: grant a role some attributes, then deny them, and see who wins.

## The boring part

The attribute filtering API is the last thing that runs before you serialise a response. You call `permission.filter(record)` and it strips the attributes the role isn't allowed to see. Deny a field and it should vanish. That's the whole feature. When it works — and for specific named attributes, it does — it's exactly what you want.

## The tilt-your-head part

The failure is precise. Grant a role an **enumerated** list of attributes, then deny with a **wildcard**:

```js
ac.grant('accountant').readAny('transaction', ['amount', 'bonus', 'currency']);
ac.deny('accountant').readAny('transaction', ['*']);   // revoke everything
```

Reads like a full revocation. Behaves like a no-op. The `granted` flag stays `true` and `filter()` returns all three fields. Root cause, `lib/utils/grants.js`:

```js
const negated = denied.map((a) => (a.startsWith('!') ? a.slice(1) : '!' + a));
return NotationGlob.normalize(allowed.concat(negated));
```

It turns the deny list into negation globs, concatenates them onto the allow list, and lets the `notation` library's `normalize()` sort it out. And `notation` ranks a *specific* positive glob (`amount`) above a *broader* negation glob (`!*`). So `normalize(['amount', '!*'])` returns `['amount']` — the broad deny loses to the specific grant. The subtraction silently degrades into nothing *precisely when the deny is widest*, which is exactly the case you most want to work.

## Proof

Against published `accesscontrol@3.1.0` (current latest), verbatim:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.cjs — accesscontrol 3.1.0</span></div>
<pre><span class="dim">=== grant enumerated attributes, then deny with a wildcard ===</span>
  granted    : <span class="bad">true</span>    (expected false)
  filter(d)  : <span class="bad">{"amount":1000,"bonus":500,"currency":"USD"}</span>    (expected {})

<span class="dim">=== control: denying a SPECIFIC attribute works ===</span>
  filter(d)  : {"a":1,"b":2}    (secret correctly stripped)

<span class="dim">=== control: grant ["*"] then deny ["*"] works ===</span>
  granted    : <span class="ok">false</span>

<span class="dim">=== accesscontrol@2.2.1 — same policy, older version ===</span>
  granted: <span class="ok">false</span> | filter: {}</pre>
</div>

Those controls matter. Specific-attribute denies work; `['*']`-grant-then-`['*']`-deny works. This isn't "deny is broken" — it's confined to *broader deny vs enumerated grant*. And the last line is the clincher: `2.2.1` handles the identical policy correctly. This is a **regression** introduced by the 3.x rewrite, so there's no "it was always meant to work this way" defence — the library used to get it right.

## The fix

Stop concatenating negations and hoping `normalize()` ranks them. Evaluate each deny glob *against* each allowed attribute and drop the matches:

```js
const denyGlobs = denied.map((a) => (a.startsWith('!') ? a.slice(1) : a));
const kept = allowed.filter((attr) => {
  const bare = attr.startsWith('!') ? attr.slice(1) : attr;
  return !denyGlobs.some((glob) => NotationGlob.test(glob, bare));
});
return NotationGlob.normalize(kept);
```

## Where this stands

Present on `accesscontrol@3.1.0`, current `latest`, no CVE, no fix. Full disclosure — and this one I feel strongly about publishing, because the gap between the README's bold promise and the behaviour is exactly the kind of thing a developer will never test, since the docs told them it was handled. If you use 3.x with any "grant specific fields, deny the rest with `*`" policy: your denies may be no-ops. Test them today, or pin `2.2.1` until a fix lands.

## Takeaways

- **A documented guarantee is a test case, not a fact.** "Deny always wins" is a claim to verify, especially when the whole point of the library is that you *don't* re-check it yourself.
- **Regressions are the strongest bug reports.** When an older version does it right, "working as intended" is off the table.
- **Glob ranking is not glob subtraction.** Letting a normalize/rank step decide precedence between allows and denies is how a broad deny quietly loses to a narrow grant.

<hr>

*Full disclosure. Present on `accesscontrol` 3.1.0 (current latest) at time of writing; a 3.x regression (2.2.1 is correct); no CVE assigned, no fix released. Reproduced against the published package.*

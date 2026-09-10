---
layout: post
title: "When a Resource Name Is a Regex"
subtitle: "acl2 denies access to a resource with no grants — by compiling every granted resource name into a regex and testing it against the one you asked for. Name a resource '.*' and you own everything."
date: 2026-09-04
tags: [access-control, authorization, nodejs, cwe-863, regex, full-disclosure]
read_time: "6 min read"
---

`acl2` (the maintained successor to `node_acl`, whose old repo now redirects to it) is a classic Node access-control library. This bug lives in its in-memory backend, on the *primary* authorization path — the code that answers `isAllowed`. And it's a lovely example of a category error: treating a name as a pattern.

## The boring part

When you ask "is this user allowed to `view` the resource `report.pdf`?", the backend needs to find the grants for `report.pdf`. If that resource has grants, great, it checks them. If it has *no* grants of its own, the answer should be simple: no grants, deny. That's the safe default the whole system rests on.

## The tilt-your-head part

Here's what the absent-grants branch actually does, in `lib/memory-backend.js`:

```js
if (!this._buckets[bucket]) {                    // requested resource has NO grants
    Object.keys(this._buckets).some(function (b) {
        re = new RegExp('^' + b + '$');          // an EXISTING granted name, compiled as a regex
        match = re.test(bucket);                 // ...tested against the requested resource
        if (match) bucket = b;                    // silently substitute the matching bucket
        return match;
    });
}
```

Instead of denying, it walks every *granted* resource name, compiles each into `^name$`, and tests the *requested* name against it. So a granted resource name isn't treated as a string — it's treated as a regular expression. And resource names are full of regex metacharacters: `report.pdf`, `public.docs`, dotted config keys, hostnames, URL paths. A dot means "any character."

Grant `viewer` access to `public.` and the pattern `^public.$` also matches `publicX`, `publicZ`, `publicA`… none of which were ever granted. Grant a low-priv role a resource literally named `.*` and the pattern `^.*$` matches *everything*.

## Proof

Against published `acl2@4.3.0` (memory backend), verbatim:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node verify_acl2.cjs — acl2 4.3.0</span></div>
<pre><span class="dim">-- viewer scoped to one dotted resource --</span>
allow('viewer', 'public.', ['view'])
isAllowed('u1', 'public.', 'view')  -> true   (granted)
isAllowed('u1', 'publicX', 'view')  -> <span class="bad">true</span>   &lt;&lt;&lt; never granted; ^public.$ matches
isAllowed('u1', 'billing', 'view')  -> <span class="ok">false</span>  (no metachar match — correct)

<span class="dim">-- worst case: a grant named ".*" --</span>
allow('lowpriv', '.*', ['read'])
isAllowed('mallory', 'topsecret',   'read') -> <span class="bad">true</span>   &lt;&lt;&lt; total bypass
isAllowed('mallory', 'admin-panel', 'read') -> <span class="bad">true</span>   &lt;&lt;&lt; total bypass

<span class="dim">-- differential fuzz vs an exact-match ground truth (13,200 queries) --</span>
vulnerable 4.3.0 :  falseALLOW = 58   falseDENY = 0
with the fix     :  falseALLOW = 0    falseDENY = 0</pre>
</div>

The fuzz result is the part I like: every single mismatch is a *false allow* — an unauthorised grant — and there are zero false denies. The bug is strictly one-directional over-authorisation, which is the worst direction for an access-control bug to fail in. `billing` is the control: no metacharacter, no match, correctly denied.

## The fix

Delete the regex fallback. A resource with no grants has no grants — return empty and deny:

```js
async union (bucket, keys) {
    if (this._buckets[bucket]) {
        /* exact-key lookup, as before */
    }
    return [];   // no grants -> deny. no regex.
}
```

With that, the differential fuzz drops to 0 / 13,200 while every legitimate grant still passes. If regex resources were ever a real feature, they'd need to be opt-in, applied consistently, and documented — today the behaviour exists only in this one function and appears nowhere in the docs. The Redis and Mongo backends use native key lookups and aren't affected; this is a memory-backend bug.

## Where this stands

Present on `acl2@4.3.0`, current `latest` (memory backend), no CVE, no fix. Full disclosure — and worth flagging upstream to the `OptimalBits/node_acl` lineage the code descends from. If you run acl2 with the memory backend, treat any resource name containing a dot as a potential over-match today.

## Takeaways

- **`new RegExp(userOrConfigString)` is a decision to treat data as code.** On an authz path, that's an over-match waiting to happen. Match strings with `===`.
- **The "no grants" branch is a security-critical branch.** The path that's supposed to deny is the one you should read most carefully — it's where fail-open hides.
- **Differential fuzzing against a trivial ground truth is cheap and devastating.** 13,200 queries, an exact-match oracle, and the direction of every failure told the whole story.

<hr>

*Full disclosure. Present on `acl2` 4.3.0 (current latest, memory backend) at time of writing; no CVE assigned, no fix released. Reproduced against the published package with differential fuzzing.*

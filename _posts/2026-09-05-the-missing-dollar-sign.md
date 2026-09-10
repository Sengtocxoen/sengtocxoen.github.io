---
layout: post
title: "The Missing Dollar Sign"
subtitle: "A read-only role granted *:read also gets *:read:write, *:read:admin, and *:readsecrets. The whole bug is one absent regex anchor — and the function right above it has it."
date: 2026-09-05
tags: [access-control, authorization, nodejs, cwe-863, regex, full-disclosure]
read_time: "5 min read"
---

`easy-rbac` is a small, popular RBAC library for Node (~38k downloads/week). It supports glob permissions — `*:read` means "read on any resource" — which is a nice ergonomic feature. It is also where the whole thing goes wrong, and the wrongness is a single character.

## The boring part

You grant an auditor role `*:read` and expect it to mean *read operations, nothing else*. The library compiles that glob into a regular expression and tests operation names against it. Standard stuff. The compiler lives at `lib/easy-rbac.js`, and there are two of them, right next to each other:

```js
function strToRegex(str) {
    return new RegExp("^" + str + "$");                  // both ends anchored — correct
}
function globToRegex(str) {
    return new RegExp("^" + str.replace(/\*/g, ".*"));   // no trailing $ — the bug
}
```

`strToRegex` anchors both ends. `globToRegex` — the one used for glob permissions — anchors only the start. It just forgot the `$`.

## The tilt-your-head part

Without the end anchor, the pattern matches anything that merely *begins* with the expansion. `globToRegex('*:read')` becomes `/^.*:read/`, and `/^.*:read/.test('billing:read:write')` is `true`, because nothing constrains what comes after `read`. So a role granted `*:read` is silently also granted `*:read:write`, `*:read:admin`, `*:readsecrets`, `*:read-delete` — any operation whose name starts the same way.

In a `resource:action:sub` taxonomy — which this library's own `*:read` examples encourage — that's a read-only role quietly acquiring writes and deletes. Privilege escalation from a missing dollar sign.

## Proof

Against published `easy-rbac@4.0.0` (current latest), verbatim:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.cjs — easy-rbac 4.0.0</span></div>
<pre>role: auditor, can: ["*:read"]

  can(auditor, "billing:read"       ) = true   expected true    (intended)
  can(auditor, "billing:write"      ) = false  expected false   (correctly denied)
  can(auditor, "billing:read:write" ) = <span class="bad">true</span>   expected false   &lt;&lt;&lt; gains write
  can(auditor, "billing:readsecrets") = <span class="bad">true</span>   expected false   &lt;&lt;&lt; different op
  can(auditor, "billing:read-delete") = <span class="bad">true</span>   expected false   &lt;&lt;&lt; gains delete
  can(auditor, "billing:read:admin" ) = <span class="bad">true</span>   expected false   &lt;&lt;&lt; gains admin

  globToRegex("x*:post").test("x:post:DELETE") = true</pre>
</div>

`billing:write` is the negative control — no shared prefix, correctly denied. So the system isn't simply broken; it fails *specifically* on prefix-sharing names, which is the tell of an anchoring bug rather than a logic error.

## The fix

The `$` that `strToRegex` already has, thirty characters up:

```diff
-    return new RegExp("^" + str.replace(/\*/g, ".*"));
+    return new RegExp("^" + str.replace(/\*/g, ".*") + "$");
```

While you're there: operation names are interpolated into a `RegExp` after only `*` is substituted, so a name containing `.` or `+` behaves as a pattern. Escape the other metacharacters too. And note the sibling library `@rbac/rbac` end-anchors its globs correctly — so, as usual, the ecosystem already agrees on the right answer.

## Where this stands

Present on `easy-rbac@4.0.0`, current `latest`, no CVE, no fix. Full disclosure. The same finding applies to the closely-related `rbac` packaging of this code. If you use glob permissions with nested/hyphenated operation names, this is live: audit whether any narrow role's glob is reaching broader operations, and either patch the anchor locally or switch to exact operation strings until it's fixed.

## Takeaways

- **`^` without `$` is a permissive-regex bug waiting to be an authz bug.** Any place a security decision compiles user-or-config strings into a regex, check both anchors.
- **The adjacent correct sibling is the smoking gun.** One function anchors both ends, the one next to it anchors one. That's an oversight, and it's the fastest possible "mistake vs feature" verdict.
- **Glob features are prefix-match traps.** The convenience of `*:read` is the same mechanism that leaks `*:read:admin`.

<hr>

*Full disclosure. Present on `easy-rbac` 4.0.0 (current latest, and the related `rbac` package) at time of writing; no CVE assigned, no fix released. Reproduced against the published package.*

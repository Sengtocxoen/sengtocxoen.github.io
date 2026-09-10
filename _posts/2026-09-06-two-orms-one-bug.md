---
layout: post
title: "Two ORMs, One Bug"
subtitle: "The original package is unmaintained. The maintained fork copied it byte-for-byte — including the identifier quoting that never escaped anything."
date: 2026-09-06
tags: [sql-injection, python, orm, cwe-89, full-disclosure]
read_time: "6 min read"
---

Masonite ORM is the data layer for the Masonite web framework — a Laravel-flavoured, "batteries included" Python stack. It has the ergonomic Eloquent-style API you'd expect: `User.select(...)`, `User.order_by(...)`, `User.where(...)`. And it has the same identifier-quoting bug I keep finding in query builders, with one extra wrinkle that makes it worth telling: there are *two* packages. The original `masonite-orm` on PyPI is now unmaintained. There is a maintained fork, `masonite-framework-orm`. The vulnerable code is byte-for-byte identical in both.

## The boring part

Masonite ORM is emphatically careful with values. Pass a value through `where()` and it comes out as a `?` bind parameter — I checked, `x' OR '1'='1` becomes a binding, not SQL. The library even ships *separate* `select_raw()`, `order_by_raw()`, `group_by_raw()` methods for when you actually want raw SQL. That separation is the contract in code form: the plain `select()` / `order_by()` / `group_by()` are supposed to take a plain identifier and be safe.

## The tilt-your-head part

Here is how a grammar quotes an identifier (SQLite shown; MySQL/Postgres/MSSQL are the same shape):

```python
def table_string(self):   return '"{table}"'
def column_string(self):  return '"{column}"{separator}'
def order_by_format(self): return "{column} {direction}"
```

`str.format()` into a bare `"{column}"`. No doubling of an embedded `"`. And `direction` — the `ASC`/`DESC` — is interpolated raw too; the only processing it gets anywhere is `.upper()`. The `Model.__passthrough__` machinery forwards `select`/`order_by`/`group_by` straight to these, so the ubiquitous pattern

```python
User.order_by(request.args["sort"]).get()
User.select(request.args["fields"]).get()
```

drops attacker text directly between two quote characters.

## Proof

Against the **maintained fork** (`masonite-framework-orm` 3.1.0), real SQLite, verbatim:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">python poc.py — masonite-framework-orm 3.1.0</span></div>
<pre><span class="dim">=== CONTROL: legit column, correctly quoted ===</span>
SQL: SELECT "users"."name" FROM "users"

<span class="dim">=== ATTACK: breakout via select() (a supposedly-safe API) ===</span>
column = <span class="cmd">name" FROM users UNION SELECT api_key FROM secrets--</span>
SQL: SELECT "users"."name" FROM users <span class="bad">UNION SELECT api_key FROM secrets</span>--" FROM "users"
EXFILTRATED: [{'name': <span class="warn">'SUPER_SECRET_KEY_42'</span>}, {'name': 'alice'}, {'name': 'bob'}]</pre>
</div>

The secret from the `secrets` table comes back through a `users` query, through the ORM's own `.get()`. The direction field is injectable too — `direction='ASC, (SELECT api_key FROM secrets)'` sails through, because `.upper()` is not validation.

## The fix

One helper, used everywhere an identifier is quoted:

```python
def quote_identifier(self, name, quote='"'):
    return quote + str(name).replace(quote, quote * 2) + quote
```

Double the delimiter (`"` for SQLite/Postgres/MSSQL, `` ` `` for MySQL) and allowlist `direction` to `{ASC, DESC}`. SQLAlchemy does this. python-sql does this. Pony does this. It is the standard implementation; Masonite's grammars just skipped it. Values are parameterised, `*_raw()` exists as the deliberate escape hatch — every signal says the plain methods were meant to be safe.

## Where this stands

Full disclosure. The legacy `masonite-orm` is **unmaintained** — its users won't get a patch and need to migrate. The fork `masonite-framework-orm` **is** maintained and **equally vulnerable** on 3.1.0, with no CVE and no fix at time of writing. If you run either: allowlist any user-influenced column/table/sort/direction against your real schema before it reaches the builder.

## Takeaways

- **"Unmaintained" doesn't mean "gone."** A dead package with a live fork means the bug is still shipping — under a new name, to people who migrated *for* the maintenance.
- **A forked codebase inherits every unescaped `.format()`.** Copy-paste carries bugs with perfect fidelity.
- **`*_raw()` existing is your evidence.** When a library provides an explicit unsafe method, the matching plain method is contractually safe — and a bug in it is a bug, not a feature.

<hr>

*Full disclosure. `masonite-orm` (unmaintained) and `masonite-framework-orm` 3.1.0 (maintained fork) both affected at time of writing; no CVE assigned, no fix released. Reproduced live on SQLite against the maintained fork.*

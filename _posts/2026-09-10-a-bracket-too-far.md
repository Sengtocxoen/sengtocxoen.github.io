---
layout: post
title: "A Bracket Too Far"
subtitle: "The 'safe' bulk-insert helper built a CREATE TABLE from your column names. What if a column name contained a ] ?"
date: 2026-09-10
tags: [sql-injection, sql-server, nodejs, cwe-89, ghsa, responsible-disclosure]
read_time: "7 min read"
---

Everyone knows you don't concatenate *values* into SQL. It's the first rule. Parameterise your inputs, never build `WHERE name = '` + userInput + `'`, we all learned this, we all have the scar.

Almost nobody extends the same suspicion to **identifiers** — table names, column names — because those feel like structure, not data. They feel like *yours*. And in a bulk-insert helper whose entire selling point is convenience, "column names" quietly turn out to be attacker data more often than anyone expects.

## The boring part

[`node-mssql`](https://github.com/tediousjs/node-mssql) is the go-to SQL Server client for Node. It has a delightful feature: `request.bulk()` with a `Table` object. You describe a table — columns, types — and it does a fast bulk insert. And if you set `table.create = true`, it will even **create the table for you** first, generating the `CREATE TABLE` DDL from your column definitions.

The DDL generation lives in `Table.prototype.declare()`, and it looked like this:

```js
const cols = this.columns.map(col => {
  const def = [`[${col.name}] ${declareType(col.type, col)}`]
  //            ^^^^^^^^^^^ column name dropped straight into [ ]
  ...
})
```

SQL Server delimits identifiers with square brackets: `[my column]`. So the code wraps each column name in `[ ]` and moves on. Looks safe — brackets are the *correct* way to quote an identifier in T-SQL. What could go wrong with the correct thing?

## The tilt-your-head part

The same question as always: *what if the name contains the delimiter?*

Inside `[ ]`, T-SQL closes the identifier at the first `]`. To put a literal `]` inside a bracketed name you have to **double it** — `]]` — exactly like doubling quotes. That's what the `QUOTENAME` built-in does. This code didn't. So a column *named* `id] INT); DROP TABLE users; --` would produce:

```sql
[id] INT); DROP TABLE users; --] ...
```

The `]` right after `id` closes the identifier, and everything after it is live DDL, executed as part of the batch that `bulk()` runs via `execSqlBatch` — which happily runs **stacked statements**. Identifier injection, straight into a `CREATE TABLE`.

"But who lets an attacker name a column?" — and this is the part that makes it real rather than cute. Column names in this helper are *routinely data-driven*. `Table.fromRecordset`, `recordset.toTable`, and every CSV/XLSX/JSON importer people build on top of them take column names **from the file**. Upload a spreadsheet whose header row is `id] INT); DROP TABLE users; --`, and the "safe" bulk helper builds your injection for you.

<div class="callout">The dangerous inputs are the ones an app treats as structure but a user actually controls: column headers, sheet names, filenames, JSON keys. "It's a column name" is not the same as "I chose it."</div>

## Proof

Here it is against the two published packages — `mssql@11.0.1` (vulnerable) and `mssql@11.0.2` (patched) — calling `Table.declare()` with a column name straight out of a hostile spreadsheet header. Real output, not a reconstruction:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node — mssql Table.declare(), before and after</span></div>
<pre><span class="dim">$</span> <span class="cmd">node poc.js</span>

<span class="dim">column name (from an uploaded CSV/XLSX header):</span>
  id] INT); DROP TABLE users; --

<span class="accent">=== mssql 11.0.1 (vulnerable) ===</span>
create table [dbo].[import] ([id<span class="bad">] INT); DROP TABLE users; --</span>] int null)
<span class="bad">&gt;&gt;&gt; identifier ends at "id" — DROP TABLE users is now free-standing SQL</span>

<span class="accent">=== mssql 11.0.2 (patched)    ===</span>
<span class="ok">THROWS EINJECT: Invalid column name 'id] INT); DROP TABLE users; --'.
                A ']' in a column name must be written as ']]'.</span></pre>
</div>

`declare()` builds the `CREATE TABLE` that `bulk({ create: true })` sends through `execSqlBatch`, which runs stacked statements — so on 11.0.1 that generated string is not a curiosity, it is the payload.

And the names that should keep working still work — the fix costs legitimate callers nothing, including the ones who already escape properly:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node — mssql@11.0.2, legitimate column names</span></div>
<pre><span class="ok">"user id"</span>      -&gt; create table [dbo].[import] ([user id] int null)
<span class="ok">"order]]id"</span>    -&gt; create table [dbo].[import] ([order]]id] int null)
<span class="bad">"id] INT); ..."</span> -&gt; THROWS EINJECT</pre>
</div>

## The fix

My proposed patch took the escape route: an `escapeIdentifier()` that doubles `]`, QUOTENAME semantics, applied to the column definitions, the primary-key list and the PK constraint name in `declare()`.

The maintainers went the other way — **reject, don't rewrite** — and shipped this in `lib/utils.js`:

```js
// A column name is emitted as a quoted identifier, `[name]`, by this module and again
// by the driver's own bulk load. Only `]` can terminate that quoting early, and doubling
// it is the documented way to include one literally.
const escapesQuotedIdentifier = (name) => String(name).replace(/]]/g, '').includes(']')

assertSafeColumnName: (name) => {
  const type = typeof name
  if (type !== 'string' && type !== 'number') {
    throw new MSSQLError(`Invalid column name '${String(name)}'. Column names must be a string or a number.`, 'EINJECT')
  }
  const column = String(name)
  if (escapesQuotedIdentifier(column)) {
    throw new MSSQLError(`Invalid column name '${column}'. A ']' in a column name must be written as ']]'.`, 'EINJECT')
  }
  return column
}
```

…wired into `declare()` at both interpolation points. Rejecting is the better call, and the comment says why: the column name is bracket-quoted **twice** — once by `declare()`, and again by the driver's own bulk-load path. Escaping in one place would desynchronise the two, and a name that arrives already-doubled (`order]]id`) would get doubled a second time. Refusing to guess keeps the caller's string authoritative and makes the ambiguity the caller's problem, loudly, at the API boundary.

The `typeof` guard in front is worth its own mention. It exists because an object can return one value from the `toString()` that validation reads and a different value from the `toString()` that string interpolation reads — check-then-use on a value that gets to change its mind in between. The whole patch is written against that: every `assertSafe*` reads the input **once** and returns what it read, so what got validated is what gets emitted.

My report was the column-name half. The advisory is wider: parameter names were checked against a denylist that rejected only a space, `--`, `/*`, `*/` and `'` — missing every other whitespace character — while column, type and procedure names were not checked at all. The shipped fix validates all four positions, with an allowlist rather than a denylist.

## Takeaways

- **Identifiers need escaping too.** Values get parameters; identifiers get *delimiter-doubling* — `'`→`''`, `"`→`""`, `]`→`]]`. Skipping it is injection, same as any value sink.
- **"Column name" often means "user input."** Anything sourced from a spreadsheet header, an uploaded file, or a JSON key is attacker-controlled, no matter how structural it feels.
- **Convenience helpers hide the sinks.** The bug wasn't in scary raw-SQL code; it was in the *friendly* `bulk({ create: true })` path people reach for precisely to avoid writing SQL.
- **Reject beats escape when the value is quoted more than once.** Two layers each trying to be helpful is how `]]]]` happens. Validate at the boundary; let exactly one layer own the quoting.
- **Denylists lose to the character you didn't think of.** A tab is whitespace too.

One bracket. The helper was doing the correct thing — bracket-quoting the identifier — and the correct thing minus delimiter-doubling is still injection. It usually is.

<hr>

*Published September 10, 2026 as [GHSA-rc93-2r6p-hc2q](https://github.com/tediousjs/node-mssql/security/advisories/GHSA-rc93-2r6p-hc2q) — High, CVSS 8.1 (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`). Reported privately via GitHub Security Advisory; credited for the independent column-name discovery and proof of concept, alongside the initial reporter (JirayuThongchotchaung) and the maintainer who built the remediation (dhensby).*

*Fixed in **9.1.4, 9.2.2, 9.3.3, 10.0.5, 11.0.2 and 12.7.2**. If you call `bulk()`, `Table.fromRecordset` or `recordset.toTable` with column names that came from a file, upgrade.*

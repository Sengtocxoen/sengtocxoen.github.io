---
layout: post
title: "The Quote That Forgot to Double"
subtitle: "A Go query builder ships a helper literally called Quote(). Its whole job is to make an identifier safe. It wraps it in quotes and calls it a day."
date: 2026-09-08
tags: [sql-injection, golang, orm, cwe-89, full-disclosure]
read_time: "6 min read"
---

If you build queries in Go, you eventually meet a helper called `Quote`. You pass it a column name, it hands you back `"column"`, and you feel good about yourself for not string-concatenating. That is the entire social contract of a function named `Quote`: *I will make this identifier safe to drop into SQL.*

[bob](https://github.com/stephenafamo/bob) is a growing, actively-maintained Go query builder and ORM — 1,700+ stars, last push two days before I looked at it. It has that helper, one per dialect: `psql.Quote`, `mysql.Quote`, `sqlite.Quote`. The docs show it off:

```go
// SQL: "table"."column"
// Go:  psql.Quote("table", "column")
```

## The boring part

bob is careful in exactly the way you'd want. *Values* are always bound parameters — Postgres gets `$1`, MySQL and SQLite get `?`. There is a separate, clearly-named `psql.Raw(query, args...)` for when you actually mean to write raw SQL. So the library plainly understands the distinction between "data I must not trust" and "structure I'm building." Values are treated as radioactive. That is the good news, and it is also what makes the next part a genuine mistake rather than a design choice.

## The tilt-your-head part

Here is the quoter — every dialect is the same shape:

```go
// dialect/psql/dialect/dialect.go
func (d dialect) WriteQuoted(w io.StringWriter, s string) {
	w.WriteString(`"`)
	w.WriteString(s)      // <- s goes in raw
	w.WriteString(`"`)
}
```

Wrap in `"`, write the string, wrap in `"`. And that's it. There is no `strings.ReplaceAll(s, `"`, `""`)`. Postgres closes a quoted identifier at the first `"`; to keep a literal `"` inside you must double it. bob doesn't. MySQL's quoter has the same gap with backticks; SQLite's with double quotes.

So the "safe" `Quote` helper is only safe for identifiers that happen not to contain the quote character. Feed it one that does — a sort column, a table alias, anything an app lets a user influence — and the identifier ends early.

## Proof

Live, Go 1.26, bob v0.50.0, output verbatim:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">go run poc.go — bob v0.50.0</span></div>
<pre>evil := <span class="cmd">`id" FROM secrets; --`</span>

benign: "users"."id"
evil  : "users"."id" FROM secrets; --"

query : SELECT
        <span class="bad">"id" FROM secrets; --"</span>
        FROM users</pre>
</div>

The payload `id" FROM secrets; --` closes the `"id"` column, appends `FROM secrets`, and comments out the trailing quote bob dutifully adds. The query the app *meant* to run against `users` now reads from `secrets`. Swap the payload for a backtick or double-quote variant and MySQL and SQLite fall the same way.

## The fix, and the proof it's a mistake

```go
// psql / sqlite
w.WriteString(`"`); w.WriteString(strings.ReplaceAll(s, `"`, `""`)); w.WriteString(`"`)
// mysql
w.WriteString("`"); w.WriteString(strings.ReplaceAll(s, "`", "``")); w.WriteString("`")
```

One `ReplaceAll` per dialect. And here's the thing that makes this unambiguous rather than a judgment call: *every other query builder in the ecosystem already does this.* drizzle-orm doubles (`name.replace(/"/g,'""')`), sequelize doubles, peewee doubles, Ruby's Sequel doubles (`name.gsub('"','""')`). Doubling the delimiter is the known, boring, correct implementation of identifier quoting. bob is the one that skipped it, in a function whose name promises it didn't.

## Where this stands

Present on bob v0.50.0 / HEAD at time of writing — actively maintained, no CVE, no fix yet. Full disclosure: the fix is one line per dialect and the correct pattern is industry-standard, so there's nothing subtle to protect here. If you use bob and route any user-influenced string into `Quote` or the column/table starter helpers, allowlist that string against your schema until the doubling lands upstream.

## Takeaways

- **A function named `Quote` is a promise. Check that it keeps it.** "Wrap in delimiters" and "safely quote" are different operations; the gap between them is a CVE.
- **Parameterised values + raw identifiers is the signature of this bug.** The care on values proves intent; the raw identifier is the oversight.
- **Cross-library controls settle the "is it WAI?" argument fast.** When five sibling libraries double the delimiter and one doesn't, the one that doesn't has a bug.

<hr>

*Full disclosure. Present on `github.com/stephenafamo/bob` v0.50.0 at time of writing; no CVE assigned, no fix released. Reproduced live on Go 1.26.*

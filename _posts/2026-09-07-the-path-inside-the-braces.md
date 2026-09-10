---
layout: post
title: "The Path Inside the Braces"
subtitle: "Objection binds the column safely with ??. Then it takes the JSON path you asked for and staples it into a string literal by hand."
date: 2026-09-07
tags: [sql-injection, nodejs, orm, postgres, cwe-89, full-disclosure]
read_time: "6 min read"
---

[objection.js](https://github.com/Vincit/objection.js) is a well-regarded Node ORM built on top of knex. It has a typed helper, `ref()`, and a `whereJson*` family, whose entire reason to exist is *safe* dynamic references — you want to point at a column, or a path inside a JSON column, chosen at runtime, without hand-rolling SQL. The typed API is the safe road. `knex.raw` is the clearly-marked unsafe road. Everyone knows which is which.

So the question, as always: is the safe road actually safe all the way down?

## The boring part

A field expression in objection looks like `col:a.b` — column `col`, then JSON path `a` → `b`. Objection parses that, and for the column part it does the right thing: it hands the column to knex as a `??` binding, the placeholder that gets safely quoted. That `??` is important. It is proof, in the code itself, that the authors know this string is untrusted and must be escaped. They escaped the column.

## The tilt-your-head part

Then they built the JSON path by hand. `lib/queryBuilder/ReferenceBuilder.js`:

```js
const extractor = this._cast ? '#>>' : '#>';
const jsonFieldRef = this._parsedExpr.access.map(f => f.ref).join(',');
return `??${extractor}'{${jsonFieldRef}}'`;   // column bound with ??, path concatenated raw
```

The column is `??` — bound. The *path elements* — `jsonFieldRef` — are joined and dropped straight inside a Postgres array literal `'{...}'` with no escaping. And the Postgres JSON helper next door has a matching second sink: it builds the quoted column with `parsed.columnName.split('.').join('"."')` — wrapping each part in `"` without doubling an embedded `"`. Two hand-built strings, right next to the one thing they remembered to bind.

A `'` in the JSON access path closes the literal. A `"` in the column part closes the identifier. Either way the field expression — a typed, "safe" input — becomes SQL.

## Proof

Against published `objection@3.1.5` (current latest). Live sqlite, the access path carrying a UNION:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.js — objection 3.1.5</span></div>
<pre>access ref : <span class="cmd">a}' UNION SELECT secret FROM u--</span>
built lit  : '{a}' <span class="bad">UNION SELECT secret FROM u</span>--}'
exec SQL   : SELECT '{a}' UNION SELECT secret FROM u--}' AS x FROM u LIMIT 1
result     : [{ "'{a}'": <span class="warn">"TOPSECRET"</span> }]   &lt;- secret exfiltrated</pre>
</div>

And through the fully-public `whereJsonSupersetOf` on Postgres, the subquery injects cleanly into the predicate:

```sql
select "users".* from "users"
where ( "data"#>'{x}' OR (SELECT 1 FROM secret_t)=1--}' )::jsonb @> '{}'::jsonb
```

The column-name sink is just as real — a field expression like `evil" FROM users; DROP TABLE users--:a` breaks straight out of the `"..."` identifier.

## The fix

Bind the access-path elements as parameters instead of concatenating them, or validate each `field.ref` and column segment against `^[A-Za-z0-9_]+$` (rejecting `'` and `"`) before building the literal — and double the embedded `"` in the split column name. The `??` on the column shows the intent was always to escape; two siblings of that line just didn't.

Because a single Postgres `query()` won't run stacked writes, the direct impact here is confidentiality — UNION/subquery exfiltration — rather than `DROP`. That's why I score it High rather than Critical, and I'd rather say so than round up.

## Where this stands

Present on `objection@3.1.5`, current `latest`, no CVE, no fix. Full disclosure. If you use objection and let users influence a field expression passed to `ref()` or `whereJson*` — user-selectable JSON paths are the classic case — validate those tokens against an allowlist now.

## Takeaways

- **`??` on one line doesn't protect the string on the next.** Partial binding is the most convincing kind of vulnerable code, because the safe part reassures you past the unsafe part.
- **JSON-path features are a recurring identifier sink.** The dot that means "traverse" is also the dot that leaves the parameterised path.
- **Score what you can show.** No stacked writes on Postgres → confidentiality-High, not Critical. Honesty is cheaper than a correction.

<hr>

*Full disclosure. Present on `objection@3.1.5` (current latest) at time of writing; no CVE assigned, no fix released. Reproduced live end-to-end on sqlite; Postgres path confirmed via generated SQL.*

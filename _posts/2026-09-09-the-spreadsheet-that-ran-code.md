---
layout: post
title: "The Spreadsheet That Ran Code"
subtitle: "promptfoo lets an assertion say javascript:<code> and runs it. That's documented for your own config. It also does it for rows fetched from a shared Google Sheet."
date: 2026-09-09
tags: [rce, nodejs, ai, supply-chain, cwe-94, full-disclosure]
read_time: "6 min read"
---

[promptfoo](https://github.com/promptfoo/promptfoo) is a widely-used LLM eval framework — you write test cases, it runs your prompts against models and checks the outputs with assertions. Some of those assertions are deliberately powerful: an assertion string that starts with `javascript:`, `python:`, `eval:`, or `file://<code>` gets turned into code and executed on the host. That's a documented feature for *config you wrote yourself*. The bug is where else that conversion reaches.

## The boring part

If the only way to get an executable assertion into promptfoo were to write it in your own local config, this would be working-as-intended: you're running your own code, your problem. Powerful, footgun-adjacent, but yours.

## The tilt-your-head part

promptfoo can pull test cases from *remote datasets* — CSV files, Google Sheets, SharePoint, Azure — where the `__expected` column holds the assertion for each row. And the same string-to-code converter runs on those fetched rows with no trust gate. Trace it: `readStandaloneTestsFile` feeds Google-Sheets/SharePoint/Azure/CSV rows through `assertionFromString`, which maps an `__expected: javascript:<code>` cell straight to an executable `{type:'javascript', value:<code>}` assertion. The `javascript` sink is a `new Function("output","context","process", body)` invoked with a `process` shim that exposes `process.mainModule.require` — so `require('child_process').execSync(...)` runs.

So: whoever controls a shared sheet or dataset an operator evaluates gets **arbitrary code execution on the operator's host**. Add a column to a Google Sheet, wait for someone to run `promptfoo eval` against it, and their machine runs your code. It's a supply-chain RCE wearing a spreadsheet.

## Proof

Against published `promptfoo@0.122.0` (current latest), a malicious dataset cell:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.cjs — promptfoo 0.122.0</span></div>
<pre>__expected: <span class="cmd">javascript:(function(){process.mainModule.require('child_process')
            .execSync('id > MARKER; ...');return true;})()</span>

runAssertion result: {"pass":true,"score":1}
MARKER present: <span class="bad">true</span>
uid=1000(kali) gid=1000(kali) groups=1000(kali)
<span class="bad">PWNED-VIA-JS-ASSERTION</span></pre>
</div>

There's a second bug in the same neighbourhood: `file://` references (for external vars and transforms) resolve through `path.resolve(basePath, pathToUse)` with **no containment**, so `file://../SECRET_OUTSIDE.txt` and `file:///etc/hostname` read arbitrary files off the host:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">file:// traversal</span></div>
<pre>file://../SECRET_OUTSIDE.txt -> "<span class="warn">TOP-SECRET-CONTENTS-outside-confdir</span>"
file:///etc/hostname         -> "<span class="warn">kali</span>"</pre>
</div>

And the fetch layer (`fetchWithProxy`) has no SSRF guard, for good measure.

## The fix

Don't derive executable assertions (`javascript`/`python`/`file://` code) from remotely-fetched dataset rows — gate that behind an explicit opt-in when the source is a network dataset, or require interactive confirmation before running code that came from a non-local source. Contain `file://` resolution to `basePath` (reject a resolved path whose `path.relative(basePath, resolved)` starts with `..` or is absolute). Add an SSRF guard to the fetch layer. The config-authored code-exec can stay — it's the *remote-dataset reachability* that turns a feature into a vulnerability.

## Where this stands

Present on `promptfoo@0.122.0`, current `latest`, no CVE, no fix. Full disclosure. The reachability that matters — remote sheet/dataset → host RCE — is the novel part; config-authored transforms running code is partly documented. If you run `promptfoo eval` over any dataset or config you don't fully control (a shared sheet, a third-party CSV, an imported remote config): assume it can run code on your box, and pin your evals to local, self-authored inputs until this is fixed.

## Takeaways

- **"Documented for local config" is not "safe from remote input."** The same converter reached from a fetched spreadsheet is a completely different trust boundary.
- **Eval tooling runs on operator/CI hosts.** RCE there is credentials, source, and CI secrets — a high-value target dressed as a dev convenience.
- **`path.resolve(base, x)` is not containment.** Without a post-resolve `..`/absolute check, a `file://` reference walks straight out of its directory.

<hr>

*Full disclosure. Present on `promptfoo` 0.122.0 (current latest) at time of writing; no CVE assigned, no fix released. RCE, file read, and SSRF reproduced against the published package.*

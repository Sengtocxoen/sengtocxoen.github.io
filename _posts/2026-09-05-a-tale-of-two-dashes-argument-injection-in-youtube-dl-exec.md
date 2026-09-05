---
layout: post
title: "A Tale of Two Dashes"
subtitle: "How a missing `--` turned a video-downloader wrapper into an argument-injection bug — and how the maintainer fixed it in an afternoon."
date: 2026-09-05
tags: [argument-injection, nodejs, cwe-88, responsible-disclosure]
read_time: "8 min read"
---

Most bug hunting is boring, and that is the part nobody tells you about. You are not staring at a wall of hex with a hoodie on. You are reading somebody else's ordinary code on an ordinary afternoon, mostly bored, waiting for the one line that makes you tilt your head.

This is the story of one of those lines. The whole bug fits in two characters: `--`.

## The boring part

I have a habit of reading the source of small npm packages I depend on. Not auditing — just *reading*, the way you might flip through a manual for an appliance you already own. `youtube-dl-exec` is one of those packages: a thin, well-loved Node wrapper (~65k downloads/week) around the `yt-dlp` binary. You give it a URL, it shells out to `yt-dlp`, you get JSON back. Nothing exotic.

Here is the entire heart of it, from version 3.1.14:

```js
const $ = require('tinyspawn')   // spawn(), no shell
const dargs = require('dargs')
const args = (flags = {}) => dargs(flags, { useEquals: false }).filter(Boolean)

const create = binaryPath => {
  const fn = (...fnArgs) => fn.exec(...fnArgs).then(parse).catch(parse)
  fn.exec = (url, flags, opts = {}) =>
    $(binaryPath, [url, ...args(flags)].filter(Boolean), opts)   // <- this line
  return fn
}
```

I almost scrolled past it. It is clean. It even spawns without a shell, so there is no `sh -c`, no metacharacter soup, none of the classic command-injection foot-guns. A previous release had specifically hardened that (`spawn yt-dlp without a shell`). Whoever wrote this was being careful.

## The tilt-your-head part

Then I looked at the argument array again:

```js
[url, ...args(flags)]
```

The user-supplied `url` goes in **first**, as `argv[0]`, and then the flags. And there is no `--` anywhere.

If you have spent time with command-line tools, `--` is muscle memory. It is the *end-of-options* marker: everything after `--` is a positional argument, never a flag. It is why `rm -- -rf` deletes a file literally named `-rf` instead of arguing with you. Wrappers that pass user input to a CLI are supposed to put a `--` in front of that input, precisely so the input can never be *reinterpreted as an option*.

This one didn't. So what happens if the "URL" is not a URL at all, but something that starts with a dash?

`yt-dlp`, like almost every CLI, parses any leading-`-` token as an option. So a caller who controls the URL string — which is the entire point of the library; you feed it user-submitted video links — can stop supplying a *URL* and start supplying *options* to `yt-dlp`. That is **argument injection** (CWE-88). Not shell injection. No shell required. The careful no-shell spawning doesn't help, because the attacker never needed a shell — they needed a dash.

<div class="callout">The mental shortcut: any time user input becomes an argument to a subprocess and there is no <code>--</code> before it, ask "what if the input starts with <code>-</code>?" Nine times out of ten it is nothing. The tenth time is a writeup.</div>

## How far does it go?

This is the part where I have to be honest, because my first draft was wrong.

My initial excited theory was: `yt-dlp` has an `--exec` option that runs a command, and it supports a `pre_process` stage that runs *before* any download. So surely a single token —

```
url = "--exec=pre_process:touch pwned"
```

— is instant, no-precondition remote code execution. One string, game over.

It isn't. I installed the *real* `yt-dlp` and tried it, and `yt-dlp` politely refused: with no actual entry to process, it exits with *"You must provide at least one URL"* and `--exec` never fires. A lone option-shaped URL is argument injection, but it is **not** instant RCE.

The realistic path needs one more ingredient the attacker also influences. `--config-locations=<file>` tells `yt-dlp` to read options from a config file. If the attacker controls that file too — an upload directory, a writable cache, a shared `/tmp` — the config can carry `--exec` *and* an entry (`--load-info-json`), and now the command runs. So the honest verdict is:

- **Argument injection: definite.** Any `yt-dlp` flag is reachable through the URL — output paths, file reads, config files.
- **Full RCE: conditional** on a second attacker-controlled input.

Still far more power than anyone expects to hand over by passing a URL string.

## Proof

Here is the whole thing against the real, unmodified package (3.1.14) and real `yt-dlp` 2026.08.19. The "app" just calls `youtubedl(<attacker-controlled url>)`.

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.js — youtube-dl-exec 3.1.14</span></div>
<pre><span class="dim">########## BEFORE — youtube-dl-exec 3.1.14 (vulnerable) ##########</span>
youtube-dl-exec version : <span class="bad">3.1.14</span>
the app calls           : youtubedl(&lt;attacker-controlled "url"&gt;)

<span class="accent">[1]</span> attacker "url" = <span class="cmd">"--version"</span>
    -&gt; yt-dlp ran --version and returned: <span class="warn">2026.08.19</span>
    -&gt; the URL was swallowed as an OPTION = argument injection

<span class="accent">[2]</span> attacker "url" = <span class="cmd">"--config-locations=evil.conf"</span>  (+ a file they control)
    -&gt; arbitrary command executed? <span class="bad">YES  *** RCE ***</span>

===== VERDICT =====
<span class="bad">VULNERABLE: a single attacker-controlled string reached code execution.</span></pre>
</div>

Step `[1]` is the tell. A real URL would make `yt-dlp` go fetch a page. Instead, `--version` was parsed as a flag and `yt-dlp` printed its version — the "URL" became an option. Step `[2]` weaponises that with the config-file trick, and the marker file gets written: code execution.

## The two-character fix

I wrote it up — definite argument injection, conditional RCE, no existing CVE — kept the severity honest, and sent it to the maintainer privately.

What happened next is the nicest part of the story. The maintainer ([Kikobeats](https://github.com/Kikobeats)) confirmed the report the same morning, and the fix diff is exactly the two characters that were missing:

```diff
- $(binaryPath, [url, ...args(flags)].filter(Boolean), opts)
+ $(binaryPath, [...args(flags), '--', url].filter(Boolean), opts)
```

Flags first, then `--`, then the URL. Now everything after `--` is a positional, and an option-shaped URL can never be reinterpreted as a flag. Same script, against the patched **3.1.15**:

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">node poc.js — youtube-dl-exec 3.1.15</span></div>
<pre><span class="dim">########## AFTER — youtube-dl-exec 3.1.15 (fixed via PR #284) ##########</span>
youtube-dl-exec version : <span class="ok">3.1.15</span>
the app calls           : youtubedl(&lt;attacker-controlled "url"&gt;)

<span class="accent">[1]</span> attacker "url" = <span class="cmd">"--version"</span>
    -&gt; rejected: <span class="dim">ERROR: [generic] '--version' is not a valid URL</span>
    -&gt; the URL is treated as a positional = injection neutralised

<span class="accent">[2]</span> attacker "url" = <span class="cmd">"--config-locations=evil.conf"</span>  (+ a file they control)
    -&gt; arbitrary command executed? <span class="ok">no</span>

===== VERDICT =====
<span class="ok">SAFE: the injected options were treated as a positional and did nothing.</span></pre>
</div>

Look at step `[1]` now: `'--version' is not a valid URL`. That error is the fix working out loud — `yt-dlp` is being handed `--version` as a *positional* (a URL to download) and, correctly, there is no such video.

## Timeline

<div class="term">
  <div class="term-bar"><span class="term-dot r"></span><span class="term-dot y"></span><span class="term-dot g"></span><span class="term-title">git log --oneline</span></div>
<pre><span class="dim">2026-09-02</span>  <span class="cmd">fix: spawn yt-dlp without a shell</span>            <span class="dim">(#283) → 3.1.14</span>
<span class="dim">2026-09-05</span>  <span class="dim">private report sent to maintainer</span>
<span class="dim">2026-09-05</span>  <span class="cmd">fix: treat url as a positional after --</span>    <span class="ok">(#284) → 3.1.15</span>
<span class="dim">           report → confirmed → patched → released, same day (~3.5h to merge)</span></pre>
</div>

Coordinated, quiet, fixed before it ever had a chance to matter. No drama, no zero-day theatre — which is exactly how this is supposed to go.

## Takeaways

If you write anything that hands user input to a subprocess:

- **Put `--` before user-controlled positionals.** `[...flags, '--', userInput]`. This one habit closes an entire bug class.
- **A defence-in-depth second line:** reject input matching `/^-/` when you know it should be a URL or path.
- **"No shell" is not "no injection."** Spawning without a shell stops metacharacter injection; it does nothing for *argument* injection. They are different bugs.
- **Be honest about severity.** My instant-RCE theory was wrong. The report was stronger, not weaker, for saying so — and the maintainer's own patch notes reflected that exact calibration.

Two dashes. That was the whole bug. Go read the boring code — the tenth line is worth it.

<hr>

*Disclosed privately to the maintainer; fixed in [`youtube-dl-exec` 3.1.15](https://github.com/microlinkhq/youtube-dl-exec) via PR #284. No CVE requested at time of writing.*

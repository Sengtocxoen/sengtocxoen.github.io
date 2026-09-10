---
layout: post
title: "The Validator That Widened Access"
subtitle: "transformers.js checks whether your modelId is a valid Hugging Face repo id. When the answer is no, it doesn't reject you — it reads the path off your disk instead."
date: 2026-09-08
tags: [path-traversal, nodejs, ai, cwe-22, full-disclosure]
read_time: "5 min read"
---

[transformers.js](https://github.com/huggingface/transformers.js) is Hugging Face's JS runtime for running models in Node and the browser. In Node, you load a model by id — `pipeline(task, modelId)`, `AutoModel.from_pretrained(modelId)` — and it resolves the model's files. There's a validator for that id. This is a story about a validator whose "invalid" verdict makes things *less* safe.

## The boring part

A model id looks like `Xenova/all-MiniLM-L6-v2`. The library has `isValidHfModelId()` to check that a caller-supplied id is a well-formed repo id, and it correctly rejects traversal — an id containing `..` returns `false`. So far so good: the validator knows `..` is bad.

## The tilt-your-head part

Here's what the code does with that `false`, in `src/utils/hub.js`:

```js
const validModelId = isValidHfModelId(path_or_repo_id);
const localPath = validModelId
    ? pathJoin(env.localModelPath, requestURL)   // valid: contained under localModelPath
    : requestURL;                                // INVALID: raw attacker path, un-prefixed
```

Read that ternary twice. When the id is *valid*, the path is built safely under `env.localModelPath`. When it's *invalid* — which is exactly the case a `..` payload triggers — it drops the containment and uses the raw path. The validator's rejection doesn't route to an error; it routes to the *wider* code path. `getFile(localPath)` then reads it with `fs`, no `path.resolve` containment, and `pathJoin` never collapses `..`.

So a crafted `modelId` escapes `env.localModelPath` and reads model-named files (`config.json`, `tokenizer.json`, `*.onnx`) from anywhere the process can reach. The perverse part, in the report's own words: the validator result is computed and then used to *widen* access rather than to deny it.

## Proof

Against published `@huggingface/transformers@4.2.0` (current latest, Node filesystem branch). A `modelId` containing `..` walks out of the model directory and reads an arbitrary file whose name matches what the loader expects to fetch. The load resolves against files outside `localModelPath`; the browser build, which has no `fs`, is unaffected.

## The honest constraints

I'll keep this calibrated, because it's a read primitive with real limits, not a fs-wide grab. The attacker chooses the *directory*, but the *filename* is one of the ones the loader looks for (`config.json`, `tokenizer.json`, `*.onnx`, …). That's narrower than "read any file" — but those are precisely the filenames that hold model configs, tokenizer data, and, in a lot of ML deployments, adjacent credentials and manifests. Confidentiality High, integrity/availability none. So: High, not Critical, and I'd rather say exactly what it can and can't read.

## The fix

Make the invalid verdict *deny*, not redirect. If `isValidHfModelId` returns false, throw — don't fall through to a raw-path read. And containment on the local branch regardless: `path.resolve` the final path and confirm it stays within `env.localModelPath` before touching `fs`. (There's even a `validModelId` guard further down the same file that throws before *remote* requests — the local read just doesn't get the same treatment.)

## Where this stands

Present on `@huggingface/transformers@4.2.0`, current `latest`, no CVE, no fix. Full disclosure. If your Node app passes any user-influenced value as a `modelId` / `from_pretrained` argument: constrain it to an allowlist of known model ids before it reaches transformers.js.

## Takeaways

- **A validator that redirects instead of rejects is worse than no validator.** "Invalid → different code path" is a pattern to hunt: the interesting question is always *what the else-branch does*.
- **Path containment must survive the `..`.** `pathJoin` isn't `path.resolve`; neither collapses traversal into a boundary check on its own.
- **State the filename constraint.** "Attacker picks the dir, loader picks the filename" is the honest shape of this read, and it's still plenty on an ML host.

<hr>

*Full disclosure. Present on `@huggingface/transformers` 4.2.0 (current latest, Node.js) at time of writing; no CVE assigned, no fix released. Reproduced against the published package.*

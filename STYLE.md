# Research repo style

How my research repos are laid out and written, so that they read as one series.
Drawn from `distributed-inference-resilience`, `distributed-inference-recovery` and
`steno-tokenizer-test`. A new repo copies this file in unchanged; a repo that has a
reason to deviate says so in its README.

## 1. The README is the paper

The README is the complete write-up. There is no separate paper, blog post or wiki;
a post on the website summarises and links here. Everything a reader needs to judge
the result is in the README, and everything the README claims is in the repo.

Order of sections:

1. **Title**: the repo name as the `#` heading, nothing else.
2. **Introduction**, unheaded, two to four paragraphs, first person. What the question
   is, where it came from (the essay, an article, a previous experiment, a hunch), who
   it is written for, what the scope is and is not, and the one-sentence outcome. The
   last paragraph says who did what (see §6) and where the numbers come from.
3. **Numbered sections** (`## 1.`, `## 2.`, ...): what was measured, one section per
   experiment or result, the method, the limitations, related work. Cross-reference
   them as `§3`, never "above" or "below". Subsections are `###` and unnumbered.
4. **`## Conclusion`**, unnumbered. What the result settles, what it does not, and
   whether the work continues.
5. **`## Repository`**, unnumbered: a list of files and directories with one line each,
   then `### Reproducing` (the exact commands, in the order to run them, with timings
   and hardware) and `### Status` (a checklist of what is done and what is left; an
   item that will not be done says so rather than staying unticked forever).
6. **`## Acknowledgement`**, last.

A repo with one experiment can fold "what was measured" into the introduction; the
rest stays.

## 2. Voice

- The introduction and the conclusion are written by me, in the first person
  singular: "I", "my hunch", "I am not continuing this". They say what I think.
- The experiment sections use "we" or the passive: "we measure", "was tested",
  "the trial sends". They say what was done.
- Plain declarative sentences. The finding first, the mechanism second, the caveat
  third. No hedging adverbs ("somewhat", "fairly", "quite"), no intensifiers
  ("very", "extremely"), no "interestingly".
- A negative result is stated as plainly as a positive one, in the same place and at
  the same length.
- Predictions are written down before the measurement and left as written; a later
  section scores them (right / wrong / partially) and says what the mechanism turned
  out to be.
- No em dashes. Use a comma, a colon, a semicolon, or parentheses.

## 3. Spelling and units

- British spelling: artefact, amortise, normalised, favour, licence (noun), optimiser.
  Exceptions, kept because they are the term of art or a product name: datacenter,
  tokenizer, pretokenizer, tokenization.
- Units take a space: `15 s`, `2.6 ms`, `68 MB`, `12 GB`, `0.06 s/token`. Percent does
  not: `5%`.
- Ranges in prose use "to": "2 to 4%", "13 to 18 minutes", "128k to 200k". Ranges in
  tables and parentheses after a median use an en dash: `275 s (272–282)`.
- Approximate values use `~` or "about", not "approx." or "roughly".
- Dates are ISO, `2026-10-21`, or spelled out, "21 October 2026"; never `10/21`.
- Maths in `$...$`: `$C$`, `$\lambda^* = 1/(S C)$`, `$e^{-N\lambda D}$`. Define each
  symbol the first time it appears.
- Numbers in tables are right-aligned where they are compared, with the same number of
  decimals down a column; the winning cell is **bold** when there is one.
- Code, file names, flags, environment variables and identifiers in backticks:
  `analyze.py`, `--mode kill`, `VLLM_EXECUTE_MODEL_TIMEOUT_SECONDS`, `RunnerIdle`.

## 4. Numbers and provenance

- Every number in the README is reproduced by a script in the repo from a committed
  record. The introduction says which script. If a number needs something that is not
  committed (a checkpoint, a model download), the README says so where the number
  appears.
- Raw records are committed: `trials.jsonl`, `runs/*.json`, `out/*.csv`. Checkpoints,
  token streams, downloaded corpora and model weights are not; `.gitignore` lists them
  with a comment saying which script regenerates each.
- Report medians with min–max and n: `15.0 s (14.3–16.0, n = 33)`. Say when and why
  trials are excluded, and keep the excluded records in the file.
- Claims read from source cite file and line at a pinned commit:
  `supervisor.py:391-407` at `bc412e2`. Constants are the defaults in code, not in
  documentation.
- Figures are rendered by `figures.py` from the same records and committed as PNG in
  `figures/` (or `out/` where the simulation writes its own). Rerunning the script
  must reproduce the committed files byte for byte. One hue per system or strategy,
  fixed across all figures in the repo; no default matplotlib palette.
- A result that depends on an assumption (a regime conversion, a derived figure from
  someone else's paper) is labelled "derived" or "assumption, not measurement" where
  it is stated.

## 5. Layout

```
README.md            the write-up (§1)
LICENSE              MIT, "Copyright (c) <year> Naithan Weigh"
requirements.txt     one package per line, what the scripts import
.gitignore           regenerated and downloaded things, with comments
STYLE.md             this file
<code>/              a package (churnsim/) or one directory per system
                     (exo/, vllm/, llamacpp/); small repos keep scripts at the root
analyze.py           records → the numbers in the README
figures.py           records → figures/
figures/ or out/     committed figures and small outputs
runs/ or */trials.jsonl   committed raw records
tests/               when there is a simulator or a library worth testing
NOTES.md, RESULTS.md, STUDY.md, FINDINGS-*.md
                     only when the README would otherwise exceed what one reading
                     holds: derivations, full tables, pre-registered predictions,
                     source readings. The README links each one where it is used.
```

Scripts take their inputs as arguments and write to a path given by `--out`; they
never depend on the working directory beyond the repo root. A `Containerfile` and a
`cluster.sh` go in the directory of the system they build.

## 6. Authorship and Claude

- Commits are authored `Naithan Weigh <me@naithanweigh.com>`, never a tool, and
  carry no `Co-Authored-By` or session trailers. Commit messages are one line, present
  tense, saying what changed and, if it is not obvious, why: `fix: llamacpp cut gives
  the main-only restart 600 s and records the rpc host's connection log`.
- Claude's part is acknowledged once, in the `## Acknowledgement` section, and named
  in the introduction's last paragraph: which parts were developed together (the
  harness, the analysis, the figures) and which are mine (the questions, the framing,
  the trials, the conclusions). Nowhere else.
- The introduction and the conclusion are mine in substance as well as wording. A
  draft may be produced; it is rewritten before it is committed.

## 7. Publishing

- A repo goes public when the README has its conclusion, every number reproduces, the
  figures regenerate unchanged, no path or file is referenced that is not in the tree,
  and there are no leftover branches. Private staging repos are used for work in
  progress; the public repo is not pushed to directly while an experiment is open.
- Follow-on experiments that would grow a public README past one reading get their own
  repo, named `<series>-<subject>`, which links back to the series in its introduction
  and whose measured constants are merged into the earlier repo where they apply.
- Bugs found in the systems under test are reported upstream and the issue numbers are
  linked from the README.

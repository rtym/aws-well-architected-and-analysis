# Writing style for every report this plugin produces

These rules apply to every artifact a skill in this plugin hands a human:
gap analyses, findings reports, strategy write-ups, and any prose added on
top of a script-generated report. The generated reports follow them by
construction (`shared/reporting/`), and `bin/lint-report-prose` checks a
finished report deterministically -- but most report prose is authored by
Claude, which is why this document exists. Load it before writing, not
after.

## Voice

- Plain sentences, active voice, one idea per sentence. No fragment
  chains ("Checked IAM. Gaps found. See below.") -- write the sentence.
- No filler vocabulary. Banned outright: *seamless*, *leverage*, *robust*,
  *comprehensive*, *delve*, *utilize*, *holistic*, *cutting-edge*,
  *state-of-the-art*, *best-in-class*, *world-class*, *game-changing*,
  *synergy*, *"it is worth noting"*, *"in today's ..."*. If a sentence
  survives without the word, the word was filler. ("Utilization" as a
  metric name -- RI utilization percentage -- is fine; the verb "utilize"
  is not: write "use".)
- Numbers where numbers exist. "Significant cost savings" is a claim;
  "$1,240/month across 14 idle volumes" is a finding. If the evidence has
  no number, say what *is* known rather than reaching for an adjective.
- Bold marks labels only (**Severity:**, **Region:**) -- never
  mid-sentence emphasis.
- No meta-commentary about the document ("This section will discuss...",
  "As mentioned above..."). State the content; cross-reference with a
  link when the reader genuinely needs the other section.

## Structure every artifact the same way

- **Open with orientation:** 1-3 plain sentences before the first section
  heading -- what this report is, what account/scope it covers, and where
  to start reading (usually the prioritized findings or summary table).
  Script-generated reports do this via `Report(intro=...)`; hand-authored
  ones must do it by hand.
- **Explain notation at first use, or legend it.** Severity, pillar, and
  priority codes get a legend listing *only the values actually used* in
  the document (`shared.reporting.report.severity_legend()` for severity).
  Never use a code (HRI, MRI, SEC04, gp3) before the reader has been told
  what it means -- one parenthetical at first use is enough.
- **Cross-references are links.** Point at another section or file with a
  relative Markdown link, not "see the other report".
- **Multi-file deliverables get an index.** If a review produces several
  documents, write a short index file naming each one and its purpose, and
  end each document with a link back to that index.

## What the lint enforces

`bin/lint-report-prose <dir>` (also run by `tests/test_prose_quality.py`
against every skill's rendered report) fails a report for: banned filler
vocabulary, unfilled template placeholders (`<AccountId>`, `{{name}}`,
`TODO`), the same prose line repeated back-to-back, a section heading
repeated verbatim, and a missing orientation paragraph. Code fences and
table rows are exempt -- they carry commands and quoted AWS data, not the
plugin's prose. This file deliberately names the banned words, so the
lint exempts it (and only it) among the plugin's own docs.

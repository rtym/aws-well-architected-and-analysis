# Contributing

Conventions and invariants for extending this plugin. These are not style
preferences -- each one below exists because getting it wrong produced a
real bug, and each is enforced by a test.

## 1. Read-only is a hard constraint

Every collector calls only `Describe*` / `List*` / `Get*`. Adding a call
that creates, modifies, or deletes AWS state breaks the plugin's core
promise (see `PERMISSIONS.md`, which tells users to grant read-only
credentials).

The single exception is `well_architected.update_answer()`, which writes
scored answers back into a real Well-Architected Tool workload. It is
never called automatically, is deliberately excluded from the
least-privilege policy in `PERMISSIONS.md`, and the skill instructs Claude
to confirm with the user first. If you ever add a second mutating call,
hold it to the same three conditions.

If you add an API call, add its IAM action to `PERMISSIONS.md`'s policy.

## 2. The HTML-escaping contract

Report content carries live AWS metadata -- bucket names, tags, IAM
usernames, Well-Architected workload names -- which a limited-privilege
principal can set to arbitrary text. Reports render to HTML that users
open in a browser, so unescaped data is a stored-XSS path.

The contract, enforced by `test_report_escapes_every_plain_text_field` and
`test_report_section_body_is_not_escaped_by_contract`:

- **`Report` escapes its own plain-text fields automatically** -- `title`
  (including inside `<title>`), `subtitle`, `meta` keys and values, and
  section headings. You don't need to do anything for these.
- **`findings_table()` escapes every cell automatically.** Prefer it for
  any AWS-sourced tabular data; it also handles pipes, newlines, and list
  values.
- **Section *bodies* are NOT escaped, by design** -- they're Markdown by
  contract (tables, `**bold**`, embedded chart images must survive). If
  you hand-build a body f-string that interpolates an AWS-sourced
  *string*, escape it yourself with `escape_text()` from
  `shared.reporting.report`.

Counts (`len(...)`), booleans, and AWS-generated identifiers (account IDs,
instance IDs, ARNs) don't need escaping -- they can't carry markup. Free
text set by a user or an API caller does.

## 3. Collector patterns

**Degrade, don't crash.** A service that isn't enabled, a region that's
opted out, or a permission that wasn't granted are *normal states* for a
plugin that scans arbitrary accounts -- not errors worth aborting a whole
run over. Wrap such calls in `@ignore_access_denied(default=...)`.

Match `default` to the function's return type: `default=list` for
functions returning lists, `default=dict` for dicts. (Seven Cost Explorer
functions were annotated `-> dict` while defaulting to `[]`; callers doing
`.get()` on the fallback would have crashed.)

When you add a call to a new service, check what error code it raises in
the "not enabled" case and add it to the set in
`session.ignore_access_denied` if it's missing. Codes already handled:

```
AccessDenied, AccessDeniedException, UnauthorizedOperation, OptInRequired,
SubscriptionRequiredException, InvalidAction, InvalidAccessException,
AWSOrganizationsNotInUseException
```

`test_ignore_access_denied_swallows_every_documented_error_code`
parametrizes over all of them -- add yours there too. (Security Hub's
`InvalidAccessException`, raised when the account isn't subscribed, was
missing and crashed the whole security scan.)

**Pagination:** use `paginate()` for operations botocore has a paginator
for, and `manual_paginate()` for those it doesn't (several
`wellarchitected` APIs). Check with
`client.can_paginate("operation_name")` rather than assuming -- calling
`paginate()` on a non-paginable operation raises `OperationNotPageableError`.
Don't hand-roll a single-page call with `MaxResults` and call it done; a
detector or analyzer with more than one page gets silently truncated.

**S3 is not really global.** `list_buckets` is, but every *per-bucket*
call must go through a client in that bucket's own region (resolve it with
`get_bucket_location`, normalizing the `None`/empty response to
`us-east-1`). A client pinned to the wrong region raises
`PermanentRedirect` for any bucket elsewhere -- the common case in real
accounts.

## 4. Testing patterns

**`moto` first, `Stubber` when moto doesn't implement the API.** As of
moto 5.x these are *not* implemented and need `botocore.stub.Stubber` (see
`tests/stub_helpers.py`): Security Hub `GetEnabledStandards` /
`GetFindings` / `DescribeStandardsControls`, GuardDuty `ListFindings` /
`GetFindings`, Access Analyzer, AWS Config compliance, Service Quotas,
Well-Architected Tool, and most Cost Explorer operations beyond
`GetCostAndUsage`.

`Stubber` validates responses against the real botocore schema, so a stub
must include **every required field** of the response shape -- not just
the fields your code reads. When a stub fails with
`ParamValidationError: Missing required parameter`, add the named field;
don't loosen the assertion.

**Every bug fix gets a regression test** that fails against the old
behavior, with a comment saying what the bug was. The suite is the record
of what's already been gotten wrong.

**Test the layer you changed:** a collector change needs a
`test_collectors_*.py` test; a `build_report()` change needs
`test_skill_scripts.py`; anything touching argparse, `save()`, or
`--json-out` needs `test_script_main.py`.

## 5. Adding a skill

`tests/test_skill_integrity.py` enforces the structure, so a new skill
must:

- Live in `skills/<name>/` with a `SKILL.md` whose frontmatter `name:`
  exactly equals the directory name.
- Have a `description:` long enough to be discoverable (>120 chars) that
  includes concrete trigger phrases a user would actually type.
- Reference only `${CLAUDE_PLUGIN_ROOT}/...` paths that exist on disk.
- Reference every file it ships under `references/` (no orphans).
- If it ships `scripts/`, each script needs a `main()` and a
  `__main__` guard, and should build its CLI from
  `shared.awslib.cli.base_parser` so `--profile` / `--region` /
  `--output-dir` / `--formats` / `--json-out` behave identically
  everywhere.

Bump the expected count in `test_expected_skill_count`, and add the skill
to the table in `README.md`.

## 6. Grounding reference content

Reference docs under `skills/*/references/` encode AWS facts that go stale
(finding-type catalogues, log record formats, framework questions). When
you add or revise one, fetch the current AWS documentation rather than
writing from memory, and record the URL in `SOURCES.md` under
"Fetched and read". If something couldn't be verified against a source,
label it as unverified in the doc itself rather than stating it flatly --
`skills/aws-network-traffic-analysis/references/detection-guide.md`'s
escalation section is the pattern to follow.

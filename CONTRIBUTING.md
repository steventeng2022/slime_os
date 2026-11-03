# Contributing to Slime OS

## The short version

Slime OS uses GitHub for collaboration, but canonical project state lives in
MyQue under `.tasks/items/`. GitHub Issues are intake for bugs and proposals.
Work items are not projected into Issues or milestones; see
[the decision](docs/decisions/no-github-issue-projection.md).

**For a product or grader change, first land a dedicated work-item PR. Only
after the item exists on `main` may you open an implementation PR.** Do not
combine a new item and its implementation, or stack implementation on
unmerged planning; CI refuses a pull request that does both. A work-item
proposal PR is the bootstrap exception: it needs no existing item. A pull
request that touches neither the product tree nor the grader closure — CI
workflows outside `codePaths`, this file, `AGENTS.md`, `docs/` — needs no work item at all; see
[Pull request scope](#pull-request-scope).

**PR merged != work item done.** Completion requires the item's exit conditions
to be observed and recorded, not just an implementation to land. For a
spec-driven item that recorded its gate evidence, a workflow on `main` runs
`just devloop complete` and proposes the transition as a `.tasks`-only PR;
a human merges it.

If those two rules read as ceremony, start with
[How work flows](docs/getting-started/00-how-work-flows.md): the same process
as a timeline, with the reason and the enforcing check beside each step. This
file owns the exact rules; that page explains them.

## Where work lives

### Human Issues are intake

Open a [GitHub Issue](https://github.com/iceice666/slime_os/issues) for a bug,
proposal, question, or discussion. For bugs, include the target, revision,
reproduction steps, expected result, and observed output when available.
The [issue chooser](https://github.com/iceice666/slime_os/issues/new/choose)
offers a bug-report form and a feature-request form.
The bug-report form guides reproduction details and keeps environment information and logs optional.
The feature-request form asks for the problem and proposed behavior, with optional verification ideas.
Use a blank issue for questions, discussions, or reports that do not fit either form.
Ordinary reporters do **not** need to install MyQue or edit `.tasks`.
Accepted work is later represented as a canonical MyQue item. The Issue does
not track that item; the item's file under `.tasks/` is its only state.

### Bot Issues are retired projections

Issues created by `github-actions[bot]` whose body begins with
`<!-- myque:id=<UUID> -->` came from the retired projection. They are closed
and no longer track their item. Read the item under `.tasks/` instead.

### Work-item hierarchy

Create children only for independently trackable work with observable exit
conditions. Admit one with `just devloop admit spec.zti --title "Describe the
work" --kind task`, then `myque parent <CHILD_UUID> <PARENT_UUID>` and
`just tasks_check`; follow the planning-PR process below. Do not change kinds
or parent relationships merely to populate a progress bar. `just tasks_graph`
and `just tasks_list` render the hierarchy from the store.

### MyQue is canonical

| Surface | Owns |
|---|---|
| `.tasks/items/<UUID>.md` | Problem, scope, state, exit conditions, hierarchy, dependencies, and observed closure evidence |
| GitHub | Intake, collaboration, reviews, projected work |
| PR | Reviewable change, claim, risk, verification, limits, and related canonical work |
| Owning docs/contracts | Current architecture, behavior, procedures, and limitations |
| [History archive](docs/history.md) | Historical investigations and raw evidence; optional exceptional reusable investigations, never a product build dependency |

UUIDs are canonical identities. Optional human keys are mutable display aliases,
not persistent references. Generated lists and `roadmap/` are not state stores.

## Proposing work

Discuss bugs and ideas in Issues first when useful. **New canonical work must be
spec-driven**: every item created on or after `2026-10-01T00:00:00Z` carries a
devloop requirements body, so propose it with `just devloop admit` as described
under [Spec-driven items](#spec-driven-items) below, not with `myque new`.
`just tasks_check` refuses a store where a post-cutoff item lacks that record,
and the rule admits no exemption by kind, tag, or state — defects included.

MyQue allocates the UUID either way; never invent one or allocate a numbered key
by scanning the store. Fill in the item's problem, scope, observable exit
conditions, and use MyQue commands for any parent/dependency relationships.
Follow [AGENTS.md](AGENTS.md)'s backlog-first and work-item rules; run
`just tasks_check`.

Items created before that instant stay valid as prose and never become subject,
even if reopened. For one of those, and only for one of those, the older form
applies:

```sh
myque new "Describe the work" --kind task   # pre-cutoff items only
```

Submit a **work-item-only planning PR**, and merge it before opening an
implementation PR. An already-landed item can cover another implementation PR
within its scope; a new planning item is not required for every PR.

### Spec-driven items

An item carries its requirements as structured data, which makes its
completion enforceable rather than asserted.
[Carrying a work item](docs/getting-started/06-work-item-lifecycle.md) walks
both lifecycles command by command; the rules that bind a pull request are
here. Author the payload as a `dev-spec/v1` `.zti` file — or as a `.zt` input
that computes it — and admit it:

```sh
just devloop admit spec.zti --title "Describe the work" --admission <token> --policy .devloop/policy.json --kind task
```

[devloop](https://github.com/mozufu/devloop) allocates nothing: MyQue assigns
the UUID, the body becomes one fenced `zti` block, and the `devloop`
frontmatter record carries the profile, pins, digest, and admission identity.
Repeating the same token is idempotent. From then on `just tasks_check`
validates that body, and work proceeds by canonical UUID:

```sh
just devloop start <ITEM> --policy .devloop/policy.json
just devloop gate <ITEM> <ACCEPTANCE> --policy .devloop/policy.json --inputs <inputs>.json --target <target> --image <image>
just devloop human <ITEM> <ACCEPTANCE> --policy .devloop/policy.json --inputs <inputs>.json --target <target> --image <image> --observations <observed>.json --observer <who>
just devloop complete <ITEM> --policy .devloop/policy.json --inputs <inputs>.json --target <target> --image <image>
```

Approval applies this repository's rules before anything starts: the item must
already be on canonical `main`, and open backlog defects come first. Gate
identities resolve through [`.devloop/policy.json`](.devloop/policy.json) to
existing `just` targets; a gate reports the typed observations that policy
declares, and the item's own predicates decide whether they satisfy an
acceptance.

Most acceptances bind the general `just-target` gate, which runs one declared
recipe and reports a single `passed` boolean. Name the recipe in the execution
inputs, never in requirement text, and commit the inputs file under
`.devloop/inputs/` in the planning PR:

```sh
echo '{"justTarget": "sel4_qos_check"}' > .devloop/inputs/<item>.json
just devloop gate <ITEM> <ACCEPTANCE> --policy .devloop/policy.json --inputs .devloop/inputs/<item>.json --target sel4-qos --image qemu-arm-virt
```

The gate refuses a recipe `just` does not publish, and devloop binds the inputs
digest into the evidence identity, so evidence recorded for one recipe never
transfers to another.

**The exam is landed before the implementation is graded.** At `eligible`
and `complete`, approval (`scripts/check/devloop-approval.py`) resolves the
inputs digest to a tracked file under `.devloop/inputs/` and refuses unless
that file, the named recipe and every recipe in its dependency chain, the
scripts those recipes invoke, and the `scripts/lib` modules they import are
byte-for-byte what `origin/main` carries. An implementation branch may add
recipes and checkers for other work, but it cannot rewrite the ones that
decide its own acceptances: a checker that needs to change is a planning
change and lands first. Inputs that name no recipe (`work-item-store`) are
only required to be landed.

When a requirement is a number — attempts refused, controls exercised, bytes
delivered — bind `just-observations` instead. It runs the same named recipe,
and the recipe's checker reports what it counted through
`scripts/lib/devloop_observations.py`:

```python
from devloop_observations import record
record(staleHandlesRejected=refusals, negativeControlsRefused=len(controls))
```

The gate adds `passed` and a `transcriptDigest` of its own, refuses an
observation the policy does not declare or a checker that reports `passed`
for itself, and the acceptance's predicate states the expected value. The
planning PR owns that number and the checker that counts it: an implementation
PR that changes either is changing its own exam, and the review skill in
[`.agents/skills/spec-review/SKILL.md`](.agents/skills/spec-review/SKILL.md)
asks why. [`.devloop/examples/`](.devloop/examples/) holds a worked spec and
its inputs. A check that needs observations the policy does not yet declare
adds them to `just-observations` in the planning PR.

`just tasks_check` also refuses a tracked file that no `codePaths` entry
covers, unless `scripts/check/check-work-items.py` exempts it by decision:
a change to a checker, recipe, pin, or fixture must stale the evidence recorded
against it. Evidence is recorded into the `devloop` record bound to the exact
requirements, helpers, code, policy, execution inputs, target, image, and run
epoch that were tested, and the newest entry for an obligation decides it — a
later failing run is never satisfied by an earlier pass. A human obligation
stays pending until an operator supplies a real observation; nothing here may
synthesize one, and `complete` refuses while any mandatory obligation is
unmet. Merging still does not complete an item.

Ordinary prose items need none of this and are unaffected.

## Development setup

Start with [Orientation](docs/getting-started/01-orientation.md), then
[Build and run](docs/getting-started/02-build-and-run.md) for submodules,
`nix develop`, toolchain pins, and QEMU. Continue with
[Your first change](docs/getting-started/04-first-change.md) or
[Add a component](docs/getting-started/05-add-a-component.md).
These guides own the tutorials; this document owns the contribution workflow.

## Making a change

- Read [AGENTS.md](AGENTS.md), the detailed repository engineering rules.
- Route through the [task-to-file index](docs/task-to-file.md) before searching. Change the owning
  implementation, not a checker that merely observes it.
- Identify the narrowest owning gate before editing; preserve capability,
  component, generation, and hardware-safety invariants.
- Use versioned Zutai schemas for cross-process, persistence, and boot formats.
  Change the canonical schema/generator and regenerate outputs together;
  never hand-edit generated bindings.
- Keep comments for current invariants beside the implementation and stable
  rationale in owning docs.
  Put long-lived cross-module choices in `docs/decisions/`, unfinished designs
  and qualification requirements in `docs/plans/`, and exploration in
  `docs/directions/`. Expensive reusable investigations or unusual verification
  campaigns belong in the private [history repository](docs/history.md).

## Pull requests

### Pull request scope

`scripts/check/check-pr-scope.py` classifies every path a pull request
changes, from lists the repository already maintains rather than a third
table, and CI runs it on every pull request. Classification uses the union of
`codePaths` from the compared base and head commits, not the checkout policy.
Removing protection in the same diff does not exempt the changed path. Renames
and detected copies retain source and destination classification; destinations
introducing a new work-item UUID count as new items even without an `A` status.
The Git comparison explicitly detects copies from unchanged sources, so a
copied schema does not qualify as an added interface merely because its source
was unchanged. Missing or malformed revision policies refuse classification.


| Class | Paths | Rule |
|---|---|---|
| **grader** | `scripts/`, `just/`, `Justfile`, `.devloop/` — the closure `devloop-approval.py` pins to `origin/main` | needs a landed work item; may land with the item as its exam |
| **product** | every other `codePaths` entry in `.devloop/policy.json`: `slime-root/`, `components/`, `contracts/`, `boot-contracts/`, `sel4/`, build inputs, pins, toolchain configuration | needs a landed work item; **never** in a PR that adds one |
| **interface** | an **added** `contracts/<name>/v<N>/schema.zt`, or a contract's `README.md` — the boundary a grader binds to | needs a landed work item; may land with the item as part of its exam. `gen_rust.zt`, generated bindings, system specs, and a modified or renamed schema are product |
| **derived** | regenerated closure sources under `contracts/system-image-closure/v3/closures/`, negative cases under `contracts/system-image-closure/v2/negative/`, and `contracts/system-test-run/v2/runs/` | mirrors whatever else changed; never decides |
| **other** | `.github/` paths outside `codePaths`, `CONTRIBUTING.md`, `AGENTS.md`, `docs/`, `.tasks/`, and anything else outside the code identity | no work item required |

The CI, closeout and retirement workflow files are explicitly
in `codePaths`: their contents affect shared-tool cache qualification, so edits
stale evidence and follow the product-classified planning-first rule. Other
workflow files remain process changes unless explicitly covered.

Two rules follow. A pull request that **adds** a `.tasks/items/*.md` file may
change grader, interface, derived and other paths — the exam and the schema it
reads land with the item — but not product paths; CI fails and names both.
Every `contracts/**/schema.zt` is compiled by `just contracts_check` whether
or not a generator or checker names it yet, so a schema landed ahead of its
implementation is still checked. See
[docs/decisions/planning-pr-schema-contracts.md](docs/decisions/planning-pr-schema-contracts.md). A pull request confined to
derived and other paths is a **process change**: it needs no landed item,
still runs every applicable check, and its description states what it
changes. Product and grader changes keep the landed-item requirement below.

### Canonical work-item requirement

Every product or grader implementation PR must implement at least one canonical
UUID **already present on `main` before the PR opens**. This includes features,
bug fixes, architecture changes, behavioral refactors, gate semantic changes,
new verification gates, protocols/schemas, drivers, hardware bring-up,
authority/security changes, and policy changes to the grader closure.

Use the existing [change](.github/PULL_REQUEST_TEMPLATE/change.md) or
[system-change](.github/PULL_REQUEST_TEMPLATE/system-change.md) template. State
what changed, the claim, risks/invariants, review surface, exact verification,
evidence class, target or image identity when relevant, known limits, and
canonical related work. Link existing evidence instead of duplicating it.
Name the implemented item by its canonical UUID in the PR description.

### No GitHub auto-close

Do not use `Closes #123`, `Fixes #123`, or `Resolves #123` to complete work.
GitHub does not own work-item completion; the item's devloop record or
`## Closure evidence` section does.

### Verification

Run the narrowest gate covering the changed behavior and the checks required
by [AGENTS.md](AGENTS.md). Record exact commands, observed results, evidence
class, scope, target or image identity when relevant, and limits; separate
direct observations from inherited evidence and label unobserved conclusions
as inference. Documentation-only PRs state that no runtime tests were run.
Ordinary changes do not require a devlog entry. Run `just docs_check` for
maintained documentation, policy, links, or command-reference changes. Archived
records retain their original checker at their immutable revision; no archive
checkout or network access is required for current docs checks. Run
`just tasks_check` when applicable and `just typos` for documentation.

## Review and completion

Review conduct — what a reviewer may post, how severity is assigned, and how an
author answers or declines a finding — is set in [AGENTS.md](AGENTS.md) under
"Code review"; it binds people, review bots, and agents alike. When an author
stops and asks, [HUMAN.md](HUMAN.md) says how to answer.

**Merge means implementation landed, not that work is complete.** Evaluate the
item's actual exit conditions: QEMU gates, cross-architecture runs, physical
hardware evidence, failure/refusal evidence, repeated reliability runs, CI,
or other item-specific observations. QEMU output does not prove hardware
support, and a green unrelated gate does not satisfy an exit condition.

For an ordinary prose item, record the observed exit evidence, scope, identity,
and limits in exactly one unambiguous `## Closure evidence` section. Retirement
extracts that section's content verbatim, through the next heading of the same
or higher level or the body's end; an `Exit conditions` list is not observed
evidence. Only then run:

```sh
myque close <ITEM>
```

A spec-driven item closes through `just devloop complete`, which verifies its
mandatory acceptance obligations against recorded evidence and then transitions
the item under the revision it checked. A direct `myque close` bypasses that
boundary; use it only for items that carry no `devloop` record.

Commit the canonical `.tasks` transition. Leave unfinished work unfinished.

### Automated closeout PRs

`just devloop complete` refuses on an implementation branch whenever that
branch changed its own grader, and always grades against `origin/main`, so
the transition is ordinarily made after merge. `myque-closeout.yml` does
this: on every push to `main` that touches the store or the grader closure it
clones canonical `main`, runs `just tasks_check`, and for every open or
active spec-driven item with recorded evidence recovers the inputs file,
target and image from the evidence identity, asks `just devloop eligible`,
and runs `just devloop complete` for each item devloop accepts. It commits
only those items' `.tasks/items` files, pushes `automation/myque-closeout/<main>`
and opens one PR; a human reviews and merges after normal CI. Items devloop
refuses — expired evidence, a changed code closure, an unmet acceptance — are
listed in the PR body with devloop's reason and left open.

The workflow never writes `main`, never records or edits evidence, and never
decides eligibility itself. `workflow_dispatch` runs a preview that completes
items in a throwaway clone and publishes nothing; the push trigger publishes
only while the `MYQUE_CLOSEOUT_ENABLED` repository variable is `true`. A
proposal whose base `main` has since advanced is closed and regenerated, not
rebased. Preview locally with
`python3 scripts/lib/work_item_closeout_publish.py` in the pinned environment.

### Storage-only retirement PRs

The separate `myque-retire.yml` workflow proposes retirement of live `done`
items from a recorded full revision of canonical `origin/main`, with no
arbitrary source refs and no additional age threshold. MyQue can retire both
`work-item/v1` and `work-item/v2` directly; this is not envelope migration,
closure, or a new completion judgment. Cancelled, unfinished, and already
retired items are not candidates. Missing/empty/ambiguous prose evidence,
unsupported consumer versions or evidence, and unknown consumer namespaces
are reported skips. Devloop retirement references recorded evidence identities
and gate results, not today's expiry or a fabricated completion receipt; its
identity fields remain in the terminal consumer entry and full evidence remains
in exact retained history.

Preview in the pinned environment with
`python3 scripts/lib/work_item_retirement_publish.py` (the default mode).
Preview changes neither the source store nor remote refs, branches, or PRs.
`--apply` is only for the trusted isolated GitHub workflow and enforces remote
merge-protection and publication guards. It runs `just tasks_check` before and
after MyQue mutation, verifies exact history and the same-UUID storage-only
diff, and pushes/verifies this batch's retained refs before the branch or PR.
Empty batches publish nothing; an existing retirement PR stops a new batch.
Partial publication is resumed only after verifying expected bot-owned state,
never by overwriting a PR under review or deleting retained refs. A human must
review and merge after normal CI; automatic merge and direct `main` writes are
not supported.

Manual dispatch defaults to preview. The daily schedule runs only when the
repository variable `MYQUE_RETIRE_ENABLED=true` is set **after real manual
GitHub qualification**, including the retained refs, maintenance PR, actual CI
trigger/approval path, and stale-base race. Do not infer qualification from
local simulations; this document does not claim the workflow tested or enabled.
Publication prerequisites are PR-required rules with no automation bypass,
the required `Canonical work-item store` check from GitHub Actions (integration
`15368`) under strict/current-base rules,
and GitHub Actions permission to create PRs (“Allow GitHub Actions to create
and approve pull requests”). Concurrency alone cannot stop stale retirement
after an item is edited or reopened on `main`. `GITHUB_TOKEN`-created PRs may
need human approval or a supported manual check trigger; do not claim automatic
CI without observing it, replace the token, or bypass the merge rules.

The [lifecycle guide](docs/getting-started/06-work-item-lifecycle.md#retirement-maintenance-prs)
owns exact evidence selection, retained-ref transport, qualification, and recovery.
An administrator must also approve the ruleset identities using the lifecycle
guide's `--approve-rules` procedure and set `MYQUE_RETIRE_RULES_APPROVAL`;
workflow tokens cannot inspect private bypass lists. A ruleset change invalidates
that approval without granting the workflow administrative credentials.

An administrator must establish these prerequisites before qualification;
automation does not modify repository settings. A token may lack
administrative read permission, so PR creation permission is ultimately
enforced by GitHub's publication request, not promised by a local preflight.

## Trivial-change exception

Within the product tree or the grader closure, a genuine typo, broken link,
format-only change, tiny wording correction, or mechanical maintenance with
**no behavioral or project-state consequence** may skip the landed-item
requirement. Judge semantics, not line count. When uncertain, create the item.
This exception does not waive applicable checks. Outside those two classes the
[process escape hatch](#pull-request-scope) applies mechanically and no
judgement call is needed.

## Continuous integration

General CI lives in `.github/workflows/ci.yml`. Pushes to `main` and `develop`,
and pull requests targeting any branch, run it; a newer run cancels the
superseded one for the same ref. The workflow's aggregate `CI` job fails unless
every gate job succeeded. Retirement publication additionally requires the
`Canonical work-item store` check with strict/current-base enforcement and
PR-required rules without an automation bypass; `CI` alone does not establish
that freshness boundary.

Host checks, Kani, and the aggregates run on `ubuntu-latest`; the seL4 image,
root tests, rollback runtime, contract sources, and the four generation shards
run on `ubuntu-24.04-arm`, which is the product's native architecture and free
for public repositories. seL4 jobs enter the repository's pinned Nix dev shell
through the local `.github/actions/slime-env` composite action, which restores
the Nix store, `~/.rustup`, `~/.cargo`, and the persistent Cargo build outputs,
then fetches both pinned toolchains' locked dependencies before the deliberately
offline product build. Jobs that need neither the seL4 prefix nor Nix use a
plain pinned toolchain and `Swatinem/rust-cache`.

Work-item CI uses `nix develop .#projection`, including its trusted retirement
verifier. It shares the architecture-qualified `projection-v2-*` Nix cache with
closeout and retirement; all three keys include the flake and local
devloop/Zutai derivations. Main push CI can populate the shared tool cache even
when another consumer's trigger only permits restores. Legacy `myque-*` entries
are not deleted by the workflows: retirement requires a measured replacement,
successful restore and separate operator authorization. Each consumer roots the
projection environment with a profile under `RUNNER_TEMP` before running its
commands and retains that profile through the cache action's post-job GC/save.
The v2 namespace excludes earlier archives whose unrooted tools could be
collected before saving; it intentionally has no fallback to that namespace.
A rooted closure can exceed the GC size target, so archive size still needs
measurement. A shared key alone does
not establish cold/warm qualification or byte savings.

Every submodule resolves from GitHub over anonymous HTTPS: `deps/zutai`, the
seL4 fork, and the three rust-sel4 checkouts, whose exact origins are pinned in
`sel4/pins.toml` and enforced by `sel4_pin_check`. QEMU runs without
hardware-device access.

SDK publication (`publish-sdk.yml`, on the dedicated signing runner) stays
separate from ordinary CI: it relies on GitHub-specific permissions, events,
and secrets. SDK publication and signing keys retain their separate owners.
The `.#projection` shell keeps its name for the cache key; it no longer
projects anything.

## Further reading

- [README](README.md): what Slime OS is.
- [Getting started](docs/getting-started/01-orientation.md): how to learn,
  build, run, and change it.
- [AGENTS.md](AGENTS.md): routing, invariants, schemas, gates, MyQue, and change-record rules.
- [Architecture](docs/architecture/README.md) and [plans](docs/plans/README.md): current subsystem rationale versus unimplemented requirements; [roadmap classification](roadmap/README.md) names unextracted detail and historical sources.
- [History](docs/history.md): immutable archive lookup, privacy, evidence boundaries, and restoration.

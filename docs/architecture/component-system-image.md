# Component, system, and image boundaries

Slime OS separates five identities that chronological delivery documents often
collapsed. Each owns a different question.

## Component specification

`contracts/component-spec/v1/` describes a component independent of any one
composition: implementation provider, declared interfaces and QoS,
configuration, lifecycle vocabulary, resource requirements, health, compatibility,
and the gate that observes it. It is host-side normalized data, not a boot wire
format.

A spec cannot grant authority to another component because it cannot know which
other instances a system will compose.

## System specification

`contracts/system-spec/v1/` describes one composition: selected component specs,
instances, authority edges, notification bindings, slot pins, state bindings,
fabric graph, resource objects, boot profile, and target requirement. System
grants are the irreducible authority facts.

`scripts/generate/generate-generation-from-spec.py` derives the generation
manifest from this record and the referenced component specs. Selected compositions
are authored as pure computed `.zt` sources, with byte-stable committed `.zti`
outputs; [system-spec authoring ownership](../../contracts/system-spec/README.md)
names the mapping, typed helpers, import/effect boundary and regeneration command.
Unmapped `.zti` remain inert hand-authored sources. A slot pin is an exception
with a declared reason; the default is deterministic assignment.

## Generation and component image

The generated manifest under `contracts/generation-manifest/v1/` is encoded into
the versioned generation wire format. `boot-contracts/src/generation.rs` decodes
it and `slime-root/src/generation.rs` admits it before constructing the graph.
The generation binds executable object digests, target identity, authority,
resource budgets, state policy, and boot profile.

Executable payloads use the component image contract under
`contracts/component/v2/`, decoded by
`boot-contracts/src/component_image.rs` and mapped by
`slime-root/src/child_vspace.rs`. Integrity comes from the generation object
digest and authority from generation grants; an executable image carries
neither independently.

Retained old executable revisions remain classified so old artifacts are not
misread. Superseded generation wire formats are rollback-safe by refusal, not by
runtime migration.

### Embedded image capacity

The component contract bounds an ELF at 128 MiB; generation v5 bounds an object
payload (including its component wrapper) at 128 MiB and the complete generation
at 256 MiB. These are independent checks. Only `aarch64-sel4-qemu-virt` admits
32,768 pages per image and 65,536 aggregate declared image pages. Every other
profile retains 512 pages per image. Footprints include gaps between LOAD
segments and the main thread's two runtime pages; additional threads add their
own IPC/window pairs to the instance frame quota.

The root reads authenticated ELF bytes without whole-image staging and allocates
child-owned frames through its scratch-page mapping. Descriptor provisioning is
aggregate-bounded rather than per-image maximum times task count. The
[decision record](../decisions/large-image-bounds.md) explains the unchanged wire
versions and qualification limits. This does not widen the boot selector's
separate 4 MiB boot-store limit or establish application-runtime compatibility.

### Embedded generation outputs

[`build-sel4.py`](../../scripts/build/build-sel4.py) writes embedded generations beneath an
`embedded/` child of the selected generation output directory.
The default QEMU output is `build/sel4-generation/embedded/generation.bin`.
Other platforms retain their platform directory, and custom output names retain their selected parent.
The root build consumes the returned generation path.

The wrapper preserves existing files in the parent, including a selector `boot-store.bin` from an earlier build.
It never removes that store to make an embedded build succeed.
[`build-generation.py`](../../scripts/build/build-generation.py) still refuses embedded output into a directory containing `boot-store.bin`.
A supplied prebuilt generation bypasses output creation and remains unchanged.

### Delivery ELF metadata

The generation builder validates each native ELF before making a stripped delivery
copy with `llvm-strip` from the explicitly selected Rust toolchain. Workspace build
artifacts and externally supplied files remain unchanged. An external component's
declared content hash authenticates the original input; the generation's executable
object digest authenticates the wrapped delivery bytes.

The symbol table is not entirely optional: `ChildImage::worker()` resolves
`__slime_rt_worker_entrypoint` and `__slime_rt_worker_stack` from it. Delivery
stripping retains these two symbols and their values/sizes for two-thread images.

The delivery check preserves entry points, LOAD offsets, virtual addresses, sizes,
permissions, zero-fill extents and segment contents. Section-table header metadata
may change. Nonloaded metadata such as RISC-V attributes may move in the file, but
its attributes and bytes must remain identical. The stripped image is admitted
again before wrapping; stripping cannot make a previously refused input acceptable.

The root builder likewise embeds `slime-root-child.delivery.elf` beside the
symbol-bearing `slime-root-child.elf` in the child Cargo output directory. It keeps
the child fixture and all its boot/fault checks. Never apply this stripping step
blindly to the final loader ELF: the packaged image contains sectionless payloads.

The root-only `root-image` Cargo profile is separate from the component and host
release profiles. Its build disables target-default unwind tables because the
pinned root uses `panic=abort`; resource rollback and fault supervision remain
active and are not Rust stack unwinding. Original root symbols remain available
in the `root-image/slime-root.elf` Cargo output and copied root artifact.

File-size reductions are not automatically RAM or CSlot reductions. Loaded memory
includes zero-fill, page alignment and reserved stacks; moving data to BSS alone
does not eliminate that footprint.

## System-image closure

A closure source in `contracts/system-image-closure/v3/closures/` names every
input to a reproducible bootable-image build: system spec, selected
implementations, target and platform prefix, root and loader roles, release
inputs, build parameters, and expected outputs. A source records paths only. It
records no digest, so an edit to an input changes no committed closure.

The resolver turns a source into a version 2 `SystemImageClosure` in the
checkout. It hashes each tree from the files git lists, tracked and untracked
but not ignored, through every submodule. Outside git, as in an exported SDK, it
walks the tree. It adds each component spec's and the system spec's compiled
identity. The resolved closure's identity is the build's derivation id.
`generate-system-image-closures.py --resolve NAME --output PATH --report REPORT`
writes that closure and a `contracts/closure-resolution/v1` report naming the
derivation id and whether an input was dirty.

An input is dirty when it holds a modified tracked file or an untracked or
ignored file, or when a submodule is checked out away from its pin. A dirty
resolution still builds, and its build result records `dirty = true`. No
evidence may name a dirty build.

The release inputs bind the generation builder, image builder and ELF delivery
helper, so a packaging change cannot reuse an old closure-cache image. They no
longer include the `just/` tree or `Justfile`, so a recipe change leaves every
derivation id unchanged.

An executable-changing scenario is part of the selected implementation or root
role. A deliberately invalid build is a separate `NegativeBuildCase`, never a
valid image closure. The generic resolver verifies declared inputs before build
and emits a version 2 `SystemImageBuildResult`, in `build-result.json` and
`build-result.zti`, binding the generation, root, loader, packaged image,
identity manifest and dirty flag to the derivation id.

### Image attestations

An image attestation records what clean builds of named closures produced at one commit.
`scripts/build/attest-system-images.py` writes it as the git note on that commit under
`refs/notes/image-attestations`, in the `contracts/image-attestation/v1` format. The record holds the
commit, the host class, the runner image, and per closure its derivation id and the SHA-256 of
`generation.bin`, `root.elf`, `loader.elf`, `image.elf` and `image.identity.json`.

The host class is the default devShell's Nix derivation path and `uname -m`. Within one host class, an
equal derivation id must give equal digests at every commit. The writer builds each closure first, then
compares the result with every earlier note. On a mismatch it refuses and writes no note. It refuses a
dirty input before it builds anything, and it never replaces a note.

`.github/workflows/image-attestations.yml` runs the writer nightly and on demand on `main`, one run at a
time, for six closures. After a rejected push the writer fetches the notes, compares again, and retries.
`attest-system-images.py --check --notes-ref REF` decodes every note and refuses a malformed note or a
conflicting pair. Nothing in PR CI reads attestations. An attestation proves bytes across commits within
one host class, not a boot.

The component SDK publishes its closure resolved: the export resolves the
source in the staged corpus and writes the version 2 closure under
`contracts/system-image-closure/v2/closures/`, which an SDK consumer builds
without git.
The component SDK is a generated, one-way release mirror. Authoritative source,
contracts, target definitions, and fixes remain in this product repository.

## System test run

`contracts/system-test-run/v2/` is deliberately separate. It declares the
execution profile, disks, networks, devices, runtime fault controls, timeout,
marker contract, and forbidden outcomes for one image closure. Changing an
oracle or timeout must not change executable identity.

A record names its closure in `imageClosure`, by the closure's file name. It
does not copy the closure's identity, so a change to a closure input leaves
every record unchanged. A negative build case names its base closure the same
way, in `baseClosure`. `check-system-test-run.py` requires a named closure to
exist, to compile, and to be the closure the run's plane gate builds.

The committed records are frozen checker declarations, not independent execution
requests. `compile_test_run_declaration` accepts paired empty fixture path/identity
or fault target/value fields as unbound declarations. Empty image identity is
allowed only where the owning gate confirms an explicit closure exemption.
`compile_test_run` remains the strict boundary used by SDK consumers: it refuses
all such placeholders. A populated digest is a declaration of expected content,
not proof that a fixture exists or matches it; the executing checker owns that
verification. No declaration alone proves that a test ran.

Run inventory distinguishes explicitly planned invocations from runnable ones.
`PLANNED_RUNS` in `scripts/generate/generate-system-test-runs.py` binds each
planning-only run to a nonterminal canonical work-item UUID, its checker and
closure, and implementation artifact paths. This is a per-run exception, not a
missing-file fallback: an active arm in the same checker remains inventoried.
A missing active closure still fails. Once any registered artifact exists, remove
the planning registration and land the complete closure and run declaration;
leaving the exception in place is refused. Item state alone never skips a run.

Reclamation execution facts are extracted per invocation: unwind retains its
180-second timeout, while large-image uses its own 1800-second timeout and failure
markers. Changing one arm must not silently alter the other's frozen declaration.
`just system_test_run_inventory_check` exercises planning transitions and arm
isolation before running the complete declaration gate. These are host checks,
not evidence that a planned image has booted.

The network checker boots 15 closures. Fourteen have a record. The fifteenth,
`sel4-io-tcp-buffers`, is in `PLANNED_RUNS` until its composition lands. Its arms
share one timeout and one set of failure markers, but they attach different devices.
Ten attach a virtio NIC and five attach nothing. Four tables in the generator state this.
`ARM_ENTRY_FUNCTIONS` names the functions that boot each arm. `QEMU_SITES` names the
functions that pass QEMU arguments and the devices each passes. `ARM_DEVICES` names
the devices each arm attaches. `ARM_CHOICES` gives the `--arm` choice of each arm. A
person edits the tables, and `extract` does not infer a device from the code.

Extraction checks that the code agrees with the tables. A QEMU token may sit only in
a site. A token in a module-level statement, in a function that is not a site, or in
a definition nested in a site is refused. Every `run_plane` call in a site gives
`additional_arguments` as a tuple or list literal of flag and value pairs. Every
launch path of the site must attach the same devices. Extraction reads each literal
element by element and counts a repeated device as many times as it appears. A flag
must be a literal from `-netdev`, `-device` and `-object`. A `-device` value must be a
literal that starts with a `virtio-` device name. A computed flag, a variable value, a
starred element and an odd count are refused. So is the keyword on any other call.

An arm attaches the devices of every site that it reaches by any name. The reach
starts at the arm's entry functions and at the branches of `main()` for its `--arm`
choice. Each entry function must be read by that branch, so a branch cannot call another
function in its place. A branch that is not exact, every `else`, and the statements outside the
branches count for every arm. The arm's declaration must equal the devices of the
sites it reaches. Every use of `arguments.arm` must be a comparison with string
literals in the test of an `if`, so no branch hides behind a constant. Each arm must
build exactly its own closure in what it reaches, so two call sites that swap their
closures are refused. No function that an arm reaches may be rebound. An assignment,
a parameter, a `global` declaration, a loop variable, a second definition, an import
and a decorator are each refused. A string equal to a function name is refused, and
so are `globals`, `getattr`, `eval` and similar names. The constants and imported
modules that supply a closure to `build_image` are bound once at the top level.
A local of the same name is refused. A protected function is reached only by its
plain name, so an attribute call or a callee that is not a name is refused. The
launcher `run_plane` is imported once from `sel4_plane` by name, without an alias.
A call through another name or an import from another module is refused. A QEMU argument that reaches the launcher by a route other
than `run_plane` is not covered.

An image-closure change needs no test-run change. After an intended change to a
plane gate's execution inputs, review it and re-freeze the records with
`just system_test_run_bless`, then run `just system_test_run_check` and
`just system_image_closure_check`. The fixed private-memory records do not inherit
the adaptive-only transport from the same checker module.

A build closure proves reproducibility of bytes. An observed test execution
proves behavior within its tested scope. Neither substitutes for the other, and
a QEMU run cannot establish a physical-board observation.

## Qualification limits

- **Target qualification:** A published `bcm2712-rpi5` platform prefix qualifies
  external component build and admission against that platform input only; it
  does not claim Raspberry Pi 5 boot support, which only a physical-board gate
  qualifies.
- **Host-side scope:** System-image closure, scenario, builder, and SDK-consumer
  machinery is host-side; it does not implement in-system compilation, executable
  admission, or live update, and does not widen physical-board qualification.
- **Hosted publication:** The controlled-remote publication gate proves publisher
  behavior—publication, refusal, regeneration, build/boot of the published SDK,
  and atomic cleanup leaving no branch commit when the remote refuses the tag—not
  the hosted repository's current branch/tag protection, credential scope, or
  deployed state. Actual release qualification must check the hosted repository.
- **Upgrade coverage:** Retained-generation admissibility and console fixtures in
  the upgrade/rollback check are not an observed QEMU health-confirmation failure;
  that failure path is unexercised.
- **Reviewed non-closure exceptions:** The exceptions retain `--component-graph`
  for mixed-source SDK admission/upgrade generations; `--demo-plane`,
  `--generation-plane`, and `--rollback-plane` for non-closure arms;
  `--sample-plane` for Milk-V Duo; `--boot-selection`; and `--skip-pin-check`:
  `check-sel4-boot-selection.py` needs per-arm `boot_bundle_identity` test-run data;
  `check-sel4-root-boot.py` has no plane-specific closure;
  `check-sel4-demo-plane.py` has a closure-less boot-selection arm and a
  wrong-target arm requiring scrubbed input; and `check-sel4-generation-plane.py`
  and `check-sel4-rollback-plane.py` have RV64 arms outside their QEMU-AArch64
  (`qemu-arm-virt`) closures. These are reviewed exceptions, not unfinished
  ordinary-plane migration: legacy-only `SLIME_*` controls remain confined to the
  aggregate reachability inventory, whose reachability rule is the source guard,
  with no independent hard-coded-path or flag guard claimed; remove entries when
  their paths migrate.

## Build and admission flow

```text
component specs + system spec
    -> derived generation manifest
    -> versioned generation bytes
    -> system-image closure resolves exact build inputs
    -> root/components/loader/image plus build-result identities
    -> system-test-run supplies execution-only inputs and oracle
    -> root admits the embedded generation and launches the declared graph
```

## Verification

- `just component_spec_check`
- `just system_spec_check`
- `just generation_check`
- `just system_image_closure_check`
- `just system_image_builder_check`
- `just system_image_closure_aggregate_check`
- `just system_test_run_check`
- `just sel4_boot_layout_check` for frozen capability layouts

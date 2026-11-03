# Task-to-file index

Where a change starts, and which files follow. This is the routing table
`AGENTS.md` points at: find your change's row, read the named module root
first, then use LSP symbols or references from there, and only then grep the
exact symbol. Do not scan `deps/`, `target/`, `roadmap/`, or `.tasks/` for
implementation symbols unless the task specifically concerns them.

The [recipes](getting-started/11-recipes.md) page turns the most common rows
into step-by-step checklists; the [glossary](glossary.md) explains the terms.
Keep this table in the same commit as any move of an owning module.

| Change | Canonical starting point | Follow-on files |
| --- | --- | --- |
| Capability kinds, rights, derivation, transfer | `slime-root/src/generation.rs` | `slime-root/src/{graph,ipc}.rs`; grants are declared in the system spec below |
| Native endpoint IPC, message bounds, endpoint lifetime | `slime-root/src/peer_endpoint.rs` | `slime-root/src/{ipc,notification}.rs`, `components/runtime/src/syscall/sel4_transport.rs` |
| Tasks, spawn, supervision, termination, reclamation | `slime-root/src/task.rs` | `slime-root/src/{main,child_vspace,fault,supervision}.rs` |
| Syscall argument validation and rights gates | `slime-root/src/ipc.rs` | owner modules in `slime-root/src/`, wrappers in `components/runtime/src/syscall.rs` |
| seL4 object allocation and VSpace construction | `slime-root/src/object_allocator.rs` | `slime-root/src/{child_vspace,buffer_adapter}.rs` |
| Shared-buffer allocation, mapping, loan, accounting | `slime-root/src/shared_buffer.rs` | `slime-root/src/{buffer_adapter,transfer_window,ipc}.rs` |
| Boot graph and component launch grants | `slime-root/src/main.rs` | generation decoding in `slime-root/src/generation.rs`, system specs below |
| Generation decoding and identity | `boot-contracts/src/generation.rs` | admission in `slime-root/src/generation.rs` |
| Composition: which components run, grants, slots, budgets, health | `contracts/system-spec/v1/sources/<name>.zt` for `COMPUTED_SYSTEM_SOURCES`, otherwise `contracts/system-spec/v1/systems/<name>.zti` | authoring ownership: `contracts/system-spec/README.md`; derivation map `DERIVED_GENERATION_FIXTURES` in `scripts/lib/system_spec.py`; regenerate with `python3 scripts/generate/generate-generation-from-spec.py`; `just system_spec_check` refuses drift. `contracts/generation-manifest/v1/{compositions,fixtures}/*.zti` are derived outputs |
| Generation construction and manifest encoding | `scripts/build/build-generation.py` | `contracts/generation-manifest/v1/schema.zt`, `components/build-support/src/lib.rs` |
| System-image closure: the build key every `sel4_*` gate resolves before booting | `scripts/generate/generate-system-image-closures.py` | `contracts/system-image-closure/v3/closures/*.zti` are derived sources that name each input by path and record no digest; `contracts/system-image-closure/v2/negative/*.zti` are derived negative cases. Rerun the generator only when a closure's input set changes. Each gate resolves its source in the checkout into `build/closure-resolved/<name>.zti`, whose identity is the derivation id, and records `dirty` in its build result. Resolver: `scripts/lib/system_image_closure.py`; drift gate: `just system_image_builder_check`; exam: `just closure_derivation_check` |
| Image attestations: what clean builds produced at a commit, as git notes | `contracts/image-attestation/v1/schema.zt` | writer `scripts/build/attest-system-images.py`, nightly workflow `.github/workflows/image-attestations.yml`, notes ref `refs/notes/image-attestations`; exam: `just image_attestation_check` |
| Component image format/loading | `contracts/component/v2/schema.zt` | generated `components/proto/src/component.rs`, decoder `boot-contracts/src/component_image.rs`, loader `slime-root/src/child_vspace.rs`; v1 is retained format history |
| Userspace component behavior | `components/<lifecycle>/<component>/src/main.rs` | shared helpers in `components/lib/src/*.rs`; the crate's own `components/<lifecycle>/<component>/Cargo.toml` |
| Userspace syscall ABI | `components/runtime/src/syscall.rs` | seL4 transport in `components/runtime/src/syscall/sel4_transport.rs`, root implementation in `slime-root/src/ipc.rs` |
| IPC/service protocol semantics | `contracts/<protocol>/v1/schema.zt` | generated Rust in `components/proto/src/<protocol>.rs`; validators in `components/proto/src/lib.rs` |
| Boot/persistence contract decoder | `boot-contracts/src/<contract>.rs` | generated constants/layouts in `boot-contracts/src/generated/` |
| Fabric schemas, graph authority, stream framing | `contracts/interface-schema/v1/`, `contracts/fabric-graph/v1/`, `contracts/fabric-stream/v1/` | `boot-contracts/src/fabric_graph.rs`, `components/services/fabric-service/src/main.rs` |
| Block/storage transport and services | `components/services/virtio-blk-driver/src/main.rs` | ring adapter `components/lib/src/block_io.rs`, per-ring rights `contracts/block-authority/v1/schema.zt` and `boot-contracts/src/block_authority.rs`, raw device authority `slime-root/src/{device,io_resource}.rs`; qualification probes in `components/testkit/`. The boot selector's pre-admission reader is `slime-root/src/boot_selector_block.rs`, compiled only into `slime_boot_selector` images |
| Generation management, rollback, recovery | `components/services/sel4-generation-manager/src/main.rs` | matching rollback/recovery/transfer probes in `components/testkit/`, all reaching storage over the userspace driver's IO0 rings |
| Architecture, traps, interrupts, platform boot | `sel4/config/qemu-arm-virt.cmake` | `slime-root/src/{fault,platform_timer}.rs`, `scripts/build/build-sel4.py` |
| Host build/check orchestration | `Justfile` target | implementation in `scripts/{build,check,generate,lib}/` |
| Work-item store policy, spec-driven bodies, terminal records, `codePaths` coverage | `scripts/check/check-work-items.py` | shared reader `scripts/lib/work_items.py`, toolchain/consumer helpers `scripts/lib/devloop.py`, operator entrypoint `scripts/lib/devloop_cli.py`, gate adapter `scripts/check/devloop-gate.py`, checker-side observations `scripts/lib/devloop_observations.py`, approval `scripts/check/devloop-approval.py`, policy [`.devloop/policy.json`](../.devloop/policy.json), pins in `flake.nix` and `nix/devloop.nix` |
| Zenoh Profile 0 wire, session or transport runtime | `components/lib/src/zenoh_profile0.rs` | encoder and session in `components/lib/src/zenoh_profile0/`, runtime `components/lib/src/zenoh_link.rs`, CDR `components/lib/src/ros_cdr.rs`, vocabulary `contracts/zenoh-profile/v1/schema.zt` (regenerate with `just zenoh_profile_gen`), stock-peer fixtures `contracts/zenoh-stock-fixtures/v1/` (regenerate with `just zenoh_stock_gen`), undeclare fixtures `contracts/zenoh-stock-undeclare/v1/` (regenerate with `just zenoh_undeclare_gen`), judge `scripts/check/check-zenoh-profile0.py` and `scripts/lib/zenoh_wire.py`; see [`architecture/zenoh-transport.md`](architecture/zenoh-transport.md) |
| Recorded ROS 2 messages: the frame store, its reader or its MCAP converter | `contracts/frame-store/v1/schema.zt` | renderer `contracts/frame-store/v1/gen_rust.zt` (regenerate with `just frame_store_gen`), reader `components/lib/src/frame_store.rs` and its fixture, converter `tools/frame-store/` (`just frame_store_tools_check`), judge `scripts/check/check-frame-store.py` and `scripts/lib/frame_store_exam.py` (`just frame_store_check`, needs `SLIME_LIDAR_BAG`); see [`contracts/frame-store/v1/README.md`](../contracts/frame-store/v1/README.md) |
| A hash-pinned payload on a disk a run attaches: the data volume, its builder or its reader | `contracts/data-volume/v1/schema.zt` | renderer `contracts/data-volume/v1/gen.zt` (`generate-bindings.py data-volume`), builder `scripts/build/build-data-volume.py`, reader `components/lib/src/data_volume.rs` with `frame_store::validate_streaming`, probe `components/testkit/data-volume-probe`, composition `sel4-data-volume`; gate `just data_volume_check` |
| The LiDAR publisher and the `sel4-lidar-external` composition | `contracts/system-spec/v1/systems/sel4-lidar-external.zti` | component `components/applications/lidar-publisher`, frame reads `data_volume::open_store`, link configuration `zenoh_profile0::limits::LIDAR`, arrival ceiling `contracts/graph-arrival-ceiling/v1`, derived manifest `contracts/generation-manifest/v1/compositions/sel4-lidar-external.zti` (never hand-edited), exam `scripts/lib/lidar_publish_exam.py`; gate `just lidar_publish_check` (needs `SLIME_LIDAR_BAG`) |
| Demo nodes and the `sel4-zenoh` composition | `contracts/system-spec/v1/systems/sel4-zenoh.zti` | nodes `components/applications/ros2-demo-{publisher,subscriber}`, component specs under `contracts/component-spec/v1/components/`, derived manifest `contracts/generation-manifest/v1/compositions/sel4-zenoh.zti` (never hand-edited), authority judge `scripts/lib/zenoh_exchange.py`, QEMU arm `check-sel4-io-network-plane.py --arm zenoh` |
| Writing a component against the runtime API | [`docs/getting-started/10-component-runtime.md`](getting-started/10-component-runtime.md) | `components/runtime/src/syscall.rs`, `docs/syscall-abi.md` |
| Adding or extending a QEMU plane gate | [`docs/getting-started/07-add-a-gate.md`](getting-started/07-add-a-gate.md) | `scripts/lib/{sel4_plane,sel4_gate_markers,closure_image}.py`, `scripts/check/check-sel4-gate-controls.py` |
| Reading a failed gate or transcript | [`docs/getting-started/08-debugging.md`](getting-started/08-debugging.md) | the owning `scripts/check/check-sel4-*-plane.py` |
| Reviewing an implementation against its spec | [`.agents/skills/spec-review/SKILL.md`](../.agents/skills/spec-review/SKILL.md) | the item's rendered body, the checker its inputs name, `docs/capability-matrix.md` |
| Root behavioral regression | `slime-root/src/<module>.rs` tests | run `just test_sel4_root` and the matching `just sel4_*_check` |
| Protocol validation regression | `components/proto/tests/<protocol>.rs` | generated protocol module and schema |
| Adding a component | new `components/{system,services,applications,testkit}/<name>/` crate | the matching `Cargo.toml` workspace member glob plus its `[profile.release.package]` stanza, a `contracts/component-spec/v1/components/` record, and a `contracts/system-spec/v1/systems/` entry with its regenerated manifest; `just component_crate_split_check` gates the shape. [`docs/getting-started/05-add-a-component.md`](getting-started/05-add-a-component.md) walks it end to end |

## Where policy and mechanism live

- Mechanism (allocation, IPC, supervision, admission) is `slime-root`; component
  policy (who spawns what, with which grants) is userspace and the system spec.
- Generated files — anything beginning `@generated`, `boot-contracts/src/generated/`,
  every derived manifest in `DERIVED_GENERATION_FIXTURES`, the computed system
  specs in `COMPUTED_SYSTEM_SOURCES`, every closure source under
  `contracts/system-image-closure/v3/closures/`, and every negative case under
  `contracts/system-image-closure/v2/negative/` — are outputs. Edit the schema or
  authoring source and regenerate; `AGENTS.md` states the rule and the
  regeneration commands.
- `scripts/check/` is verification code, never the implementation of the
  behavior it checks; the shared plane mechanism is `scripts/lib/`.

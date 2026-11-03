# Userspace I/O substrate

## Boundary

Device semantics live in supervised userspace drivers and services. `slime-root`
creates and accounts explicit device, MMIO, interrupt, DMA, shared-buffer, and
supervision authority; it does not parse block, Ethernet, USB, audio, display, or
GPU commands on the product path.

The substrate shares asynchronous lifetime and accounting mechanisms, not one
universal device protocol. Each device class keeps its own Zutai request and
completion schema.

Current owners:

- generic queue/epoch/lease format: `contracts/io-queue/v1/`;
- hardware authority and budgets: `contracts/io-resource/v1/`,
  `contracts/block-authority/v1/`, `boot-contracts/src/io_resource.rs`, and
  `slime-root/src/{device,io_resource}.rs`;
- shared ring adapters: `components/lib/src/`;
- virtio-blk, virtio-net and virtio-rng drivers:
  `components/services/virtio-*-driver/`;
- exact network destinations: `contracts/network-destination/v1/`;
- declared network interface/MAC/address: `contracts/network-interface/v1/`;
- declared entropy holders: `contracts/entropy-authority/v1/`;
- service protocols: `contracts/block/v2/`, `contracts/link-device/v1/`,
  `contracts/network-service/v1/`, `contracts/entropy-source/v1/`, and
  `contracts/entropy-service/v1/`.

## Queue, request, and lease semantics

A queue has one client-written cache line and one driver-written cache line,
fixed power-of-two submission and completion rings, an absolute sequence space,
and one driver epoch. A request identity is unique only inside that epoch. Reset,
restart, disconnect, or generation transition advances the epoch so a late
completion from an old driver is rejected.

Requests move through `Queued -> InFlight -> Complete | Cancelled | Reset |
PeerDead`. Terminal state is single-assignment and every terminal answer settles
the request's buffer lease exactly once. Notification badges indicate which ring
must be drained; they do not count events.

A buffer-slice descriptor names shared-buffer identity, lease, offset, length,
and direction. It contains no physical address or IOVA. CPU access through a
`SharedBuffer` and device access through a DMA mapping are independent
authorities. Ordinary service clients never receive raw DMA or MMIO authority.

## Hardware authority and drivers

A driver receives only generation-declared resource capabilities: one device,
exact MMIO subranges, declared interrupt sources, a bounded DMA account, queue
bindings, and supervision. Bounds cover mapping bytes/counts, DMA pages/counts,
interrupt sources, outstanding requests, and buffer loans. Task death and
restart revoke the old resources and charges.

Direct MMIO mapping requires page exclusivity. QEMU's eight 0x200-byte virtio
transports share one 4 KiB granule, so these drivers use bounded mediated
`read32`/`write32`, not direct mapping or page-wide authority. `IRQ_ACK`
(operation 62) acknowledges a pending declared sequence; it does not wait for
hardware arrival. IO1 checks spoofed/stale authority refusal and opaque DMA
mapping identity rather than exposing the device physical address as a token.
Its fault/restart gate covers live MMIO, IRQ and driver-owned queue DMA
reclamation, charge return and predecessor-epoch refusal. Live-loan payload DMA
and contiguous driver-owned queue DMA both count against the driver budget.

For IO3, IRQ authority is granted and reclaimed, but the device completes before
the line is dispatched: the driver drains the used ring and the gate establishes
no actual interrupt-sequence arrival. It exercises duplex traffic, backpressure,
paused RX replenishment, coalesced-wake draining, malformed-frame/slice refusal
before programming, reset settlement, zero-charge restart and stale TX/RX
completion rejection. Legitimate traffic must not stall or trigger device-input
refusal; adversarial-device behavior is a separate source-proof scope below.

The product's block and link paths are userspace drivers. `virtio-blk-driver`
serves typed block requests over IO0 rings. `virtio-net-driver` exposes one
bounded `LinkDevice` with duplex queueing and replenished receive buffers. The
boot selector retains a narrow pre-admission block reader compiled only into
selector images; it is not a root product driver.

All nine block compositions (`sel4-storage`, `sel4-store`, `sel4-rollback`,
`sel4-replay`, `sel4-generation`, `sel4-filesystem`, `sel4-recovery`,
`sel4-transfer`, and `sel4-data-volume`) use `components/lib/src/block_io.rs` and
userspace-driver rings.
Their gates require driver authority, bring-up/release and root DMA reclamation,
not a root block service. The selector reader is `boot_selector_block.rs` under
`#[cfg(slime_boot_selector)]`; the root product has no block command/descriptor
implementation or block-transaction runtime wrapper.

Shared submissions alone authenticate no rights. `contracts/block-authority/v1`
binds one holder and device to one ring, independent read/write bits and a sector
ceiling. Strict `(device, ring)` ordering excludes two holders on one ring;
wildcard holders, device ranges and “all rights” are unrepresentable. The driver
reads its table through the root's identity-gated cursor-paged path (label 69).
The root authenticates the reader and bounds bytes; it interprets no block rights.
IO1's budget supplies a per-instance device ordinal throughout device identity.
`sel4-recovery` declares a writable recovery disk and byte-identity-checked
read-only guard disk; `sel4-transfer` declares a source and receiver. Each has two
driver instances; read-only refusal belongs to driver ring authority.
`virtio-blk-driver` reports the rights its own ring holds and each request it
refuses for them, so a gate observes the refusal from the component that
enforces it rather than from the refused client.

### Data volumes

A data volume carries one hash-pinned payload on a disk a run attaches read-only
(`contracts/data-volume/v1`). The payload is a run input, not an image input: no
system-image closure names the disk, so a new recording changes no derivation id.
`scripts/build/build-data-volume.py` writes the one GPT disk image of a frame
store; its GUIDs derive from the payload's SHA-256.

`components/lib/src/data_volume.rs` validates the disk through a block ring in the
contract's order: GPT, partition, volume header, length, padding and payload hash.
It then validates the payload with `frame_store::validate_streaming`, which applies
`FrameStore::parse`'s checks in the same order to a store read where it lies. The
reader holds one sector and one 4 KiB chunk, never the payload. `data_volume::open_store`
validates the same way and keeps the store open: `StoreReader::frame` reads a frame's
index entry again under the checks it passed, and `StoreReader::read` copies a range
of that frame's payload into storage the caller owns. `data-volume-probe`
in `sel4-data-volume` runs it over a ring with read rights only and links no
allocator.

A finite plane's root stops serving after 131072 requests unless the generation
declares a larger [graph arrival ceiling](runtime-authority.md#graph-arrival-ceiling).
One 4 KiB read costs about six, so one boot at the default reads at most about
80 MiB.

A dynamically spawned client receives exactly its generation-declared crossing
grant vector, supplied by init to `drive_probe_plane_with_token`.
`grant_crosses_spawn` and `declared_crossing_grants` in
`slime-root/src/generation.rs` share the dispatcher/host-check rule. Counts come
from declarations, leaving no slot for an undeclared grant.

QEMU uses trusted DMA and makes no containment claim. Physical containment is a
target-specific IOMMU/SMMU qualification and cannot be inherited from an emulator
or another board.

## Network boundary

The network service (exact per-holder destination authority, `LinkDevice`
attachment, smoltcp external and loopback backends, bounded TCP streams, and
the bounded HTTP/DNS client) has its own page:
[network service](network-service.md). It shares this substrate's queue,
epoch, lease, and reset semantics and adds nothing to the hardware authority
model above.

## Entropy boundary

`virtio-rng-driver` holds io-resource authority for one virtio-rng transport
and answers exactly one declared consumer, `entropy-service`, over
`entropy-source/v1`. Without the device every fill is answered `unavailable`;
the driver never substitutes bytes. `entropy-service` reads the generation's
`entropy-authority/v1` rows through `CAPABILITY ENTROPY AUTHORITY READ`, which
the root answers only for the instance named `entropy-service`, and serves each
row's holder over its own non-transferable `<holder>-entropy` endpoint with
`entropy-service/v1`. Every holder draws from its own HMAC-DRBG; raw device
bytes never leave the service. The decision and its alternatives are in
[entropy authority](../decisions/entropy-authority.md); `just sel4_entropy_check`
is the owning gate.

## Verification

- `just io_queue_check` — queue, epoch, cancellation, and lease behavior;
- `just io_driver_authority_check` — exact hardware authority and reclamation;
- `just io_block_check` — userspace block driver behavior;
- `just io_link_check` — userspace virtio-net/LinkDevice behavior;
- model and Kani targets below — bounded interleavings and selected wire/device
  arithmetic, not whole-substrate correctness.

Physical checks remain owned by the consuming platform plan; no QEMU or model
result completes a device-specific hardware claim.

IO2's block gate establishes read/write/flush/geometry, same-boot readback and
byte-for-byte backing-image flush verification, rights and malformed-request
refusals, identity-safe completions and full-ring backpressure. It does not
establish fresh-boot durability, injected descriptor/timeout/cancellation/reset/
interrupt-loss or coalescing/crash/peer-death settlement, their numeric zero-leak
reclamation, supervised restart with a fresh epoch, or stale-completion injection.
Those remain required by [IO2 acceptance](../../roadmap/11-io-substrate.md#io2--userspace-virtio-blk-and-asynchronous-blockdevice-plane);
IO1 or IO3 evidence cannot silently qualify the missing block-driver paths.

### Bounded lifetime and accounting models (IO5)

The models quantify over all interleavings of their **bounded abstractions**;
QEMU gates observe concrete schedules. Neither substitutes for the other, and
there is no machine-checked refinement from these models to the Rust implementation.

- [`io-queue.zt`](../../contracts/io-queue/model/io-queue.zt) models one queue,
  client and driver, three request identities, two ring slots and two epochs.
  It covers submit/take/complete/cancel/drain, reset settlement, peer death and
  epoch advance. Its safety properties are `RingNeverOverwrites`,
  `SingleTerminalAssignment`, `LeaseReleasedAtMostOnce`, `LeaseHeldUntilTerminal`,
  `LeaseSettledOnDrain`, `NoLiveRequestAcrossEpoch` and `EpochStrictlyAdvances`.
  Reachability covers a full ring, cancellation/reset/peer-death settlement,
  a fresh epoch and full reclamation. `EveryLiveRequestSettlesAndReleases`
  requires every maximal path from a live request to reach quiescence without
  a held lease. Stale-completion refusal is not a separate model property;
  `NoLiveRequestAcrossEpoch` carries the honest-model epoch invariant.
- [`io-resource.zt`](../../contracts/io-resource/model/io-resource.zt) models
  one driver/device and two epochs, with one MMIO mapping, one DMA mapping over
  two pages, one IRQ source, one pending acknowledgement and one outstanding
  request. Its safety properties are `WithinDeclaredBudget`,
  `DeathReturnsEveryCharge`, `ReclaimRunsAtMostOnce`, `NoChargeAcrossEpoch`,
  `EpochStrictlyAdvances`, `StaleAckRefused` and `NoAuthorityWithoutDevice`.
  Reachability covers full charging, an in-flight request, a pending ACK,
  fault with charges, zero-charge reclamation and a fresh running epoch.
  DMA mapping accounting is **per region**, charged on its first mapped page
  and returned with its last, not one mapping charge per page.
  `FaultedDriverAlwaysReachesZeroCharges` starts from a faulted driver;
  unconditional eventual return while a driver keeps running is not claimed.
  The checker assumes no fairness: a running driver may map/release forever.

Both models define terminal states as having no successor; deadlock is therefore
unrepresentable by construction, not an independently established runtime property.
They exclude concrete wire layout/sequence encoding, slice overflow, MMIO
subrange arithmetic, page exclusivity versus mediated access and DMA token
opacity. Concrete validators, root host tests and plane gates own those checks;
the I/O Kani harnesses cover the selected wire arithmetic below, not root code.

Source routing: `just io_queue_model_check` and `just io_resource_model_check`.
Each model also owns its expected-counterexample scenarios.

### Bit-precise I/O source proofs (IO6)

[`io_queue_proofs.rs`](../../components/proto/src/io_queue_proofs.rs) specifies
symbolic **all-value** checks under its harness assumptions, not all schedules.
[`verification/io-proofs/Cargo.toml`](../../verification/io-proofs/Cargo.toml)
points directly at the shipped `components/proto/src/lib.rs`, not a code copy.
The harnesses cover:

- slot indexing over `u64` sequences and symbolic admissible power-of-two ring
  depths: bounds and modular reduction; slot distinctness assumes ordered
  sequences less than one depth apart, not a window spanning sequence wrap;
- accepted-header cursor subtraction and occupancy bounds, no excess
  completions, and a nonzero active-driver epoch (wire constants and reserved
  bytes are fixed valid; cursors, state and epoch are symbolic);
- exact mapping size and non-overlapping request/completion ring extents;
- exact agreement between valid completion statuses and terminal states;
- accepted slice bounds without addition overflow and empty/no-lease control
  slices (reserved bytes fixed zero), plus rejection of unknown directions
  with symbolic reserved bytes;
- `Outstanding<2>` single-assignment settlement, retained-lease return,
  duplicate/capacity refusal, no epoch advance while live, monotonic epoch
  adoption, all-or-nothing `settle_all`, repeated-start refusal and foreign-epoch
  lookup refusal, for the operation sequences specified in the harnesses.

`Outstanding` capacity is fixed at **2**, not quantified over const-generic `N`.
The bounded IO5 model supplies an abstract lifetime argument, not a proof for
every concrete table capacity. The harnesses do not symbolically execute full
shared mappings or `Queue::submit`, `take_request`, `complete` and
`take_completion`; header and slot arithmetic are prerequisites, not proof of
those complete paths or of shared-memory ordering. There is no whole-substrate
refinement claim and **no `slime-root` proof**: its resource accounting remains
modelled and plane-observed.

Source routing: `nix develop .#kani --command just kani_io_proofs` (or bare
`just kani_io_proofs` with `cargo-kani` on `PATH`).

Each wire-arithmetic proof must be shown non-vacuous by a breaking mutation.

### Device-input source proofs (IO7)

The `proofs` module in
[`virtio_mmio.rs`](../../components/lib/src/virtio_mmio.rs) covers exactly three
pure functions used by virtio-net:

- `used_descriptor_slot`: accepted device-written `u32` ids are exactly even
  heads below `slots * 2`, in bounds, distinct and round-trippable. Symbolic
  depth is constrained to `0 < slots <= usize::MAX / 2`; head round-tripping
  additionally requires a head representable as `u32`.
- `used_ring_progress`: symbolic `u16` published/consumed indices yield exact
  wrapping distance if it does not exceed the supplied outstanding-chain count,
  otherwise refusal. Idle is zero; zero outstanding chains admit only idle.
- `received_payload_len`: symbolic report/header/minimum/frame lengths enforce
  exact, non-truncated payload size within the offered frame and at least the
  requested minimum, with header-short reports refused. Acceptance is equivalent
  to the declared rule, including header/minimum representability as `u32`.

[`verification/virtio-proofs/Cargo.toml`](../../verification/virtio-proofs/Cargo.toml)
uses that shipped module as its crate root with syscall-backed `component-runtime`
code disabled. These are **not whole-driver or virtio-blk proofs**. They do not
prove `drain_used` invokes every check, the supplied outstanding count is correct,
or `ControlQueue::submit` descriptor/ring writes are correct. Driver integration
is argued from the implementation and exercised by `just io_link_check`, not
machine-checked by these harnesses. No adversarial-device refusal is claimed as
observed on a booted plane; the refusal claims here concern symbolic values only.

Source routing: `nix develop .#kani --command just kani_virtio_proofs`.

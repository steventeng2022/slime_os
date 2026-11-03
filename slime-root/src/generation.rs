//! Bounded generation preflight and authority derivation for `slime-root`.
//!
//! Admission is a pure decision over decoded v5 generation data: it classifies
//! executable payloads and preserves the explicit instance launch model.
//! Initial authority comes only from per-instance bindings; executables are
//! never inferred to be instances.

use boot_contracts::block_authority::{self, BlockAuthority};
use boot_contracts::clock_authority::{self, ClockAuthority};
use boot_contracts::component_image::{self, ComponentTargetError};
use boot_contracts::entropy_authority::{self, EntropyAuthority};
use boot_contracts::fabric_graph::{self, FabricGraph, MAX_INTERPOSITION_HOPS};
use boot_contracts::generation::{
    BootAction, DecodeError, Generation, Instance, InstanceBinding, KIND_BOOTSTRAP, KIND_COMPONENT,
    KIND_RESOURCE, RIGHT_TRANSFER, ResourceQuota, Rights,
};
use boot_contracts::graph_arrival_ceiling::{self, GraphArrivalCeiling};
use boot_contracts::instance_lifetime::{self, InstanceLifetime, Lifetime};
use boot_contracts::io_resource::{self, IoResourceBudget};
use boot_contracts::lifecycle_policy::{self, LifecyclePolicy};
use boot_contracts::network_application::{self, NetworkApplications};
use boot_contracts::network_destination::{self, NetworkDestinations};
use boot_contracts::network_interface::{self, NetworkInterfaces};
use boot_contracts::private_memory_budget::{self, PrivateMemoryBudget};
use boot_contracts::private_memory_policy::{self, Policy as PrivateMemoryPolicy};
use boot_contracts::recording_policy::{self, RecordingPolicy};
use boot_contracts::scheduling_class::{self, SchedulingClass};
use boot_contracts::target_profile::TargetProfile;
use boot_contracts::wait_set::{self, WaitSet};

use crate::object_allocator::{ObjectAllocator, guarantee_vault};
// B59: the capability-rights vocabulary is generated from
// `contracts/generation/v5/schema.zt`; these were local copies of the same
// bit numbering.
use boot_contracts::generation::{RIGHT_RECV, RIGHT_SEND};

pub const MAX_ADMITTED_EXECUTABLES: usize = 48;
pub const MAX_ADMITTED_INSTANCES: usize = 48;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationError {
    Decode(DecodeError),
    UnsupportedGenerationVersion,
    MalformedClosure {
        bootstrap: usize,
        executables: usize,
    },
    /// A declared resource quota exceeds what the root can actually place
    /// (B49). Named per class so a refusal says which ceiling was hit.
    /// The plan's object counts, summed across every process, exceed the root
    /// CSlots available to hold capabilities to them (B49).
    PlanExceedsRootSlots {
        required: usize,
        available: usize,
    },
    ImageQuotaTooSmall {
        instance: usize,
        declared: usize,
        required: usize,
    },
    MalformedImage {
        executable: usize,
    },
    ImagePlanExceedsCeiling {
        declared: usize,
        limit: usize,
    },
    QuotaExceedsCeiling {
        instance: usize,
        kind: &'static str,
        declared: u32,
        limit: u32,
    },
    TooManyExecutables {
        declared: usize,
        limit: usize,
    },
    TooManyInstances {
        declared: usize,
        limit: usize,
    },
    DanglingExecutable {
        executable: usize,
    },
    BareElfPayload {
        executable: usize,
    },
    /// The generation carries a fabric graph whose declared limits this root
    /// cannot satisfy, or which contradicts itself (C8.2).
    ///
    /// Distinct from [`Self::Decode`] because the bytes are well formed: the
    /// graph says what it needs and the answer is no. The whole generation
    /// fails closed, before the fabric or any participant launches.
    UnsatisfiableFabricGraph,
    /// The fabric graph names a participant this generation does not declare
    /// as a component (C8.3).
    ///
    /// Distinct from [`Self::UnsatisfiableFabricGraph`]: the graph is
    /// internally consistent and fits every ceiling, but it promises an edge
    /// to a component that will never exist, so the promise cannot be kept by
    /// any mechanism.
    UndeclaredFabricParticipant,
    /// The generation carries a private-memory budget this root cannot honour,
    /// or one that will not decode (C10.2).
    ///
    /// Distinct from [`Self::Decode`] for the well-formed case: the bytes say
    /// what they need and the answer is no. The whole generation fails closed,
    /// before any component launches — a quota the root cannot honour must not
    /// become a runtime refusal against a ceiling the generation promised.
    UnsatisfiablePrivateMemoryBudget,
    ConflictingPrivateMemoryPolicies,
    MalformedPrivateMemoryPolicy,
    UnsupportedPrivateMemoryPolicy,
    UnsupportedAdaptivePrivateMemoryPolicy,
    /// The generation carries an IO-resource budget that is malformed or asks
    /// for aggregate/per-driver ceilings this root cannot honour (IO1).
    UnsatisfiableIoResourceBudget,
    /// The generation carries clock authority that is malformed or asks for
    /// more live timers than this root can provision (C9.1).
    UnsatisfiableClockAuthority,
    /// The generation carries a wait-set source table that is malformed, names a
    /// badge no declared signaller or timer produces, or attributes a source to
    /// a Notification its waiter does not wait on (C9.2).
    ///
    /// One variant rather than one per rule, on
    /// [`Self::UnsatisfiableClockAuthority`]'s precedent: every case is the same
    /// decision — the declared source table cannot be honoured — and a component
    /// never sees these, so a finer vocabulary would only be read by the marker
    /// the root prints, which names the failing entry itself.
    UnsatisfiableWaitSet,
    /// The generation carries a scheduling-class policy that is malformed,
    /// names an instance this generation does not declare, or grants a
    /// promotion edge to a holder carrying no `schedulingPromote` right (C9.3).
    ///
    /// One variant on [`Self::UnsatisfiableClockAuthority`]'s precedent: every
    /// case is the same decision — the declared policy cannot be honoured — and
    /// the marker the root prints names the failing entry itself.
    UnsatisfiableSchedulingClass,
    /// The generation carries a lifecycle policy that is malformed, names an
    /// instance this generation does not declare, or declares a restart or
    /// parameter edge no capability could reach (C9.4).
    ///
    /// One variant on [`Self::UnsatisfiableClockAuthority`]'s precedent, for its
    /// reason: every case is the same decision, and the marker the root prints
    /// names the failing entry itself.
    UnsatisfiableLifecyclePolicy,
    /// The generation carries a recording resource that is malformed, names an
    /// instance this generation does not declare, or claims a component is
    /// deterministic while granting it an unrecorded nondeterminism source
    /// (C9.5).
    ///
    /// One variant on [`Self::UnsatisfiableClockAuthority`]'s precedent, for its
    /// reason: every case is the same decision, and the marker the root prints
    /// names the failing entry itself.
    UnsatisfiableRecordingPolicy,
    /// The generation carries an instance-lifetime resource that is malformed
    /// or names an instance this generation does not declare.
    UnsatisfiableInstanceLifetime,
    /// The generation carries a graph-arrival-ceiling resource that is
    /// malformed, appears twice, or rides on a product generation, whose graph
    /// has no arrival ceiling to raise.
    UnsatisfiableGraphArrivalCeiling,
}

impl From<DecodeError> for GenerationError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

/// How a component's payload is encoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadFormat {
    /// A target-qualified image carrying a native ELF for this root task's
    /// profile. Loadable.
    QualifiedElf,
    /// A bare little-endian ELF64 image carrying no target qualification.
    /// Recognized for diagnostics, but never loadable from a generation: only
    /// target-qualified component images cross admission.
    BareElf,
    /// A Slime component image whose payload is a segment table
    /// (`SLIMECMP`/`SLIMECM2`). These are the custom format the retired Slime
    /// kernel loaded, and `slime-root` has no loader for them.
    SlimeComponent,
    /// A qualified image that is not admitted for this profile — wrong
    /// architecture, ABI, page profile, or feature set. Never loadable, and
    /// distinguished from [`Self::Unrecognized`] so a wrong-target artifact is
    /// reported as refused rather than as malformed.
    WrongTarget,
    /// None of the above.
    Unrecognized,
}

impl PayloadFormat {
    pub const fn is_loadable(self) -> bool {
        matches!(self, Self::QualifiedElf)
    }

    /// Classify a payload, admitting a qualified image against `profile`.
    ///
    /// The magic is read through `boot_contracts::component_image`, not by
    /// prefix comparison: `SLIMECME` and `SLIMECM2` share a seven-byte prefix,
    /// so a `starts_with(b"SLIMECM")` test would call every ELF-carrying image
    /// an unloadable legacy one. The contract decoder distinguishes them by the
    /// full eight-byte magic, which is what it is for.
    ///
    /// Target admission happens *here*, before any byte reaches the loader,
    /// which is roadmap invariant 9: a wrong-target executable is refused
    /// before it is mapped, not after.
    pub fn classify(bytes: &[u8], profile: &TargetProfile) -> Self {
        const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
        const ELF_CLASS64: u8 = 2;
        const ELF_DATA_LSB: u8 = 1;
        const ELF_MACHINE_AARCH64: u16 = 183;
        const ELF_MACHINE_RISCV: u16 = 243;
        match component_image::target(bytes) {
            // A segment-carrying image is unloadable here whatever it targets:
            // `slime-root` has no loader for the retired kernel's format. Its
            // target is therefore not consulted, so a retained x86 generation
            // is still reported as the Slime component images it holds rather
            // than as a pile of wrong-target artifacts.
            Ok((revision, _)) if !revision.carries_elf() => return Self::SlimeComponent,
            // An ELF-carrying image is one this root task could load, so the
            // target is exactly what decides whether it may.
            Ok(_) => {
                return match component_image::admit(bytes, profile) {
                    Ok(_) => Self::QualifiedElf,
                    Err(ComponentTargetError::Target(_)) => Self::WrongTarget,
                    Err(_) => Self::Unrecognized,
                };
            }
            // Not a Slime component image at all; fall through to the bare-ELF
            // test below.
            Err(ComponentTargetError::BadMagic) => {}
            Err(_) => return Self::Unrecognized,
        }

        let Some(header) = bytes.get(..20) else {
            return Self::Unrecognized;
        };
        let machine = u16::from_le_bytes([header[18], header[19]]);
        if header[..4] == ELF_MAGIC
            && header[4] == ELF_CLASS64
            && header[5] == ELF_DATA_LSB
            && matches!(machine, ELF_MACHINE_AARCH64 | ELF_MACHINE_RISCV)
        {
            Self::BareElf
        } else {
            Self::Unrecognized
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutablePlan {
    pub executable: usize,
    pub format: PayloadFormat,
}

/// The endpoint authority a task receives, derived from declared grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Authority {
    pub rights: Rights,
    pub grants: usize,
}

impl Authority {
    pub const NONE: Self = Self {
        rights: 0,
        grants: 0,
    };

    /// Map logical Slime rights onto seL4 endpoint rights.
    ///
    /// `write` is the send right. `read` is the receive right, which for a
    /// service endpoint means the holder may block on it. `grant_reply` is
    /// granted alongside send because a call must be able to hand the root task
    /// a reply authority, and because the non-MCS kernel refuses a fault
    /// handler endpoint that carries neither `grant` nor `grant_reply`. Full
    /// `grant` — the right to pass capabilities through the endpoint — is only
    /// given when the generation declares the grant transferable.
    pub fn endpoint_rights(self) -> sel4::CapRights {
        let can_send = self.rights & RIGHT_SEND != 0;
        sel4::CapRightsBuilder::none()
            .write(can_send)
            .read(self.rights & RIGHT_RECV != 0)
            .grant_reply(can_send)
            .grant(self.rights & RIGHT_TRANSFER != 0)
            .build()
    }
}

pub fn bound_authority(
    generation: &Generation<'_>,
    instance: Instance<'_>,
) -> Result<Authority, GenerationError> {
    let instance_index = (0..generation.instance_count())
        .find(|index| {
            generation
                .instance(*index)
                .is_ok_and(|candidate| candidate.name == instance.name)
        })
        .ok_or(GenerationError::Decode(DecodeError::BadIndex))?;
    let mut authority = Authority::NONE;
    for index in 0..instance.binding_count() {
        let InstanceBinding { grant, .. } = generation.binding(instance, index)?;
        let grant = generation.grant(grant)?;
        if generation.grant_applies_to_instance(grant, instance_index) {
            authority.rights |= grant.rights;
            authority.grants += 1;
        }
    }
    Ok(authority)
}

/// Whether this root can satisfy a declared fabric graph (C8.2).
///
/// Separated from the generation walk so it is reachable without constructing
/// a generation blob: the interesting content is *which ceilings* are passed,
/// and those are this implementation's rather than the retired kernel's. The
/// predicate itself is `boot_contracts`, shared byte-for-byte with the oracle,
/// so the two can disagree only where their mechanisms genuinely differ —
/// which is the reason validating in both places is not redundant.
pub fn fabric_graph_is_satisfiable(graph: &FabricGraph<'_>) -> Result<(), GenerationError> {
    graph
        .validate_against(
            crate::ipc::MAX_WAIT_SOURCES as u32,
            crate::graph::MAX_TASK_CAPS as u32,
            crate::shared_buffer::MAX_TOTAL_PAGES as u32,
            crate::shared_buffer::MAX_SHARED_BUFFERS as u32,
            crate::shared_buffer::MAX_MAPPINGS as u32,
            crate::shared_buffer::MAX_LOANS as u32,
            crate::ipc::MAX_MESSAGE_BYTES as u32,
            u32::MAX,
        )
        .map_err(|_| GenerationError::UnsatisfiableFabricGraph)?;
    // Every matched pair's offered QoS must satisfy the requested one
    // (P5.4.10). `validate_against` bounds the graph's *aggregate* demand;
    // this is the per-pair question, and the two are independent — a graph can
    // fit every ceiling and still promise a reader more than its writer offers.
    //
    // Queue depth is deliberately not a root ceiling after B46. Buffered
    // streams use the generation-provisioned v2 shared ring, while native
    // Endpoint rendezvous has no root-owned queue. The graph may still declare
    // its policy depth; only the component provisioning path must honour it.
    if graph.all_pairs_qos_compatible() {
        Ok(())
    } else {
        Err(GenerationError::UnsatisfiableFabricGraph)
    }
}

/// Validate a declared fabric graph against this root's own ceilings (C8.2),
/// reporting whether one was present.
///
/// A no-op for a generation that declares no graph, which is every `sel4-*`
/// fixture but the stream plane's — though *not* the retained x86 generation
/// the P5.1 fixture variant boots, which carries a larger graph than any
/// `sel4-*` fixture and the only interposition hop of the set. That is
/// deliberate rather than incidental: the check must be silent on graphs that
/// make no fabric promise, and refuse exactly those whose promises this
/// mechanism cannot keep.
///
/// `None` versus `Some(shape)` is what lets a boot marker distinguish
/// "checked and satisfiable" from "nothing to check", which is the difference
/// a gate needs to see; the shape itself is C8.4's structural arm.
fn fabric_graph_admission(
    generation: &Generation<'_>,
) -> Result<Option<FabricShape>, GenerationError> {
    let Some(graph) = fabric_graph_object(generation) else {
        return Ok(None);
    };
    // A graph that will not decode is refused here rather than surfaced as a
    // decode error, because the generation is otherwise well formed: it is the
    // graph that is wrong, and the caller's marker should say so.
    let graph = graph.map_err(|_| GenerationError::UnsatisfiableFabricGraph)?;
    fabric_graph_is_satisfiable(&graph)?;
    fabric_graph_participants_are_declared(generation, &graph)?;
    Ok(Some(FabricShape {
        schemas: graph.schema_count(),
        routes: graph.route_count(),
        participants: graph.participant_count(),
        interpositions: graph.interposition_count(),
        capability_slots: graph.limits().capability_slots,
    }))
}

/// Every participant in the graph must name a component this generation
/// declares (C8.3).
///
/// The graph identifies participants by a hash of the component name, and the
/// fabric service answers requests from a *build-time* table generated from the
/// same manifest. Nothing checked that the two agreed: a graph naming a
/// component the generation had since dropped would decode, satisfy every
/// ceiling, and launch — and the mismatch would surface only as a participant
/// whose control endpoint never arrives, which reads as a hang rather than as
/// the provenance failure it is.
///
/// Checked in the direction that can actually be wrong. A component with no
/// participant is ordinary (most components are not on the fabric); a
/// participant with no component is a graph promising an edge to nobody.
fn fabric_graph_participants_are_declared(
    generation: &Generation<'_>,
    graph: &FabricGraph<'_>,
) -> Result<(), GenerationError> {
    let declared = generation.instance_count();
    if declared > MAX_ADMITTED_INSTANCES {
        return Err(GenerationError::TooManyInstances {
            declared,
            limit: MAX_ADMITTED_INSTANCES,
        });
    }
    let mut names = [None; MAX_ADMITTED_INSTANCES];
    for (slot, name) in names.iter_mut().enumerate().take(declared) {
        *name = Some(generation.instance(slot)?.name);
    }
    participants_are_declared(&names[..declared], graph)
}

/// The set half of [`fabric_graph_participants_are_declared`], over the
/// component names rather than the generation that carries them.
///
/// Split out so the property is testable: building a whole `Generation` by
/// hand would make the fixture the thing under test.
fn participants_are_declared(
    names: &[Option<&str>],
    graph: &FabricGraph<'_>,
) -> Result<(), GenerationError> {
    let declares = |identity: [u8; 32]| {
        names
            .iter()
            .flatten()
            .any(|name| fabric_graph::component_identity(name) == identity)
    };
    // The fabric host itself. `decode` only rejects an all-zero value, and a
    // graph naming a host the manifest dropped fits every ceiling — but no
    // participant would receive anything, because the host that mints every
    // route half does not exist. Checked first: it is the failure that
    // disables the whole graph rather than one edge of it.
    if !declares(graph.fabric_component_identity()) {
        return Err(GenerationError::UndeclaredFabricParticipant);
    }
    for index in 0..graph.participant_count() {
        let participant = graph
            .participant(index)
            .ok_or(GenerationError::UnsatisfiableFabricGraph)?;
        if !declares(participant.component_identity) {
            return Err(GenerationError::UndeclaredFabricParticipant);
        }
    }
    // Interposition hops. `validate_interposition` checks chain termination,
    // revisits, and self-bypass, never membership — and a hop is a *mandatory*
    // proxy on its route, so a dropped one silently breaks the route it was
    // added to mediate. The retained generation this root boots by default
    // carries one, so this arm is exercised on every fixture-variant boot.
    for index in 0..graph.interposition_count() {
        let hop = graph
            .interposition(index)
            .ok_or(GenerationError::UnsatisfiableFabricGraph)?;
        if !declares(hop.component_identity) {
            return Err(GenerationError::UndeclaredFabricParticipant);
        }
    }
    Ok(())
}

/// The component names the graph's interposition hops resolve to, in chain order.
///
/// B70. The two fabric brokers each carried an `assert_declared_chain` that
/// compared a build-time table against a hard-coded proxy name, which is
/// exactly the compile-time coupling B70 removes — and which could only ever
/// check the table against itself, never against the graph the root admitted.
///
/// Resolved here because this is the only place both facts are in hand. A hop
/// is identified in the wire graph by `component_identity`, a hash, and the
/// preimage exists only as an instance name in the generation; the same
/// reverse map [`participants_are_declared`] already does for its membership
/// check is what turns one into the other. A hop that resolves to no declared
/// instance cannot reach here — admission refuses that graph — so an
/// unresolved entry means the graph decoded differently than it validated, and
/// is reported as `None` rather than skipped.
pub fn interposition_hop_names<'a>(
    generation: &Generation<'a>,
) -> [Option<&'a str>; MAX_INTERPOSITION_HOPS] {
    let mut names = [None; MAX_ADMITTED_INSTANCES];
    let declared = generation.instance_count().min(MAX_ADMITTED_INSTANCES);
    for (slot, name) in names.iter_mut().enumerate().take(declared) {
        *name = generation.instance(slot).ok().map(|instance| instance.name);
    }
    let Some(Ok(graph)) = fabric_graph_object(generation) else {
        return [None; MAX_INTERPOSITION_HOPS];
    };
    resolve_interposition_hops(&names[..declared], &graph)
}

/// The name half of [`interposition_hop_names`], over the component names
/// rather than the generation that carries them.
///
/// Split for the same reason [`participants_are_declared`] is: building a
/// whole `Generation` by hand would make the fixture the thing under test.
/// This is the half that can be wrong — a hop resolving to the wrong name, or
/// to none — and the plane gates now assert on its output.
fn resolve_interposition_hops<'a>(
    names: &[Option<&'a str>],
    graph: &FabricGraph<'_>,
) -> [Option<&'a str>; MAX_INTERPOSITION_HOPS] {
    let mut hops = [None; MAX_INTERPOSITION_HOPS];
    for (index, slot) in hops
        .iter_mut()
        .enumerate()
        .take(graph.interposition_count())
    {
        let Some(hop) = graph.interposition(index) else {
            continue;
        };
        *slot = names
            .iter()
            .flatten()
            .find(|name| fabric_graph::component_identity(name) == hop.component_identity)
            .copied();
    }
    hops
}

/// The shape a declared fabric graph fixes. See [`Admission::fabric_schemas`].
#[derive(Clone, Copy)]
struct FabricShape {
    schemas: usize,
    routes: usize,
    participants: usize,
    interpositions: usize,
    /// The graph's declared per-child capability-slot ceiling (C8.13.3).
    capability_slots: u32,
}

/// Locate the fabric-graph resource object, if the generation declares one.
///
/// The same shape as the retired kernel's: a `KIND_RESOURCE` object whose
/// payload carries the fabric-graph magic, first match wins.
/// The generation's embedded fabric-graph resource, decoded.
///
/// `pub(crate)` so `ipc`'s `GRAPH_READ` answers from the same object admission
/// validated, rather than locating the resource a second way. A second lookup
/// is how the boot-layout resource drifted from the bindings it described
/// (B71): two statements of one fact, kept in agreement by nothing.
pub(crate) fn fabric_graph_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<FabricGraph<'a>, fabric_graph::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE
            && object.bytes.len() >= fabric_graph::MAGIC.len()
            && object.bytes[..fabric_graph::MAGIC.len()] == fabric_graph::MAGIC
        {
            return Some(FabricGraph::decode(object.bytes));
        }
    }
    None
}

/// Resolve the entire resource family before choosing a version. An earlier
/// valid object must not conceal a later conflicting declaration.
fn private_memory_object<'a>(
    generation: &Generation<'a>,
) -> Result<Option<&'a [u8]>, GenerationError> {
    select_private_memory_object((0..generation.object_count()).map(|index| {
        generation
            .object(index)
            .map(|object| (object.kind, object.bytes))
            .map_err(GenerationError::from)
    }))
}

fn select_private_memory_object<'a>(
    objects: impl Iterator<Item = Result<(u32, &'a [u8]), GenerationError>>,
) -> Result<Option<&'a [u8]>, GenerationError> {
    let mut found = None;
    for object in objects {
        let (kind, bytes) = object?;
        if kind == KIND_RESOURCE && bytes.starts_with(&private_memory_policy::MAGIC) {
            if found.is_some() {
                return Err(GenerationError::ConflictingPrivateMemoryPolicies);
            }
            found = Some(bytes);
        }
    }
    Ok(found)
}

/// The declared format version of the generation's private-memory resource.
///
/// One family, two formats: the version decides which reader owns the bytes,
/// and a resource that is neither is refused rather than read by the older one.
fn private_memory_version(bytes: &[u8]) -> Result<u32, GenerationError> {
    let version = bytes
        .get(
            private_memory_policy::OFF_HEADER_FORMAT_VERSION
                ..private_memory_policy::OFF_HEADER_FORMAT_VERSION_END,
        )
        .ok_or(GenerationError::MalformedPrivateMemoryPolicy)?;
    Ok(u32::from_le_bytes(version.try_into().unwrap()))
}

/// Fixed-budget lookup for launch paths.
///
/// A generation carrying the adaptive format answers `None`: it declares no
/// fixed budget, so every holder resolves to no quota through this reader and
/// the adaptive path owns its own binding. Returning a decode error instead
/// would fail an adaptive boot on the reader rather than on the policy.
pub fn private_memory_budget_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<PrivateMemoryBudget<'a>, GenerationError>> {
    match private_memory_object(generation) {
        Ok(Some(bytes)) => match private_memory_version(bytes) {
            Ok(private_memory_policy::FORMAT_VERSION) => None,
            Ok(_) => Some(
                PrivateMemoryBudget::decode(bytes)
                    .map_err(|_| GenerationError::UnsatisfiablePrivateMemoryBudget),
            ),
            Err(error) => Some(Err(error)),
        },
        Ok(None) => None,
        Err(error) => Some(Err(error)),
    }
}

/// Adaptive-policy lookup for the paths that bind entitlements.
///
/// The mirror of [`private_memory_budget_object`]: a fixed budget answers
/// `None` here, so each reader sees only the format it owns and neither has to
/// guess what the other's absence means.
pub fn private_memory_policy_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<PrivateMemoryPolicy<'a>, GenerationError>> {
    match private_memory_object(generation) {
        Ok(Some(bytes)) => match private_memory_version(bytes) {
            Ok(private_memory_policy::FORMAT_VERSION) => Some(
                PrivateMemoryPolicy::decode(bytes)
                    .map_err(|_| GenerationError::MalformedPrivateMemoryPolicy),
            ),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        },
        Ok(None) => None,
        Err(error) => Some(Err(error)),
    }
}

/// This generation's instances as the policy's trusted topology.
///
/// Identities are derived from the instance names the generation itself
/// declares and ownership from its own owner field, so a policy can never
/// name a subject this generation does not contain, and membership stays
/// explicit: a subtree root restricts its listed members rather than
/// admitting every descendant.
pub fn private_memory_instances(
    generation: &Generation<'_>,
    instances: &mut [private_memory_policy::Instance],
) -> Result<usize, GenerationError> {
    let count = generation.instance_count();
    if count > instances.len() {
        return Err(GenerationError::MalformedPrivateMemoryPolicy);
    }
    for (index, slot) in instances.iter_mut().enumerate().take(count) {
        let instance = generation.instance(index)?;
        *slot = private_memory_policy::Instance {
            identity: private_memory_policy::subject_identity(instance.name),
            owner: match instance.owner {
                boot_contracts::generation::InstanceOwner::Root => None,
                boot_contracts::generation::InstanceOwner::Instance(owner) => Some(
                    private_memory_policy::subject_identity(generation.instance(owner)?.name),
                ),
            },
        };
    }
    Ok(count)
}
pub fn io_resource_budget_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<IoResourceBudget<'a>, io_resource::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE
            && object.bytes.len() >= io_resource::MAGIC.len()
            && object.bytes[..io_resource::MAGIC.len()] == io_resource::MAGIC
        {
            return Some(IoResourceBudget::decode(object.bytes));
        }
    }
    None
}

fn io_resource_budget_admission(
    generation: &Generation<'_>,
) -> Result<Option<usize>, GenerationError> {
    let Some(budget) = io_resource_budget_object(generation) else {
        return Ok(None);
    };
    let budget = budget.map_err(|_| GenerationError::UnsatisfiableIoResourceBudget)?;
    budget
        .validate_against(io_resource::DriverQuota {
            driver_identity: [0; 32],
            mmio_bytes: crate::io_resource::MAX_MMIO_MAPPINGS as u32
                * crate::io_resource::PAGE_SIZE,
            mmio_mappings: crate::io_resource::MAX_MMIO_MAPPINGS as u32,
            dma_pages: crate::io_resource::MAX_DMA_MAPPINGS as u32,
            dma_mappings: crate::io_resource::MAX_DMA_MAPPINGS as u32,
            irq_sources: crate::io_resource::MAX_IRQ_SOURCES as u32,
            outstanding_requests: crate::io_resource::MAX_REQUESTS as u32,
            buffer_loans: crate::io_resource::MAX_LEASES as u32,
            // How many device slots this root can back. An ordinal at or above
            // it names a transport that cannot exist, so admission refuses it
            // rather than letting a driver boot and fail its first MMIO (B84).
            device: crate::device::MAX_IO_DEVICES as u32,
        })
        .map_err(|_| GenerationError::UnsatisfiableIoResourceBudget)?;
    Ok(Some(budget.driver_count()))
}

/// Locate the authenticated IO4 destination table. The root decodes it only
/// to bound and page authenticated bytes; destination policy remains userspace.
pub(crate) fn network_destinations_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<NetworkDestinations<'a>, network_destination::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE
            && object.bytes.len() >= network_destination::MAGIC.len()
            && object.bytes[..network_destination::MAGIC.len()] == network_destination::MAGIC
        {
            return Some(NetworkDestinations::decode(object.bytes));
        }
    }
    None
}
/// Locate the authenticated IO11 interface table. Decoded only to bound and
/// page authenticated bytes; the root learns no address from it.
pub(crate) fn network_interface_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<NetworkInterfaces<'a>, network_interface::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE
            && object.bytes.len() >= network_interface::MAGIC.len()
            && object.bytes[..network_interface::MAGIC.len()] == network_interface::MAGIC
        {
            return Some(NetworkInterfaces::decode(object.bytes));
        }
    }
    None
}
/// Locate the authenticated entropy-authority table. Decoded only to bound and
/// page authenticated bytes; budgets and streams belong to the entropy service.
pub(crate) fn entropy_authority_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<EntropyAuthority<'a>, entropy_authority::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE && object.bytes.starts_with(&entropy_authority::MAGIC) {
            return Some(EntropyAuthority::decode(object.bytes));
        }
    }
    None
}
/// Locate authenticated application rows without interpreting userspace policy.
pub(crate) fn network_application_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<NetworkApplications<'a>, network_application::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE && object.bytes.starts_with(&network_application::MAGIC) {
            return Some(NetworkApplications::decode(object.bytes));
        }
    }
    None
}

/// Locate the authenticated B83 per-ring block authority table. Decoded here
/// only to bound and page authenticated bytes; which ring may write is the
/// driver's decision, because that is device policy.
pub(crate) fn block_ring_authority_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<BlockAuthority<'a>, block_authority::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE
            && object.bytes.len() >= block_authority::MAGIC.len()
            && object.bytes[..block_authority::MAGIC.len()] == block_authority::MAGIC
        {
            return Some(BlockAuthority::decode(object.bytes));
        }
    }
    None
}
/// Locate the generation-authenticated clock-authority resource, if declared.
///
/// First match wins, including a malformed first match. Continuing after a bad
/// resource would make authority depend on object ordering and could silently
/// select a later permissive declaration.
pub fn clock_authority_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<ClockAuthority<'a>, clock_authority::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE
            && object.bytes.len() >= clock_authority::MAGIC.len()
            && object.bytes[..clock_authority::MAGIC.len()] == clock_authority::MAGIC
        {
            return Some(ClockAuthority::decode(object.bytes));
        }
    }
    None
}

/// Validate a declared clock authority, reporting how many holders it names.
/// Missing authority denies the service to every component; malformed timer
/// delivery or a scheduler quota this root cannot honour fails admission.
fn clock_authority_admission(
    generation: &Generation<'_>,
) -> Result<Option<usize>, GenerationError> {
    let Some(authority) = clock_authority_object(generation) else {
        return Ok(None);
    };
    let authority = authority.map_err(|_| GenerationError::UnsatisfiableClockAuthority)?;
    for holder_index in 0..authority.holder_count() {
        let entry = authority
            .holder(holder_index)
            .ok_or(GenerationError::UnsatisfiableClockAuthority)?;
        if !entry.allows(boot_contracts::generation::RIGHT_CLOCK_TIMER_USE) {
            continue;
        }
        let mut target = None;
        for grant_index in 0..generation.notification_grant_count() {
            let grant = generation
                .notification_grant(grant_index)
                .map_err(|_| GenerationError::UnsatisfiableClockAuthority)?;
            let instance = generation
                .instance(grant.target)
                .map_err(|_| GenerationError::UnsatisfiableClockAuthority)?;
            if clock_authority::holder_identity(instance.name) == entry.holder_identity
                && clock_authority::notification_grant_identity(grant.name)
                    == entry.notification_grant_identity
            {
                target = Some((grant_index, grant.target));
                break;
            }
        }
        let Some((grant_index, target_instance)) = target else {
            return Err(GenerationError::UnsatisfiableClockAuthority);
        };
        let mut waits = 0usize;
        for binding_index in 0..generation.notification_binding_count() {
            let binding = generation
                .notification_binding(binding_index)
                .map_err(|_| GenerationError::UnsatisfiableClockAuthority)?;
            if binding.grant != grant_index {
                continue;
            }
            match binding.role {
                boot_contracts::generation::NotificationRole::Wait => {
                    if binding.holder == target_instance {
                        waits += 1;
                    }
                }
                boot_contracts::generation::NotificationRole::Signal => {
                    let badge = 1u64 << (binding.slot % 63);
                    if badge == entry.notification_badge {
                        return Err(GenerationError::UnsatisfiableClockAuthority);
                    }
                }
            }
        }
        if waits != 1 {
            return Err(GenerationError::UnsatisfiableClockAuthority);
        }
    }
    Ok(Some(authority.holder_count()))
}

/// Locate the generation-authenticated wait-set resource, if declared.
///
/// First match wins including a malformed one, on `clock_authority_object`'s
/// rule: continuing would make a waiter's source table depend on object
/// ordering.
pub fn wait_set_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<WaitSet<'a>, wait_set::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE
            && object.bytes.len() >= wait_set::MAGIC.len()
            && object.bytes[..wait_set::MAGIC.len()] == wait_set::MAGIC
        {
            return Some(WaitSet::decode(object.bytes));
        }
    }
    None
}

/// Validate a declared wait set, reporting how many sources it names.
///
/// Every entry must resolve to a badge this generation actually produces on a
/// Notification the waiter actually waits on: a declared signaller's
/// `1 << (slot % 63)`, or — for a timer source — the C9.1 expiry badge declared
/// for that same holder. That is what makes the resource grant nothing. It
/// renames facts the notification and clock tables already fix, so an entry
/// naming an unsignalled bit, another instance's grant, or a timer badge it has
/// no clock authority for is refused here rather than presenting at runtime as a
/// source that never fires.
fn wait_set_admission(generation: &Generation<'_>) -> Result<Option<usize>, GenerationError> {
    let Some(sources) = wait_set_object(generation) else {
        return Ok(None);
    };
    let sources = sources.map_err(|_| GenerationError::UnsatisfiableWaitSet)?;
    let clocks = match clock_authority_object(generation) {
        Some(Ok(authority)) => Some(authority),
        Some(Err(_)) => return Err(GenerationError::UnsatisfiableWaitSet),
        None => None,
    };
    for index in 0..sources.entry_count() {
        let entry = sources
            .entry(index)
            .ok_or(GenerationError::UnsatisfiableWaitSet)?;
        // The grant must be one this waiter waits on, resolved through the
        // waiter's own identity so an entry cannot borrow a peer's grant.
        let mut target = None;
        for grant_index in 0..generation.notification_grant_count() {
            let grant = generation
                .notification_grant(grant_index)
                .map_err(|_| GenerationError::UnsatisfiableWaitSet)?;
            let instance = generation
                .instance(grant.target)
                .map_err(|_| GenerationError::UnsatisfiableWaitSet)?;
            if wait_set::waiter_identity(instance.name) == entry.waiter_identity
                && wait_set::notification_grant_identity(grant.name)
                    == entry.notification_grant_identity
            {
                target = Some((grant_index, grant.target, grant.name));
                break;
            }
        }
        let Some((grant_index, waiter_instance, grant_name)) = target else {
            return Err(GenerationError::UnsatisfiableWaitSet);
        };
        let mut waits = 0usize;
        let mut signalled = false;
        for binding_index in 0..generation.notification_binding_count() {
            let binding = generation
                .notification_binding(binding_index)
                .map_err(|_| GenerationError::UnsatisfiableWaitSet)?;
            if binding.grant != grant_index {
                continue;
            }
            match binding.role {
                boot_contracts::generation::NotificationRole::Wait => {
                    if binding.holder == waiter_instance {
                        waits += 1;
                    }
                }
                boot_contracts::generation::NotificationRole::Signal => {
                    if 1u64 << (binding.slot % 63) == entry.badge {
                        signalled = true;
                    }
                }
            }
        }
        if waits != 1 {
            return Err(GenerationError::UnsatisfiableWaitSet);
        }
        // Three producers write this one word, and a badge belongs to exactly
        // one of them. A peer signals its declared `1 << (slot % 63)`; the root
        // signals a C9.1 timer badge; and the root signals a supervision badge
        // when a task the waiter supervises ends. Two producers on one bit would
        // make a wake ambiguous, and none would make the source unreachable, so
        // both are refused.
        let timer_badge = clocks.is_some_and(|authority| {
            generation.instance(waiter_instance).is_ok_and(|instance| {
                authority
                    .authority_for(&clock_authority::holder_identity(instance.name))
                    .is_some_and(|holder| {
                        holder.notification_badge == entry.badge
                            && holder.notification_grant_identity
                                == clock_authority::notification_grant_identity(grant_name)
                    })
            })
        });
        let root_signalled = matches!(
            entry.kind,
            wait_set::SourceKind::Timer | wait_set::SourceKind::Supervision
        );
        // A root-signalled source must not also be a peer's badge; a
        // peer-signalled one must be exactly that and nothing else.
        if signalled == root_signalled {
            return Err(GenerationError::UnsatisfiableWaitSet);
        }
        // The timer badge is C9.1's own, so only a timer source may claim it and
        // a timer source must.
        if timer_badge != (entry.kind == wait_set::SourceKind::Timer) {
            return Err(GenerationError::UnsatisfiableWaitSet);
        }
    }
    Ok(Some(sources.entry_count()))
}

/// Locate the generation-authenticated scheduling-class resource, if declared.
///
/// First match wins including a malformed one, on [`clock_authority_object`]'s
/// rule: continuing would make a component's priority band depend on object
/// ordering, and could silently select a later, more permissive policy.
///
/// Public so the launch path resolves each thread's band from the object
/// admission validated rather than locating the resource a second way — the
/// second-lookup shape that let the boot-layout resource drift from the
/// bindings it described (B71).
pub fn scheduling_class_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<SchedulingClass<'a>, scheduling_class::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE
            && object.bytes.len() >= scheduling_class::MAGIC.len()
            && object.bytes[..scheduling_class::MAGIC.len()] == scheduling_class::MAGIC
        {
            return Some(SchedulingClass::decode(object.bytes));
        }
    }
    None
}

/// Validate a declared scheduling-class policy, reporting how many instances it
/// names.
///
/// The decoder already owns the resource's internal consistency — bands
/// ascending and distinct, no self-promotion edge, every ceiling naming a
/// declared band. What this adds is the half only the generation knows: every
/// identity the policy names must be an instance this generation declares, and
/// every promotion holder must actually hold `schedulingPromote` on a grant it
/// is the source of. Without the second rule a policy could declare an edge no
/// operation can reach, which reads at runtime as a promotion that silently
/// never applies.
fn scheduling_class_admission(
    generation: &Generation<'_>,
) -> Result<Option<usize>, GenerationError> {
    let Some(policy) = scheduling_class_object(generation) else {
        return Ok(None);
    };
    let policy = policy.map_err(|_| GenerationError::UnsatisfiableSchedulingClass)?;
    let named = |identity: &[u8; 32]| -> Result<usize, GenerationError> {
        for index in 0..generation.instance_count() {
            let instance = generation
                .instance(index)
                .map_err(|_| GenerationError::UnsatisfiableSchedulingClass)?;
            if scheduling_class::instance_identity(instance.name) == *identity {
                return Ok(index);
            }
        }
        Err(GenerationError::UnsatisfiableSchedulingClass)
    };
    for index in 0..policy.instance_count() {
        let entry = policy
            .assignment(index)
            .ok_or(GenerationError::UnsatisfiableSchedulingClass)?;
        named(&entry.subject_identity)?;
    }
    for index in 0..policy.promotion_count() {
        let entry = policy
            .promotion(index)
            .ok_or(GenerationError::UnsatisfiableSchedulingClass)?;
        let holder = named(&entry.holder_identity)?;
        // The subject must be an instance this holder actually owns. That is the
        // half only the generation knows, and it is what makes the edge
        // reachable: the root mints the promotion bit onto the supervision
        // handle a *spawner* receives for its child, so an edge naming a subject
        // this holder does not own could never resolve to a capability and would
        // read at runtime as a declared policy that silently never applies.
        let subject = named(&entry.subject_identity)?;
        let owner = generation
            .instance(subject)
            .map_err(|_| GenerationError::UnsatisfiableSchedulingClass)?
            .owner;
        if owner != boot_contracts::generation::InstanceOwner::Instance(holder) {
            return Err(GenerationError::UnsatisfiableSchedulingClass);
        }
    }
    Ok(Some(policy.instance_count()))
}

/// Locate the generation-authenticated lifecycle-policy resource, if declared.
///
/// First match wins including a malformed one, on [`scheduling_class_object`]'s
/// rule: continuing would make a component's restart bound depend on object
/// ordering, and could silently select a later, more permissive policy.
///
/// Public so the launch and service paths resolve the policy the admission
/// validated rather than locating the resource a second way — the second-lookup
/// shape that let the boot-layout resource drift from the bindings it described
/// (B71).
pub fn lifecycle_policy_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<LifecyclePolicy<'a>, lifecycle_policy::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE
            && object.bytes.len() >= lifecycle_policy::MAGIC.len()
            && object.bytes[..lifecycle_policy::MAGIC.len()] == lifecycle_policy::MAGIC
        {
            return Some(LifecyclePolicy::decode(object.bytes));
        }
    }
    None
}

/// Validate a declared lifecycle policy, reporting how many restart bounds it
/// declares.
///
/// The decoder owns the resource's internal consistency — the transition graph's
/// order and endpoints, the attempt ceiling, the cause vocabulary, the backoff
/// range, the parameter flags. What this adds is the half only the generation
/// knows, and each of the three rules closes a "declared but unreachable" gap:
///
/// * every identity the policy names is an instance this generation declares, so
///   no row can name a subject the root could never resolve;
/// * every restart subject is *owned* by some declared instance, because the
///   `lifecycleRestart` right rides on the supervision handle a spawner receives
///   for its own child. A root-autostart instance has no such holder, so a
///   restart bound on one could never be charged through `RESTART_ADMIT` and
///   would read at runtime as supervision that silently never applies — exactly
///   the shape C9.3's promotion-ownership rule refuses;
/// * every health dependency's dependency is a declared instance, so a start
///   cannot wait on a state nothing can ever be in.
fn lifecycle_policy_admission(
    generation: &Generation<'_>,
) -> Result<Option<usize>, GenerationError> {
    let Some(policy) = lifecycle_policy_object(generation) else {
        return Ok(None);
    };
    let policy = policy.map_err(|_| GenerationError::UnsatisfiableLifecyclePolicy)?;
    let named = |identity: &[u8; 32]| -> Result<usize, GenerationError> {
        for index in 0..generation.instance_count() {
            let instance = generation
                .instance(index)
                .map_err(|_| GenerationError::UnsatisfiableLifecyclePolicy)?;
            if lifecycle_policy::instance_identity(instance.name) == *identity {
                return Ok(index);
            }
        }
        Err(GenerationError::UnsatisfiableLifecyclePolicy)
    };
    // Tallied here rather than returned as `policy.restart_count()`, and the
    // difference is the whole value of the number. A count read straight off the
    // resource would make the startup cross-check compare the decode to itself
    // (found by review); this counts the subjects admission *proved* are
    // owner-spawned, which is a fact only the generation's ownership forest
    // establishes. A disagreement with the resource's own count then means a
    // restart row was skipped, which is the drift B71 closed.
    let mut admitted_restarts = 0usize;
    for index in 0..policy.restart_count() {
        let entry = policy
            .restart(index)
            .ok_or(GenerationError::UnsatisfiableLifecyclePolicy)?;
        let subject = named(&entry.subject_identity)?;
        // A restart bound is charged through a supervision handle, and the root
        // mints one only for a spawner over its own child. An instance the root
        // itself autostarts has no such holder anywhere in the graph.
        if !matches!(
            generation
                .instance(subject)
                .map_err(|_| GenerationError::UnsatisfiableLifecyclePolicy)?
                .owner,
            boot_contracts::generation::InstanceOwner::Instance(_)
        ) {
            return Err(GenerationError::UnsatisfiableLifecyclePolicy);
        }
        admitted_restarts += 1;
    }
    for index in 0..policy.dependency_count() {
        let entry = policy
            .dependency(index)
            .ok_or(GenerationError::UnsatisfiableLifecyclePolicy)?;
        let subject = named(&entry.subject_identity)?;
        named(&entry.dependency_identity)?;
        // A dependency gates a *start*, and the only start it can gate is a
        // `SPAWN`: the root's own autostart path evaluates `Instance.dependencies`
        // — a one-shot activation barrier — and not this table. So an edge whose
        // subject the root autostarts would decode, admit, and never be
        // evaluated, which reads as a start condition the graph honours while the
        // subject launches regardless. The same rule the restart bound above
        // enforces, for the same reason (found by review).
        if !matches!(
            generation
                .instance(subject)
                .map_err(|_| GenerationError::UnsatisfiableLifecyclePolicy)?
                .owner,
            boot_contracts::generation::InstanceOwner::Instance(_)
        ) {
            return Err(GenerationError::UnsatisfiableLifecyclePolicy);
        }
    }
    for index in 0..policy.parameter_count() {
        let entry = policy
            .parameter(index)
            .ok_or(GenerationError::UnsatisfiableLifecyclePolicy)?;
        named(&entry.holder_identity)?;
        named(&entry.subject_identity)?;
    }
    Ok(Some(admitted_restarts))
}
/// The generation's C9.5 recording resource, if it declares one.
///
/// First match by magic, and a malformed first match is *returned* rather than
/// skipped: continuing to a later valid object would let object order select
/// which determinism policy applies (B71).
pub fn recording_policy_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<RecordingPolicy<'a>, recording_policy::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE
            && object.bytes.len() >= recording_policy::MAGIC.len()
            && object.bytes[..recording_policy::MAGIC.len()] == recording_policy::MAGIC
        {
            return Some(RecordingPolicy::decode(object.bytes));
        }
    }
    None
}

pub fn instance_lifetime_object<'a>(
    generation: &Generation<'a>,
) -> Option<Result<InstanceLifetime<'a>, instance_lifetime::DecodeError>> {
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind == KIND_RESOURCE && object.bytes.starts_with(&instance_lifetime::MAGIC) {
            return Some(InstanceLifetime::decode(object.bytes));
        }
    }
    None
}

/// The arrival ceiling the resource objects declare, judged with the boot
/// action they ride on: `None` when no object carries one, otherwise the one
/// decoded ceiling. More than one object, an object that does not decode, and
/// any ceiling on a product generation are refused: a product graph has no
/// ceiling, so carrying one there would claim a bound the root never applies.
fn declared_arrival_ceiling<'a>(
    boot_action: BootAction,
    resources: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Option<usize>, GenerationError> {
    let mut declared = None;
    for bytes in resources {
        if !bytes.starts_with(&graph_arrival_ceiling::MAGIC) {
            continue;
        }
        let ceiling = GraphArrivalCeiling::decode(bytes)
            .map_err(|_| GenerationError::UnsatisfiableGraphArrivalCeiling)?;
        if declared.replace(ceiling.arrivals()).is_some() {
            return Err(GenerationError::UnsatisfiableGraphArrivalCeiling);
        }
    }
    if declared.is_some() && boot_action == BootAction::Product {
        return Err(GenerationError::UnsatisfiableGraphArrivalCeiling);
    }
    Ok(declared)
}

/// The ceiling verdict over this generation's resource objects. An object the
/// table cannot yield is left to the admission loop that refuses it.
fn graph_arrival_ceiling_verdict(
    generation: &Generation<'_>,
) -> Result<Option<usize>, GenerationError> {
    let resources = (0..generation.object_count())
        .filter_map(|index| generation.object(index).ok())
        .filter(|object| object.kind == KIND_RESOURCE)
        .map(|object| object.bytes);
    declared_arrival_ceiling(generation.boot_action, resources)
}

/// The component arrivals a finite plane's graph service handles when the
/// generation declares a ceiling, or `None` when it keeps the root's default.
/// Admission has already refused a malformed or misplaced ceiling, so a
/// refusal here reads as no declaration rather than a second verdict.
pub fn graph_arrival_ceiling(generation: &Generation<'_>) -> Option<usize> {
    graph_arrival_ceiling_verdict(generation).ok().flatten()
}

/// Every resident row names an instance this generation declares, so a
/// resident declaration can never silently fail to apply.
fn instance_lifetime_admission(generation: &Generation<'_>) -> Result<(), GenerationError> {
    let Some(table) = instance_lifetime_object(generation) else {
        return Ok(());
    };
    let table = table.map_err(|_| GenerationError::UnsatisfiableInstanceLifetime)?;
    for index in 0..table.row_count() {
        let identity = table
            .resident(index)
            .ok_or(GenerationError::UnsatisfiableInstanceLifetime)?;
        let mut named = false;
        for candidate in 0..generation.instance_count() {
            let instance = generation
                .instance(candidate)
                .map_err(|_| GenerationError::UnsatisfiableInstanceLifetime)?;
            if instance_lifetime::instance_identity(instance.name) == identity {
                named = true;
                break;
            }
        }
        if !named {
            return Err(GenerationError::UnsatisfiableInstanceLifetime);
        }
    }
    Ok(())
}

/// The declared lifetime of `instance`. Bounded when the generation carries no
/// lifetime object or does not name the instance; admission has already refused
/// a malformed object.
pub fn instance_lifetime(generation: &Generation<'_>, instance: usize) -> Lifetime {
    let Some(Ok(table)) = instance_lifetime_object(generation) else {
        return Lifetime::Bounded;
    };
    match generation.instance(instance) {
        Ok(instance) => table.lifetime_of(&instance_lifetime::instance_identity(instance.name)),
        Err(_) => Lifetime::Bounded,
    }
}

/// Every right `instance` holds at launch, excluding the one grant its recording
/// stream travels over.
///
/// Derived from the instance's own *bindings* under
/// [`Generation::grant_applies_to_instance`] — the same rule
/// [`bound_authority`] and the launch path use — rather than by comparing
/// `grant.target` to the instance. The two differ: an executable capability's
/// target is an `Executable`, so a target comparison silently drops every
/// executable grant a component is bound, and a deterministic instance bound
/// `spawn` would have been admitted (found by review). Minted bindings are read
/// alongside because the root installs those as authority too.
///
/// `exempt_grant` is the declared stream grant from `recording-policy/v1`, and
/// subtracting it is what makes the determinism claim expressible at all: every
/// authority carrying bytes into a component is an unrecorded source, `recv`
/// included, so a replayer needs exactly one to receive the recording it
/// replays. One named edge is excused and every other authority is checked
/// unchanged, which is a declared exception rather than a hole.
fn instance_held_rights(
    generation: &Generation<'_>,
    instance: usize,
    exempt_grant: Option<u64>,
) -> Result<u64, GenerationError> {
    let record = generation
        .instance(instance)
        .map_err(|_| GenerationError::UnsatisfiableRecordingPolicy)?;
    let mut held = 0u64;
    for index in 0..record.binding_count() {
        let InstanceBinding { grant, .. } = generation
            .binding(record, index)
            .map_err(|_| GenerationError::UnsatisfiableRecordingPolicy)?;
        let grant = generation
            .grant(grant)
            .map_err(|_| GenerationError::UnsatisfiableRecordingPolicy)?;
        if !generation.grant_applies_to_instance(grant, instance) {
            continue;
        }
        if exempt_grant
            .is_some_and(|exempt| recording_policy::stream_grant_identity(grant.name) == exempt)
        {
            continue;
        }
        held |= grant.rights;
    }
    for index in 0..generation.minted_binding_count() {
        let minted = generation
            .minted_binding(index)
            .map_err(|_| GenerationError::UnsatisfiableRecordingPolicy)?;
        if minted.holder != instance {
            continue;
        }
        if exempt_grant
            .is_some_and(|exempt| recording_policy::stream_grant_identity(minted.name) == exempt)
        {
            continue;
        }
        held |= minted.rights;
    }
    Ok(held)
}

/// Validate a declared recording resource, reporting how many entries it
/// declares.
///
/// The decoder owns the resource's internal consistency — its order, its role
/// vocabulary, its capacity ceiling, and the one-recorder-one-replayer pairing
/// of every stream. What this adds is the half only the generation knows, and it
/// is C9.5's second required check:
///
/// * every identity the resource names is an instance this generation declares,
///   so no entry can name a participant the root could never resolve;
/// * an entry claiming `deterministic` is refused when the generation grants
///   that instance any right whose declared `determinism` class is `unrecorded`.
///
/// The second rule is re-derived here rather than trusted from the builder, and
/// that is deliberate: the builder computes it over manifest names, this
/// computes it over the *encoded* grant table the root will actually install
/// from, and both read the same generated `RIGHT_UNRECORDED` mask. A generation
/// hand-edited between build and boot to add an unrecorded grant is refused
/// here, which is what makes the claim a property of the admitted generation
/// rather than of the tool that wrote it.
///
/// Refusal is at admission rather than at replay because a component that got
/// half way through a replay before discovering its inputs were never captured
/// has already produced output nobody can compare.
fn recording_policy_admission(
    generation: &Generation<'_>,
) -> Result<Option<usize>, GenerationError> {
    let Some(policy) = recording_policy_object(generation) else {
        return Ok(None);
    };
    let policy = policy.map_err(|_| GenerationError::UnsatisfiableRecordingPolicy)?;
    for index in 0..policy.entry_count() {
        let entry = policy
            .entry(index)
            .ok_or(GenerationError::UnsatisfiableRecordingPolicy)?;
        let mut named = None;
        for candidate in 0..generation.instance_count() {
            let instance = generation
                .instance(candidate)
                .map_err(|_| GenerationError::UnsatisfiableRecordingPolicy)?;
            if recording_policy::instance_identity(instance.name) == entry.instance_identity {
                named = Some(candidate);
                break;
            }
        }
        let Some(instance) = named else {
            return Err(GenerationError::UnsatisfiableRecordingPolicy);
        };
        // A declared stream grant must be a grant this instance is actually
        // bound, or the exemption would name nothing and silently excuse
        // whichever authority the composition intended it to cover.
        if let Some(exempt) = entry.stream_grant_identity {
            let bound = (0..generation
                .instance(instance)
                .map_err(|_| GenerationError::UnsatisfiableRecordingPolicy)?
                .binding_count())
                .filter_map(|index| {
                    let record = generation.instance(instance).ok()?;
                    let InstanceBinding { grant, .. } = generation.binding(record, index).ok()?;
                    generation.grant(grant).ok()
                })
                .any(|grant| recording_policy::stream_grant_identity(grant.name) == exempt);
            if !bound {
                return Err(GenerationError::UnsatisfiableRecordingPolicy);
            }
        }
        if entry.deterministic
            && instance_held_rights(generation, instance, entry.stream_grant_identity)?
                & boot_contracts::generation::RIGHT_UNRECORDED
                != 0
        {
            return Err(GenerationError::UnsatisfiableRecordingPolicy);
        }
    }
    Ok(Some(policy.entry_count()))
}
/// Whether the generation's recording resource claims `instance` deterministic.
///
/// The runtime half of [`recording_policy_admission`]'s refusal. Admission
/// certifies the claim against the authority a generation *declares*; this lets a
/// path that would hand the instance more authority ask whether the claim exists,
/// so the certification stays true after launch rather than only at it.
///
/// Absence answers `false` at every step — no resource, an undecodable one, an
/// unnamed instance, or a named one carrying no claim — because none of those is
/// a determinism claim, and a path that widens authority must not be blocked by
/// a resource it cannot read.
pub fn recording_declares_deterministic(generation: &Generation<'_>, instance: usize) -> bool {
    let Some(Ok(policy)) = recording_policy_object(generation) else {
        return false;
    };
    let Ok(record) = generation.instance(instance) else {
        return false;
    };
    policy.is_deterministic(&recording_policy::instance_identity(record.name))
}

/// Whether the admitted generation target can honour its private-memory budget.
///
/// Capacity is selected from the authenticated generation target, while the
/// image-target equality is enforced by the existing target admission path.
pub fn private_memory_budget_is_satisfiable(
    budget: &PrivateMemoryBudget<'_>,
    target: &str,
) -> Result<(), GenerationError> {
    if target != crate::private_memory::IMAGE_TARGET_NAME {
        return Err(GenerationError::UnsatisfiablePrivateMemoryBudget);
    }
    let (region_pages, total_pages) = boot_contracts::private_memory_budget::capacity_for(target);
    budget
        .validate_against(region_pages as u32, total_pages as u32)
        .map_err(|_| GenerationError::UnsatisfiablePrivateMemoryBudget)
}

/// Validate a declared private-memory budget against this root's ceilings,
/// reporting how many holders it names.
///
/// A generation declaring no budget is not an error: it declares that no
/// component may grow a page, and every holder resolves to zero. A *malformed*
/// one is, and that is the difference from the C7.3 path, which treats a
/// malformed budget as absent. The two are asymmetric on purpose. Deny-by-default
/// makes an undecodable shared-buffer budget harmless — every holder is refused,
/// which is the conservative answer. But C10.2's exit condition requires that
/// every malformed budget fail the generation closed, because a budget that
/// silently reads as absent is indistinguishable from one a component was
/// promised and never got: the component simply cannot allocate, and the boot
/// looks healthy. Failing here names the real fault before anything launches.
fn private_memory_budget_admission(
    generation: &Generation<'_>,
) -> Result<Option<usize>, GenerationError> {
    let Some(bytes) = private_memory_object(generation)? else {
        return Ok(None);
    };
    let version = private_memory_version(bytes)?;
    if version == private_memory_policy::FORMAT_VERSION {
        let mut instances = [private_memory_policy::Instance {
            identity: [0; 32],
            owner: None,
        }; MAX_ADMITTED_INSTANCES];
        let count = private_memory_instances(generation, &mut instances)?;
        return adaptive_private_memory_activation(bytes, &instances[..count]);
    }
    if version != private_memory_budget::FORMAT_VERSION {
        return Err(GenerationError::UnsupportedPrivateMemoryPolicy);
    }
    let budget = PrivateMemoryBudget::decode(bytes)
        .map_err(|_| GenerationError::UnsatisfiablePrivateMemoryBudget)?;
    private_memory_budget_is_satisfiable(&budget, generation.target)?;
    Ok(Some(budget.holder_count()))
}

/// Admit an adaptive policy's structure against this generation's topology.
///
/// Structure only. Whether the machine can actually reserve every guarantee is
/// a question about inventory the allocator owns, and it is answered by
/// [`admit_private_memory_ledger`] before any task is published; deciding it
/// here would compare a policy against a pool this code cannot see.
fn adaptive_private_memory_activation(
    bytes: &[u8],
    instances: &[private_memory_policy::Instance],
) -> Result<Option<usize>, GenerationError> {
    let policy = PrivateMemoryPolicy::decode(bytes)
        .map_err(|_| GenerationError::MalformedPrivateMemoryPolicy)?;
    policy
        .validate_instances(instances)
        .map_err(|_| GenerationError::MalformedPrivateMemoryPolicy)?;
    Ok(Some(policy.subject_count()))
}

/// Reserve an adaptive policy's guarantees against the real ordinary pool.
///
/// The resource half of admission, and the reason it takes an allocator: a
/// policy is admissible only against the inventory this machine actually has,
/// after its own operational reserve and every already-committed root
/// allocation. Each entitlement's guarantee is reserved in full and
/// simultaneously, with a conservative per-page envelope that covers the
/// page's bytes and its table, descriptor, extent and slot alike. Elastic
/// maxima are never summed: permission to ask is not a promise, and adding
/// them would refuse compositions this machine can serve.
///
/// Nothing is physically provisioned here. The ledger records what is
/// reserved so a later growth cannot spend another holder's guarantee.
///
/// `residual` is the inventory left *after* every guarantee was reserved. The
/// ledger subtracts each guarantee's envelope itself, so the envelopes are
/// added back first: subtracting them from a residual that no longer contains
/// them would strand that much ordinary memory in neither the pool nor any
/// guarantee.
pub fn admit_private_memory_ledger<'a>(
    policy: PrivateMemoryPolicy<'a>,
    instances: &[private_memory_policy::Instance],
    residual: private_memory_policy::ledger::Resources,
) -> Result<private_memory_policy::ledger::Ledger<'a>, private_memory_policy::ledger::Error> {
    use private_memory_policy::ledger::{Error, Resources};
    let mut guarantees = [Resources::ZERO; private_memory_policy::MAX_ENTITLEMENTS];
    let count = policy.entitlement_count();
    if count > guarantees.len() {
        return Err(Error::Guarantee);
    }
    let mut available = residual;
    for (index, slot) in guarantees.iter_mut().enumerate().take(count) {
        let entitlement = policy.entitlement(index).ok_or(Error::Guarantee)?;
        *slot = guarantee_reservation_resources(entitlement.guarantee_pages)?;
        available = available.checked_add(*slot)?;
    }
    private_memory_policy::ledger::Ledger::admit(policy, instances, available, &guarantees[..count])
}

/// Why an admitted policy's guarantees could not be made physical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuaranteeReservationError {
    /// More entitlements carry a guarantee than the allocator can hold
    /// identities for. Refused whole: reserving a prefix would publish a graph
    /// whose later entitlements promise backing nobody owns.
    Entitlements {
        declared: usize,
        limit: usize,
    },
    Overflow,
    Backing(guarantee_vault::ReservationError),
}

/// Every entitlement's guarantee, made physical simultaneously.
///
/// Holds only what was actually materialized. `reserved_bytes`/
/// `reserved_extents`/`reserved_anchor_slots` are read back from the
/// allocator after the fact, never from the request, so a caller reporting
/// them is reporting ownership rather than an intention.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuaranteeReservations {
    entries: [Option<(usize, guarantee_vault::ReservationId)>; guarantee_vault::MAX_RESERVATIONS],
    len: usize,
    pub guarantee_pages: u64,
    pub reserved_bytes: usize,
    pub reserved_extents: usize,
    /// Root CSlots this reservation holds: one spent anchor per backing
    /// extent, plus the count withheld from every ordinary consumer.
    pub reserved_slots: usize,
    /// Allocation descriptors withheld from every ordinary consumer.
    pub reserved_descriptors: usize,
    /// Leaf tables the reserved table extents are funded to hold: one per
    /// guaranteed page, which is the conservative bound for a cohort whose
    /// pages can land one per span across several address spaces.
    pub reserved_tables: u64,
}

impl GuaranteeReservations {
    /// The reservation funding one entitlement, or `None` when it promises
    /// nothing.
    pub fn reservation_for(&self, entitlement: usize) -> Option<guarantee_vault::ReservationId> {
        self.entries[..self.len]
            .iter()
            .flatten()
            .find(|(index, _)| *index == entitlement)
            .map(|(_, id)| *id)
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return every reservation to common capacity.
    ///
    /// Used to fail an admission closed. A reservation with backing already
    /// borrowed refuses to close, and that refusal is reported rather than
    /// ignored: capacity a holder still owns is not free.
    pub fn release(
        &mut self,
        allocator: &mut ObjectAllocator,
    ) -> Result<(), guarantee_vault::ReservationError> {
        let mut failure = None;
        for (_, id) in self.entries[..self.len].iter().flatten() {
            if let Err(error) = allocator.close_reservation(*id) {
                failure = Some(error);
            }
        }
        self.len = 0;
        self.entries = [None; guarantee_vault::MAX_RESERVATIONS];
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// Make every entitlement's guarantee physical, all of them or none.
///
/// Runs before any task is constructed: a guarantee that static construction
/// could still spend is not a guarantee, so the reservation takes its backing
/// out of the pool first and a construction that then cannot be funded fails
/// the boot closed. Elastic maxima are never summed — only `guaranteePages`
/// is reserved, and an entitlement promising nothing reserves nothing and
/// takes no identity.
///
/// What is reserved is backing extents. Allocation descriptors, root CSlots
/// beyond each extent's own parent anchor, and metadata pages are still taken
/// from the common pool when a growth uses them, so this is not yet the
/// complete funded tuple [`admit_private_memory_ledger`] prices.
pub fn reserve_private_memory_guarantees(
    allocator: &mut ObjectAllocator,
    policy: PrivateMemoryPolicy<'_>,
) -> Result<GuaranteeReservations, GuaranteeReservationError> {
    let declared = (0..policy.entitlement_count())
        .filter(|index| {
            policy
                .entitlement(*index)
                .is_some_and(|entitlement| entitlement.guarantee_pages != 0)
        })
        .count();
    if declared > guarantee_vault::MAX_RESERVATIONS {
        return Err(GuaranteeReservationError::Entitlements {
            declared,
            limit: guarantee_vault::MAX_RESERVATIONS,
        });
    }
    let mut promised = [(0usize, 0u64); guarantee_vault::MAX_RESERVATIONS];
    let mut len = 0;
    for index in 0..policy.entitlement_count() {
        let Some(entitlement) = policy.entitlement(index) else {
            continue;
        };
        if entitlement.guarantee_pages != 0 {
            promised[len] = (index, entitlement.guarantee_pages);
            len += 1;
        }
    }
    reserve_guarantee_pages(allocator, &promised[..len])
}

/// The reservation loop, over the guarantees a policy resolved to.
///
/// Separated from decoding so the all-or-none boundary can be driven directly:
/// what must hold is that a second entitlement the machine cannot fund leaves
/// the first one's backing returned, not that a particular encoding produced
/// the numbers.
pub(crate) fn reserve_guarantee_pages(
    allocator: &mut ObjectAllocator,
    promised: &[(usize, u64)],
) -> Result<GuaranteeReservations, GuaranteeReservationError> {
    if promised.len() > guarantee_vault::MAX_RESERVATIONS {
        return Err(GuaranteeReservationError::Entitlements {
            declared: promised.len(),
            limit: guarantee_vault::MAX_RESERVATIONS,
        });
    }
    let mut reservations = GuaranteeReservations::default();
    for (index, pages) in promised.iter().copied() {
        // An entitlement promising nothing takes no identity: the table is
        // small, and an empty reservation would spend one for a promise
        // nobody can redeem.
        if pages == 0 {
            continue;
        }
        let spans = usize::try_from(guarantee_vault::spans_for_pages(pages))
            .map_err(|_| GuaranteeReservationError::Overflow)?;
        let envelope =
            guaranteed_page_envelope().map_err(|_| GuaranteeReservationError::Overflow)?;
        let fungible = |unit: u64| {
            pages
                .checked_mul(unit)
                .and_then(|total| usize::try_from(total).ok())
                .ok_or(GuaranteeReservationError::Overflow)
        };
        // The anchors the spans themselves spend are not withheld here: they
        // are already gone from the pool, and withholding them again would
        // charge one CSlot twice.
        let descriptors = fungible(envelope.descriptors)?;
        let slots = fungible(envelope.slots)?;
        let opened = allocator.open_reservation().and_then(|id| {
            // The identity is closed here rather than by the rollback below,
            // because an identity whose backing was refused is not in the
            // published set and would otherwise be held for the whole boot.
            if let Err(error) = allocator
                .reserve_guarantee_spans(id, spans)
                .and_then(|()| allocator.reserve_guarantee_resources(id, descriptors, slots))
            {
                let _ = allocator.close_reservation(id);
                return Err(error);
            }
            Ok(id)
        });
        match opened {
            Ok(id) => {
                reservations.entries[reservations.len] = Some((index, id));
                reservations.len += 1;
                reservations.guarantee_pages = reservations
                    .guarantee_pages
                    .checked_add(pages)
                    .ok_or(GuaranteeReservationError::Overflow)?;
            }
            Err(error) => {
                let _ = reservations.release(allocator);
                return Err(GuaranteeReservationError::Backing(error));
            }
        }
    }
    // Read back rather than accumulated: these are the totals a boot reports,
    // and they must describe extents the allocator owns right now.
    for (_, id) in reservations.entries[..reservations.len].iter().flatten() {
        let backing = allocator
            .reservation_backing(*id)
            .map_err(GuaranteeReservationError::Backing)?;
        reservations.reserved_bytes += backing.bytes;
        reservations.reserved_extents += backing.extents;
        // One retained parent capability per backing extent, on top of the
        // count withheld from ordinary consumers.
        reservations.reserved_slots += backing.extents;
    }
    reservations.reserved_slots += allocator.reserved_slots();
    reservations.reserved_descriptors = allocator.reserved_descriptors();
    reservations.reserved_tables = reservations.guarantee_pages;
    Ok(reservations)
}

/// What one entitlement's guarantee actually costs the machine.
///
/// The larger of two true lower bounds, component by component, because both
/// can dominate: the per-page envelope is what the pages cost at their worst
/// placement, and the span shape is what the reservation physically takes.
/// A guarantee smaller than one span still removes a whole aligned span from
/// the pool, so pricing it at the per-page envelope alone would admit a policy
/// against bytes the reservation had already taken.
pub fn guarantee_reservation_resources(
    pages: u64,
) -> Result<private_memory_policy::ledger::Resources, private_memory_policy::ledger::Error> {
    use private_memory_policy::ledger::{Error, Resources};
    if pages == 0 {
        return Ok(Resources::ZERO);
    }
    let page = guaranteed_page_envelope()?;
    let spans = guarantee_vault::spans_for_pages(pages);
    let span_bytes = 1u64
        .checked_shl(guarantee_vault::GUARANTEE_SPAN_BITS as u32)
        .ok_or(Error::Overflow)?;
    let per_page = |unit: u64| pages.checked_mul(unit).ok_or(Error::Overflow);
    // Two extents per span, payload and tables, each of one span's size.
    let span_extents = spans.checked_mul(2).ok_or(Error::Overflow)?;
    let span_total = span_extents
        .checked_mul(span_bytes)
        .ok_or(Error::Overflow)?;
    Ok(Resources {
        bytes: per_page(page.bytes)?.max(span_total),
        // Per page: one CSlot for the frame and one for its worst-case leaf
        // table. Per extent: the parent anchor the reservation retains.
        slots: per_page(page.slots)?
            .checked_add(span_extents)
            .ok_or(Error::Overflow)?,
        descriptors: per_page(page.descriptors)?,
        // Coarse parents, not one per page: one aligned extent owns every
        // page retyped inside it, which is what lets a cohort member take a
        // page without stranding the rest of that span from its peers.
        extents: span_extents,
        tables: per_page(page.tables)?,
    })
}

/// The complete resource cost of one guaranteed page, at its worst placement.
///
/// Priced by the same demand code a growth is charged with rather than
/// restated here. The worst case for a guaranteed page is its own base page
/// plus its own leaf table, because a cohort's pages can land one per span
/// across several address spaces; deriving the tuple is what stops an envelope
/// from drifting away from what a transaction actually costs, which is the
/// drift that makes a guarantee unfundable at the moment it is redeemed.
///
/// A reservation whose extents are coarser — one aligned 2 MiB block backing a
/// whole span of base pages — costs strictly fewer extents and slots than this
/// bound and exactly these bytes, descriptors and tables, so the bound stays
/// conservative for the shape the allocator actually reserves.
fn guaranteed_page_envelope()
-> Result<private_memory_policy::ledger::Resources, private_memory_policy::ledger::Error> {
    let demand = crate::object_allocator::elastic::ElasticRequest {
        large_frames: 0,
        base_pages: 1,
        tables: 1,
    }
    .demand()
    .map_err(|_| private_memory_policy::ledger::Error::Guarantee)?
    .resources();
    // The demand prices a page that brings its own extents, because that is
    // what an elastic growth does. A guaranteed page is retyped inside an
    // extent its reservation already owns, so the parent anchors and the
    // extent records are charged to the span instead. What remains here is
    // the page's own objects: its frame, its worst-case leaf table, and the
    // CSlot and descriptor each of those needs.
    Ok(private_memory_policy::ledger::Resources {
        slots: demand
            .slots
            .checked_sub(demand.extents)
            .ok_or(private_memory_policy::ledger::Error::Overflow)?,
        extents: 0,
        ..demand
    })
}

/// The result of admitting a v5 generation graph.
pub struct Admission {
    executable_plans: [Option<ExecutablePlan>; MAX_ADMITTED_EXECUTABLES],
    executable_len: usize,
    instance_indices: [usize; MAX_ADMITTED_INSTANCES],
    instance_len: usize,
    pub bootstrap_instance: usize,
    pub bootstrap_objects: usize,
    pub component_objects: usize,
    pub grants: usize,
    pub health: usize,
    pub loadable: usize,
    pub slime_component_images: usize,
    pub unrecognized_images: usize,
    pub wrong_target_images: usize,
    /// Root CSlots required by the admitted product graph before future private
    /// capacity holders are added. Filled from the actual BootInfo span in
    /// `main` after aggregate slot admission succeeds.
    pub required_root_slots: usize,
    pub fabric_graph_admitted: bool,
    pub fabric_schemas: usize,
    pub fabric_routes: usize,
    pub fabric_participants: usize,
    pub fabric_interpositions: usize,
    /// The declared `capabilitySlots` ceiling, or 0 when this generation
    /// declares no fabric graph (C8.13.3).
    ///
    /// Zero always means "no ceiling to report against". A graph that declares
    /// the field may itself declare zero — the decoder bounds it only from
    /// above — so `crate::cspace::breaches_ceiling` treats both cases alike
    /// rather than distinguishing an absent graph from a permissive one.
    pub fabric_capability_slots: u32,
    /// Holders named by the authenticated clock-authority resource, or `None`
    /// when the generation declares no clock authority at all (C9.1).
    pub clock_holders: Option<usize>,
    /// Holders the generation's private-memory budget names, or `None` when it
    /// declares no budget at all (C10.2).
    ///
    /// `None` and `Some(0)` are distinguished because a boot marker must be
    /// able to say "nothing to honour" apart from "a budget that names nobody":
    /// both deny every component, but only the second means the generation
    /// carries a budget resource whose contents a gate can check.
    pub private_memory_holders: Option<usize>,
    pub io_resource_drivers: Option<usize>,
    /// Wake sources named by the authenticated wait-set resource, or `None` when
    /// the generation declares none at all (C9.2).
    ///
    /// `None` and `Some(0)` are distinguished for the reason
    /// `private_memory_holders` is: both leave every waiter with nothing to
    /// register, but only the second carries a resource whose contents a gate can
    /// check.
    pub wait_set_sources: Option<usize>,
    /// Instances named by the authenticated scheduling-class resource, or `None`
    /// when the generation declares no class policy at all (C9.3).
    ///
    /// `None` and `Some(0)` are distinguished on `wait_set_sources`' rule: both
    /// leave every instance at the root's default priority, but only the second
    /// carries a policy whose band mapping a gate can check.
    pub scheduling_instances: Option<usize>,
    /// Instances the authenticated lifecycle policy declares a restart bound
    /// for, or `None` when the generation declares no lifecycle policy at all
    /// (C9.4).
    ///
    /// `None` and `Some(0)` are distinguished on `scheduling_instances`' rule: a
    /// policy declaring a transition graph but no restart bound is a real
    /// composition — nothing restarts, but every transition is still admitted —
    /// and it is not the same as carrying no policy, where every transition is
    /// refused too.
    pub lifecycle_restarts: Option<usize>,
    /// Participants the authenticated recording resource names, or `None` when
    /// the generation declares no recording at all (C9.5).
    ///
    /// `None` and `Some(0)` are distinguished on `lifecycle_restarts`' rule:
    /// neither admits a determinism claim, but only the second carries a resource
    /// whose declared streams and capacities a gate can check.
    pub recording_entries: Option<usize>,
}

impl Admission {
    pub fn admit(
        generation: &Generation<'_>,
        profile: &TargetProfile,
    ) -> Result<Self, GenerationError> {
        if !generation.is_v5() {
            return Err(GenerationError::UnsupportedGenerationVersion);
        }
        let executable_len = generation.executable_count();
        if executable_len > MAX_ADMITTED_EXECUTABLES {
            return Err(GenerationError::TooManyExecutables {
                declared: executable_len,
                limit: MAX_ADMITTED_EXECUTABLES,
            });
        }
        let instance_len = generation.instance_count();
        if instance_len > MAX_ADMITTED_INSTANCES {
            return Err(GenerationError::TooManyInstances {
                declared: instance_len,
                limit: MAX_ADMITTED_INSTANCES,
            });
        }
        // B49: the object plan is proven to fit before anything activates.
        //
        // The quota record says how many CNodes, TCBs, endpoints, frames, and
        // CSlots each process needs. Checking it here rather than discovering
        // it during construction is the difference between a graph refused
        // whole and one that half-activates and then fails to place a
        // capability -- at which point some children are already running.
        //
        // Per class, not as a total: a plan that needs one CSlot too many is a
        // different defect from one that needs an extra TCB, and a single
        // "too big" would say neither.
        let (image_limit, aggregate_limit) = component_image::capacity_for(profile.name);
        let mut image_pages = 0usize;
        for index in 0..generation.resource_quota_count() {
            let quota = generation.resource_quota(index)?;
            admit_resource_quota(&quota, image_limit)?;
            let process = generation.process(quota.owner_process)?;
            let instance = generation.instance(process.instance)?;
            let executable = generation.executable(instance.executable)?;
            let object = generation.object(executable.object)?;
            if PayloadFormat::classify(object.bytes, profile) == PayloadFormat::QualifiedElf {
                let pages =
                    component_image::elf_footprint_pages(object.bytes, profile).map_err(|_| {
                        GenerationError::MalformedImage {
                            executable: instance.executable,
                        }
                    })?;
                let required = pages + 2 * quota.tcb_count.saturating_sub(1) as usize;
                if (quota.frame_count as usize) < required {
                    return Err(GenerationError::ImageQuotaTooSmall {
                        instance: process.instance,
                        declared: quota.frame_count as usize,
                        required,
                    });
                }
            }
            // Worker IPC/window pairs have separate per-task capacity; the image
            // envelope includes the main thread's pair exactly once per instance.
            image_pages += quota
                .frame_count
                .saturating_sub(2 * quota.tcb_count.saturating_sub(1))
                as usize;
        }
        if image_pages > aggregate_limit {
            return Err(GenerationError::ImagePlanExceedsCeiling {
                declared: image_pages,
                limit: aggregate_limit,
            });
        }
        let fabric = fabric_graph_admission(generation)?;
        // C10.2: every declared private-memory quota is one this root can
        // honour, checked here so an over-declared or over-committed budget
        // fails the whole generation rather than becoming a refusal against a
        // ceiling the generation promised a component it had.
        let private_memory_holders = private_memory_budget_admission(generation)?;
        let io_resource_drivers = io_resource_budget_admission(generation)?;
        // C9.1: validate the authority resource and every timer-delivery
        // binding before any instance launches. The runtime authority table is
        // separately bounded by the concurrently live TaskTable.
        let clock_holders = clock_authority_admission(generation)?;
        // C9.2: every declared wake source resolves to a badge this generation
        // produces on a Notification its waiter waits on. Checked with the
        // clock authority above, because a timer source is valid only against
        // that same resource.
        let wait_set_sources = wait_set_admission(generation)?;
        // C9.3: every instance a class policy names is declared here, and every
        // promotion holder actually carries the right the operation is gated
        // on. The resource's internal consistency is the decoder's.
        let scheduling_instances = scheduling_class_admission(generation)?;
        // C9.4: every identity the lifecycle policy names is a declared
        // instance, every restart subject is reachable by a supervisor that
        // could hold its handle, and every parameter edge names two declared
        // instances. The graph's internal consistency is the decoder's.
        let lifecycle_restarts = lifecycle_policy_admission(generation)?;
        // C9.5: every identity the recording resource names is a declared
        // instance, and no instance it claims deterministic holds a right this
        // generation classifies as an unrecorded nondeterminism source. Computed
        // over the encoded grant table rather than trusted from the builder, so a
        // generation edited after build is refused here too. The resource's
        // stream pairing and capacity ceiling are the decoder's.
        let recording_entries = recording_policy_admission(generation)?;
        instance_lifetime_admission(generation)?;
        graph_arrival_ceiling_verdict(generation)?;
        let mut bootstrap_objects = 0;
        let mut component_objects = 0;
        for index in 0..generation.object_count() {
            match generation.object(index)?.kind {
                KIND_BOOTSTRAP => bootstrap_objects += 1,
                KIND_COMPONENT => component_objects += 1,
                _ => {}
            }
        }
        if bootstrap_objects == 0 || executable_len == 0 {
            return Err(GenerationError::MalformedClosure {
                bootstrap: bootstrap_objects,
                executables: executable_len,
            });
        }

        let mut executable_plans = [None; MAX_ADMITTED_EXECUTABLES];
        let mut loadable = 0;
        let mut slime_component_images = 0;
        let mut unrecognized_images = 0;
        let mut wrong_target_images = 0;
        for (executable, plan) in executable_plans.iter_mut().enumerate().take(executable_len) {
            let record = generation.executable(executable)?;
            let object = generation
                .object(record.object)
                .map_err(|_| GenerationError::DanglingExecutable { executable })?;
            let format = PayloadFormat::classify(object.bytes, profile);
            match format {
                PayloadFormat::QualifiedElf => loadable += 1,
                PayloadFormat::BareElf => {
                    return Err(GenerationError::BareElfPayload { executable });
                }
                PayloadFormat::SlimeComponent => slime_component_images += 1,
                PayloadFormat::WrongTarget => wrong_target_images += 1,
                PayloadFormat::Unrecognized => unrecognized_images += 1,
            }
            *plan = Some(ExecutablePlan { executable, format });
        }
        let mut instance_indices = [0; MAX_ADMITTED_INSTANCES];
        for (index, slot) in instance_indices.iter_mut().enumerate().take(instance_len) {
            generation.instance(index)?;
            *slot = index;
        }
        for index in 0..generation.grant_count() {
            generation.grant(index)?;
        }
        for index in 0..generation.health_count() {
            generation.health_instance(index)?;
        }

        Ok(Self {
            executable_plans,
            executable_len,
            instance_indices,
            instance_len,
            bootstrap_instance: generation.bootstrap_instance,
            bootstrap_objects,
            component_objects,
            grants: generation.grant_count(),
            health: generation.health_count(),
            loadable,
            slime_component_images,
            unrecognized_images,
            wrong_target_images,
            required_root_slots: 0,
            clock_holders,
            fabric_graph_admitted: fabric.is_some(),
            fabric_schemas: fabric.map_or(0, |shape| shape.schemas),
            fabric_routes: fabric.map_or(0, |shape| shape.routes),
            fabric_participants: fabric.map_or(0, |shape| shape.participants),
            fabric_interpositions: fabric.map_or(0, |shape| shape.interpositions),
            fabric_capability_slots: fabric.map_or(0, |shape| shape.capability_slots),
            private_memory_holders,
            io_resource_drivers,
            wait_set_sources,
            scheduling_instances,
            lifecycle_restarts,
            recording_entries,
        })
    }

    pub const fn executable_len(&self) -> usize {
        self.executable_len
    }
    pub const fn instance_len(&self) -> usize {
        self.instance_len
    }
    pub const fn is_empty(&self) -> bool {
        self.instance_len == 0
    }
    pub fn executable_plans(&self) -> impl Iterator<Item = &ExecutablePlan> {
        self.executable_plans
            .iter()
            .take(self.executable_len)
            .flatten()
    }
    pub fn loadable_executables(&self) -> impl Iterator<Item = &ExecutablePlan> {
        self.executable_plans()
            .filter(|plan| plan.format.is_loadable())
    }
    pub fn executable_plan(&self, executable: usize) -> Option<&ExecutablePlan> {
        self.executable_plans
            .get(executable)
            .and_then(Option::as_ref)
    }
    pub fn instances<'a>(
        &'a self,
        generation: &'a Generation<'a>,
    ) -> impl Iterator<Item = Instance<'a>> + 'a {
        self.instance_indices[..self.instance_len]
            .iter()
            .filter_map(|index| generation.instance(*index).ok())
    }
    pub fn root_autostart_instances<'a>(
        &'a self,
        generation: &'a Generation<'a>,
    ) -> impl Iterator<Item = Instance<'a>> + 'a {
        self.instances(generation)
            .filter(|instance| instance.is_root_autostart())
    }
}

/// Root CSlots consumed per object a process declares.
///
/// Measured, not derived: the 48-instance stress plane consumed 3186 slots
/// constructing 39 instances whose quotas declared 33 objects each. The excess
/// is intermediate page tables, window aliases, and arena parent untypeds --
/// root-side costs that belong to no child's plan.
const ROOT_SLOTS_PER_DECLARED_OBJECT: usize = 3;

/// Refuse a plan whose quotas, summed, exceed the root CSlots available
/// (B49).
///
/// The per-instance ceilings say each process fits on its own; this says they
/// all fit together. Without it a 48-instance graph admits and then dies
/// mid-construction with children already running, which is exactly the
/// failure admission exists to prevent — observed as
/// `VSpace(Alloc(SlotsExhausted))` at instance 39 of the stress plane.
///
/// The root holds a capability per object it creates for a child, so a
/// process's root-side cost is its own object count; the CSlots inside the
/// child's CNode are the child's, carved from the arena rather than the
/// root's pool.
pub fn admit_total_slots(
    generation: &Generation<'_>,
    available: usize,
) -> Result<usize, GenerationError> {
    let mut declared_objects = 0usize;
    for index in 0..generation.resource_quota_count() {
        let quota = generation.resource_quota(index)?;
        let per_process = (quota.cnode_count
            + quota.tcb_count
            + quota.endpoint_count
            + quota.notification_count
            + quota.frame_count
            + quota.page_table_count) as usize;
        declared_objects = declared_objects.saturating_add(per_process);
    }
    // Each declared object costs at least one root CSlot, and in practice
    // more: intermediate page tables the loader creates, the window alias, and
    // the arena's parent untyped are root-side costs no per-process quota
    // names. The factor remains the measured conservative construction cost.
    let mut required = declared_objects.saturating_mul(ROOT_SLOTS_PER_DECLARED_OBJECT);

    // Private backing CSlots are different: task construction reserves these
    // eagerly and exactly, before any child starts. Add the authenticated
    // budget's quota-scaled reservation rather than hiding it inside the
    // measured factor, so a graph cannot admit and then exhaust root CSpace
    // partway through construction.
    //
    // A holder costs one CSlot per allocation descriptor *and* one per extent,
    // because each extent retains its parent untyped in a root CSlot. Counting
    // only descriptors leaves a two-or-three-slot-per-holder margin in which
    // admission succeeds and task staging then fails with `SlotsExhausted`,
    // which is precisely the mid-construction death this check exists to
    // prevent.
    if let Some(budget) = private_memory_budget_object(generation) {
        let budget = budget.map_err(|_| GenerationError::UnsatisfiablePrivateMemoryBudget)?;
        for index in 0..budget.holder_count() {
            let quota = budget
                .holder(index)
                .ok_or(GenerationError::UnsatisfiablePrivateMemoryBudget)?;
            let layout =
                crate::object_allocator::PrivateBackingLayout::for_quota(quota.page_quota as usize);
            required = required
                .saturating_add(layout.allocation_descriptors)
                .saturating_add(layout.extent_parent_slots());
        }
    }
    if required > available {
        return Err(GenerationError::PlanExceedsRootSlots {
            required,
            available,
        });
    }
    Ok(required)
}

/// Refuse a declared quota that exceeds what the root can actually place
/// (B49).
///
/// Per class, not as a total: a plan needing one CSlot too many is a different
/// defect from one needing an extra TCB, and a single "too big" would say
/// neither. Checked at admission rather than during construction, which is the
/// difference between a graph refused whole and one that half-activates and
/// then cannot place a capability, with children already running.
fn admit_resource_quota(
    quota: &ResourceQuota<'_>,
    image_limit: usize,
) -> Result<(), GenerationError> {
    for (kind, declared, limit) in [
        (
            "cslot",
            quota.cslot_count,
            (1u32 << crate::task::CHILD_CNODE_SIZE_BITS),
        ),
        // One TCB and one IPC-buffer frame per thread, bounded by what
        // the child VSpace maps buffer/window pairs for (B47). A plan
        // asking for more would have a thread with no buffer.
        (
            "tcb",
            quota.tcb_count,
            crate::child_vspace::MAX_CHILD_THREADS as u32,
        ),
        (
            // One IPC-buffer/window pair per thread plus the image's own
            // pages, which the loader maps from root CSlots (B49).
            "frame",
            quota.frame_count,
            image_limit as u32
                + 2 * quota
                    .tcb_count
                    .min(crate::child_vspace::MAX_CHILD_THREADS as u32)
                    .saturating_sub(1),
        ),
        ("cnode", quota.cnode_count, 1),
        // The child's VSpace root. One per process by definition -- a
        // second would be a second address space, which is a second
        // process.
        ("vspace", quota.page_table_count, 1),
        // Fault + console + one native endpoint per declared relative slot.
        // The plan still bounds the total by the child CSpace capacity above;
        // refusing at two would reject every process that has a real peer.
        (
            "endpoint",
            quota.endpoint_count,
            2 + crate::task::CHILD_NATIVE_REGION_SLOTS as u32,
        ),
    ] {
        if declared > limit {
            return Err(GenerationError::QuotaExceedsCeiling {
                instance: quota.owner_process,
                kind,
                declared,
                limit,
            });
        }
    }
    Ok(())
}

/// Whether a grant-backed binding is one the child's *owner* must supply at
/// spawn.
///
/// Two classes are excluded, and both are authority the root places itself:
///
/// * an **endpoint**, which is a generation-owned seL4 Endpoint object the root
///   materializes and installs into both declared ends, and
/// * a **self-loop**, whose source and target are the child itself — authority
///   it holds in its own right, installed by `construct_child`.
///
/// Neither crosses the spawn boundary, so neither is counted in the total a
/// request must match nor given a position in the ordering that pairs requests
/// with declarations. Those two must agree: a count that skips a declaration the
/// ordering still numbers makes every child holding one unspawnable, because the
/// request at index 0 resolves to a declaration its owner was never asked for.
///
/// Lives here rather than beside the dispatcher because it is a pure rule over
/// decoded generation data, and because it is the rule two IO2 passes misread:
/// the first concluded the root could not carry a crossing grant at all. It can,
/// and [`declared_crossing_grants`] is the number an owner must supply.
pub fn grant_crosses_spawn(
    grant: boot_contracts::generation::Grant<'_>,
    child_instance: usize,
) -> bool {
    use boot_contracts::generation::{CapabilityKind, GrantEndpoint};
    grant.capability_kind != CapabilityKind::Endpoint
        && (grant.source != GrantEndpoint::Instance(child_instance)
            || grant.target != GrantEndpoint::Instance(child_instance))
}

/// How many crossing grants the generation declares for `child_instance` — the
/// exact vector length its owner must pass at spawn.
///
/// This is the authority on "how many", and the only one: a spawn supplying a
/// different count is refused with nothing constructed. It deliberately counts
/// *declarations* rather than trusting a request, which is what makes widening
/// unrepresentable — an owner cannot add a grant the generation never declared,
/// because there is no index for it to occupy.
pub fn declared_crossing_grants(
    generation: &Generation<'_>,
    child: Instance<'_>,
    child_instance: usize,
) -> Result<usize, DecodeError> {
    let mut crossing = 0;
    for index in 0..child.binding_count() {
        let binding = generation.binding(child, index)?;
        let grant = generation.grant(binding.grant)?;
        crossing += usize::from(grant_crosses_spawn(grant, child_instance));
    }
    for index in 0..generation.minted_binding_count() {
        let minted = generation.minted_binding(index)?;
        crossing += usize::from(minted.holder == child_instance);
    }
    Ok(crossing)
}

#[cfg(test)]
mod large_image_tests;

#[cfg(test)]
mod tests {
    use super::{
        Authority, FabricGraph, GenerationError, PayloadFormat, PrivateMemoryBudget, RIGHT_RECV,
        RIGHT_SEND, fabric_graph_is_satisfiable, participants_are_declared,
        private_memory_budget_is_satisfiable, resolve_interposition_hops,
    };
    use boot_contracts::component_image::wire;
    use boot_contracts::generation::{RIGHT_TRANSFER, ResourceQuota};

    use super::admit_resource_quota;

    fn ceiling_object(arrivals: u64) -> alloc::vec::Vec<u8> {
        use boot_contracts::graph_arrival_ceiling as ceiling;
        let mut bytes = alloc::vec::Vec::new();
        bytes.extend_from_slice(&ceiling::MAGIC);
        bytes.extend_from_slice(&ceiling::FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(ceiling::HEADER_BYTES as u32).to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&arrivals.to_le_bytes());
        bytes
    }

    /// A finite plane takes the ceiling it declares, and keeps the default
    /// when it declares none; other resources are not read as a ceiling.
    #[test]
    fn a_finite_plane_takes_its_one_declared_arrival_ceiling() {
        use boot_contracts::generation::BootAction;
        let declared = ceiling_object(4_194_304);
        let other = *b"SLIMELT\0";
        assert_eq!(
            super::declared_arrival_ceiling(BootAction::DataVolume, [&declared[..], &other[..]]),
            Ok(Some(4_194_304))
        );
        assert_eq!(
            super::declared_arrival_ceiling(BootAction::DataVolume, [&other[..]]),
            Ok(None)
        );
        assert_eq!(
            super::declared_arrival_ceiling(BootAction::Product, []),
            Ok(None)
        );
    }

    /// A ceiling on a product graph, a second ceiling, and one that does not
    /// decode are each refused at admission.
    #[test]
    fn a_misplaced_duplicate_or_malformed_arrival_ceiling_is_refused() {
        use boot_contracts::generation::BootAction;
        let declared = ceiling_object(4_194_304);
        let default = ceiling_object(131_072);
        for (action, resources) in [
            (BootAction::Product, alloc::vec![&declared[..]]),
            (
                BootAction::DataVolume,
                alloc::vec![&declared[..], &declared[..]],
            ),
            (BootAction::DataVolume, alloc::vec![&default[..]]),
            (BootAction::DataVolume, alloc::vec![&declared[..31]]),
        ] {
            assert_eq!(
                super::declared_arrival_ceiling(action, resources),
                Err(GenerationError::UnsatisfiableGraphArrivalCeiling)
            );
        }
    }

    /// One declared grant, for the crossing-grant rule below.
    fn declared_grant(
        kind: boot_contracts::generation::CapabilityKind,
        source: usize,
        target: usize,
    ) -> boot_contracts::generation::Grant<'static> {
        use boot_contracts::generation::GrantEndpoint;
        boot_contracts::generation::Grant {
            name: "fixture:grant",
            source: GrantEndpoint::Instance(source),
            target: GrantEndpoint::Instance(target),
            rights: RIGHT_SEND,
            transferable: false,
            capability_kind: kind,
        }
    }

    /// The rule that decides which declarations an owner must supply at spawn,
    /// and the one two IO2 passes misread.
    ///
    /// The first pass concluded the root could not carry a crossing grant to a
    /// dynamically spawned child at all, and reverted a working migration on
    /// that basis. It can: a grant whose source is the owner and whose target
    /// is the child *does* cross, and is exactly what the owner passes. What
    /// does not cross is an endpoint (the root installs both declared ends) or
    /// a self-loop (the child holds it in its own right). Both exclusions are
    /// authority the root places, so counting them would demand a vector no
    /// owner can produce -- which is the `requested=0 parent=N` refusal that
    /// cost those passes.
    #[test]
    fn only_owner_supplied_authority_crosses_a_spawn() {
        use boot_contracts::generation::CapabilityKind;
        const CHILD: usize = 1;
        const OWNER: usize = 0;

        // Crosses: the owner is the declared source, the child the target. This
        // is the case the previous passes believed impossible.
        assert!(super::grant_crosses_spawn(
            declared_grant(CapabilityKind::SharedBufferFactory, OWNER, CHILD),
            CHILD,
        ));

        // Does not cross: the child's own authority, installed by the root.
        assert!(!super::grant_crosses_spawn(
            declared_grant(CapabilityKind::Device, CHILD, CHILD),
            CHILD,
        ));

        // Does not cross: an endpoint, even owner-to-child. The root
        // materializes the Endpoint object and installs it into both ends, so
        // an owner holds nothing to hand over.
        assert!(!super::grant_crosses_spawn(
            declared_grant(CapabilityKind::Endpoint, OWNER, CHILD),
            CHILD,
        ));

        // ...and not even a self-loop endpoint, which is how an `idle`
        // duplicate instance declares its own run token.
        assert!(!super::grant_crosses_spawn(
            declared_grant(CapabilityKind::Endpoint, CHILD, CHILD),
            CHILD,
        ));
    }

    /// A spawn cannot widen authority, expressed as a property of the count.
    ///
    /// `declared_crossing_grants` counts *declarations*, and `preflight_spawn_grants`
    /// admits a request only when its length equals that number and each record
    /// resolves to the declaration at its index. So an owner has no index at
    /// which to place a grant the generation never declared: widening is
    /// unrepresentable rather than merely refused. This pins the direction that
    /// matters -- a grant reaching a child because the manifest declared it, not
    /// because its owner asked.
    #[test]
    fn a_declaration_the_root_places_is_never_charged_to_the_owner() {
        use boot_contracts::generation::CapabilityKind;
        const CHILD: usize = 1;
        const OWNER: usize = 0;

        // Every kind the root places itself, against the same child. None may
        // be counted, because none is a capability its owner could pass.
        for kind in [
            CapabilityKind::Device,
            CapabilityKind::MmioRegion,
            CapabilityKind::InterruptSource,
            CapabilityKind::DmaAccount,
        ] {
            assert!(
                !super::grant_crosses_spawn(declared_grant(kind, CHILD, CHILD), CHILD),
                "a child's own {kind:?} authority is placed by the root, not passed at spawn",
            );
        }

        // The converse, so this is not passing by refusing everything: the
        // storage family's factory grant is owner-supplied and must be counted,
        // or its holder becomes unspawnable.
        assert!(super::grant_crosses_spawn(
            declared_grant(CapabilityKind::SharedBufferFactory, OWNER, CHILD),
            CHILD,
        ));
    }

    /// The quota a single-threaded process declares: one CNode, one VSpace,
    /// one TCB, one IPC-buffer frame, two endpoints, and a full CNode of
    /// slots. Matches what `build-generation.py` packs.
    fn single_threaded_quota() -> ResourceQuota<'static> {
        ResourceQuota {
            name: "fixture:quota",
            owner_process: 0,
            cnode_count: 1,
            tcb_count: 1,
            endpoint_count: 2,
            notification_count: 0,
            frame_count: 1,
            page_table_count: 1,
            mapping_count: 0,
            irq_count: 0,
            cslot_count: 1u32 << crate::task::CHILD_CNODE_SIZE_BITS,
            untyped_bytes: 0,
            dynamic_reserve_bytes: 0,
            flags: 0,
        }
    }

    #[test]
    fn the_quota_a_single_threaded_process_declares_is_admitted() {
        admit_resource_quota(&single_threaded_quota(), 512)
            .expect("the plan the builder emits must be placeable");
    }

    #[test]
    fn a_two_thread_process_may_declare_a_tcb_and_frame_per_thread() {
        // B47: threads own a TCB and an IPC buffer each, so the ceiling is per
        // thread rather than one. A ceiling of 1 here would refuse every
        // multi-threaded process.
        let mut quota = single_threaded_quota();
        quota.tcb_count = 2;
        quota.frame_count = 2;
        admit_resource_quota(&quota, 512).expect("two threads declare two of each");
    }

    #[test]
    fn one_object_over_any_ceiling_is_refused_naming_its_class() {
        // Every class the root places, each raised by exactly one. A ceiling
        // that admitted one over would let a graph activate and then fail to
        // place a capability, with children already running -- which is the
        // failure admission exists to prevent.
        let cases: [(&str, fn(&mut ResourceQuota<'_>), u32, u32); 6] = [
            ("cnode", |q| q.cnode_count = 2, 2, 1),
            ("tcb", |q| q.tcb_count = 3, 3, 2),
            ("endpoint", |q| q.endpoint_count = 34, 34, 33),
            ("frame", |q| q.frame_count = 513, 513, 512),
            ("vspace", |q| q.page_table_count = 2, 2, 1),
            ("cslot", |q| q.cslot_count = 129, 129, 128),
        ];
        for (class, mutate, declared, limit) in cases {
            let mut quota = single_threaded_quota();
            mutate(&mut quota);
            match admit_resource_quota(&quota, 512) {
                Err(GenerationError::QuotaExceedsCeiling {
                    instance,
                    kind,
                    declared: reported,
                    limit: reported_limit,
                }) => {
                    assert_eq!(kind, class, "the refusal must name the class it hit");
                    assert_eq!(instance, 0, "and the process whose plan it was");
                    assert_eq!(reported, declared);
                    assert_eq!(reported_limit, limit);
                }
                other => panic!("{class}: one over its ceiling was not refused: {other:?}"),
            }
        }
    }
    use boot_contracts::target_profile::TargetProfile;

    fn sel4_profile() -> &'static TargetProfile {
        TargetProfile::by_name("aarch64-sel4-qemu-virt").expect("declared profile")
    }

    /// Bytes an [`elf_header`] fixture occupies. Named so [`qualified`] sizes
    /// its tail from the same constant rather than from a literal.
    const ELF_TAIL: usize = wire::LEGACY_HEADER_LEN + 8;

    /// A bare ELF64 header prefix, padded past `LEGACY_HEADER_LEN`.
    ///
    /// The padding is load-bearing, and it is what B23's first host run
    /// surfaced. `classify` reaches its bare-ELF test only when
    /// `component_image::target` answers `BadMagic`; a blob shorter than
    /// `LEGACY_HEADER_LEN` (32) answers `Truncated` instead and falls straight
    /// to `Unrecognized`. These fixtures were 20 bytes and had been asserting
    /// against the wrong arm since `target` gained that guard — invisibly,
    /// because nothing compiled them.
    ///
    /// No production path is affected: every real ELF is far longer than 32
    /// bytes, and a payload that short is not one this root could load anyway.
    fn elf_header(class: u8, data: u8, machine: u16) -> [u8; ELF_TAIL] {
        let mut bytes = [0u8; ELF_TAIL];
        bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = class;
        bytes[5] = data;
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    /// A qualified component image for `profile`, under `magic`.
    ///
    /// The helper writes every canonical admission field so mutations below
    /// isolate the field they intend to test.
    fn qualified(magic: u64, profile: &TargetProfile) -> [u8; wire::HEADER_LEN + ELF_TAIL] {
        let mut bytes = [0u8; wire::HEADER_LEN + ELF_TAIL];
        bytes[wire::OFF_HEADER_MAGIC..][..8].copy_from_slice(&magic.to_le_bytes());
        bytes[wire::OFF_HEADER_FORMAT_VERSION..][..4]
            .copy_from_slice(&wire::FORMAT_VERSION.to_le_bytes());
        bytes[wire::OFF_HEADER_HEADER_SIZE..][..4]
            .copy_from_slice(&(wire::HEADER_LEN as u32).to_le_bytes());
        bytes[wire::OFF_HEADER_KERNEL_ABI..][..4]
            .copy_from_slice(&wire::KERNEL_ABI_VERSION.to_le_bytes());
        bytes[wire::OFF_HEADER_ARCHITECTURE..][..4]
            .copy_from_slice(&profile.architecture.to_le_bytes());
        bytes[wire::OFF_HEADER_ABI..][..4].copy_from_slice(&profile.abi.to_le_bytes());
        bytes[wire::OFF_HEADER_PAGE_PROFILE..][..4]
            .copy_from_slice(&profile.page_profile.to_le_bytes());
        bytes[wire::OFF_HEADER_STACK_BYTES..][..4]
            .copy_from_slice(&wire::DEFAULT_STACK_BYTES.to_le_bytes());
        bytes[wire::OFF_HEADER_TARGET_PROFILE..][..4].copy_from_slice(&profile.id.to_le_bytes());
        bytes[wire::OFF_HEADER_REQUIRED_FEATURES..][..8]
            .copy_from_slice(&profile.required_features.to_le_bytes());
        bytes[wire::HEADER_LEN..].copy_from_slice(&elf_header(2, 1, 183));
        bytes
    }

    /// A minimal well-formed fabric graph carrying `limits`, with no schemas,
    /// routes, participants, or interposition hops.
    ///
    /// Hand-built rather than borrowed from `boot_contracts`, whose encoder is
    /// `#[cfg(test)]` and so not reachable from here. The empty tables are what
    /// make it minimal: `validate_against` reads only the limits block, so an
    /// empty graph isolates the ceiling comparison from everything else the
    /// decoder checks.
    fn graph_with(limits: [u32; 21]) -> alloc::vec::Vec<u8> {
        use boot_contracts::fabric_graph::{FORMAT_VERSION, HEADER_BYTES, MAGIC};
        let mut bytes = alloc::vec![0u8; HEADER_BYTES];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
        bytes[24..28].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
        // The fabric component's identity. Non-zero or the decoder answers
        // `MissingReference`: a graph naming no fabric describes no plane.
        bytes[48..80].copy_from_slice(&[0xab; 32]);
        for (index, value) in limits.iter().enumerate() {
            bytes[80 + index * 4..][..4].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    /// The components `qos_graph` names: the fabric host and its two
    /// participants. Derived identities, not raw bytes, so a provenance test
    /// can declare the same components by name.
    const QOS_FABRIC: &str = "fabric-service";
    const QOS_PUBLISHER: &str = "fabric-publisher";
    const QOS_SUBSCRIBER: &str = "fabric-subscriber";

    /// A one-route stream graph with a publisher and a subscriber, each
    /// carrying the reliability the caller names.
    ///
    /// Enough structure to reach `all_pairs_qos_compatible`, which
    /// [`graph_with`]'s empty participant table cannot: with no pairs the
    /// predicate is vacuously true, so a graph built there proves nothing about
    /// QoS either way.
    fn qos_graph(offered: u8, requested: u8) -> alloc::vec::Vec<u8> {
        use boot_contracts::fabric_graph::{
            CONTRACT_KIND_STREAM, DIRECTION_PUBLISH, DIRECTION_SUBSCRIBE, DURABILITY_VOLATILE,
            FORMAT_VERSION, HEADER_BYTES, INTERPOSITION_NONE, LIVELINESS_AUTOMATIC, MAGIC,
            PARTICIPANT_ENTRY_BYTES, ROUTE_ENTRY_BYTES, SCHEMA_ENTRY_BYTES, VISIBILITY_GRAPH,
            grant_identity, route_identity,
        };
        // Route and grant identities are derived hashes, not arbitrary bytes:
        // the decoder recomputes and compares them, so a hand-built graph must
        // fold them the same way. That check is what makes an identity name one
        // exact (route, component, direction) tuple rather than a label.
        const SCHEMA_IDENTITY: [u8; 32] = [0x11; 32];
        let route_id = route_identity("telemetry", &SCHEMA_IDENTITY, CONTRACT_KIND_STREAM);
        let total =
            HEADER_BYTES + SCHEMA_ENTRY_BYTES + ROUTE_ENTRY_BYTES + 2 * PARTICIPANT_ENTRY_BYTES;
        let mut bytes = alloc::vec![0u8; total];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
        bytes[24..28].copy_from_slice(&(total as u32).to_le_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_le_bytes()); // schemas
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes()); // routes
        bytes[36..40].copy_from_slice(&2u32.to_le_bytes()); // participants
        // The fabric host, named rather than arbitrary: admission now checks
        // this identity against the generation too, so a raw constant would
        // make every graph built here unadmittable.
        bytes[48..80].copy_from_slice(&boot_contracts::fabric_graph::component_identity(
            QOS_FABRIC,
        ));
        for (index, value) in SATISFIABLE.iter().enumerate() {
            bytes[80 + index * 4..][..4].copy_from_slice(&value.to_le_bytes());
        }

        let schema = HEADER_BYTES;
        bytes[schema..schema + 32].copy_from_slice(&SCHEMA_IDENTITY);
        bytes[schema + 32..schema + 40].copy_from_slice(&0xAAAAu64.to_le_bytes());
        bytes[schema + 40..schema + 44].copy_from_slice(&CONTRACT_KIND_STREAM.to_le_bytes());
        bytes[schema + 44..schema + 48].copy_from_slice(&64u32.to_le_bytes());

        let route = schema + SCHEMA_ENTRY_BYTES;
        bytes[route..route + 32].copy_from_slice(&route_id);
        bytes[route + 32..route + 36].copy_from_slice(&0u32.to_le_bytes()); // schema index
        bytes[route + 36..route + 40].copy_from_slice(&CONTRACT_KIND_STREAM.to_le_bytes());
        bytes[route + 40..route + 44].copy_from_slice(&2u32.to_le_bytes()); // participants

        // Grant identities must be distinct and sorted: the decoder rejects a
        // duplicate, and `encode` sorts, so a hand-built graph must too.
        let mut placed = [([0u8; 32], [0u8; 32], 0u32, 0u8); 2];
        for (slot, (component, direction, reliability)) in [
            (
                boot_contracts::fabric_graph::component_identity(QOS_PUBLISHER),
                DIRECTION_PUBLISH,
                offered,
            ),
            (
                boot_contracts::fabric_graph::component_identity(QOS_SUBSCRIBER),
                DIRECTION_SUBSCRIBE,
                requested,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            placed[slot] = (
                grant_identity(&route_id, &component, direction),
                component,
                direction,
                reliability,
            );
        }
        // The decoder requires grant identities in ascending order, as the
        // builder's own encoder sorts them.
        placed.sort_by_key(|entry| entry.0);
        for (slot, (identity, component, direction, reliability)) in placed.into_iter().enumerate()
        {
            let at = route + ROUTE_ENTRY_BYTES + slot * PARTICIPANT_ENTRY_BYTES;
            bytes[at..at + 32].copy_from_slice(&identity);
            bytes[at + 32..at + 64].copy_from_slice(&component);
            bytes[at + 64..at + 68].copy_from_slice(&0u32.to_le_bytes()); // route
            bytes[at + 68..at + 72].copy_from_slice(&direction.to_le_bytes());
            bytes[at + 72..at + 76].copy_from_slice(&VISIBILITY_GRAPH.to_le_bytes());
            bytes[at + 76..at + 80].copy_from_slice(&INTERPOSITION_NONE.to_le_bytes());
            bytes[at + 104..at + 108].copy_from_slice(&1u32.to_le_bytes()); // history
            bytes[at + 112] = reliability;
            bytes[at + 113] = DURABILITY_VOLATILE as u8;
            bytes[at + 114] = LIVELINESS_AUTOMATIC as u8;
        }
        bytes
    }

    /// A two-schema graph whose schemas carry distinct full identities and the
    /// tags given (C8.1). No route or participant: `validate_schemas` runs
    /// before anything references a schema, so a collision is refusable on the
    /// schema table alone.
    ///
    /// The generation-local tag is a *lookup key*. Two distinct interfaces
    /// sharing one tag makes every later resolution ambiguous, and the wrong
    /// answer is a message decoded against the wrong schema rather than an
    /// error, which is why this is refused at decode rather than reported.
    fn two_schema_graph(first_tag: u64, second_tag: u64) -> alloc::vec::Vec<u8> {
        use boot_contracts::fabric_graph::{
            CONTRACT_KIND_STREAM, FORMAT_VERSION, HEADER_BYTES, MAGIC, SCHEMA_ENTRY_BYTES,
        };
        let total = HEADER_BYTES + 2 * SCHEMA_ENTRY_BYTES;
        let mut bytes = alloc::vec![0u8; total];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
        bytes[24..28].copy_from_slice(&(total as u32).to_le_bytes());
        bytes[28..32].copy_from_slice(&2u32.to_le_bytes()); // schemas
        bytes[48..80].copy_from_slice(&[0xab; 32]);
        for (index, value) in SATISFIABLE.iter().enumerate() {
            bytes[80 + index * 4..][..4].copy_from_slice(&value.to_le_bytes());
        }
        // Schema identities must ascend: the decoder checks the ordering
        // separately from the tag collision, so a descending pair would fail
        // for the wrong reason and the test would prove nothing.
        for (slot, (identity, tag)) in [([0x11u8; 32], first_tag), ([0x22u8; 32], second_tag)]
            .into_iter()
            .enumerate()
        {
            let at = HEADER_BYTES + slot * SCHEMA_ENTRY_BYTES;
            bytes[at..at + 32].copy_from_slice(&identity);
            bytes[at + 32..at + 40].copy_from_slice(&tag.to_le_bytes());
            bytes[at + 40..at + 44].copy_from_slice(&CONTRACT_KIND_STREAM.to_le_bytes());
            bytes[at + 44..at + 48].copy_from_slice(&64u32.to_le_bytes());
        }
        bytes
    }

    /// Limits every ceiling admits. Field order is the wire order:
    /// routes, ingress_sources, publishers, subscribers, clients, servers,
    /// sample_bytes, queue_depth, history_depth, event_depth, retained_samples,
    /// retries, in_flight_calls, in_flight_operations, buffer_pages, buffers,
    /// mappings, loans, capability_slots, trace_depth, trace_overflow.
    const SATISFIABLE: [u32; 21] = [
        1,
        4,
        1,
        1,
        0,
        0,
        64,
        8,
        4,
        4,
        2,
        2,
        0,
        0,
        8,
        2,
        4,
        4,
        16,
        16,
        boot_contracts::fabric_graph::TRACE_OVERFLOW_SATURATE,
    ];

    /// [`qos_graph`] with one interposition hop naming `hop`, appended.
    ///
    /// The hop is left off every participant's chain (`interposition_head`
    /// stays `INTERPOSITION_NONE`), which `validate_interposition` allows: its
    /// per-hop arm requires only a non-zero identity and an in-range
    /// `next_hop`, and the chain walk never reaches an unreferenced entry. That
    /// keeps the fixture to the one fact under test — the identity-to-name
    /// resolution — instead of also re-encoding a participant's chain head.
    fn hop_graph(hop: &str) -> alloc::vec::Vec<u8> {
        use boot_contracts::fabric_graph::{
            INTERPOSITION_ENTRY_BYTES, INTERPOSITION_NONE, RELIABILITY_RELIABLE,
        };
        let mut bytes = qos_graph(RELIABILITY_RELIABLE as u8, RELIABILITY_RELIABLE as u8);
        let at = bytes.len();
        bytes.resize(at + INTERPOSITION_ENTRY_BYTES, 0);
        bytes[at..at + 32].copy_from_slice(&boot_contracts::fabric_graph::component_identity(hop));
        bytes[at + 32..at + 36].copy_from_slice(&INTERPOSITION_NONE.to_le_bytes());
        bytes[40..44].copy_from_slice(&1u32.to_le_bytes()); // interposition hops
        let total = bytes.len() as u32;
        bytes[24..28].copy_from_slice(&total.to_le_bytes());
        bytes
    }

    /// B70: the root resolves a declared hop's identity back to the generation
    /// instance name, so a gate can assert *which* component mediates a route.
    ///
    /// The property that failed before this existed: both fabric brokers
    /// checked their build-time interposition table against a proxy name
    /// compiled into the same crate, so the two operands regenerated together
    /// and the check could only ever confirm the table agreed with itself.
    /// Substituting another component on the chain admitted cleanly and left
    /// the gate green.
    #[test]
    fn an_interposition_hop_resolves_to_the_declared_component_name() {
        let bytes = hop_graph(QOS_SUBSCRIBER);
        let graph = FabricGraph::decode(&bytes).expect("well-formed graph");
        let declared = [
            Some(QOS_FABRIC),
            Some(QOS_PUBLISHER),
            Some(QOS_SUBSCRIBER),
            Some("init"),
        ];

        // The hop names a declared component: resolved, and to that exact name.
        let hops = resolve_interposition_hops(&declared, &graph);
        assert_eq!(hops[0], Some(QOS_SUBSCRIBER));

        // Only the declared count is filled. A gate reads these in order, so a
        // stale entry past the count would name a hop the graph does not have.
        assert!(hops[1..].iter().all(Option::is_none));

        // The discriminating half. A hop naming a *different* component must
        // not resolve to the one the gate expects — this is the substitution
        // that used to pass, and the whole reason the resolution moved to the
        // root.
        let other = hop_graph(QOS_PUBLISHER);
        let other = FabricGraph::decode(&other).expect("well-formed graph");
        assert_eq!(
            resolve_interposition_hops(&declared, &other)[0],
            Some(QOS_PUBLISHER)
        );

        // A hop no declared name hashes to resolves to `None` rather than to a
        // neighbouring entry. Admission refuses such a graph, so reaching this
        // means the graph decoded differently than it validated; reporting a
        // wrong name there would be worse than reporting none.
        let undeclared = [Some(QOS_FABRIC), Some(QOS_PUBLISHER), Some("init")];
        assert_eq!(resolve_interposition_hops(&undeclared, &graph)[0], None);
    }

    /// C8.3 (P5.4.10): a graph may only name participants the generation
    /// declares as components.
    ///
    /// The fabric answers requests from a build-time table generated from the
    /// same manifest, and nothing checked the two still agreed. A graph naming
    /// a dropped component decodes, fits every ceiling, and launches; the
    /// mismatch then surfaces as a control endpoint that never arrives, which
    /// reads as a hang rather than as a provenance failure.
    #[test]
    fn a_graph_may_not_name_a_component_the_generation_lacks() {
        use boot_contracts::fabric_graph::RELIABILITY_RELIABLE;
        let bytes = qos_graph(RELIABILITY_RELIABLE as u8, RELIABILITY_RELIABLE as u8);
        let graph = FabricGraph::decode(&bytes).expect("well-formed graph");

        // Host and both participants declared: admitted. Without this half the
        // test would pass on a check that refused every graph.
        let complete = [
            Some(QOS_FABRIC),
            Some(QOS_PUBLISHER),
            Some(QOS_SUBSCRIBER),
            Some("init"),
        ];
        assert_eq!(participants_are_declared(&complete, &graph), Ok(()));

        // The subscriber dropped from the generation, its participant left in
        // the graph: refused before anything launches.
        let missing = [Some(QOS_FABRIC), Some(QOS_PUBLISHER), Some("init")];
        assert_eq!(
            participants_are_declared(&missing, &graph),
            Err(GenerationError::UndeclaredFabricParticipant)
        );

        // The fabric host itself dropped. Every participant is still declared,
        // so only the host arm can catch this — and nothing would receive a
        // route half if it booted.
        let hostless = [Some(QOS_PUBLISHER), Some(QOS_SUBSCRIBER), Some("init")];
        assert_eq!(
            participants_are_declared(&hostless, &graph),
            Err(GenerationError::UndeclaredFabricParticipant)
        );

        // A component no participant names is ordinary, not an error: most
        // components are not on the fabric at all.
        let extra = [
            Some(QOS_FABRIC),
            Some(QOS_PUBLISHER),
            Some(QOS_SUBSCRIBER),
            Some("console"),
            Some("sysinfo"),
        ];
        assert_eq!(participants_are_declared(&extra, &graph), Ok(()));
    }

    /// C8.1 (P5.4.10): two distinct interfaces may not share one
    /// generation-local type tag.
    ///
    /// The positive half is load-bearing. Without it this test would pass on a
    /// decoder that refused every two-schema graph, which is the failure mode
    /// a negative-only test cannot see.
    #[test]
    fn distinct_schemas_may_share_no_type_tag() {
        let distinct = two_schema_graph(0xAAAA, 0xBBBB);
        assert!(
            FabricGraph::decode(&distinct).is_ok(),
            "two schemas with distinct tags are a legal graph"
        );

        let collided = two_schema_graph(0xAAAA, 0xAAAA);
        assert!(
            matches!(
                FabricGraph::decode(&collided),
                Err(boot_contracts::fabric_graph::DecodeError::IdentityMismatch)
            ),
            "a shared type tag must be refused at decode, not resolved later"
        );
    }

    /// C8.2's exit condition on this side: a graph the root can satisfy is
    /// admitted, so the check is not refusing everything.
    #[test]
    fn a_satisfiable_fabric_graph_is_admitted() {
        let bytes = graph_with(SATISFIABLE);
        let graph = FabricGraph::decode(&bytes).expect("well-formed graph");
        assert_eq!(fabric_graph_is_satisfiable(&graph), Ok(()));
    }

    /// A private-memory budget, hand-built for the same reason `graph_with` is:
    /// `boot_contracts`'s encoder is `#[cfg(test)]` and not reachable here.
    fn budget_with(quotas: &[(u8, u32)]) -> alloc::vec::Vec<u8> {
        use boot_contracts::private_memory_budget::{
            ENTRY_BYTES, FORMAT_VERSION, HEADER_BYTES, MAGIC,
        };
        let total = HEADER_BYTES + quotas.len() * ENTRY_BYTES;
        let mut bytes = alloc::vec::Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&(quotas.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(total as u32).to_le_bytes());
        for (identity, pages) in quotas {
            bytes.extend_from_slice(&[*identity; 32]);
            bytes.extend_from_slice(&pages.to_le_bytes());
        }
        bytes
    }

    /// C10.2's exit condition on this side: a budget every ceiling can hold is
    /// admitted, so the check is not refusing everything. Exactly the per-task
    /// reservation, which is the boundary case a strict comparison would drop.
    #[test]
    fn a_satisfiable_private_memory_budget_is_admitted() {
        let bytes = budget_with(&[(0x11, crate::private_memory::MAX_REGION_PAGES as u32)]);
        let budget = PrivateMemoryBudget::decode(&bytes).expect("well-formed budget");
        assert_eq!(
            private_memory_budget_is_satisfiable(&budget, crate::private_memory::IMAGE_TARGET_NAME),
            Ok(())
        );
    }

    /// A quota above the per-task reservation is refused: the window's address
    /// space is sized for the reservation and the base cannot move, so the
    /// ceiling could never be reached. Refused here rather than clamped at
    /// growth, which is the difference between a declaration the root honours
    /// and one it quietly reinterprets.
    #[test]
    fn a_quota_above_the_task_reservation_is_refused() {
        let bytes = budget_with(&[(0x11, crate::private_memory::MAX_REGION_PAGES as u32 + 1)]);
        let budget = PrivateMemoryBudget::decode(&bytes).expect("well-formed budget");
        assert_eq!(
            private_memory_budget_is_satisfiable(&budget, crate::private_memory::IMAGE_TARGET_NAME),
            Err(GenerationError::UnsatisfiablePrivateMemoryBudget)
        );
    }

    /// B8's rule on this mechanism: holders that each fit but cannot all peak
    /// at once are refused. Without this the declaration degrades into
    /// first-come-first-served and a late-growing component is refused a quota
    /// the generation promised it.
    #[test]
    fn an_over_committed_private_memory_budget_is_refused() {
        let per_task = crate::private_memory::MAX_REGION_PAGES as u32;
        let fits = crate::private_memory::MAX_TOTAL_PAGES / crate::private_memory::MAX_REGION_PAGES;
        // Exactly the root-wide ceiling: every holder at its own maximum, which
        // must pass, or the aggregate arm would be refusing what it should
        // admit.
        let holders: alloc::vec::Vec<(u8, u32)> = (1..=fits as u8)
            .map(|identity| (identity, per_task))
            .collect();
        let bytes = budget_with(&holders);
        let budget = PrivateMemoryBudget::decode(&bytes).expect("well-formed budget");
        assert_eq!(
            private_memory_budget_is_satisfiable(&budget, crate::private_memory::IMAGE_TARGET_NAME),
            Ok(())
        );
        let mut one_extra = holders.clone();
        one_extra.push((fits as u8 + 1, 1));
        let bytes = budget_with(&one_extra);
        let budget =
            PrivateMemoryBudget::decode(&bytes).expect("well-formed exact-boundary budget");
        assert_eq!(
            private_memory_budget_is_satisfiable(&budget, crate::private_memory::IMAGE_TARGET_NAME),
            Err(GenerationError::UnsatisfiablePrivateMemoryBudget)
        );
        // One more holder at the same ceiling passes every per-holder bound and
        // still cannot be honoured in full.
        let holders: alloc::vec::Vec<(u8, u32)> = (1..=fits as u8 + 1)
            .map(|identity| (identity, per_task))
            .collect();
        let bytes = budget_with(&holders);
        let budget = PrivateMemoryBudget::decode(&bytes).expect("well-formed budget");
        assert_eq!(
            private_memory_budget_is_satisfiable(&budget, crate::private_memory::IMAGE_TARGET_NAME),
            Err(GenerationError::UnsatisfiablePrivateMemoryBudget)
        );
    }

    #[test]
    fn a_budget_for_a_different_generation_target_is_refused() {
        let bytes = budget_with(&[(0x11, 512)]);
        let budget = PrivateMemoryBudget::decode(&bytes).expect("well-formed budget");
        assert_eq!(
            private_memory_budget_is_satisfiable(&budget, "riscv64-sel4-milkv-duo"),
            Err(GenerationError::UnsatisfiablePrivateMemoryBudget)
        );
    }

    /// A matched pair whose offer satisfies the request is admitted, so the
    /// QoS half of the check is not refusing every graph that has pairs at all.
    #[test]
    fn a_compatible_qos_pair_is_admitted() {
        use boot_contracts::fabric_graph::RELIABILITY_RELIABLE;
        let bytes = qos_graph(RELIABILITY_RELIABLE as u8, RELIABILITY_RELIABLE as u8);
        let graph = FabricGraph::decode(&bytes).expect("well-formed graph");
        assert_eq!(fabric_graph_is_satisfiable(&graph), Ok(()));
    }

    /// P5.4.10: a graph within every ceiling but promising a reader more than
    /// its writer offers is refused. This is the assertion
    /// `kernel/tests/fabric_manifest.rs` makes over the booted graph and no
    /// seL4 gate made — `validate_against` bounds aggregate demand and says
    /// nothing about per-pair compatibility, so the two are independent.
    ///
    /// A BEST_EFFORT writer against a RELIABLE reader: the reader asks for
    /// delivery the writer never promised.
    #[test]
    fn an_incompatible_qos_pair_is_refused_within_every_ceiling() {
        use boot_contracts::fabric_graph::{RELIABILITY_BEST_EFFORT, RELIABILITY_RELIABLE};
        let bytes = qos_graph(RELIABILITY_BEST_EFFORT as u8, RELIABILITY_RELIABLE as u8);
        let graph = FabricGraph::decode(&bytes).expect("well-formed graph");
        assert!(
            !graph.all_pairs_qos_compatible(),
            "the fixture must actually declare an incompatible pair",
        );
        assert_eq!(
            fabric_graph_is_satisfiable(&graph),
            Err(GenerationError::UnsatisfiableFabricGraph),
        );
    }

    /// The other half, and the one that matters: no graph exceeding a ceiling
    /// this root owns is ever admitted. Exercised one field at a time so a
    /// ceiling wired to the wrong constant is visible rather than masked by a
    /// sibling that happens to refuse.
    ///
    /// Queue depth is absent deliberately: after B46 it is a generation-owned
    /// ring property, not a root queue ceiling.
    #[test]
    fn no_graph_exceeding_a_ceiling_is_admitted() {
        // (index into the limits block, a value past this root's ceiling)
        let over = [
            (1, crate::ipc::MAX_WAIT_SOURCES as u32 + 1),
            // index 7 is queue depth: native Endpoint/ring provisioning owns it.
            (14, crate::shared_buffer::MAX_TOTAL_PAGES as u32 + 1),
            (15, crate::shared_buffer::MAX_SHARED_BUFFERS as u32 + 1),
            (16, crate::shared_buffer::MAX_MAPPINGS as u32 + 1),
            (17, crate::shared_buffer::MAX_LOANS as u32 + 1),
            (18, crate::graph::MAX_TASK_CAPS as u32 + 1),
        ];
        for (index, value) in over {
            let mut limits = SATISFIABLE;
            limits[index] = value;
            let bytes = graph_with(limits);
            let admitted = FabricGraph::decode(&bytes)
                .is_ok_and(|graph| fabric_graph_is_satisfiable(&graph).is_ok());
            assert!(
                !admitted,
                "limit {index} at {value} exceeds this root's ceiling and was admitted",
            );
        }
    }

    /// A graph is refused for contradicting itself, not only for exceeding a
    /// ceiling: the fabric brokers one loan and one mapping per matched
    /// subscriber, so promising more subscribers than either cannot be
    /// delivered however small the numbers are.
    ///
    /// The subscriber count stays at the contract's own per-role ceiling: a
    /// count above it is refused at *decode*, which would prove nothing about
    /// this root's satisfiability arm.
    #[test]
    fn a_self_contradicting_graph_is_refused_within_every_ceiling() {
        let mut limits = SATISFIABLE;
        limits[3] = boot_contracts::fabric_graph::MAX_ROLE_PARTICIPANTS as u32; // subscribers
        limits[16] = 2; // mappings
        limits[17] = 2; // loans
        let bytes = graph_with(limits);
        let graph = FabricGraph::decode(&bytes).expect("well-formed graph");
        assert_eq!(
            fabric_graph_is_satisfiable(&graph),
            Err(GenerationError::UnsatisfiableFabricGraph),
        );
    }

    #[test]
    fn a_qualified_elf_image_is_loadable() {
        let profile = sel4_profile();
        let image = qualified(wire::ELF_IMAGE_MAGIC, profile);
        let format = PayloadFormat::classify(&image, profile);
        assert_eq!(format, PayloadFormat::QualifiedElf);
        assert!(format.is_loadable());
    }

    /// `SLIMECME` and `SLIMECM2` share a seven-byte prefix, so a `starts_with`
    /// test would call every ELF-carrying image an unloadable legacy one and
    /// the graph would silently never launch. This is that regression.
    #[test]
    fn the_elf_and_segment_magics_are_not_confused_by_their_shared_prefix() {
        let profile = sel4_profile();
        assert!(wire::ELF_IMAGE_MAGIC_BYTES.starts_with(b"SLIMECM"));
        assert!(wire::IMAGE_MAGIC_BYTES.starts_with(b"SLIMECM"));
        assert_ne!(wire::ELF_IMAGE_MAGIC, wire::IMAGE_MAGIC);
        assert_eq!(
            PayloadFormat::classify(&qualified(wire::ELF_IMAGE_MAGIC, profile), profile),
            PayloadFormat::QualifiedElf
        );
        assert_eq!(
            PayloadFormat::classify(&qualified(wire::IMAGE_MAGIC, profile), profile),
            PayloadFormat::SlimeComponent
        );
    }

    /// Invariant 9: a wrong-target executable is refused before mapping, and is
    /// reported as refused rather than as malformed.
    #[test]
    fn an_image_for_another_profile_is_refused_not_loaded() {
        let board = TargetProfile::by_name("aarch64-rpi5").expect("declared profile");
        let image = qualified(wire::ELF_IMAGE_MAGIC, board);
        let format = PayloadFormat::classify(&image, sel4_profile());
        assert_eq!(format, PayloadFormat::WrongTarget);
        assert!(!format.is_loadable());
    }

    #[test]
    fn malformed_qualified_elf_headers_are_not_loadable() {
        let profile = sel4_profile();
        let mut wrong_abi = qualified(wire::ELF_IMAGE_MAGIC, profile);
        wrong_abi[wire::OFF_HEADER_KERNEL_ABI..][..4]
            .copy_from_slice(&(wire::KERNEL_ABI_VERSION + 1).to_le_bytes());
        let mut bad_stack = qualified(wire::ELF_IMAGE_MAGIC, profile);
        bad_stack[wire::OFF_HEADER_STACK_BYTES..][..4].copy_from_slice(&0u32.to_le_bytes());
        let mut nonzero_entry = qualified(wire::ELF_IMAGE_MAGIC, profile);
        nonzero_entry[wire::OFF_HEADER_ENTRY_OFFSET..][..4].copy_from_slice(&1u32.to_le_bytes());
        let mut nonzero_segments = qualified(wire::ELF_IMAGE_MAGIC, profile);
        nonzero_segments[wire::OFF_HEADER_SEGMENT_COUNT..][..2]
            .copy_from_slice(&1u16.to_le_bytes());

        for bytes in [wrong_abi, bad_stack, nonzero_entry, nonzero_segments] {
            let format = PayloadFormat::classify(&bytes, profile);
            assert_eq!(format, PayloadFormat::Unrecognized);
            assert!(!format.is_loadable());
        }
    }

    #[test]
    fn bare_aarch64_elf64_is_recognized_but_refused_for_loading() {
        let bytes = elf_header(2, 1, 183);
        let format = PayloadFormat::classify(&bytes, sel4_profile());
        assert_eq!(format, PayloadFormat::BareElf);
        assert!(!format.is_loadable());
    }

    #[test]
    fn bare_riscv64_elf64_is_recognized_but_refused_for_loading() {
        let bytes = elf_header(2, 1, 243);
        let format = PayloadFormat::classify(&bytes, sel4_profile());
        assert_eq!(format, PayloadFormat::BareElf);
        assert!(!format.is_loadable());
    }

    #[test]
    fn wrong_class_machine_or_endianness_is_not_loadable() {
        for bytes in [
            elf_header(1, 1, 183),
            elf_header(2, 2, 183),
            elf_header(2, 1, 62),
        ] {
            assert_eq!(
                PayloadFormat::classify(&bytes, sel4_profile()),
                PayloadFormat::Unrecognized
            );
        }
    }

    /// A segment-carrying image is unloadable here whatever it targets, so its
    /// target is not consulted. This is what keeps a retained x86 generation
    /// reported as the Slime component images it holds — P5.1's
    /// `slimecm=[1-9]\d*` evidence — rather than as wrong-target artifacts.
    #[test]
    fn segment_carrying_images_are_recognized_without_consulting_their_target() {
        let x86 = TargetProfile::legacy().expect("legacy profile");
        let mut v1 = [0u8; wire::LEGACY_HEADER_LEN];
        v1[wire::OFF_HEADER_MAGIC..][..8].copy_from_slice(&wire::LEGACY_IMAGE_MAGIC.to_le_bytes());
        v1[wire::OFF_HEADER_FORMAT_VERSION..][..4]
            .copy_from_slice(&wire::LEGACY_FORMAT_VERSION.to_le_bytes());
        v1[wire::OFF_HEADER_HEADER_SIZE..][..4]
            .copy_from_slice(&(wire::LEGACY_HEADER_LEN as u32).to_le_bytes());
        for profile in [x86, sel4_profile()] {
            let format = PayloadFormat::classify(&v1, profile);
            assert_eq!(format, PayloadFormat::SlimeComponent);
            assert!(!format.is_loadable());
        }
        // The same holds for a v2 image built for another architecture.
        let board = TargetProfile::by_name("aarch64-rpi5").expect("declared profile");
        assert_eq!(
            PayloadFormat::classify(&qualified(wire::IMAGE_MAGIC, board), sel4_profile()),
            PayloadFormat::SlimeComponent
        );
    }

    #[test]
    fn short_payloads_are_unrecognized() {
        assert_eq!(
            PayloadFormat::classify(&[0x7f, b'E', b'L', b'F'], sel4_profile()),
            PayloadFormat::Unrecognized
        );
        assert_eq!(
            PayloadFormat::classify(&[], sel4_profile()),
            PayloadFormat::Unrecognized
        );
        // The band between `classify`'s own 20-byte discriminator and
        // `LEGACY_HEADER_LEN` (32): long enough to answer every class, data,
        // and machine test, short enough that `component_image::target`
        // answers `Truncated` and never yields `BadMagic`. A well-formed
        // AArch64 ELF *prefix* in that band must still be unrecognized.
        //
        // Pinned explicitly because widening `elf_header` past the guard is
        // what made the two tests above it meaningful, and would otherwise
        // have vacated this band entirely — removing the guard or moving
        // `LEGACY_HEADER_LEN` would then leave the suite green.
        let elf = elf_header(2, 1, 183);
        assert_eq!(
            PayloadFormat::classify(&elf[..wire::LEGACY_HEADER_LEN - 1], sel4_profile()),
            PayloadFormat::Unrecognized
        );
    }

    #[test]
    fn no_declared_grant_yields_no_endpoint_authority() {
        assert_eq!(
            Authority::NONE.endpoint_rights(),
            sel4::CapRights::none(),
            "an ungranted component must not be able to invoke the root endpoint"
        );
    }

    #[test]
    fn send_implies_reply_authority_but_not_capability_transfer() {
        let send_only = Authority {
            rights: RIGHT_SEND | RIGHT_RECV,
            grants: 1,
        };
        assert_eq!(
            send_only.endpoint_rights(),
            sel4::CapRights::new(true, false, true, true)
        );
        let transferable = Authority {
            rights: RIGHT_SEND | RIGHT_RECV | RIGHT_TRANSFER,
            grants: 1,
        };
        assert_eq!(
            transferable.endpoint_rights(),
            sel4::CapRights::new(true, true, true, true)
        );
    }
}

#[cfg(test)]
mod adaptive_policy_tests {
    use super::*;

    fn deny_all_policy() -> alloc::vec::Vec<u8> {
        private_memory_policy::Header {
            magic: private_memory_policy::MAGIC,
            format_version: private_memory_policy::FORMAT_VERSION,
            header_size: private_memory_policy::HEADER_BYTES as u32,
            required_flags: 0,
            entitlement_count: 0,
            subject_count: 0,
            total_len: private_memory_policy::HEADER_BYTES as u32,
            reserved: 0,
            reserve_bytes: 0,
            reserve_slots: 0,
            reserve_descriptors: 0,
            reserve_extents: 0,
            reserve_tables: 0,
        }
        .encode()
        .to_vec()
    }

    #[test]
    fn private_policy_family_duplicates_refuse_before_version_selection() {
        let adaptive = deny_all_policy();
        let fixed = private_memory_budget::MAGIC;
        for objects in [
            alloc::vec![
                (KIND_RESOURCE, fixed.as_slice()),
                (KIND_RESOURCE, adaptive.as_slice())
            ],
            alloc::vec![
                (KIND_RESOURCE, adaptive.as_slice()),
                (KIND_RESOURCE, fixed.as_slice())
            ],
            alloc::vec![
                (KIND_RESOURCE, adaptive.as_slice()),
                (KIND_RESOURCE, adaptive.as_slice())
            ],
        ] {
            assert_eq!(
                select_private_memory_object(objects.into_iter().map(Ok)),
                Err(GenerationError::ConflictingPrivateMemoryPolicies)
            );
        }
        assert_eq!(
            select_private_memory_object(
                [
                    (KIND_COMPONENT, adaptive.as_slice()),
                    (KIND_RESOURCE, fixed.as_slice())
                ]
                .into_iter()
                .map(Ok)
            ),
            Ok(Some(fixed.as_slice()))
        );
    }

    #[test]
    fn an_adaptive_policy_is_admitted_on_structure_and_refused_on_malformation() {
        let valid = deny_all_policy();
        // A policy naming no subject admits, and says so: nobody may grow,
        // which is a composition rather than a failure.
        assert_eq!(adaptive_private_memory_activation(&valid, &[]), Ok(Some(0)));
        let mut invalid = valid;
        invalid[private_memory_policy::OFF_HEADER_REQUIRED_FLAGS] = 1;
        assert_eq!(
            adaptive_private_memory_activation(&invalid, &[]),
            Err(GenerationError::MalformedPrivateMemoryPolicy)
        );
    }

    /// The residual after reservation already excludes each guarantee, so the
    /// admitted pool must be exactly that residual less the operational
    /// reserve: a second subtraction would strand the guarantee's envelope.
    #[test]
    fn a_reserved_guarantee_is_subtracted_from_the_pool_once() {
        use private_memory_policy::ledger::Resources;
        let entitlement = private_memory_policy::Entitlement {
            identity: private_memory_policy::entitlement_identity("promised"),
            subtree_root: [0; 32],
            guarantee_pages: 64,
            maximum_pages: 0,
            maximum_mode: private_memory_policy::POOL,
            reserved: 0,
        };
        let subject = private_memory_policy::Subject {
            identity: private_memory_policy::subject_identity("holder"),
            entitlement: entitlement.identity,
            maximum_pages: 0,
            maximum_mode: private_memory_policy::POOL,
            reserved: 0,
        };
        let mut bytes = deny_all_policy();
        let mut header = private_memory_policy::Header::decode(&bytes).expect("header");
        header.entitlement_count = 1;
        header.subject_count = 1;
        header.total_len = (private_memory_policy::HEADER_BYTES
            + private_memory_policy::ENTITLEMENT_BYTES
            + private_memory_policy::SUBJECT_BYTES) as u32;
        header.reserve_bytes = 4096;
        bytes = header.encode().to_vec();
        bytes.extend(entitlement.encode());
        bytes.extend(subject.encode());
        let policy = PrivateMemoryPolicy::decode(&bytes).expect("policy");
        let instances = [private_memory_policy::Instance {
            identity: subject.identity,
            owner: None,
        }];
        let residual = Resources {
            bytes: 1 << 24,
            slots: 4096,
            descriptors: 4096,
            extents: 64,
            tables: 4096,
        };
        let ledger = admit_private_memory_ledger(policy, &instances, residual).expect("admitted");
        assert_eq!(ledger.available().bytes, residual.bytes - 4096);
        assert_eq!(ledger.available().slots, residual.slots);
    }

    #[test]
    fn a_guarantee_larger_than_the_pool_is_refused_before_anything_launches() {
        use private_memory_policy::ledger::Resources;
        let bytes = deny_all_policy();
        let policy = PrivateMemoryPolicy::decode(&bytes).expect("policy");
        // No entitlement, so the only claim on the pool is the policy's own
        // reserve, which this one declares as zero.
        assert!(admit_private_memory_ledger(policy, &[], Resources::ZERO).is_ok());

        let mut over = bytes.clone();
        over[private_memory_policy::OFF_HEADER_RESERVE_BYTES
            ..private_memory_policy::OFF_HEADER_RESERVE_BYTES + 8]
            .copy_from_slice(&4096u64.to_le_bytes());
        let policy = PrivateMemoryPolicy::decode(&over).expect("policy");
        // The reserve is subtracted from the real pool first, so a machine
        // that cannot fund it refuses the policy rather than publishing tasks
        // whose operational capacity was never there.
        assert!(admit_private_memory_ledger(policy, &[], Resources::ZERO).is_err());
        let policy = PrivateMemoryPolicy::decode(&over).expect("policy");
        assert!(
            admit_private_memory_ledger(
                policy,
                &[],
                Resources {
                    bytes: 8192,
                    slots: 8,
                    descriptors: 8,
                    extents: 8,
                    tables: 8,
                }
            )
            .is_ok()
        );
    }

    /// An entitlement's reserved cost is never below what the reservation
    /// physically takes. A guarantee under one span still removes a whole
    /// aligned span, and a policy admitted against the per-page envelope alone
    /// would be admitted against bytes that were already gone.
    #[test]
    fn a_guarantee_is_priced_at_least_at_what_its_reservation_takes() {
        use private_memory_policy::ledger::Resources;
        let span_pages = guarantee_vault::GUARANTEE_SPAN_PAGES as u64;
        let span_bytes = 1u64 << guarantee_vault::GUARANTEE_SPAN_BITS;
        assert_eq!(guarantee_reservation_resources(0), Ok(Resources::ZERO));
        for pages in [1, 2, span_pages - 1, span_pages, span_pages + 1, 4096] {
            let spans = pages.div_ceil(span_pages);
            let priced = guarantee_reservation_resources(pages).expect("priced");
            // Never below what the reservation physically takes: two coarse
            // extents per span, each one span wide, and their anchors.
            assert!(priced.bytes >= 2 * spans * span_bytes, "pages {pages}");
            assert_eq!(priced.extents, 2 * spans, "pages {pages}");
            assert!(priced.slots >= 2 * spans, "pages {pages}");
            // Never below what the pages themselves cost at their worst
            // placement: payload plus one leaf table each.
            assert!(priced.bytes >= 2 * pages * private_memory_policy::PAGE_BYTES);
            assert!(priced.descriptors >= 2 * pages);
            assert!(priced.tables >= pages);
            assert!(priced.slots >= 2 * pages + 2 * spans);
        }
        // A whole span of pages is exactly where the two bounds meet.
        let exact = guarantee_reservation_resources(span_pages).expect("priced");
        assert_eq!(exact.bytes, 2 * span_bytes);
        assert_eq!(
            exact.bytes,
            2 * span_pages * private_memory_policy::PAGE_BYTES
        );
    }

    /// The guaranteed envelope is the real cost of the worst page placement,
    /// taken from the demand code that charges a growth. A page that lands
    /// alone in its own span costs its own base page *and* its own leaf table:
    /// two granules of backing, four root CSlots, two allocation descriptors,
    /// two extents and one table. An envelope of one unit per page — what this
    /// reserved before — funds a quarter of the slots such a page needs.
    #[test]
    fn the_guaranteed_page_envelope_is_priced_by_the_growth_path() {
        use private_memory_policy::ledger::Resources;
        assert_eq!(
            guaranteed_page_envelope(),
            Ok(Resources {
                bytes: 2 * private_memory_policy::PAGE_BYTES,
                // One CSlot and one descriptor each for the frame and its
                // worst-case leaf table. The extents those objects are
                // retyped from belong to the span, not to the page.
                slots: 2,
                descriptors: 2,
                extents: 0,
                tables: 1,
            })
        );
        // Every component is at least the ledger's own admission minimum of
        // one unit per guaranteed page, so raising it can never make a policy
        // the old envelope admitted structurally inadmissible.
        let envelope = guaranteed_page_envelope().expect("envelope");
        for unit in [
            envelope.bytes / private_memory_policy::PAGE_BYTES,
            envelope.slots,
            envelope.descriptors,
            envelope.tables,
        ] {
            assert!(unit >= 1);
        }
        // Every entitlement still owns at least one extent, which is the
        // shape-neutral minimum the ledger admits against.
        assert!(guarantee_reservation_resources(1).expect("priced").extents >= 1);
    }
}

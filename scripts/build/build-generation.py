#!/usr/bin/env python3

from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))
# This script's own directory, for sibling modules when imported by host checks.
_sys.path.insert(0, str(_Path(__file__).resolve().parent))

import argparse
import copy
import json
import os
import struct
import subprocess
from pathlib import Path
from elf_delivery import strip_elf_delivery

from boot_contracts import (
    BOOTSTATE_ACCEPTED_RELEASE_SEQUENCE_OFFSET,
    BOOTSTATE_CHECKSUM_END,
    BOOTSTATE_CHECKSUM_OFFSET,
    BOOTSTATE_GENERATION_ROOT_END,
    BOOTSTATE_GENERATION_ROOT_OFFSET,
    BOOTSTATE_KNOWN_GOOD_END,
    BOOTSTATE_KNOWN_GOOD_OFFSET,
    BOOTSTATE_MAGIC,
    BOOTSTATE_PENDING_END,
    BOOTSTATE_PENDING_OFFSET,
    BOOTSTATE_REMAINING_ATTEMPTS_OFFSET,
    BOOTSTATE_SLOT_BYTES,
    BOOTSTATE_STATE_ROOT_END,
    BOOTSTATE_STATE_ROOT_OFFSET,
    BOOTSTATE_VERSION,
    BOOTSTORE_CAPACITY,
    BOOTSTORE_DIRECTORY_OFFSET,
    BOOTSTORE_ENTRY,
    BOOTSTORE_GENERATIONS_OFFSET,
    BOOTSTORE_RELEASES_OFFSET,
    BOOTSTORE_HEADER,
    BOOTSTORE_MAGIC,
    BOOTSTORE_VERSION,
    COMPONENT_DEFAULT_STACK_BYTES,
    COMPONENT_IMAGE_ELF_HEADER_LEN,
    COMPONENT_IMAGE_ELF_MAGIC,
    COMPONENT_IMAGE_ELF_VERSION,
    COMPONENT_IMAGE_HEADER,
    COMPONENT_IMAGE_KERNEL_ABI,
    COMPONENT_IMAGE_MAGIC,
    COMPONENT_IMAGE_MAX_SEGMENTS,
    COMPONENT_IMAGE_SEGMENT,
    COMPONENT_IMAGE_VERSION,
    COMPONENT_MAX_STACK_BYTES,
    COMPONENT_SEGMENT_FLAG_EXEC,
    COMPONENT_SEGMENT_FLAG_WRITE,
    MAX_COMPONENT_IMAGE_BYTES,
    component_image_capacity_for,
    GENERATION_BINDING,
    GENERATION_DEPENDENCY,
    GENERATION_EXECUTABLE,
    GENERATION_INSTANCE,
    GENERATION_GRANT,
    GENERATION_HEADER,
    GENERATION_HEALTH,
    GENERATION_MAGIC,
    GENERATION_OBJECT,
    GENERATION_RIGHT_ALL,
    GENERATION_RIGHT_BY_MANIFEST_NAME,
    GENERATION_RIGHT_TRANSFER,
    GENERATION_STATE,
    GENERATION_PROCESS,
    GENERATION_THREAD,
    GENERATION_KERNEL_OBJECT,
    GENERATION_MAPPING,
    GENERATION_CAP_BINDING,
    GENERATION_SERVICE_BINDING,
    GENERATION_SCHEDULE,
    GENERATION_FAULT_POLICY,
    GENERATION_SPAWN_TEMPLATE,
    GENERATION_MINTED_BINDING,
    GENERATION_NOTIFICATION_GRANT,
    GENERATION_NOTIFICATION_BINDING,
    GENERATION_RESOURCE_QUOTA,
    GENERATION_VERSION,
    TARGET_PROFILES_BY_NAME,
    TargetProfile,
    MAX_BINDINGS,
    MAX_DEPENDENCIES,
    MAX_EXECUTABLES,
    MAX_INSTANCES,
    MAX_GENERATION_BYTES,
    MAX_GRANTS,
    MAX_HEALTH_INSTANCES,
    MAX_OBJECT_PAYLOAD_BYTES,
    MAX_OBJECTS,
    MAX_STATES,
    MAX_STRING_BYTES,
    MAX_STRING_TABLE_BYTES,
    MAX_PROCESSES,
    MAX_THREADS,
    MAX_KERNEL_OBJECTS,
    MAX_MAPPINGS,
    MAX_CAP_BINDINGS,
    MAX_SERVICE_BINDINGS,
    MAX_SCHEDULES,
    MAX_FAULT_POLICIES,
    MAX_SPAWN_TEMPLATES,
    MAX_MINTED_BINDINGS,
    MAX_NOTIFICATION_GRANTS,
    MAX_NOTIFICATION_BINDINGS,
    MAX_RESOURCE_QUOTAS,
    bootstate_checksum,
    bootstore_checksum,
    generation_identity,
    sha256,
)
from boot_layout import LAYOUT_KIND_ROLES, build_boot_layout, layout_from_manifest
from interface_schema import InterfaceSchemaError, admit_interfaces, resolve_interface_paths
from release_trust import RELEASE_BYTES, build_release
from zutai_cli import STDLIB, binary
import private_memory_policy

from harness import GENERATION_COMPOSITIONS, GENERATION_FIXTURES, ROOT
from generation_resources import (
    build_block_ring_authority,
    build_clock_authority,
    build_entropy_authority,
    build_graph_arrival_ceiling,
    build_zenoh_grants_table,
    build_instance_lifetime,
    instance_lifetime_identity,  # noqa: F401 -- read by check-system-spec.py through this module
    build_io_resource_budget,
    build_network_destinations,
    build_network_interfaces,
    build_network_applications,
    build_lifecycle_policy,
    build_private_memory_budget,
    build_recording_policy,
    build_scheduling_class,
    build_shared_buffer_budget,
    build_wait_set,
    validated_private_memory_quotas,
    validated_scheduling_class,
)
from generation_fabric import *  # noqa: F403
from generation_fabric import resolve_fabric_profile as _resolve_fabric_profile


def declared_boot_profiles(manifest: dict) -> list[str]:
    """Every boot profile the manifest names, selected or not."""
    return [profile["name"] for profile in manifest.get("bootProfiles", [])]


def boot_profile(manifest: dict, name: str) -> dict:
    """The one boot profile `name` selects."""
    profiles = manifest.get("bootProfiles", [])
    names = [profile["name"] for profile in profiles]
    if len(names) != len(set(names)):
        fail("boot profile: duplicate profile name")
    matches = [profile for profile in profiles if profile["name"] == name]
    if len(matches) != 1:
        fail(f"boot profile: expected exactly one {name} profile")
    return matches[0]


def resolve_boot_profile(manifest: dict, name: str) -> dict:
    """Narrow the manifest to the instances one boot profile declares."""
    profile = boot_profile(manifest, name)
    scaffolding = profile["instances"]
    if len(set(scaffolding)) != len(scaffolding):
        fail(f"boot profile {name}: duplicate instance")
    declared = {instance["name"] for instance in manifest["instances"]}
    unknown = sorted(set(scaffolding) - declared)
    if unknown:
        fail(f"boot profile {name}: undeclared instance(s) {', '.join(unknown)}")
    scaffolding_everywhere = {
        instance for entry in manifest.get("bootProfiles", []) for instance in entry["instances"]
    }
    kept = (declared - scaffolding_everywhere) | set(scaffolding)
    resolved = copy.deepcopy(manifest)
    resolved.pop("bootProfiles", None)
    resolved["instances"] = [
        instance for instance in manifest["instances"] if instance["name"] in kept
    ]
    # Boot profiles select initial instances. The executable catalogue is
    # independent and remains complete so an initial instance may spawn any
    # executable its explicit exec grant authorizes.
    used_executables = {executable["name"] for executable in manifest["executables"]}
    resolved["executables"] = copy.deepcopy(manifest["executables"])
    kept_objects = {executable["object"] for executable in resolved["executables"]}
    resolved["objects"] = [
        object_
        for object_ in manifest["objects"]
        if object_["kind"] != "component" or object_["id"] in kept_objects
    ]
    resolved["grants"] = [
        grant
        for grant in manifest["grants"]
        if grant["source"] in kept
        and (grant["target"] in kept or grant["target"] in used_executables)
    ]
    retained_grants = {grant["name"] for grant in resolved["grants"]}
    for instance in resolved["instances"]:
        instance["bindings"] = [
            binding for binding in instance["bindings"] if binding["grant"] in retained_grants
        ]
    resolved["state"] = [binding for binding in manifest["state"] if binding["owner"] in kept]
    resolved["sharedBufferBudget"] = [
        entry for entry in manifest["sharedBufferBudget"] if entry["holder"] in kept
    ]
    # Same rule as the shared-buffer budget above: a profile that does not
    # declare an instance carries no quota for it, so the resource a boot
    # profile emits names only holders that profile actually launches.
    if manifest.get("privateMemoryBudget") is not None:
        resolved["privateMemoryBudget"] = [
            entry for entry in manifest["privateMemoryBudget"] if entry["holder"] in kept
        ]
    if manifest.get("privateMemoryPolicy") is not None:
        try:
            private_memory_policy.manifest_policy(manifest)
            resolved["privateMemoryPolicy"] = private_memory_policy.narrow(
                manifest["privateMemoryPolicy"], resolved["instances"]
            )
        except ValueError as error:
            fail(str(error))
    if manifest.get("ioResourceBudget") is not None:
        resolved["ioResourceBudget"] = [
            entry for entry in manifest["ioResourceBudget"] if entry["holder"] in kept
        ]
    if manifest.get("clockAuthority") is not None:
        resolved["clockAuthority"] = [
            entry for entry in manifest["clockAuthority"] if entry["holder"] in kept
        ]
    required = profile["requiredInstances"] or manifest["health"]["requiredInstances"]
    missing = sorted(set(required) - kept)
    if missing:
        fail(f"boot profile {name}: required instance(s) {', '.join(missing)} not declared")
    resolved["health"] = dict(manifest["health"], requiredInstances=list(required))
    graph = resolved.get("fabricGraph")
    if graph is not None:
        graph["profiles"] = [
            entry
            for entry in graph.get("profiles", [])
            if entry["name"] == profile["fabricProfile"]
        ]
        if len(graph["profiles"]) != 1:
            fail(
                f"boot profile {name}: fabric profile "
                f"{profile['fabricProfile']} is not declared exactly once"
            )
        for chain in graph["profiles"][0]["interpositions"]:
            absent = sorted(set(chain["chain"]) - kept)
            if absent:
                fail(
                    f"boot profile {name}: interposition chain names "
                    f"{', '.join(absent)}, which this profile does not declare"
                )
        routes = []
        for route in graph["routes"]:
            route["participants"] = [
                member for member in route["participants"] if member["component"] in kept
            ]
            for member in route["participants"]:
                hidden = sorted(set(member["interposition"]) - kept)
                if hidden:
                    fail(
                        f"boot profile {name}: route {route['name']} interposes through "
                        f"{', '.join(hidden)}, which this profile does not declare"
                    )
            # A route every participant of which was scaffolding carries no
            # traffic in this profile. Keeping it would declare a route the
            # fabric must provision and nobody can use, and `build_fabric_graph`
            # rejects a participant-less route outright.
            if route["participants"]:
                routes.append(route)
        graph["routes"] = routes
    return resolved


def resolve_fabric_profile(
    manifest: dict, interfaces: list, profile_name: str
) -> ResolvedFabricProfile:
    import generation_fabric

    generation_fabric.MAX_FABRIC_GRAPH_INGRESS_SOURCES = MAX_FABRIC_GRAPH_INGRESS_SOURCES
    generation_fabric.FABRIC_TRACE_MAX_DEPTH = FABRIC_TRACE_MAX_DEPTH
    generation_fabric.FABRIC_TRACE_TERMINAL_RESERVE = FABRIC_TRACE_TERMINAL_RESERVE
    return _resolve_fabric_profile(manifest, interfaces, profile_name, resolve_boot_profile)


# Imported lazily for compatibility with host checks that load this script as a
# module and call the resource identity helpers directly. The builder itself
# uses only the names imported above.
def __getattr__(name: str):
    import generation_resources

    try:
        return getattr(generation_resources, name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


SOURCE = GENERATION_FIXTURES / "valid.zti"
# P5.2: seL4 graphs are sibling manifests rather than boot profiles of
# `valid.zti`, because `resolve_boot_profile` narrows by subtraction and naming
# a component in a new profile would drop it from `default`, changing the frozen
# product generation. See `sel4.md` beside it.
SEL4_SOURCE = GENERATION_COMPOSITIONS / "sel4.zti"
SEL4_TARGET_PROFILE = "aarch64-sel4-qemu-virt"
# P4's physical target. It builds the same seL4 manifests from the same graph
# declarations; only the profile every executable is admitted for differs, so
# `manifest["target"]` is rewritten and immutable root admission refuses QEMU-
# qualified components on the board and board-qualified ones under QEMU.
SEL4_BOARD_TARGET_PROFILE = "aarch64-rpi5"
# P3's RV64 reference uses the same generated graph and native seL4 transport,
# but every executable is rebuilt and qualified for a distinct ABI/profile.
SEL4_RISCV64_TARGET_PROFILE = "riscv64-sel4-qemu-virt"
# P3.E's physical RV64 target shares the seL4 userspace ABI, not its platform
# identity. Rewriting the manifest target forces every embedded executable to be
# rebuilt and admitted for the named Duo profile.
SEL4_RISCV64_DUO_TARGET_PROFILE = "riscv64-sel4-milkv-duo"
# P6.1's x86-64 reference and its named Framework counterpart. Same generated
# graph and native seL4 transport as every other seL4 profile; a distinct ABI
# and platform identity, so no executable is interchangeable with them.
SEL4_X86_64_TARGET_PROFILE = "x86_64-sel4-qemu-pc99"
SEL4_X86_64_FRAMEWORK_TARGET_PROFILE = "x86_64-sel4-framework13-ai300"
SEL4_TARGET_PROFILES = (
    SEL4_TARGET_PROFILE,
    SEL4_BOARD_TARGET_PROFILE,
    SEL4_RISCV64_TARGET_PROFILE,
    SEL4_RISCV64_DUO_TARGET_PROFILE,
    SEL4_X86_64_TARGET_PROFILE,
    SEL4_X86_64_FRAMEWORK_TARGET_PROFILE,
)
# Additional seL4 manifests carry distinct authenticated boot actions and
# generation-derived component tables while sharing the same target profile.
SEL4_MANIFESTS = {
    "sel4": SEL4_SOURCE,
    # RP2: the demo-scoped slice — one generation that both launches the
    # product component graph and runs the bounded data path.
    "sel4-demo": GENERATION_COMPOSITIONS / "sel4-demo.zti",
    "sel4-channel": GENERATION_COMPOSITIONS / "sel4-channel.zti",
    "sel4-large-image": GENERATION_COMPOSITIONS / "sel4-large-image.zti",
    "sel4-loan": GENERATION_COMPOSITIONS / "sel4-loan.zti",
    "sel4-io-queue": GENERATION_COMPOSITIONS / "sel4-io-queue.zti",
    "sel4-io-driver-authority": GENERATION_COMPOSITIONS / "sel4-io-driver-authority.zti",
    "sel4-io-network": GENERATION_COMPOSITIONS / "sel4-io-network.zti",
    "sel4-io-tcp": GENERATION_COMPOSITIONS / "sel4-io-tcp.zti",
    "sel4-io-block": GENERATION_COMPOSITIONS / "sel4-io-block.zti",
    "sel4-io-link": GENERATION_COMPOSITIONS / "sel4-io-link.zti",
    "sel4-spawn": GENERATION_COMPOSITIONS / "sel4-spawn.zti",
    "sel4-sample": GENERATION_COMPOSITIONS / "sel4-sample.zti",
    "sel4-stream": GENERATION_COMPOSITIONS / "sel4-stream.zti",
    "sel4-supervision": GENERATION_COMPOSITIONS / "sel4-supervision.zti",
    "sel4-reclamation": GENERATION_COMPOSITIONS / "sel4-reclamation.zti",
    # C10.2: one executable declared twice, as a granted holder and an omitted
    # one, against a generation-declared private-memory budget.
    "sel4-private-memory": GENERATION_COMPOSITIONS / "sel4-private-memory.zti",
    # MEM-64M's reuse clause: one declared 64 MiB holder init relaunches until
    # the root has reclaimed and re-served that quota twenty times.
    "sel4-private-memory-cycles": GENERATION_COMPOSITIONS / "sel4-private-memory-cycles.zti",
    "sel4-private-memory-1g": GENERATION_COMPOSITIONS / "sel4-private-memory-1g.zti",
    "sel4-private-memory-isolation": GENERATION_COMPOSITIONS / "sel4-private-memory-isolation.zti",
    # C9.3: a declared scheduling class, its band mapping, and promotion
    # authority over another component's class.
    "sel4-scheduling-class": GENERATION_COMPOSITIONS / "sel4-scheduling-class.zti",
    # C9.4: an admitted lifecycle transition graph, a supervised restart under a
    # declared attempt bound and backoff, a health dependency, and parameter
    # authority.
    "sel4-lifecycle-restart": GENERATION_COMPOSITIONS / "sel4-lifecycle-restart.zti",
    # C9.5: a recorded run and a deterministic replay of it, plus a component
    # whose unrecorded grant makes a determinism claim inadmissible.
    "sel4-replay": GENERATION_COMPOSITIONS / "sel4-replay.zti",
    # C9.6: a sensor -> controller -> actuator graph over the native fabric,
    # under declared best-effort CPU contention and an injected controller
    # restart.
    "sel4-robot-runtime": GENERATION_COMPOSITIONS / "sel4-robot-runtime.zti",
    # C9.1: independently grantable monotonic, timer, and simulated clocks.
    "sel4-clock-authority": GENERATION_COMPOSITIONS / "sel4-clock-authority.zti",
    # C9.2: a bounded userspace wait set over one declared Notification.
    "sel4-wait-set": GENERATION_COMPOSITIONS / "sel4-wait-set.zti",
    "sel4-crossing": GENERATION_COMPOSITIONS / "sel4-crossing.zti",
    "sel4-call": GENERATION_COMPOSITIONS / "sel4-call.zti",
    "sel4-qos": GENERATION_COMPOSITIONS / "sel4-qos.zti",
    # 48 instances: the admitted ceiling, so the graph that boots is the
    # largest one admission will accept (B49).
    "sel4-stress": GENERATION_COMPOSITIONS / "sel4-stress.zti",
    "sel4-operation": GENERATION_COMPOSITIONS / "sel4-operation.zti",
    "sel4-visibility": GENERATION_COMPOSITIONS / "sel4-visibility.zti",
    "sel4-boot": GENERATION_COMPOSITIONS / "sel4-boot.zti",
    "sel4-traffic": GENERATION_COMPOSITIONS / "sel4-traffic.zti",
    "sel4-matrix": GENERATION_COMPOSITIONS / "sel4-matrix.zti",
    # C8.12's negative arm shares this manifest (B62): one `telemetry-alt`
    # publisher is weakened to BEST_EFFORT against its RELIABLE subscriber
    # through a declared per-variant QoS override, rather than by a second
    # 1069-line copy. The builder emits the incompatible graph — pairwise QoS is
    # not a shape property — and `slime-root` refuses it at admission, which is
    # where that rule lives.
    "sel4-storage": GENERATION_COMPOSITIONS / "sel4-storage.zti",
    "sel4-store": GENERATION_COMPOSITIONS / "sel4-store.zti",
    "sel4-data-volume": GENERATION_COMPOSITIONS / "sel4-data-volume.zti",
    "sel4-lidar-external": GENERATION_COMPOSITIONS / "sel4-lidar-external.zti",
    "sel4-rollback": GENERATION_COMPOSITIONS / "sel4-rollback.zti",
    "sel4-recovery": GENERATION_COMPOSITIONS / "sel4-recovery.zti",
    "sel4-generation": GENERATION_COMPOSITIONS / "sel4-generation.zti",
    "sel4-directory": GENERATION_COMPOSITIONS / "sel4-directory.zti",
    "sel4-filesystem": GENERATION_COMPOSITIONS / "sel4-filesystem.zti",
    "sel4-input": GENERATION_COMPOSITIONS / "sel4-input.zti",
    "sel4-powerbox": GENERATION_COMPOSITIONS / "sel4-powerbox.zti",
    "sel4-transfer": GENERATION_COMPOSITIONS / "sel4-transfer.zti",
}
# These manifests require an explicitly supplied non-workspace ELF and matching
# component-spec corpus. Keep them selectable by the product builder without
# making corpus-wide checks pretend a Rust workspace package can build them.
SEL4_EXTERNAL_MANIFESTS = {
    "sel4-c-runtime": GENERATION_COMPOSITIONS / "sel4-c-runtime.zti",
    "sel4-slisp": GENERATION_COMPOSITIONS / "sel4-slisp.zti",
}
SEL4_SELECTABLE_MANIFESTS = SEL4_MANIFESTS | SEL4_EXTERNAL_MANIFESTS
COMPONENTS_TARGET_DIR = Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target" / "components")
# The components whose crates declare `boot-contracts/gpt` and `slime-rt/heap`,
# and so link a `#[global_allocator]`. CP3 scoped that allocator to exactly
# these six by moving the feature declaration into their own manifests; this set
# is what keeps the *build* honest about it, because Cargo unifies features
# across every package named in one invocation, so a plain component compiled
# alongside one of these would silently gain the heap too.
#
# Declared here rather than read from the manifests because it must be the
# builder's own statement of the split: `just component_crate_split_check`
# compares it against what the crates actually declare, so a component gaining
# an allocator without moving groups is a gate failure rather than a silent
# regrouping.
STORE_COMPONENTS = frozenset(
    {
        "sel4-filesystem-service",
        "sel4-generation-manager",
        "sel4-recovery-probe",
        "sel4-rollback-probe",
        "sel4-store-probe",
        "sel4-transfer-probe",
    }
)
# C10.3's private-region allocator, scoped the same way and for the same
# reason: `slime-rt/private-heap` registers a *different*
# `#[global_allocator]`, mutually exclusive with the store plane's, so its
# consumers need a third build group rather than joining either of the other
# two. `just component_crate_split_check` compares this against what the crates
# declare.
#
# C10.4 adds `fabric-service`: its role and frame tables are now sized from the
# graph a generation declared rather than from the contract's ceilings, so they
# come from the task-private region. It is the first *product* component here
# rather than a probe, which is the point — the mechanism is only load-bearing
# once something that ships uses it.
#
# `network-service` links it for socket pools above the minimum buffer size, which
# only a generation declaring a larger network-application buffer needs. It is not
# in `PRIVATE_HEAP_REQUIRED`: a generation whose rows declare the minimum size runs
# on the static pools and takes no quota.
#
# `lidar-publisher` holds one recorded frame and its link's reassembly and
# transmit buffers on the heap; frames are about half a megabyte each.
PRIVATE_HEAP_COMPONENTS = frozenset({"fabric-service", "lidar-publisher", "network-service", "private-heap-probe"})
# Of those, the ones that cannot provision at all without a quota (C10.4).
#
# A subset rather than the same set: linking the allocator and *requiring* a
# quota are different facts. `private-heap-probe` links it precisely so it can be
# run both ways — the private-memory plane declares one instance with a quota and
# one without, and the omitted instance proving it is denied is that plane's
# whole point. `fabric-service` has no such mode: its role and frame tables are
# the first thing it allocates and it fails provisioning without them, so a
# generation carrying it and omitting its quota is one that cannot boot.
# `lidar-publisher` is the same: it allocates its frame buffer before it
# publishes anything.
#
# Checked against `privateMemoryBudget` where the budget is encoded, so the
# refusal is a build failure rather than a named component failure at boot.
PRIVATE_HEAP_REQUIRED = frozenset({"fabric-service", "lidar-publisher"})
PAGE_SIZE = 4096
KIND = {"kernel": 1, "bootstrap": 2, "component": 3, "resource": 4}
ROLE = {"init": 1, "service": 2, "driver": 3, "application": 4}
# Rights numbering is generated-contract truth. Both the manifest-spelling table
# and `RIGHT_ALL` come from `contracts/generation/v5/schema.zt` via
# `boot_contracts`, so the builder, the root, and the oracle cannot disagree
# about which bit a right is or which bits exist. `RIGHT_ALL` is the union of
# the named bits rather than a bit-width mask, which is what closes B57's hole
# at bit 17.
RIGHT = GENERATION_RIGHT_BY_MANIFEST_NAME
RIGHT_TRANSFER = GENERATION_RIGHT_TRANSFER
RIGHT_ALL = GENERATION_RIGHT_ALL

CAPABILITY_KIND = {
    "endpoint": 1,
    "executable": 2,
    "sharedBufferFactory": 3,
    # 4 was `block`, retired with B90. Reserved rather than reassigned: a
    # discriminant is wire identity, and storage authority is now declared per
    # ring in `contracts/block-authority/v1`.
    "directory": 5,
    "input": 6,
    "supervision": 7,
    "sharedBuffer": 8,
    "loan": 9,
    # IO1's hardware-resource classes. Four kinds rather than one `device`,
    # because they are four separately grantable authorities and collapsing them
    # would make "this driver may map MMIO but must not touch DMA" unsayable.
    # A `device` names one physical instance; the other three are the bounded
    # resources that instance's driver may request against it.
    "device": 10,
    "mmioRegion": 11,
    "interruptSource": 12,
    "dmaAccount": 13,
}


SUPERVISION_NAME_SUFFIX = "-supervision"
# The `minted:` resolve string a component builds for a supervision handle, and
# the stack buffer it builds it in. `fabric-service.rs`'s `supervision_slot_for`
# formats `minted:<component>-supervision` into a fixed 64-byte array, because a
# `no_std` component has no allocator; a name that overflowed it would be a
# runtime `fail()` on a real boot. Bounding it here makes that a build failure
# instead, which is the only place the two can be kept in agreement.
SUPERVISION_RESOLVE_PREFIX = "minted:"
SUPERVISION_RESOLVE_NAME_BYTES = 64


def validate_supervision_binding_names(manifest: dict, instances: list) -> None:
    """A supervision binding is named for the task it supervises.

    The `minted:` resolve axis lets a component ask the root which of its slots
    holds a named binding, which is only usable if the name means the same thing
    in every generation that declares it. Three conventions were in the fixtures
    at once — `fabric-publisher-supervision`,
    `fabric-service-supervision-publisher`, and
    `fabric-service-call-client-supervision` — so a component could not ask by
    name without a manifest-specific alias table, which is exactly the
    compile-time coupling B70 exists to remove. Naming the handle for the
    *supervised* task is the one choice that is a property of the graph rather
    than of which manifest happens to declare it: `fabric-service` and
    `fabric-call-worker` both supervise `fabric-call-client`, and under this rule
    both name that handle `fabric-call-client-supervision`.

    Asserted here rather than merely applied, so a fourth convention is a build
    failure rather than a name a component silently cannot resolve. Scoped to
    `supervision`, the one kind whose object is a task identity; other minted
    kinds name channels and have no supervised instance to be named for.

    Instance names may be prefixes of one another — `fabric-op-client-b` and
    `fabric-op-client-b-restart` both exist, each with its own handle — so the
    check strips the suffix and looks up the whole remainder, rather than
    searching for a known instance name inside the string. A substring search
    would resolve `fabric-op-client-b-restart-supervision` to the wrong task.

    The owner clause is what makes the name *answerable*. `resolve_minted_slot`
    scopes to the calling holder, so the name only has to be unique per holder —
    but a handle can only exist if its minter owns the task it names, which the
    holder-ownership check below already requires of the holder. Requiring the
    supervised instance to be owned by the same minter keeps the two halves
    consistent: a name pointing at a task its minter cannot supervise would pass
    the string check and fail at spawn.
    """
    owners = {instance["name"]: instance["owner"] for instance in instances}
    for minted in manifest.get("mintedBindings", []):
        if minted["capabilityKind"] != "supervision":
            continue
        name = minted["name"]
        if not name.endswith(SUPERVISION_NAME_SUFFIX):
            fail(
                f"minted binding {name}: a supervision binding is named "
                f"<supervised-instance>{SUPERVISION_NAME_SUFFIX}"
            )
        supervised = name[: -len(SUPERVISION_NAME_SUFFIX)]
        if supervised not in owners:
            fail(
                f"minted binding {name}: names no declared instance "
                f"({supervised!r} is not an instance in this generation)"
            )
        if supervised == minted["holder"]:
            fail(f"minted binding {name}: holder would supervise itself")
        if owners[supervised] != minted["owner"]:
            fail(
                f"minted binding {name}: supervises an instance owned by "
                f"{owners[supervised]!r}, but is minted by {minted['owner']!r}"
            )
        resolve_bytes = len((SUPERVISION_RESOLVE_PREFIX + name).encode("utf-8"))
        if resolve_bytes > SUPERVISION_RESOLVE_NAME_BYTES:
            fail(
                f"minted binding {name}: its resolve string is {resolve_bytes} "
                f"bytes, over the {SUPERVISION_RESOLVE_NAME_BYTES}-byte buffer a "
                "component formats it in"
            )


def validate_capability_rights(name: str, kind: str, rights: int) -> None:
    masks = {
        "endpoint": RIGHT["send"] | RIGHT["recv"] | RIGHT_TRANSFER,
        "executable": RIGHT["exec"] | RIGHT["spawn"] | RIGHT_TRANSFER,
        "sharedBufferFactory": RIGHT["bufferCreate"] | RIGHT_TRANSFER,
        "directory": (
            RIGHT["directoryRead"]
            | RIGHT["directoryWrite"]
            | RIGHT["directoryList"]
            | RIGHT["directoryDerive"]
            | RIGHT_TRANSFER
        ),
        "input": RIGHT["inputRead"],
        "supervision": RIGHT["supervise"] | RIGHT_TRANSFER,
        "sharedBuffer": (
            RIGHT["bufferWrite"] | RIGHT["bufferMap"] | RIGHT["bufferLoan"] | RIGHT_TRANSFER
        ),
        "loan": RIGHT["bufferWrite"] | RIGHT["bufferMap"] | RIGHT_TRANSFER,
        "device": RIGHT["mapMmio"],
        "mmioRegion": RIGHT["mapMmio"],
        "interruptSource": RIGHT["irqAck"],
        "dmaAccount": RIGHT["dmaPin"] | RIGHT["dmaRelease"],
    }
    required = {
        "endpoint": RIGHT["send"] | RIGHT["recv"],
        "executable": RIGHT["exec"] | RIGHT["spawn"],
        "sharedBufferFactory": RIGHT["bufferCreate"],
        "directory": (
            RIGHT["directoryRead"]
            | RIGHT["directoryWrite"]
            | RIGHT["directoryList"]
            | RIGHT["directoryDerive"]
        ),
        "input": RIGHT["inputRead"],
        "supervision": RIGHT["supervise"],
        "sharedBuffer": RIGHT["bufferWrite"] | RIGHT["bufferMap"] | RIGHT["bufferLoan"],
        "loan": RIGHT["bufferMap"],
        "device": RIGHT["mapMmio"],
        "mmioRegion": RIGHT["mapMmio"],
        "interruptSource": RIGHT["irqAck"],
        "dmaAccount": RIGHT["dmaPin"] | RIGHT["dmaRelease"],
    }
    mask = masks.get(kind)
    if mask is None:
        fail(f"{name}: unknown capability kind {kind!r}")
    if rights == 0 or rights & ~mask or rights & required[kind] == 0:
        fail(f"{name}: rights do not match capability kind {kind}")
    if kind == "executable" and rights & (RIGHT["exec"] | RIGHT["spawn"]) != (
        RIGHT["exec"] | RIGHT["spawn"]
    ):
        fail(f"{name}: executable capability requires exec and spawn")
    if kind == "input" and rights != RIGHT["inputRead"]:
        fail(f"{name}: input capability has an exact inputRead right")
    if kind == "dmaAccount" and rights != RIGHT["dmaPin"] | RIGHT["dmaRelease"]:
        fail(f"{name}: DMA account requires dmaPin and dmaRelease")


MAX_SPAWN_BUDGET = 32
POLICY = {
    "immutable": 1,
    "ephemeral": 2,
    "preserve": 3,
    "snapshotBeforeUpgrade": 4,
    "discardOnRollback": 5,
}


def fail(message: str) -> None:
    raise SystemExit(message)


def parse_external_components(values: list[str]) -> dict[str, Path]:
    """Parse the explicit external implementation-name to ELF-path mapping."""
    mappings: dict[str, Path] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if not separator or not name or not raw_path:
            fail("--external-component must be <implementation-name>=<elf-path>")
        if name in mappings:
            fail(f"duplicate external component mapping for {name!r}")
        path = Path(raw_path).expanduser().resolve()
        if not path.is_file():
            fail(f"external component {name!r}: no regular ELF file at {path}")
        mappings[name] = path
    return mappings


def component_specs_for_manifest(
    manifest: dict, component_spec_root: Path | None = None
) -> dict[str, dict]:
    """Resolve specs for executables the component-spec corpus declares.

    Verification-only fixture binaries predate CP0 and are intentionally not
    component-platform declarations. They stay on the workspace path; a spec,
    when present, is authoritative and may select the external path.
    """
    from component_spec import ComponentSpecError, admit_specs, spec_paths

    try:
        paths = spec_paths(component_spec_root) if component_spec_root is not None else None
        admitted = admit_specs(paths)
    except ComponentSpecError as error:
        fail(f"component specification corpus refused: {error}")
    specs: dict[str, dict] = {}
    for executable in manifest["executables"]:
        name = executable["name"]
        matches = [
            entry.spec
            for entry in admitted
            if entry.name == name
            or (
                entry.spec["implementation"]["provider"] != "undeclared"
                and entry.spec["implementation"]["binary"] == name
            )
        ]
        if len(matches) > 1:
            fail(f"executable {name!r}: component specification identity is ambiguous")
        if matches:
            specs[name] = matches[0]
    return specs


def resolve_component_sources(
    manifest: dict,
    external_components: dict[str, Path],
    component_spec_root: Path | None = None,
) -> tuple[dict[str, dict], set[str]]:
    import component_spec_contract

    specs = component_specs_for_manifest(manifest, component_spec_root)

    manifest_names = {executable["name"] for executable in manifest["executables"]}
    product_slisp_digest = os.environ.get("SLIME_PRODUCT_SLISP_SHA256")
    slisp_spec = specs.get("slisp")
    if product_slisp_digest is not None:
        if slisp_spec is None or slisp_spec["implementation"]["provider"] != "external":
            fail("SLIME_PRODUCT_SLISP_SHA256 requires an external Slisp component spec")
        slisp_spec["implementation"]["contentHash"] = product_slisp_digest
    workspace = manifest_names - set(specs)
    expected_external: set[str] = set()
    for executable_name, spec in specs.items():
        implementation = spec["implementation"]
        provider = implementation["provider"]
        binary_name = implementation["binary"]
        if provider == component_spec_contract.PROVIDER_WORKSPACE:
            workspace.add(binary_name)
        elif provider == component_spec_contract.PROVIDER_EXTERNAL:
            expected_external.add(binary_name)
        else:
            fail(f"executable {executable_name!r}: implementation is undeclared")
    supplied = set(external_components)
    missing = sorted(expected_external - supplied)
    if missing:
        fail(f"missing external component ELF mapping(s): {missing}")
    unused = sorted(supplied - expected_external)
    if unused:
        fail(f"external component mapping(s) not declared external: {unused}")
    return specs, workspace


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def manifest_source() -> Path:
    """Which generation manifest this build encodes.

    The target profile selects the family, so the target and the graph it
    declares cannot be chosen independently and then disagree. Within the seL4
    family `SLIME_SEL4_MANIFEST` names which graph, because P5.3.1 adds a second
    one built for the same target; absent, it is the P5.2 graph, so every
    existing caller keeps its behaviour without passing anything.
    """
    if os.environ.get("SLIME_TARGET_PROFILE") in SEL4_TARGET_PROFILES:
        name = os.environ.get("SLIME_SEL4_MANIFEST", "sel4")
        source = SEL4_SELECTABLE_MANIFESTS.get(name)
        if source is None:
            fail(f"unknown seL4 manifest {name!r}")
        return source
    return SOURCE


def load_manifest() -> dict:
    environment = os.environ.copy()
    environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
    source = manifest_source()
    output = subprocess.run(
        [str(binary()), "json", str(source)],
        cwd=ROOT,
        env=environment,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout
    manifest = json.loads(output)
    # Validate reasons before allocation fills omitted slots, so every product
    # build enforces exactly what the source manifest declares.
    validate_slot_reasons(manifest, source.name)
    return assign_declared_slots(manifest)


def assign_declared_slots(manifest: dict) -> dict:
    """Fill in every omitted `slot`, deterministically and per namespace.

    A manifest may omit `slot` on an instance binding, a minted binding, or a
    notification binding; this assigns the lowest free number in that holder's
    namespace, taking omitted entries in grant-name order so the result is a
    function of the manifest alone. Explicit slots are never moved and are
    reserved before any assignment, so a manifest that pins every number --
    which the byte-frozen boot-layout fixtures do -- encodes exactly as before.

    The namespaces are separate because the runtime regions are. Capability
    bindings and minted bindings share one per holder, since both land in the
    child's capability table and the decoder refuses a duplicate there.
    Notification bindings are their own, relative to the native notification
    region, so a notification at 0 and a capability at 0 do not collide.
    """

    def fill(entries: list, holder_of, limit: int) -> None:
        taken: dict[str, set[int]] = {}
        for entry in entries:
            slot = entry.get("slot")
            if slot is not None:
                taken.setdefault(holder_of(entry), set()).add(slot)
        pending = [entry for entry in entries if entry.get("slot") is None]
        for entry in sorted(pending, key=lambda item: item.get("name") or item.get("grant") or ""):
            holder = holder_of(entry)
            used = taken.setdefault(holder, set())
            slot = next((n for n in range(limit) if n not in used), None)
            if slot is None:
                fail(f"declared slots for {holder} exhaust the {limit}-slot namespace")
            used.add(slot)
            entry["slot"] = slot

    for instance in manifest.get("instances", []):
        # One namespace per holder, shared by both kinds, matching the decoder.
        shared = list(instance.get("bindings", [])) + [
            minted
            for minted in manifest.get("mintedBindings", [])
            if minted["holder"] == instance["name"]
        ]
        fill(shared, lambda _entry, name=instance["name"]: name, 32)
    fill(
        manifest.get("notificationBindings", []),
        lambda entry: entry["holder"],
        15,
    )
    return manifest


# The closed `InstanceBinding.slotReason` vocabulary, ordered strongest first.
# Order is meaningful: a pin is labelled with the strongest external invariant
# that forces its number, so a weaker claim beside a stronger truth is refused
# rather than accepted as merely incomplete.
#
# The first three are decidable from the manifest alone and are therefore
# verified rather than trusted. Only `componentAbi` rests on a claim about
# component source, which the contract check audits against the components.
SLOT_REASON_BOOT_LAYOUT = "bootLayout"
SLOT_REASON_ALLOCATOR_ORDER = "allocatorOrder"
SLOT_REASON_ENCODED_LAYOUT = "encodedLayout"
SLOT_REASON_COMPONENT_ABI = "componentAbi"
SLOT_REASONS = (
    SLOT_REASON_BOOT_LAYOUT,
    SLOT_REASON_ALLOCATOR_ORDER,
    SLOT_REASON_ENCODED_LAYOUT,
    SLOT_REASON_COMPONENT_ABI,
)


def resolved_slot_table(manifest: dict) -> dict[tuple[str, str, str], int]:
    """Every slot this manifest resolves to, keyed by holder, namespace, name.

    The comparison basis for `allocatorOrder`: two manifests differing only in
    which pins are written down resolve to equal tables exactly when the omitted
    pins were redundant. Keyed by namespace as well as holder because a
    notification at 0 and a capability at 0 are different slots.
    """
    resolved = assign_declared_slots(copy.deepcopy(manifest))
    table: dict[tuple[str, str, str], int] = {}
    for instance in resolved.get("instances", []):
        for binding in instance.get("bindings", []):
            table[(instance["name"], "capability", binding["grant"])] = binding["slot"]
    for minted in resolved.get("mintedBindings", []) or []:
        table[(minted["holder"], "capability", minted["name"])] = minted["slot"]
    for notification in resolved.get("notificationBindings", []) or []:
        table[(notification["holder"], "notification", notification["grant"])] = notification[
            "slot"
        ]
    return table


def boot_layout_row_bindings(manifest: dict) -> set[tuple[str, str]]:
    """The `(holder, grant)` pairs a `contracts/boot-layout/v1` row is derived from.

    Reads `boot_layout.layout_from_manifest`'s own inputs rather than restating
    its rule: the bootstrap instance is the one the manifest *names*, not one
    inferred from executable roles, and a row exists only for the capability
    kinds `LAYOUT_KIND_ROLES` maps. Inferring the instance instead would be a
    second statement of a fact the manifest already declares — the drift B71
    deleted — and would silently mislabel every pin in any composition where the
    two disagreed.

    Endpoint bindings deliberately produce no row, so pinning one is never
    justified by the layout.
    """
    if not any(entry["id"] == "boot-layout" for entry in manifest.get("objects", [])):
        return set()
    bootstrap = manifest.get("bootstrapInstance")
    instance = next(
        (entry for entry in manifest.get("instances", []) if entry["name"] == bootstrap),
        None,
    )
    if instance is None:
        return set()
    kinds = {grant["name"]: grant["capabilityKind"] for grant in manifest.get("grants", [])}
    return {
        (bootstrap, binding["grant"])
        for binding in instance.get("bindings", [])
        if kinds.get(binding["grant"]) in LAYOUT_KIND_ROLES
    }


# Effects a pin's removal can have, weakest first. A pin's reason must hold for
# every generation built from its source, so where the source and one of its boot
# profiles disagree the *stronger* effect wins: the number is load-bearing if any
# admitted narrowing needs it.
PIN_EFFECT_ORDER = ("nothing", "self", "neighbour")


def pin_removal_effects(manifest: dict) -> dict[tuple[str, str], str]:
    """What each pin actually holds in place, measured one removal at a time.

    Returns `(holder, grant) -> "neighbour" | "self" | "nothing"`:

      `neighbour` -- dropping this pin moves some *other* binding's resolved
                     slot, because the freed number goes to the next binding in
                     grant-name order. The strongest manifest-internal reason.
      `self`      -- only this binding's own encoded slot changes. Nothing else
                     in the manifest depends on the number, but the generation
                     bytes and the capability layout the root installs do, so it
                     cannot be dropped without changing what boots.
      `nothing`   -- the allocator reproduces the number exactly. The manifest
                     has no stake in it at all, so whatever keeps it must be
                     outside the manifest: a positional consumer in source.

    Separating `self` from `neighbour` is the point. Collapsing them calls 185 of
    this corpus's 196 pins load-bearing-for-others when only 11 are; collapsing
    `self` into `nothing` instead claims 185 numbers are reproduced by the
    allocator when removing them changes the encoded layout. Both collapses hide
    the distinction the reason vocabulary must preserve, in opposite directions.

    One pin at a time, because that is the question a per-pin label answers:
    joint removability is a separate, stronger claim and is not implied.
    """
    baseline = resolved_slot_table(manifest)
    effects: dict[tuple[str, str], str] = {}
    for position, instance in enumerate(manifest.get("instances", [])):
        for index, binding in enumerate(instance.get("bindings", [])):
            if binding.get("slot") is None:
                continue
            trial = copy.deepcopy(manifest)
            del trial["instances"][position]["bindings"][index]["slot"]
            trial["instances"][position]["bindings"][index].pop("slotReason", None)
            after = resolved_slot_table(trial)
            own = (instance["name"], "capability", binding["grant"])
            if any(value != after.get(key) for key, value in baseline.items() if key != own):
                effect = "neighbour"
            elif baseline[own] != after.get(own):
                effect = "self"
            else:
                effect = "nothing"
            effects[(instance["name"], binding["grant"])] = effect
    return effects


def declared_pin_effects(manifest: dict) -> dict[tuple[str, str], str]:
    """Each pin's strongest effect across this source and every boot profile.

    A `slotReason` is a claim about the source manifest, but the manifest is not
    what boots: `resolve_boot_profile` drops instances and filters each
    survivor's bindings to the retained grants, which changes what the allocator
    would do. A pin that is redundant in the whole composition can be
    load-bearing in a narrowing of it, so measuring the source alone would label
    such a pin `componentAbi` and invite a migration that breaks a real profile.

    Taking the maximum over the source and all of its profiles makes one label
    true of every generation the source can produce, which is what a single
    per-binding field can honestly mean. Bindings a profile drops keep whatever
    the wider manifest said about them.
    """
    combined = pin_removal_effects(manifest)
    for profile in manifest.get("bootProfiles") or []:
        narrowed = pin_removal_effects(
            resolve_boot_profile(copy.deepcopy(manifest), profile["name"])
        )
        for key, effect in narrowed.items():
            if PIN_EFFECT_ORDER.index(effect) > PIN_EFFECT_ORDER.index(
                combined.get(key, "nothing")
            ):
                combined[key] = effect
    return combined


def classify_slot_pin(holder: str, grant: str, layout_rows: set, effects: dict) -> str:
    """The strongest reason this manifest itself can prove for pinning a slot.

    `componentAbi` is the residue, and the only label that is not a fact about
    the manifest: the allocator reproduces the number and nothing encoded moves
    if it goes, so the only remaining justification is a positional consumer in
    the holder's source. The contract check audits that class against component
    source.
    """
    if (holder, grant) in layout_rows:
        return SLOT_REASON_BOOT_LAYOUT
    effect = effects.get((holder, grant))
    if effect == "neighbour":
        return SLOT_REASON_ALLOCATOR_ORDER
    if effect == "self":
        return SLOT_REASON_ENCODED_LAYOUT
    return SLOT_REASON_COMPONENT_ABI


def validate_slot_reasons(manifest: dict, source: str) -> None:
    """Refuse a manifest whose pin labels disagree with what it actually implies.

    Three separate failures, because they are three different mistakes:
    a pin with no reason (or a reason with no pin) is an incomplete edit; an
    unknown reason is a typo the closed vocabulary should catch; and a reason
    that is merely *wrong* is the one this whole field exists to prevent — a
    number claimed to be frozen by an artifact that does not freeze it, or
    claimed to be reproduced by the allocator when removing it would move a
    neighbour's slot or change this binding's own encoded position.

    Called on the source manifest before allocation fills anything in, so
    `slot is None` really means the source omitted it, and the expected reason is
    taken over this source *and* every boot profile it declares — one label has
    to be true of every generation the source can produce.
    """
    layout_rows = boot_layout_row_bindings(manifest)
    effects = declared_pin_effects(manifest)
    for instance in manifest.get("instances", []):
        for binding in instance.get("bindings", []):
            holder, grant = instance["name"], binding["grant"]
            where = f"{source}: {holder}/{grant}"
            declared = binding.get("slotReason")
            if binding.get("slot") is None:
                if declared is not None:
                    fail(f"{where}: slotReason declared for an unpinned binding")
                continue
            if declared is None:
                fail(
                    f"{where}: pins slot {binding['slot']} without a slotReason; "
                    f"expected {classify_slot_pin(holder, grant, layout_rows, effects)}"
                )
            if declared not in SLOT_REASONS:
                fail(
                    f"{where}: unknown slotReason {declared!r}; expected one of {', '.join(SLOT_REASONS)}"
                )
            expected = classify_slot_pin(holder, grant, layout_rows, effects)
            if declared != expected:
                fail(
                    f"{where}: declares slotReason {declared!r} but this manifest implies {expected!r}"
                )


def resolve_target_profile(target: object) -> TargetProfile:
    if not isinstance(target, str):
        fail(
            f"unknown target {target!r}; admitted targets: {', '.join(sorted(TARGET_PROFILES_BY_NAME))}"
        )
    profile = TARGET_PROFILES_BY_NAME.get(target)
    if profile is None:
        fail(
            f"unknown target {target!r}; admitted targets: {', '.join(sorted(TARGET_PROFILES_BY_NAME))}"
        )
    return profile


def component_target_dir(root: Path, target_profile: TargetProfile, name: str) -> Path:
    """Keep profiles sharing one Cargo target from reusing executable outputs."""
    return root / target_profile.name / name


def component_executable(built: Path, name: str, target_profile: TargetProfile) -> Path:
    """Where cargo wrote one component's executable.

    The rust-sel4 target specifications set `"exe-suffix": ".elf"`, so a binary
    named `init` is written as `init.elf`. Resolving it here rather than at each
    call site keeps the suffix a property of the target, which is what it is.
    """
    if is_json_target(target_profile):
        return built / f"{name}.elf"
    return built / name


def is_json_target(target_profile: TargetProfile) -> bool:
    """Whether this profile's Cargo target is a JSON specification file.

    A JSON target is not merely a different triple: cargo needs `-Z
    json-target-spec`, has no prebuilt `core`/`alloc` so it needs `build-std`,
    names its output directory by the file *stem* rather than the path, and is
    not matched by the per-triple `rustflags` in `components/.cargo/config.toml`.
    Each of those is handled below.
    """
    return target_profile.cargo_target.endswith(".json")


def cargo_target_argument(target_profile: TargetProfile) -> str:
    """What `--target` receives: an absolute path for a JSON spec, else the
    triple verbatim."""
    if is_json_target(target_profile):
        return str(ROOT / target_profile.cargo_target)
    return target_profile.cargo_target


def cargo_target_directory_name(target_profile: TargetProfile) -> str:
    """The directory cargo writes artifacts into.

    For a JSON specification this is the file stem, not the path — the single
    most common way a JSON target silently breaks a build script that assumed
    the two were the same string.
    """
    if is_json_target(target_profile):
        return Path(target_profile.cargo_target).stem
    return target_profile.cargo_target


def sel4_component_environment(
    environment: dict[str, str],
    target_profile: TargetProfile,
    *,
    toolchain: str | None = None,
    prefix: Path | None = None,
) -> dict[str, str]:
    """Add the explicit seL4 component toolchain and prefix inputs.

    Legacy callers may omit them and retain the repository pin routes. Closure
    builds pass both values, so their executable inputs cannot fall back to the
    checkout's ambient `sel4/pins.toml` or `build/` tree.
    """
    if toolchain is None or prefix is None:
        pins_path = ROOT / "sel4" / "pins.toml"
        if not pins_path.is_file():
            fail(f"missing pin manifest: {pins_path.relative_to(ROOT)}")
        import tomllib

        pins = tomllib.loads(pins_path.read_text(encoding="utf-8"))
        toolchain = pins["rust_sel4"]["toolchain"]
        prefix_by_profile = {
            SEL4_TARGET_PROFILE: ROOT / "build" / "sel4-prefix",
            SEL4_BOARD_TARGET_PROFILE: ROOT / "build" / "sel4-rpi5-prefix",
            SEL4_RISCV64_TARGET_PROFILE: ROOT / "build" / "sel4-riscv64-prefix",
            SEL4_RISCV64_DUO_TARGET_PROFILE: ROOT / "build" / "sel4-cv1800b-duo-prefix",
            SEL4_X86_64_TARGET_PROFILE: ROOT / "build" / "sel4-pc99-prefix",
            # The Framework profile is built against the same pc99 kernel: P6.1
            # admits its identity, and P6.5/P6.6 own producing a physical image.
            # Sharing the prefix would be wrong once its kernel configuration
            # diverges, and the profile has no gate until then.
            SEL4_X86_64_FRAMEWORK_TARGET_PROFILE: ROOT / "build" / "sel4-pc99-prefix",
        }
        prefix = prefix_by_profile.get(target_profile.name)
        if prefix is None:
            fail(f"no seL4 prefix route for target {target_profile.name!r}")
    if not (prefix / "libsel4" / "include" / "kernel" / "gen_config.json").is_file():
        fail(f"no installed seL4 prefix at {prefix} for {target_profile.name}")
    environment["RUSTUP_TOOLCHAIN"] = toolchain
    environment["SEL4_PREFIX"] = str(prefix)
    if not environment.get("LIBCLANG_PATH"):
        fail(
            "LIBCLANG_PATH is unset, so bindgen cannot generate the libsel4 bindings; "
            "enter the pinned shell with `nix develop` or export LIBCLANG_PATH"
        )
    return environment


def build_rust_components(
    generation_number: int,
    target_profile: TargetProfile,
    recovery: bool = False,
    candidate_identity: bytes | None = None,
    components: set[str] | None = None,
    *,
    toolchain: str | None = None,
    prefix: Path | None = None,
    build_profile: str = "default",
    closure_target_name: str | None = None,
) -> Path:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key != "SLIME_TRANSFER_ACTIVATE"
        and not (
            key.endswith("_CHECK")
            and (key.startswith("SLIME_FABRIC_") or key.startswith("SLIME_SEL4_"))
        )
    }
    if os.environ.get("SLIME_BOOT_SELECTION_FAIL") == "1":
        environment["SLIME_BOOT_SELECTION_FAIL"] = "1"
    else:
        environment.pop("SLIME_BOOT_SELECTION_FAIL", None)
    if build_profile == "closure":
        # A closure build inherits no scenario knob from its caller's
        # environment: `build-system-image.py` clears every `SLIME_*` before
        # setting exactly the ones its resolved closure's build profiles
        # select (CP14). So the knobs present here arrived from closure data,
        # and stripping them would discard the very selection the closure
        # identity is a claim about. `SLIME_GENERATION_CANDIDATE` is not a
        # closure profile and is still removed.
        environment.pop("SLIME_GENERATION_CANDIDATE", None)
    elif build_profile != "default":
        fail(f"unsupported component build profile {build_profile!r}")
    environment["SLIME_TARGET_PROFILE"] = target_profile.name
    # Product graph selectors are deliberately absent: generated manifest data
    # selects component behavior. Validation-only injection controls remain.
    if environment.get("SLIME_FABRIC_PROXY_EARLY_EXIT") == "1":
        environment["SLIME_FABRIC_PROXY_EARLY_EXIT"] = "1"
    else:
        environment.pop("SLIME_FABRIC_PROXY_EARLY_EXIT", None)
    if environment.get("SLIME_FABRIC_STREAM_EARLY_EXIT") == "1":
        environment["SLIME_FABRIC_STREAM_EARLY_EXIT"] = "1"
    else:
        environment.pop("SLIME_FABRIC_STREAM_EARLY_EXIT", None)
    if recovery:
        environment["SLIME_RECOVERY_IMAGE"] = "1"
    if environment.get("SLIME_GENERATION_CMD_CHECK") == "1" and candidate_identity is not None:
        environment["SLIME_GENERATION_CANDIDATE"] = candidate_identity.hex()
    # Keep separate target directories for distinct manifests because their
    # generated layout and profile inputs intentionally produce distinct images.
    #
    # A closure build passes its manifest identity in `SLIME_SEL4_MANIFEST`
    # rather than a composition name, and that hex identity must not become the
    # target directory: CP3 established that the Cargo target directory name
    # reaches the shipped ELF's symbol names, so keying it by identity would
    # make every component's bytes change whenever any closure input moved.
    # `closure_target_name` supplies the composition-derived name the legacy
    # path would have used, so both paths build byte-identical components.
    sel4_manifest = (
        closure_target_name if build_profile == "closure" else os.environ.get("SLIME_SEL4_MANIFEST")
    )
    if recovery:
        target_name = "recovery"
    elif sel4_manifest is not None and sel4_manifest != "sel4":
        target_name = f"{sel4_manifest}-{generation_number}"
    elif candidate_identity is None and os.environ.get("SLIME_TRANSFER_RECEIVER") == "1":
        target_name = f"generation-{generation_number}-transfer-receiver"
    elif candidate_identity is not None and os.environ.get("SLIME_TRANSFER_ACTIVATE") == "1":
        target_name = f"generation-{generation_number}-transfer-activate"
    else:
        target_name = f"generation-{generation_number}"
    target_dir = component_target_dir(COMPONENTS_TARGET_DIR, target_profile, target_name)
    environment["CARGO_TARGET_DIR"] = str(target_dir)
    base = [
        "cargo",
        "build",
        "--release",
        "--target",
        cargo_target_argument(target_profile),
    ]
    # CP3: one package per component, so the build names packages rather than
    # `--bin` targets of one crate. Each invocation is a *group* of packages
    # sharing a feature set, not one call per component: 52 cargo startups per
    # plane across 29 fixtures is a real cost, and grouping keeps it at today's.
    invocations: list[list[str]] = []
    if is_json_target(target_profile):
        # No command-profile manifest is exported: `spawn-service` resolves its
        # command bindings, launch contexts, request endpoint, and spawn budget
        # from the authenticated generation at runtime (B70).
        # Build exactly the components this generation declares, rather than
        # every component crate. The fabric components are compiled against a
        # generated C8 profile this target has no graph for, so building them
        # would fail on constants that describe routes the generation does not
        # declare. Naming the packages keeps the build's contents equal to the
        # manifest's, which is the same property the boot layout already has.
        if components is None:
            fail("seL4 component builds must name the components to build")
        # CP3: the allocator is scoped to the components that actually need it,
        # by declaring `boot-contracts/gpt` and `slime-rt/heap` in those six
        # crates' own manifests. Grouping the build by that split is what makes
        # the scoping real: Cargo unifies features across every package in one
        # invocation, so building a store component alongside a plain one would
        # switch `#[global_allocator]` on for the plain one too — measured, not
        # assumed. Separate invocations keep the plain group's `slime-rt`
        # heap-free.
        #
        # C10.3 adds a third group rather than widening either: its
        # `private-heap` allocator is mutually exclusive with the store plane's
        # (`slime-rt/lib.rs` refuses both with a `compile_error!`, since
        # `#[global_allocator]` is one symbol per link), so unifying the two
        # feature sets in one invocation would fail to compile rather than
        # silently over-link.
        store = sorted(name for name in components if name in STORE_COMPONENTS)
        private_heap = sorted(name for name in components if name in PRIVATE_HEAP_COMPONENTS)
        plain = sorted(
            name
            for name in components
            if name not in STORE_COMPONENTS and name not in PRIVATE_HEAP_COMPONENTS
        )
        for group in (plain, store, private_heap):
            if not group:
                continue
            command = list(base)
            for component in group:
                command += ["-p", f"slime-component-{component}"]
            command += [
                "-Z",
                "json-target-spec",
                "-Z",
                "build-std=core,alloc,compiler_builtins",
                "-Z",
                "build-std-features=compiler-builtins-mem",
            ]
            invocations.append(command)
        # `components/.cargo/config.toml` keys `rustflags` by triple, so a JSON
        # target inherits none of them. Passing the determinism-relevant ones
        # explicitly keeps the link reproducible instead of silently dropping
        # them. `-T` and the load base are deliberately absent: a component here
        # is an ordinary seL4 ELF task at its own link addresses.
        # `--remap-path-prefix` for the target directory is what keeps a
        # panic location out of the shipped bytes. `target_dir` is remapped to
        # a logical name derived from the profile and manifest, and `ROOT` to
        # `.`, so two checkouts produce identical ELFs.
        #
        # The `target_dir` rule is listed first so it wins for a path that is
        # both under `ROOT` and inside the target directory: `ROOT` -> `.`
        # would otherwise rewrite the leading portion and leave the caller's
        # output directory in `core::panic::Location` strings, making one
        # closure produce different bytes per output directory.
        environment["RUSTFLAGS"] = " ".join(
            [
                "-C link-arg=--build-id=none",
                f"--remap-path-prefix={target_dir}=./target/components/{target_profile.name}/{target_name}",
                f"--remap-path-prefix={ROOT}=.",
            ]
        )
        environment = sel4_component_environment(
            environment, target_profile, toolchain=toolchain, prefix=prefix
        )
    else:
        # B12: `components/.cargo/config.toml` carried a hardcoded
        # `--remap-path-prefix` naming one developer's checkout. Any other
        # checkout made it a no-op — or worse, when the stale literal was a
        # *prefix* of the real path it rewrote the leading portion and left the
        # remainder, mangling recorded paths instead of normalizing them.
        #
        # Appended through `--config` rather than `RUSTFLAGS`, which would
        # *replace* the config's rustflags and silently drop the
        # relocation-model, code-model, and link-arg settings the x86 link
        # depends on. The JSON-target branch above can set `RUSTFLAGS` freely
        # because a JSON target inherits none of those to begin with.
        remap = f"--remap-path-prefix={ROOT}=."
        # Guarded like the JSON branch above. Before CP3 `-p slime-components`
        # sat in the shared prefix, so both branches were package-scoped
        # unconditionally; building the `-p` list from `components` means an
        # empty set would leave a bare `cargo build` that resolves the root
        # workspace and builds every default member for a bare-metal target.
        # Unreachable today — `build_sel4_generation` is the only caller — which
        # is why it is a guard rather than a fix.
        if not components:
            fail("component builds must name the components to build")
        command = list(base)
        for component in sorted(components):
            command += ["-p", f"slime-component-{component}"]
        command += [
            "--config",
            f'target.{target_profile.cargo_target}.rustflags=["{remap}"]',
        ]
        invocations.append(command)
    for command in invocations:
        subprocess.run(
            command,
            cwd=ROOT / "components",
            env=environment,
            check=True,
        )
    return target_dir / cargo_target_directory_name(target_profile) / "release"


def _elf64_load_segments(
    name: str, data: bytes, profile: TargetProfile
) -> tuple[int, list[tuple[int, int, int, int, int]]]:
    """Validate the ELF shape shared by the component wrappers."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1 or data[6] != 1:
        fail(f"{name}: not a 64-bit little-endian ELF")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    if elf_type != 2 or machine != profile.elf_machine:
        fail(f"{name}: not a static executable for target {profile.name}")
    entry, phoff = struct.unpack_from("<QQ", data, 24)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize != 56 or phnum == 0:
        fail(f"{name}: invalid program header table")
    segments: list[tuple[int, int, int, int, int]] = []
    for index in range(phnum):
        header = phoff + index * phentsize
        if header < phoff or header > len(data) - 56:
            fail(f"{name}: truncated program header")
        p_type, p_flags = struct.unpack_from("<II", data, header)
        p_offset, p_vaddr, _, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", data, header + 8)
        if p_type == 1 and p_memsz:
            if p_filesz > p_memsz or p_offset > len(data) or p_filesz > len(data) - p_offset:
                fail(f"{name}: malformed load segment")
            segments.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))
    if not segments:
        fail(f"{name}: no loadable segment")
    return entry, segments


def _validate_sel4_elf(name: str, data: bytes, profile: TargetProfile) -> None:
    """Apply the canonical component and root-loader checks before stripping."""
    if len(data) > MAX_COMPONENT_IMAGE_BYTES:
        fail(f"{name}: image exceeds the component image bound")
    entry, segments = _elf64_load_segments(name, data, profile)
    page_flags: dict[int, int] = {}
    start: int | None = None
    end = 0
    entry_ok = False
    mapped_bytes = 0
    for vaddr, _offset, _filesz, memsz, elf_flags in segments:
        if vaddr > (1 << 64) - memsz:
            fail(f"{name}: malformed load segment")
        segment_end = vaddr + memsz
        segment_pages = -(-memsz // profile.page_bytes)
        segment_mapped = segment_pages * profile.page_bytes
        if mapped_bytes > MAX_COMPONENT_IMAGE_BYTES - segment_mapped:
            fail(f"{name}: mapped component image exceeds the component image bound")
        mapped_bytes += segment_mapped
        start = vaddr if start is None else min(start, vaddr)
        end = max(end, segment_end)
        entry_ok |= bool(elf_flags & 1 and vaddr <= entry < segment_end)
    if not entry_ok:
        fail(f"{name}: entry point is not executable")
    if start is None:
        fail(f"{name}: no loadable segment")
    footprint_start = start - start % profile.page_bytes
    footprint_end = -(-end // profile.page_bytes) * profile.page_bytes
    pages = (footprint_end - footprint_start) // profile.page_bytes + 2
    if footprint_start == 0 or footprint_end + 2 * profile.page_bytes > 1 << 40:
        fail(f"{name}: component image footprint is out of range")
    image_ceiling, _ = component_image_capacity_for(profile.name)
    if pages > image_ceiling:
        fail(f"{name}: component image footprint exceeds {image_ceiling} pages")
    for vaddr, _offset, _filesz, memsz, elf_flags in segments:
        segment_end = vaddr + memsz
        first_page = vaddr // profile.page_bytes
        last_page = -(-segment_end // profile.page_bytes)
        for page in range(first_page, last_page):
            page_flags[page] = page_flags.get(page, 0) | elf_flags
    if any(flags & 2 and flags & 1 for flags in page_flags.values()):
        fail(f"{name}: writable executable page")


def _admit_sel4_elf(name: str, data: bytes, stack_bytes: int, profile: TargetProfile) -> bytes:
    _validate_sel4_elf(name, data, profile)
    header = COMPONENT_IMAGE_HEADER.pack(
        COMPONENT_IMAGE_ELF_MAGIC,
        COMPONENT_IMAGE_ELF_VERSION,
        COMPONENT_IMAGE_ELF_HEADER_LEN,
        COMPONENT_IMAGE_KERNEL_ABI,
        profile.architecture,
        profile.abi,
        profile.page_profile,
        0,
        0,
        0,
        stack_bytes,
        profile.id,
        profile.required_features,
    )
    return header + data


def elf_component_image(
    name: str,
    elf: Path | bytes,
    stack_bytes: int,
    profile: TargetProfile,
    *,
    toolchain: str,
) -> bytes:
    """Admit the immutable source, strip its delivery copy, then admit and wrap it."""
    data = elf if isinstance(elf, bytes) else elf.read_bytes()
    _validate_sel4_elf(name, data, profile)
    try:
        delivery = strip_elf_delivery(data, toolchain=toolchain)
    except ValueError as error:
        fail(f"{name}: {error}")
    return _admit_sel4_elf(name, delivery, stack_bytes, profile)


def component_image(
    name: str,
    elf: Path | bytes,
    stack_bytes: int,
    profile: TargetProfile,
    *,
    toolchain: str | None = None,
) -> bytes:
    if is_json_target(profile):
        if toolchain is None:
            import tomllib

            toolchain = tomllib.loads((ROOT / "sel4" / "pins.toml").read_text())["rust_sel4"][
                "toolchain"
            ]
        return elf_component_image(name, elf, stack_bytes, profile, toolchain=toolchain)
    data = elf if isinstance(elf, bytes) else elf.read_bytes()
    entry, segments = _elf64_load_segments(name, data, profile)
    segments = [segment for segment in segments if segment[3]]
    segments.sort()
    if (
        not 1 <= len(segments) <= COMPONENT_IMAGE_MAX_SEGMENTS
        or segments[0][0] != profile.component_base
        or entry < profile.component_base
    ):
        fail(f"{name}: invalid component load layout")
    records = bytearray()
    payload = bytearray()
    previous_end = 0
    entry_offset = entry - profile.component_base
    entry_ok = False
    total_pages = 0
    for vaddr, offset, filesz, memsz, elf_flags in segments:
        if (
            filesz > memsz
            or vaddr % profile.page_bytes
            or vaddr < previous_end
            or offset + filesz > len(data)
        ):
            fail(f"{name}: invalid or overlapping segment")
        flags = (COMPONENT_SEGMENT_FLAG_EXEC if elf_flags & 1 else 0) | (
            COMPONENT_SEGMENT_FLAG_WRITE if elf_flags & 2 else 0
        )
        if flags == COMPONENT_SEGMENT_FLAG_EXEC | COMPONENT_SEGMENT_FLAG_WRITE:
            fail(f"{name}: writable executable segment")
        relative = vaddr - profile.component_base
        entry_ok |= bool(
            flags & COMPONENT_SEGMENT_FLAG_EXEC and relative <= entry_offset < relative + memsz
        )
        records += COMPONENT_IMAGE_SEGMENT.pack(relative, memsz, len(payload), filesz, flags, 0)
        payload += data[offset : offset + filesz]
        previous_end = vaddr + memsz
        total_pages += -(-memsz // profile.page_bytes)
    if not entry_ok or total_pages * profile.page_bytes > MAX_COMPONENT_IMAGE_BYTES:
        fail(f"{name}: invalid entry or image size")
    header = COMPONENT_IMAGE_HEADER.pack(
        COMPONENT_IMAGE_MAGIC,
        COMPONENT_IMAGE_VERSION,
        COMPONENT_IMAGE_HEADER.size,
        COMPONENT_IMAGE_KERNEL_ABI,
        profile.architecture,
        profile.abi,
        profile.page_profile,
        entry_offset,
        len(segments),
        0,
        stack_bytes,
        profile.id,
        profile.required_features,
    )
    return header + records + payload


def validate_interface_schemas(entries: object) -> list:
    """Admit the manifest's declared interface set and return it compiled.

    The C8.2 fabric graph is built from these exact admitted interfaces, so a
    route can only ever name a schema that already passed C8.1 normalization,
    identity, tag-collision, and bounds admission.
    """
    try:
        paths = resolve_interface_paths(entries)
        return admit_interfaces(paths)
    except InterfaceSchemaError as error:
        fail(str(error))
        raise


def unique_sorted(items: list[dict], key: str, label: str) -> list[dict]:
    values = [item[key] for item in items]
    if len(set(values)) != len(values):
        fail(f"{label} must be unique")
    return sorted(items, key=lambda item: item[key])


def validate_acyclic(instances: list[dict]) -> None:
    graph = {instance["name"]: instance["dependencies"] for instance in instances}
    for name, dependencies in graph.items():
        if name in dependencies or len(set(dependencies)) != len(dependencies):
            fail(f"instance {name}: invalid dependencies")
        for dependency in dependencies:
            if dependency not in graph:
                fail(f"instance {name}: missing dependency {dependency}")
    active: set[str] = set()
    complete: set[str] = set()

    def visit(name: str) -> None:
        if name in complete:
            return
        if name in active:
            fail("instance dependency cycle")
        active.add(name)
        for dependency in graph[name]:
            visit(dependency)
        active.remove(name)
        complete.add(name)

    for name in graph:
        visit(name)


PLAN_NONE = 0xFFFFFFFF
# One below the root task's own priority, matching `slime-root`'s
# `task::CHILD_PRIORITY`. A child at or above the root cannot be preempted by
# the service loop, so this is a ceiling as well as a default.
DEFAULT_CHILD_PRIORITY = 254
GRANT_POLICY_ONLY = 1
# Grant flags. No bit is defined: `GRANT_MINTED` named a send/recv grant whose
# object its source created at runtime, which the native cutover made
# impossible — an endpoint is a generation-owned seL4 Endpoint the root
# materializes — so B50 deleted the concept rather than leaving a flag nothing
# can set.
GRANT_FLAGS_NONE = 0
# Endpoint and notification slots are relative to distinct 31-entry child
# CSpace regions. The receiver slot occupies the last CSpace entry, so 31 is a
# count, never a legal relative slot.
MAX_DECLARED_NATIVE_SLOT = 31
# Must match `slime-root::task::CHILD_CNODE_SIZE_BITS`; the admitted v5 quota
# and the CNode object are derived from this one value.
CHILD_CNODE_SIZE_BITS = 7
SERVICE_LIFECYCLE = 1
SERVICE_SPAWN = 2
SERVICE_SUPERVISION = 3
SERVICE_CAPABILITY_TRANSFER = 4
SERVICE_SHARED_BUFFER = 5
SERVICE_DIRECTORY = 6
SERVICE_INPUT = 7
# 8 was `SERVICE_BLOCK`, retired with B90 once no root label mapped to it.
# Reserved rather than reassigned.
SERVICE_CONSOLE = 9
SERVICE_CLOCK = 10
SERVICE_IO_RESOURCE = 11
# Fixed userspace ABI slots. Several typed mechanisms share the root transport
# endpoint at slot 1; the service discriminant states the authority carried.
ROOT_SERVICE_SLOT = 1
CONSOLE_SERVICE_SLOT = 32
SERVICE_BY_CAPABILITY_KIND = {
    "sharedBufferFactory": SERVICE_SHARED_BUFFER,
    "sharedBuffer": SERVICE_SHARED_BUFFER,
    "loan": SERVICE_SHARED_BUFFER,
    "directory": SERVICE_DIRECTORY,
    "input": SERVICE_INPUT,
    "supervision": SERVICE_SUPERVISION,
    # IO1's four hardware-resource kinds share one root service, because they
    # are one mechanism: a driver's device, its MMIO subranges, its interrupt,
    # and its DMA account are constructed and reclaimed together, and splitting
    # them across services would let a generation grant half a driver.
    "device": SERVICE_IO_RESOURCE,
    "mmioRegion": SERVICE_IO_RESOURCE,
    "interruptSource": SERVICE_IO_RESOURCE,
    "dmaAccount": SERVICE_IO_RESOURCE,
}
KERNEL_OBJECT_CNODE = 1
KERNEL_OBJECT_VSPACE = 2
KERNEL_OBJECT_TCB = 3
KERNEL_OBJECT_FRAME = 4
KERNEL_OBJECT_ENDPOINT = 5
KERNEL_OBJECT_PAGE_TABLE = 6
KERNEL_OBJECT_NOTIFICATION = 7
NOTIFICATION_ROLE_SIGNAL = 1
NOTIFICATION_ROLE_WAIT = 2
CAP_RIGHT_ALL = (1 << 64) - 1


def declared_services(
    instance: dict,
    executable: dict,
    grants_by_name: dict[str, dict],
    minted_bindings: list[dict],
    shared_buffer_holders: set[str],
    clock_holders: set[str],
    parameter_holders: frozenset[str] = frozenset(),
) -> set[int]:
    services = {SERVICE_LIFECYCLE, SERVICE_CONSOLE}
    if executable["role"] == "init" or executable["spawnBudget"] > 0:
        # Spawn returns a supervision capability. A caller that can acquire
        # one must also be allowed to release it, even when no endpoint or
        # separately transferable grant happens to imply the table service.
        services.update({SERVICE_SPAWN, SERVICE_SUPERVISION, SERVICE_CAPABILITY_TRANSFER})
    if instance["name"] in shared_buffer_holders:
        # A receiver may map and return a loan created by another process even
        # though no persistent loan capability appears in its manifest. The
        # authenticated per-holder budget is the declaration that authorizes
        # that receiver-side shared-buffer mechanism.
        services.add(SERVICE_SHARED_BUFFER)
    if instance["name"] in parameter_holders:
        # Parameter edges authorize the mediated supervision transport; the root
        # still enforces each exact subject and independent read/write right.
        services.add(SERVICE_SUPERVISION)
    if instance["name"] in clock_holders:
        # The authenticated clock-authority resource is the service declaration:
        # holders get the shared root transport, while absent instances have no
        # clock service binding and are refused before dispatch.
        services.add(SERVICE_CLOCK)
    capability_declarations = [
        grants_by_name[binding["grant"]] for binding in instance["bindings"]
    ] + [minted for minted in minted_bindings if minted["holder"] == instance["name"]]
    for declaration in capability_declarations:
        service = SERVICE_BY_CAPABILITY_KIND.get(declaration["capabilityKind"])
        if service is not None:
            services.add(service)
        if declaration["capabilityKind"] == "executable":
            services.add(SERVICE_SPAWN)
        # A declared endpoint is both the carrier used by capability delegation
        # and the source of received capabilities that `cap_drop` releases. The
        # transport therefore needs the narrow transfer service even when the
        # endpoint itself is not re-delegatable.
        if declaration["capabilityKind"] == "endpoint" or declaration["transferable"]:
            services.add(SERVICE_CAPABILITY_TRANSFER)
    return services


def build_sel4_plan(
    manifest: dict,
    instances: list[dict],
    grants: list[dict],
    grant_rights: list[int],
    instance_index: dict[str, int],
    executable_index: dict[str, int],
    string_offset,
    # Pages each executable's image occupies, keyed by object id, so a
    # process's declared frame count covers what the loader actually maps
    # (B49).
    image_pages: dict[str, int],
) -> tuple[bytes, ...]:
    """Materialize the required v5 process and authority plan.

    The builder owns this expansion because it has the authenticated manifest
    and the exact executable catalogue in hand. Counts and references are
    checked here, before a byte is emitted; the decoder repeats the checks at
    the trust boundary.
    """
    process_records = bytearray()
    thread_records = bytearray()
    kernel_records = bytearray()
    mapping_records = bytearray()
    cap_records = bytearray()
    service_records = bytearray()
    schedule_records = bytearray()
    fault_records = bytearray()
    spawn_records = bytearray()
    quota_records = bytearray()
    # Resolved once for the whole plan: the band mapping is read here and
    # nowhere else, so a class and the priority it names cannot come from two
    # readers that disagree (C9.3).
    scheduling_policy = validated_scheduling_class(manifest)
    object_index: dict[tuple[str, str], int] = {}
    grants_by_name = {grant["name"]: grant for grant in grants}
    executables_by_name = {entry["name"]: entry for entry in manifest["executables"]}

    # Every declared instance is a process in the plan. A child instance is
    # constructed by its owner rather than by root, but its CSpace, VSpace,
    # TCB, IPC buffer, fault endpoint, schedule, and quota are all fixed here:
    # B39's whole point is that the generation proves the object plan before
    # anything activates, and an owner-spawned process consumes kernel objects
    # exactly as a root-autostart one does.
    planned_instances = list(instances)
    if not planned_instances or len(planned_instances) > MAX_PROCESSES:
        fail("seL4 process plan count exceeds bound")

    for process, instance in enumerate(planned_instances):
        name = instance["name"]
        quota = process
        # Named once so the CSpace object and the quota's `cslot_count` cannot
        # disagree about how many slots the child has. Six bits, matching
        # `slime-root`'s `task::CHILD_CNODE_SIZE_BITS`: fixed declared slots
        # end at 32 and the native mirrored regions fill the remaining CSpace.
        cnode_size_bits = CHILD_CNODE_SIZE_BITS
        cspace = len(object_index)
        object_index[(name, "cspace")] = cspace
        kernel_records.extend(
            GENERATION_KERNEL_OBJECT.pack(
                string_offset(f"{name}:cspace"),
                KERNEL_OBJECT_CNODE,
                process,
                cnode_size_bits,
                1,
                PLAN_NONE,
                0,
            )
        )
        vspace = len(object_index)
        object_index[(name, "vspace")] = vspace
        kernel_records.extend(
            GENERATION_KERNEL_OBJECT.pack(
                string_offset(f"{name}:vspace"), KERNEL_OBJECT_VSPACE, process, 12, 1, PLAN_NONE, 0
            )
        )
        tcb = len(object_index)
        object_index[(name, "tcb")] = tcb
        kernel_records.extend(
            GENERATION_KERNEL_OBJECT.pack(
                string_offset(f"{name}:tcb"), KERNEL_OBJECT_TCB, process, 11, 1, PLAN_NONE, 0
            )
        )
        ipc = len(object_index)
        object_index[(name, "ipc-buffer")] = ipc
        kernel_records.extend(
            GENERATION_KERNEL_OBJECT.pack(
                string_offset(f"{name}:ipc-buffer"),
                KERNEL_OBJECT_FRAME,
                process,
                12,
                1,
                PLAN_NONE,
                0,
            )
        )
        fault_endpoint = len(object_index)
        object_index[(name, "fault-endpoint")] = fault_endpoint
        kernel_records.extend(
            GENERATION_KERNEL_OBJECT.pack(
                string_offset(f"{name}:fault-endpoint"),
                KERNEL_OBJECT_ENDPOINT,
                process,
                4,
                1,
                PLAN_NONE,
                0,
            )
        )

        # Indices into the thread, schedule, and fault tables. These used to be
        # `= process`, which held only while every process had exactly one
        # thread and all four tables grew in lockstep. Counting them lets a
        # process declare more without the tables silently misaligning (B47).
        thread = len(thread_records) // GENERATION_THREAD.size
        schedule = len(schedule_records) // GENERATION_SCHEDULE.size
        fault = len(fault_records) // GENERATION_FAULT_POLICY.size
        thread_records.extend(
            GENERATION_THREAD.pack(
                string_offset(f"{name}:main"), process, tcb, schedule, fault, ipc, 0, 0, 0
            )
        )
        process_records.extend(
            GENERATION_PROCESS.pack(
                string_offset(name), instance_index[name], cspace, vspace, thread, quota, 0
            )
        )
        # Priority is the instance's to declare. Absent, it is the root's
        # default: one below the root's own, so the service loop always
        # preempts a runnable child.
        #
        # Bounded here as well as in the root, because a manifest is the wrong
        # place to learn that a number was silently clamped. `budget_us` and
        # `period_us` stay zero until MCS is admitted -- seL4 without it has no
        # notion of either, and writing a figure the kernel cannot enforce
        # would make the record say more than the system does. Since B77 that is
        # also enforced rather than trusted: both validators refuse a nonzero
        # value, so writing one here fails admission instead of shipping.
        priority = instance.get("priority", DEFAULT_CHILD_PRIORITY)
        if not isinstance(priority, int) or isinstance(priority, bool):
            fail(f"instance {name}: invalid priority")
        if not 0 <= priority <= DEFAULT_CHILD_PRIORITY:
            fail(
                f"instance {name}: priority {priority} outside 0..={DEFAULT_CHILD_PRIORITY}; "
                "a child at or above the root's priority can stall the service loop"
            )
        # A worker's priority is its own to declare, defaulting to its main
        # thread's (B48). Declaring it *below* the main thread is the case that
        # matters: it lets one component hold a busy thread without stalling
        # its own IPC, which is what "a budget-exhausting client cannot starve
        # an unrelated service" reduces to under a priority-only scheduler.
        worker_priority = instance.get("workerPriority", priority)
        if not isinstance(worker_priority, int) or isinstance(worker_priority, bool):
            fail(f"instance {name}: invalid workerPriority")
        if not 0 <= worker_priority <= DEFAULT_CHILD_PRIORITY:
            fail(
                f"instance {name}: workerPriority {worker_priority} outside "
                f"0..={DEFAULT_CHILD_PRIORITY}"
            )
        # C9.3: a declared class *is* the priority. `validated_scheduling_class`
        # has already refused any instance whose class and explicit priority
        # disagree, so this substitution cannot silently override a manifest
        # statement -- it can only supply the number the class names. An
        # instance the policy does not name keeps the resolution above, which is
        # the declared default rather than a denial.
        if scheduling_policy is not None and name in scheduling_policy["resolved"]:
            declared_class = scheduling_policy["resolved"][name]
            priority = declared_class["priority"]
            worker_priority = declared_class["worker_priority"]
        schedule_records.extend(
            GENERATION_SCHEDULE.pack(
                string_offset(f"{name}:schedule"),
                thread,
                PLAN_NONE,
                priority,
                priority,
                0,
                0,
                0,
            )
        )
        fault_records.extend(
            GENERATION_FAULT_POLICY.pack(
                string_offset(f"{name}:fault"), thread, PLAN_NONE, fault_endpoint, process + 1, 1
            )
        )
        console_endpoint = len(object_index)
        object_index[(name, "console-endpoint")] = console_endpoint
        kernel_records.extend(
            GENERATION_KERNEL_OBJECT.pack(
                string_offset(f"{name}:console-endpoint"),
                KERNEL_OBJECT_ENDPOINT,
                process,
                4,
                1,
                PLAN_NONE,
                0,
            )
        )
        for service in sorted(
            declared_services(
                instance,
                executables_by_name[instance["executable"]],
                grants_by_name,
                manifest.get("mintedBindings", []),
                {entry["holder"] for entry in manifest.get("sharedBufferBudget", [])},
                {entry["holder"] for entry in manifest.get("clockAuthority") or []},
                frozenset(entry["holder"] for entry in (manifest.get("lifecyclePolicy") or {}).get("parameters", []) if entry["read"] or entry["write"]),
            )
        ):
            if service == SERVICE_CONSOLE:
                slot, endpoint = CONSOLE_SERVICE_SLOT, console_endpoint
            else:
                slot, endpoint = ROOT_SERVICE_SLOT, fault_endpoint
            service_records.extend(
                GENERATION_SERVICE_BINDING.pack(
                    process, service, slot, endpoint, RIGHT["send"], process + 1, 0
                )
            )
        cap_records.extend(
            GENERATION_CAP_BINDING.pack(process, 2, tcb, CAP_RIGHT_ALL, 0, PLAN_NONE, 0)
        )
        cap_records.extend(
            GENERATION_CAP_BINDING.pack(process, 3, fault_endpoint, 1, process + 1, PLAN_NONE, 0)
        )
        # Counted from the objects this loop just declared for the process,
        # not guessed. The row used to be a literal `1, 1, 2, 0, 2, 4, 6, ...`
        # that no builder derived and no root read; `frame_count=2` and
        # `mapping_count=6` in particular described no plan (B49).
        #
        # One CNode, one VSpace, and two endpoints — the fault endpoint and the
        # console endpoint — plus one TCB and one IPC-buffer frame *per thread*,
        # which is what the loop below declares for the extra threads (B47).
        # The frame quota includes the mapped image span and each thread's
        # IPC-buffer/window pair, including pages allocated by the root.
        thread_total = 1 + instance.get("extraThreads", 0)
        # The image's own frames, from the payload the loader will map. The
        # root allocates one frame capability per page out of its own CSlots,
        # so leaving them out understated a process's cost by an order of
        # magnitude: the 48-instance stress plane declared 6 slots per instance
        # and consumed 81 (B49).
        executable_object = next(
            (e["object"] for e in manifest["executables"] if e["name"] == instance["executable"]),
            None,
        )
        image_frame_count = image_pages.get(executable_object, 0)
        process_objects = {
            "cnode": 1,
            "vspace": 1,
            "tcb": thread_total,
            # One IPC-buffer/window pair per thread, plus the image itself.
            "frame": 2 * thread_total + image_frame_count,
            "endpoint": 2
            + sum(
                1
                for grant in grants
                if grant["capabilityKind"] == "endpoint" and grant["source"] == name
            ),
            # Each static notification object is owned once, by its declared
            # signal source; wait holders receive capabilities to that object.
            "notification": sum(
                1 for grant in manifest.get("notificationGrants", []) if grant["source"] == name
            ),
        }
        quota_records.extend(
            GENERATION_RESOURCE_QUOTA.pack(
                string_offset(f"{name}:quota"),
                process,
                process_objects["cnode"],
                process_objects["tcb"],
                process_objects["endpoint"],
                process_objects["notification"],
                process_objects["frame"],
                process_objects["vspace"],
                0,
                0,
                # CSlots the child's own CNode holds, from the same size the
                # CSpace object above was given.
                1 << cnode_size_bits,
                0,
                0,
                0,
            )
        )

        # Extra threads, if the instance declares any (B47). Each gets its own
        # TCB, IPC buffer, fault endpoint, fault policy, and schedule, and
        # shares this process's CSpace and VSpace -- which is exactly what
        # makes it a second *thread* rather than a second process.
        #
        # Appended after the main thread's records so the indices above stay
        # the ones the process names, and counted from the tables themselves
        # so a plan with several multi-threaded processes still lines up.
        extra_threads = instance.get("extraThreads", 0)
        if not isinstance(extra_threads, int) or isinstance(extra_threads, bool):
            fail(f"instance {name}: invalid extraThreads")
        if extra_threads < 0:
            fail(f"instance {name}: extraThreads {extra_threads} is negative")
        for extra in range(extra_threads):
            label = f"{name}:thread{extra + 1}"
            extra_tcb = len(object_index)
            object_index[(name, f"tcb{extra + 1}")] = extra_tcb
            kernel_records.extend(
                GENERATION_KERNEL_OBJECT.pack(
                    string_offset(f"{label}:tcb"), KERNEL_OBJECT_TCB, process, 11, 1, PLAN_NONE, 0
                )
            )
            extra_ipc = len(object_index)
            object_index[(name, f"ipc-buffer{extra + 1}")] = extra_ipc
            kernel_records.extend(
                GENERATION_KERNEL_OBJECT.pack(
                    string_offset(f"{label}:ipc-buffer"),
                    KERNEL_OBJECT_FRAME,
                    process,
                    12,
                    1,
                    PLAN_NONE,
                    0,
                )
            )
            extra_fault_endpoint = len(object_index)
            object_index[(name, f"fault-endpoint{extra + 1}")] = extra_fault_endpoint
            kernel_records.extend(
                GENERATION_KERNEL_OBJECT.pack(
                    string_offset(f"{label}:fault-endpoint"),
                    KERNEL_OBJECT_ENDPOINT,
                    process,
                    4,
                    1,
                    PLAN_NONE,
                    0,
                )
            )
            extra_schedule = len(schedule_records) // GENERATION_SCHEDULE.size
            schedule_records.extend(
                GENERATION_SCHEDULE.pack(
                    string_offset(f"{label}:schedule"),
                    len(thread_records) // GENERATION_THREAD.size,
                    PLAN_NONE,
                    worker_priority,
                    worker_priority,
                    0,
                    0,
                    0,
                )
            )
            extra_fault = len(fault_records) // GENERATION_FAULT_POLICY.size
            fault_records.extend(
                GENERATION_FAULT_POLICY.pack(
                    string_offset(f"{label}:fault"),
                    len(thread_records) // GENERATION_THREAD.size,
                    PLAN_NONE,
                    extra_fault_endpoint,
                    process + 1,
                    1,
                )
            )
            thread_records.extend(
                GENERATION_THREAD.pack(
                    string_offset(label),
                    process,
                    extra_tcb,
                    extra_schedule,
                    extra_fault,
                    extra_ipc,
                    0,
                    0,
                    0,
                )
            )

    process_for_instance = {
        instance["name"]: index for index, instance in enumerate(planned_instances)
    }
    for grant_index, (grant, rights) in enumerate(zip(grants, grant_rights, strict=True)):
        # A grant materializes in whichever instance declares a binding for it.
        # An `exec` or channel grant is bound by its source; a delegated
        # authority such as `bufferCreate` is bound only by its target, which is
        # the instance that actually holds the capability.
        holder = next(
            (
                name
                for name in (grant["source"], grant["target"])
                if name in instance_index
                and any(
                    binding["grant"] == grant["name"]
                    for binding in instances[instance_index[name]]["bindings"]
                )
            ),
            None,
        )
        if holder is None:
            fail(f"authority-bearing grant {grant['name']} has no concrete binding")
        source_process = process_for_instance[holder]
        bound = next(
            binding
            for binding in instances[instance_index[holder]]["bindings"]
            if binding["grant"] == grant["name"]
        )
        if grant["capabilityKind"] == "executable":
            target = executable_index[grant["target"]]
            spawn_records.extend(
                GENERATION_SPAWN_TEMPLATE.pack(
                    string_offset(grant["name"]),
                    target,
                    source_process,
                    source_process,
                    source_process,
                    source_process,
                    1,
                    0,
                )
            )
            cap_records.extend(
                GENERATION_CAP_BINDING.pack(
                    source_process,
                    bound["slot"],
                    object_index[(grant["source"], "tcb")],
                    rights,
                    0,
                    grant_index,
                    0,
                )
            )
        elif grant["capabilityKind"] == "endpoint":
            endpoint = len(object_index)
            object_index[(grant["name"], "endpoint")] = endpoint
            kernel_records.extend(
                GENERATION_KERNEL_OBJECT.pack(
                    string_offset(f"{grant['name']}:endpoint"),
                    KERNEL_OBJECT_ENDPOINT,
                    source_process,
                    4,
                    1,
                    PLAN_NONE,
                    0,
                )
            )
            cap_records.extend(
                GENERATION_CAP_BINDING.pack(
                    source_process, bound["slot"], endpoint, rights, 0, grant_index, 0
                )
            )
        else:
            cap_records.extend(
                GENERATION_CAP_BINDING.pack(
                    source_process,
                    bound["slot"],
                    object_index[(grant["source"], "tcb")],
                    rights,
                    0,
                    grant_index,
                    GRANT_POLICY_ONLY,
                )
            )
    notification_grant_records = bytearray()
    notification_binding_records = bytearray()
    notification_grants = sorted(
        manifest.get("notificationGrants", []), key=lambda grant: grant["name"]
    )
    notification_index = {grant["name"]: index for index, grant in enumerate(notification_grants)}
    if len(notification_index) != len(notification_grants):
        fail("notification grant names must be unique")
    bindings_by_grant: dict[str, list[dict]] = {name: [] for name in notification_index}
    seen_notification_slots: set[tuple[int, int]] = set()
    for binding in manifest.get("notificationBindings", []):
        grant = notification_index.get(binding["grant"])
        holder = instance_index.get(binding["holder"])
        role = {"signal": NOTIFICATION_ROLE_SIGNAL, "wait": NOTIFICATION_ROLE_WAIT}.get(
            binding["role"]
        )
        slot = binding["slot"]
        if grant is None or holder is None or role is None:
            fail("notification binding names unknown grant, holder, or role")
        if (
            not isinstance(slot, int)
            or isinstance(slot, bool)
            or not 0 <= slot < MAX_DECLARED_NATIVE_SLOT
        ):
            fail(f"notification binding {binding['grant']}: relative slot outside 0..30")
        if (holder, slot) in seen_notification_slots:
            fail(f"notification binding {binding['grant']}: duplicate holder slot")
        seen_notification_slots.add((holder, slot))
        bindings_by_grant[binding["grant"]].append(binding)
        notification_binding_records.extend(
            GENERATION_NOTIFICATION_BINDING.pack(grant, holder, slot, role, 0)
        )
    for grant in notification_grants:
        source = instance_index.get(grant["source"])
        target = instance_index.get(grant["target"])
        if source is None or target is None or source == target:
            fail(f"notification grant {grant['name']}: invalid endpoints")
        bindings = bindings_by_grant[grant["name"]]
        # One waiter, and at least the declared source signalling it. Several
        # signallers are the point of a Notification: a waiter blocked on one
        # object learns which of them spoke from the badge, which is the only
        # way a broker can wait on a whole peer set at once. `source` names the
        # edge the grant is *for*; any additional signaller must still be a
        # declared instance, and each gets its own badge bit from its slot.
        waiters = [b for b in bindings if b["role"] == "wait"]
        signals = [b for b in bindings if b["role"] == "signal"]
        if len(waiters) != 1 or instance_index[waiters[0]["holder"]] != target:
            fail(f"notification grant {grant['name']}: requires exactly one target wait binding")
        if not signals or source not in {instance_index[b["holder"]] for b in signals}:
            fail(f"notification grant {grant['name']}: requires a source signal binding")
        object_ = len(object_index)
        object_index[(grant["name"], "notification")] = object_
        kernel_records.extend(
            GENERATION_KERNEL_OBJECT.pack(
                string_offset(f"{grant['name']}:notification"),
                KERNEL_OBJECT_NOTIFICATION,
                process_for_instance[grant["source"]],
                4,
                1,
                PLAN_NONE,
                0,
            )
        )
        notification_grant_records.extend(
            GENERATION_NOTIFICATION_GRANT.pack(
                string_offset(grant["name"]), source, target, object_, 0
            )
        )
    if (
        len(notification_grants) > MAX_NOTIFICATION_GRANTS
        or len(manifest.get("notificationBindings", [])) > MAX_NOTIFICATION_BINDINGS
    ):
        fail("notification topology count exceeds bound")

    # Minted bindings: a capability the owner creates at runtime and hands to
    # an instance it owns at spawn. Sorted by name so the section is canonical,
    # and validated here so an unsatisfiable declaration fails before output.
    minted_records = bytearray()
    seen_holder_slots: set[tuple[int, int]] = set()
    validate_supervision_binding_names(manifest, instances)
    for minted in sorted(manifest.get("mintedBindings", []), key=lambda entry: entry["name"]):
        owner = instance_index.get(minted["owner"])
        holder = instance_index.get(minted["holder"])
        if owner is None or holder is None:
            fail(f"minted binding {minted['name']}: unknown owner or holder")
        if instances[holder]["owner"] != minted["owner"]:
            fail(f"minted binding {minted['name']}: holder is not owned by its minter")
        slot = minted["slot"]
        if not isinstance(slot, int) or isinstance(slot, bool) or not 0 <= slot < 32:
            fail(f"minted binding {minted['name']}: logical slot outside 0..31")
        if (holder, slot) in seen_holder_slots:
            fail(f"minted binding {minted['name']}: duplicate holder slot")
        seen_holder_slots.add((holder, slot))
        rights = RIGHT_TRANSFER if minted["transferable"] else 0
        for right in minted["rights"]:
            if right not in RIGHT:
                fail(f"minted binding {minted['name']}: unknown right {right}")
            rights |= RIGHT[right]
        kind = minted["capabilityKind"]
        validate_capability_rights(f"minted binding {minted['name']}", kind, rights)
        minted_records.extend(
            GENERATION_MINTED_BINDING.pack(
                string_offset(minted["name"]),
                owner,
                holder,
                slot,
                rights,
                0,
                CAPABILITY_KIND[kind],
            )
        )

    counts = (
        len(process_records) // GENERATION_PROCESS.size,
        len(thread_records) // GENERATION_THREAD.size,
        len(kernel_records) // GENERATION_KERNEL_OBJECT.size,
        len(mapping_records) // GENERATION_MAPPING.size,
        len(cap_records) // GENERATION_CAP_BINDING.size,
        len(service_records) // GENERATION_SERVICE_BINDING.size,
        len(schedule_records) // GENERATION_SCHEDULE.size,
        len(fault_records) // GENERATION_FAULT_POLICY.size,
        len(spawn_records) // GENERATION_SPAWN_TEMPLATE.size,
        len(quota_records) // GENERATION_RESOURCE_QUOTA.size,
        len(minted_records) // GENERATION_MINTED_BINDING.size,
        len(notification_grant_records) // GENERATION_NOTIFICATION_GRANT.size,
        len(notification_binding_records) // GENERATION_NOTIFICATION_BINDING.size,
    )
    limits = (
        MAX_PROCESSES,
        MAX_THREADS,
        MAX_KERNEL_OBJECTS,
        MAX_MAPPINGS,
        MAX_CAP_BINDINGS,
        MAX_SERVICE_BINDINGS,
        MAX_SCHEDULES,
        MAX_FAULT_POLICIES,
        MAX_SPAWN_TEMPLATES,
        MAX_RESOURCE_QUOTAS,
        MAX_MINTED_BINDINGS,
        MAX_NOTIFICATION_GRANTS,
        MAX_NOTIFICATION_BINDINGS,
    )
    if any(count > limit for count, limit in zip(counts, limits, strict=True)):
        fail("seL4 execution plan count exceeds bound")
    return (
        process_records,
        thread_records,
        kernel_records,
        mapping_records,
        cap_records,
        service_records,
        schedule_records,
        fault_records,
        spawn_records,
        quota_records,
        minted_records,
        notification_grant_records,
        notification_binding_records,
        counts,
    )


def layout_executables(manifest: dict) -> set[str]:
    """Executables the initial graph addresses through its boot slot table."""
    initial = {instance["name"] for instance in manifest["instances"]}
    names = {instance["executable"] for instance in manifest["instances"]}
    names.update(
        grant["target"]
        for grant in manifest["grants"]
        if grant["source"] in initial and grant["capabilityKind"] == "executable"
    )
    return names


def build_generation(
    manifest: dict,
    payloads: dict[str, bytes],
    parent: bytes | None,
    number: int,
    profile: TargetProfile,
) -> bytes:
    try:
        adaptive = private_memory_policy.manifest_policy(manifest)
    except ValueError as error:
        fail(str(error))
    if adaptive is not None:
        encoded = private_memory_policy.encode(adaptive, manifest["instances"])
        if payloads.get("private-memory-policy") != encoded:
            fail("private memory policy payload differs from its declaration")
    if "boot-layout" in {object_["id"] for object_ in manifest["objects"]}:
        payloads = dict(payloads)
        # Derived from the manifest's own `InstanceBinding` records rather than
        # from a second, static statement of the same thing (B71). The root
        # places the bootstrap component's capabilities from those bindings, so
        # this is the only derivation that cannot drift from what boots — the
        # static table had `spawn-service` at 4 where the root placed 5, and
        # nothing noticed until CP2's query read the resource's content.
        payloads["boot-layout"] = build_boot_layout(
            number,
            fail,
            entries=layout_from_manifest(manifest, RIGHT, RIGHT_TRANSFER),
        )
    objects = unique_sorted(manifest["objects"], "id", "object ids")
    executables = unique_sorted(manifest["executables"], "name", "executable names")

    # Pages each executable's image occupies, read back from the payload the
    # loader will actually map (B49). The root allocates one frame capability
    # per page from its own CSlots, so a quota that omitted them understated a
    # process's cost by an order of magnitude -- the 48-instance stress plane
    # declared 6 slots per instance and consumed 81.
    image_pages: dict[str, int] = {}
    for object_id, payload in payloads.items():
        if len(payload) < COMPONENT_IMAGE_HEADER.size:
            continue
        # The seL4 profile carries the whole ELF after the qualification
        # header rather than a re-based segment table, so the pages come from
        # that ELF's own program headers -- the same LOAD segments
        # `child_vspace` will map.
        if payload[:8] != COMPONENT_IMAGE_ELF_MAGIC:
            continue
        elf = payload[COMPONENT_IMAGE_ELF_HEADER_LEN:]
        if len(elf) < 64 or elf[:4] != b"\x7fELF":
            continue
        phoff = struct.unpack_from("<Q", elf, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", elf, 0x36)
        first: int | None = None
        last = 0
        for index in range(phnum):
            at = phoff + index * phentsize
            if at + 56 > len(elf):
                fail(f"object {object_id}: truncated program header")
            p_type = struct.unpack_from("<I", elf, at)[0]
            if p_type != 1:
                continue
            vaddr = struct.unpack_from("<Q", elf, at + 0x10)[0]
            memsz = struct.unpack_from("<Q", elf, at + 0x28)[0]
            if memsz:
                first = vaddr if first is None else min(first, vaddr)
                last = max(last, vaddr + memsz)
        if first is None:
            fail(f"object {object_id}: no loadable segment")
        image_pages[object_id] = -(-last // profile.page_bytes) - first // profile.page_bytes
    instances = unique_sorted(manifest["instances"], "name", "instance names")
    grants = sorted(
        manifest["grants"], key=lambda grant: (grant["name"], grant["source"], grant["target"])
    )
    states = unique_sorted(manifest["state"], "name", "state names")
    if len({(grant["name"], grant["source"], grant["target"]) for grant in grants}) != len(grants):
        fail("grant identities must be unique")
    if (
        not 1 <= len(objects) <= MAX_OBJECTS
        or not 1 <= len(executables) <= MAX_EXECUTABLES
        or not 1 <= len(instances) <= MAX_INSTANCES
        or len(grants) > MAX_GRANTS
        or len(states) > MAX_STATES
    ):
        fail("manifest count exceeds bound")
    validate_acyclic(instances)
    object_index = {object_["id"]: index for index, object_ in enumerate(objects)}
    executable_index = {executable["name"]: index for index, executable in enumerate(executables)}
    instance_index = {instance["name"]: index for index, instance in enumerate(instances)}
    grant_index = {grant["name"]: index for index, grant in enumerate(grants)}
    if len(grant_index) != len(grants):
        fail("grant names must be unique")
    if manifest["target"] != profile.name:
        fail(
            f"manifest target {manifest['target']!r} does not match resolved profile {profile.name!r}"
        )
    bootstrap = instance_index.get(manifest["bootstrapInstance"])
    if bootstrap is None:
        fail("bootstrapInstance must name an instance")

    strings = bytearray()
    offsets: dict[str, int] = {}

    def string_offset(value: str) -> int:
        if value in offsets:
            return offsets[value]
        encoded = value.encode("utf-8")
        if len(encoded) > MAX_STRING_BYTES:
            fail("string exceeds bound")
        offset = len(strings)
        strings.extend(struct.pack("<H", len(encoded)))
        strings.extend(encoded)
        offsets[value] = offset
        if len(strings) > MAX_STRING_TABLE_BYTES:
            fail("string table exceeds bound")
        return offset

    target_offset = string_offset(manifest["target"])
    boot_action_offset = string_offset(manifest["bootAction"])
    for object_ in objects:
        string_offset(object_["id"])
    for executable in executables:
        string_offset(executable["name"])
    for instance in instances:
        string_offset(instance["name"])
    for grant in grants:
        string_offset(grant["name"])
    for state in states:
        string_offset(state["name"])

    grant_rights: list[int] = []
    for grant in grants:
        rights = 0
        for right in grant["rights"]:
            if right not in RIGHT:
                fail(f"unsupported right {right}")
            rights |= RIGHT[right]
        transferable = int(bool(grant["transferable"]))
        rights |= RIGHT_TRANSFER if transferable else 0
        validate_capability_rights(f"grant {grant['name']}", grant["capabilityKind"], rights)
        grant_rights.append(rights)

    expected_bindings: dict[str, set[str]] = {name: set() for name in instance_index}
    for grant, _rights in zip(grants, grant_rights, strict=True):
        source = instance_index.get(grant["source"])
        if source is None:
            fail(f"grant source missing: {grant['name']}")
        if grant["capabilityKind"] == "executable":
            expected_bindings[grant["source"]].add(grant["name"])
            if executable_index.get(grant["target"]) is None:
                fail(f"executable grant target missing: {grant['name']}")
        else:
            target = instance_index.get(grant["target"])
            if target is None:
                fail(f"grant target missing: {grant['name']}")
            # An endpoint's two ends are both declared, so the source binds it
            # as well as the target. Every other kind lands only in its target.
            if grant["capabilityKind"] == "endpoint":
                expected_bindings[grant["source"]].add(grant["name"])
            expected_bindings[grant["target"]].add(grant["name"])

    dependency_records = bytearray()
    binding_records = bytearray()
    instance_rows: list[tuple] = []
    dependency_count = 0
    binding_count = 0
    required_from_instances: set[str] = set()
    for instance in instances:
        executable = executable_index.get(instance["executable"])
        if executable is None:
            fail(f"instance {instance['name']}: missing executable")
        owner = instance["owner"]
        if owner == "root":
            owner_kind, owner_index = 0, 0
        else:
            owner_kind, owner_index = 1, instance_index.get(owner, -1)
            if owner_index < 0 or owner == instance["name"]:
                fail(f"instance {instance['name']}: invalid owner")
        autostart = instance["autostart"]
        if not isinstance(autostart, bool):
            fail(f"instance {instance['name']}: invalid autostart")
        dependencies = sorted(instance["dependencies"])
        if autostart:
            for dependency in dependencies:
                depended = instances[instance_index[dependency]]
                if depended["owner"] == "root" and not depended["autostart"]:
                    fail(f"instance {instance['name']}: autostart dependency is inactive")
        dependency_start = dependency_count
        for dependency in dependencies:
            dependency_records += GENERATION_DEPENDENCY.pack(instance_index[dependency])
            dependency_count += 1
        declared = instance["bindings"]
        names = [binding["grant"] for binding in declared]
        slots = [binding["slot"] for binding in declared]
        if len(set(names)) != len(names) or len(set(slots)) != len(slots):
            fail(f"instance {instance['name']}: duplicate binding grant or slot")
        if any(
            not isinstance(slot, int) or isinstance(slot, bool) or not 0 <= slot < 32
            for slot in slots
        ):
            fail(f"instance {instance['name']}: logical binding slot outside 0..31")
        for binding in declared:
            grant = (
                grants[grant_index[binding["grant"]]] if binding["grant"] in grant_index else None
            )
            if (
                grant is not None
                and set(grant["rights"]) & {"send", "recv"}
                and binding["slot"] >= MAX_DECLARED_NATIVE_SLOT
            ):
                fail(f"instance {instance['name']}: endpoint-relative slot outside 0..30")
        expected = expected_bindings[instance["name"]]
        extra = set(names) - expected
        for name in extra:
            grant = grants[grant_index[name]] if name in grant_index else None
            if grant is None or grant["source"] not in (instance["name"], owner):
                fail(f"instance {instance['name']}: binding names unrelated grant")
            rights = grant_rights[grant_index[name]]
            delegated_to_instance = grant["target"] == instance["name"]
            delegated_from_owner = grant["source"] == owner
            delegated_to_owned_instance = any(
                child["owner"] == instance["name"] and child["name"] == grant["target"]
                for child in instances
            )
            delegated_to_owned_executable = grant["capabilityKind"] == "executable" and any(
                child["owner"] == instance["name"] and child["executable"] == grant["target"]
                for child in instances
            )
            if (
                not delegated_from_owner
                and not delegated_to_instance
                and not delegated_to_owned_instance
                and not delegated_to_owned_executable
            ):
                fail(f"instance {instance['name']}: binding names unrelated grant")
        if not expected.issubset(names):
            fail(f"instance {instance['name']}: bindings do not close over related grants")
        binding_start = binding_count
        for binding in sorted(declared, key=lambda binding: binding["slot"]):
            grant = grant_index.get(binding["grant"])
            if grant is None:
                fail(f"instance {instance['name']}: binding names unknown grant")
            binding_records += GENERATION_BINDING.pack(grant, binding["slot"])
            binding_count += 1
        if instance["health"] not in ("required", "optional"):
            fail(f"instance {instance['name']}: invalid health")
        health = int(instance["health"] == "required")
        if health:
            required_from_instances.add(instance["name"])
        instance_rows.append(
            (
                string_offset(instance["name"]),
                executable,
                owner_kind,
                owner_index,
                int(autostart),
                dependency_start,
                len(dependencies),
                binding_start,
                len(declared),
                health,
            )
        )
    if dependency_count > MAX_DEPENDENCIES or binding_count > MAX_BINDINGS:
        fail("dependency or binding count exceeds bound")

    health = manifest["health"]
    required = sorted(health["requiredInstances"])
    if (
        health["bootAttempts"] <= 0
        or len(required) > MAX_HEALTH_INSTANCES
        or len(set(required)) != len(required)
        or set(required) != required_from_instances
    ):
        fail("invalid health policy")

    object_records = bytearray()
    executable_records = bytearray()
    instance_records = bytearray()
    grant_records = bytearray()
    state_records = bytearray()
    (
        process_records,
        thread_records,
        kernel_object_records,
        mapping_records,
        cap_binding_records,
        service_binding_records,
        schedule_records,
        fault_policy_records,
        spawn_template_records,
        resource_quota_records,
        minted_binding_records,
        notification_grant_records,
        notification_binding_records,
        plan_counts,
    ) = build_sel4_plan(
        manifest,
        instances,
        grants,
        grant_rights,
        instance_index,
        executable_index,
        string_offset,
        image_pages,
    )
    health_records = bytearray()
    blobs = bytearray()
    plan_bytes = sum(
        len(records)
        for records in (
            process_records,
            thread_records,
            kernel_object_records,
            mapping_records,
            cap_binding_records,
            service_binding_records,
            schedule_records,
            fault_policy_records,
            spawn_template_records,
            resource_quota_records,
            minted_binding_records,
            notification_grant_records,
            notification_binding_records,
        )
    )
    payload_start = (
        GENERATION_HEADER.size
        + len(objects) * GENERATION_OBJECT.size
        + len(executables) * GENERATION_EXECUTABLE.size
        + len(instances) * GENERATION_INSTANCE.size
        + len(dependency_records)
        + len(binding_records)
        + len(grants) * GENERATION_GRANT.size
        + len(states) * GENERATION_STATE.size
        + len(required) * GENERATION_HEALTH.size
        + plan_bytes
        + len(strings)
    )
    for object_ in objects:
        if object_["kind"] not in KIND:
            fail(f"unsupported object kind {object_['kind']}")
        payload = payloads.get(object_["id"])
        if payload is None or len(payload) > MAX_OBJECT_PAYLOAD_BYTES:
            fail(f"missing or oversized payload for {object_['id']}")
        object_records += GENERATION_OBJECT.pack(
            string_offset(object_["id"]),
            KIND[object_["kind"]],
            payload_start + len(blobs),
            len(payload),
            sha256(payload),
        )
        blobs += payload
    for executable in executables:
        object_ = object_index.get(executable["object"])
        if object_ is None or objects[object_]["kind"] not in ("bootstrap", "component"):
            fail(f"executable {executable['name']}: invalid object")
        if executable["role"] not in ROLE:
            fail(f"executable {executable['name']}: unsupported role")
        spawn_budget = executable["spawnBudget"]
        if not isinstance(spawn_budget, int) or not 0 <= spawn_budget <= MAX_SPAWN_BUDGET:
            fail(f"executable {executable['name']}: invalid spawn budget")
        executable_records += GENERATION_EXECUTABLE.pack(
            string_offset(executable["name"]), object_, ROLE[executable["role"]], spawn_budget
        )
    bootstrap_instance = instances[bootstrap]
    bootstrap_executable = executables[executable_index[bootstrap_instance["executable"]]]
    if (
        bootstrap_instance["owner"] != "root"
        or not bootstrap_instance["autostart"]
        or bootstrap_executable["role"] != "init"
        or objects[object_index[bootstrap_executable["object"]]]["kind"] != "bootstrap"
    ):
        fail("bootstrap instance must be root-owned autostart init/bootstrap")
    for row in instance_rows:
        instance_records += GENERATION_INSTANCE.pack(*row)
    for grant, rights in zip(grants, grant_rights, strict=True):
        source = instance_index[grant["source"]]
        target = (
            executable_index[grant["target"]]
            if grant["capabilityKind"] == "executable"
            else instance_index[grant["target"]]
        )
        grant_records += GENERATION_GRANT.pack(
            string_offset(grant["name"]),
            source,
            target,
            rights,
            int(bool(grant["transferable"])),
            GRANT_FLAGS_NONE,
            CAPABILITY_KIND[grant["capabilityKind"]],
        )
    for state in states:
        owner = instance_index.get(state["owner"])
        if owner is None or state["schemaVersion"] <= 0 or state["policy"] not in POLICY:
            fail(f"invalid state {state['name']}")
        state_records += GENERATION_STATE.pack(
            string_offset(state["name"]), owner, state["schemaVersion"], POLICY[state["policy"]]
        )
    for name in required:
        health_records += GENERATION_HEALTH.pack(instance_index[name])

    object_offset = GENERATION_HEADER.size
    executable_offset = object_offset + len(object_records)
    instance_offset = executable_offset + len(executable_records)
    dependency_offset = instance_offset + len(instance_records)
    binding_offset = dependency_offset + len(dependency_records)
    grant_offset = binding_offset + len(binding_records)
    state_offset = grant_offset + len(grant_records)
    health_offset = state_offset + len(state_records)
    process_offset = health_offset + len(health_records)
    thread_offset = process_offset + len(process_records)
    kernel_object_offset = thread_offset + len(thread_records)
    mapping_offset = kernel_object_offset + len(kernel_object_records)
    cap_binding_offset = mapping_offset + len(mapping_records)
    service_binding_offset = cap_binding_offset + len(cap_binding_records)
    schedule_offset = service_binding_offset + len(service_binding_records)
    fault_policy_offset = schedule_offset + len(schedule_records)
    spawn_template_offset = fault_policy_offset + len(fault_policy_records)
    resource_quota_offset = spawn_template_offset + len(spawn_template_records)
    minted_binding_offset = resource_quota_offset + len(resource_quota_records)
    notification_grant_offset = minted_binding_offset + len(minted_binding_records)
    notification_binding_offset = notification_grant_offset + len(notification_grant_records)
    string_table_offset = notification_binding_offset + len(notification_binding_records)
    actual_payload_offset = string_table_offset + len(strings)
    if actual_payload_offset != payload_start:
        fail("internal payload offset mismatch")
    total_len = actual_payload_offset + len(blobs)
    if total_len > MAX_GENERATION_BYTES:
        fail("generation exceeds bound")
    header = GENERATION_HEADER.pack(
        GENERATION_MAGIC,
        GENERATION_VERSION,
        GENERATION_HEADER.size,
        0,
        bytes(32),
        number,
        parent or bytes(32),
        target_offset,
        boot_action_offset,
        bootstrap,
        health["bootAttempts"],
        len(objects),
        len(executables),
        len(instances),
        dependency_count,
        binding_count,
        len(grants),
        len(states),
        len(required),
        *plan_counts,
        0,
        object_offset,
        executable_offset,
        instance_offset,
        dependency_offset,
        binding_offset,
        grant_offset,
        state_offset,
        health_offset,
        process_offset,
        thread_offset,
        kernel_object_offset,
        mapping_offset,
        cap_binding_offset,
        service_binding_offset,
        schedule_offset,
        fault_policy_offset,
        spawn_template_offset,
        resource_quota_offset,
        minted_binding_offset,
        notification_grant_offset,
        notification_binding_offset,
        string_table_offset,
        len(strings),
        actual_payload_offset,
        total_len,
    )
    generation = bytearray(
        header
        + object_records
        + executable_records
        + instance_records
        + dependency_records
        + binding_records
        + grant_records
        + state_records
        + health_records
        + process_records
        + thread_records
        + kernel_object_records
        + mapping_records
        + cap_binding_records
        + service_binding_records
        + schedule_records
        + fault_policy_records
        + spawn_template_records
        + resource_quota_records
        + minted_binding_records
        + notification_grant_records
        + notification_binding_records
        + strings
        + blobs
    )
    generation[24:56] = generation_identity(generation)
    return bytes(generation)


def encode_bootstate(
    sequence: int,
    known_good: bytes,
    generation_root: bytes,
    pending: bytes | None = None,
    accepted_release_sequence: int = 0,
    remaining_attempts: int = 0,
    state_root: bytes | None = None,
) -> bytes:
    slot = bytearray(BOOTSTATE_SLOT_BYTES)
    slot[:8] = BOOTSTATE_MAGIC
    struct.pack_into("<IIQQ", slot, 8, BOOTSTATE_VERSION, BOOTSTATE_SLOT_BYTES, 0, sequence)
    slot[BOOTSTATE_KNOWN_GOOD_OFFSET:BOOTSTATE_KNOWN_GOOD_END] = known_good
    if pending is not None:
        slot[BOOTSTATE_PENDING_OFFSET:BOOTSTATE_PENDING_END] = pending
    struct.pack_into("<II", slot, BOOTSTATE_REMAINING_ATTEMPTS_OFFSET, remaining_attempts, 0)
    slot[BOOTSTATE_GENERATION_ROOT_OFFSET:BOOTSTATE_GENERATION_ROOT_END] = generation_root
    slot[BOOTSTATE_STATE_ROOT_OFFSET:BOOTSTATE_STATE_ROOT_END] = state_root or sha256(b"")
    struct.pack_into(
        "<Q", slot, BOOTSTATE_ACCEPTED_RELEASE_SEQUENCE_OFFSET, accepted_release_sequence
    )
    slot[BOOTSTATE_CHECKSUM_OFFSET:BOOTSTATE_CHECKSUM_END] = bootstate_checksum(slot)
    return bytes(slot)


# Must equal `slime-root/src/boot_selector.rs`'s `SELECTOR_GENERATION_BYTES`.
# Lowered from 8 MiB with that constant: the selector's buffer is `.bss`, so
# every page of it costs a root CSlot before the root runs, and 8 MiB spent
# ~2048 of the root CNode's 4096 — enough that the selector refused generations
# every other image admits. See that constant for the measurement.
SELECTOR_GENERATION_BYTES = 4 * 1024 * 1024


def build_bootstore(generations: list[bytes]) -> bytes:
    if any(len(generation) > SELECTOR_GENERATION_BYTES for generation in generations):
        fail(f"generation exceeds selector ceiling ({SELECTOR_GENERATION_BYTES} bytes)")
    release_sequences = [index + 1 for index in range(len(generations))]
    pending_sequence = os.environ.get("SLIME_PENDING_RELEASE_SEQUENCE")
    if pending_sequence is not None:
        release_sequences[-1] = int(pending_sequence)
    boot_bundle_hex = os.environ.get("SLIME_BOOT_BUNDLE_IDENTITY")
    try:
        boot_bundle = bytes.fromhex(boot_bundle_hex) if boot_bundle_hex is not None else None
    except ValueError:
        fail("SLIME_BOOT_BUNDLE_IDENTITY must be a nonzero 32-byte hex digest")
    if boot_bundle is not None and (len(boot_bundle) != 32 or boot_bundle == bytes(32)):
        fail("SLIME_BOOT_BUNDLE_IDENTITY must be a nonzero 32-byte hex digest")
    entries = sorted(
        (
            generation[24:56],
            generation,
            build_release(generation, release_sequences[index], boot_bundle_identity=boot_bundle),
        )
        for index, generation in enumerate(generations)
    )
    entries.sort(key=lambda item: item[0])
    generation_root = sha256(b"".join(identity for identity, _, _ in entries))
    known_good = generations[-1][24:56]
    pending = None
    remaining_attempts = 0
    if os.environ.get("SLIME_KNOWN_GOOD_FIRST") == "1":
        known_good = generations[0][24:56]
    if os.environ.get("SLIME_PENDING_GENERATION") == "1":
        known_good = generations[0][24:56]
        pending = generations[-1][24:56]
        remaining_attempts = int(os.environ.get("SLIME_PENDING_ATTEMPTS") or "2")
    image = bytearray(BOOTSTORE_CAPACITY)
    accepted_sequence = int(
        os.environ.get("SLIME_ACCEPTED_RELEASE_SEQUENCE")
        or (1 if known_good == generations[0][24:56] else len(generations))
    )
    image[:BOOTSTATE_SLOT_BYTES] = encode_bootstate(
        2,
        known_good,
        generation_root,
        pending=pending,
        accepted_release_sequence=accepted_sequence,
        remaining_attempts=remaining_attempts,
    )
    image[BOOTSTATE_SLOT_BYTES : BOOTSTATE_SLOT_BYTES * 2] = encode_bootstate(
        1,
        known_good,
        generation_root,
        pending=pending,
        accepted_release_sequence=accepted_sequence,
        remaining_attempts=remaining_attempts,
    )
    directory = bytearray()
    release_cursor = BOOTSTORE_RELEASES_OFFSET
    generation_cursor = BOOTSTORE_GENERATIONS_OFFSET
    for identity, generation, release in entries:
        release_cursor = align_up(release_cursor, RELEASE_BYTES)
        generation_cursor = align_up(generation_cursor, PAGE_SIZE)
        directory += BOOTSTORE_ENTRY.pack(
            identity,
            generation_cursor,
            len(generation),
            release_cursor,
            len(release),
        )
        image[release_cursor : release_cursor + len(release)] = release
        image[generation_cursor : generation_cursor + len(generation)] = generation
        release_cursor += len(release)
        generation_cursor += len(generation)
    if release_cursor > BOOTSTORE_GENERATIONS_OFFSET or generation_cursor > BOOTSTORE_CAPACITY:
        fail("boot store capacity exceeded")
    header = BOOTSTORE_HEADER.pack(
        BOOTSTORE_MAGIC,
        BOOTSTORE_VERSION,
        BOOTSTORE_HEADER.size,
        0,
        len(entries),
        0,
        len(directory),
        BOOTSTORE_CAPACITY,
        bytes(32),
    )
    image[BOOTSTORE_DIRECTORY_OFFSET : BOOTSTORE_DIRECTORY_OFFSET + len(header)] = header
    image[
        BOOTSTORE_DIRECTORY_OFFSET + len(header) : BOOTSTORE_DIRECTORY_OFFSET
        + len(header)
        + len(directory)
    ] = directory
    checksum = bootstore_checksum(image)
    image[BOOTSTORE_DIRECTORY_OFFSET + 48 : BOOTSTORE_DIRECTORY_OFFSET + 80] = checksum
    return bytes(image)


def bootstrap_binding_projection(manifest: dict) -> tuple[dict[str, int], dict[str, int]]:
    """Project explicit bootstrap bindings onto the compile-time slot API."""
    bootstrap = manifest["bootstrapInstance"]
    instance = next(item for item in manifest["instances"] if item["name"] == bootstrap)
    grants_by_name = {grant["name"]: grant for grant in manifest["grants"]}
    binding_slots: dict[str, int] = {}
    role_bindings: dict[str, int] = {}
    kind_roles = {
        "sharedBufferFactory": "shared-buffer-factory",
        "input": "input",
    }
    for binding in instance["bindings"]:
        grant = grants_by_name[binding["grant"]]
        if "exec" in grant["rights"]:
            binding_slots[grant["target"]] = binding["slot"]
        elif set(grant["rights"]) & {"send", "recv"}:
            binding_slots[grant["name"]] = binding["slot"]
        role = kind_roles.get(grant["capabilityKind"])
        if role is not None:
            role_bindings[role] = binding["slot"]
    return binding_slots, role_bindings


def build_sel4_generation(
    output: Path,
    manifest: dict,
    target_profile: TargetProfile,
    external_components: dict[str, Path] | None = None,
    component_spec_root: Path | None = None,
    *,
    toolchain: str | None = None,
    prefix: Path | None = None,
    build_profile: str = "default",
    closure_target_name: str | None = None,
    generation_only: bool = False,
) -> None:
    """Build the `aarch64-sel4-qemu-virt` generation (P5.2).

    This is the product generation path. seL4 is the kernel, so the generation
    carries the pinned external-kernel identity required by the format but no
    custom-kernel executable. Recovery, storage, and generation management run
    as userspace planes selected by their manifests.

    A fabric graph is conditional rather than absent: a graph that declares one
    resolves the same authenticated profile the userspace fabric consumes.
    """

    # P5.5.2: a manifest that declares a fabric graph resolves it through the
    # same function every x86 profile uses, so a seL4 route identity, QoS row,
    # and control-slot base are folded from the same schemas and the same
    # validation rather than from a second implementation.
    #
    # The resolution produces the authenticated resource bytes below and
    # nothing a component compiles against: B70's per-plane Rust profile is
    # gone, so no image is parameterized by which plane built it.
    resolved_profile = None
    try:
        adaptive_policy = private_memory_policy.manifest_policy(manifest)
    except ValueError as error:
        fail(str(error))
    if manifest.get("fabricGraph"):
        interfaces = validate_interface_schemas(manifest["interfaceSchemas"])
        resolved_profile = resolve_fabric_profile(
            manifest, interfaces, manifest["fabricGraph"]["profiles"][0]["name"]
        )
    import component_spec_contract

    external_components = external_components or {}
    component_specs, workspace_binaries = resolve_component_sources(
        manifest, external_components, component_spec_root
    )
    built = (
        build_rust_components(
            manifest["generation"],
            target_profile,
            candidate_identity=None,
            components=workspace_binaries,
            toolchain=toolchain,
            prefix=prefix,
            build_profile=build_profile,
            closure_target_name=closure_target_name,
        )
        if workspace_binaries
        else None
    )
    payloads: dict[str, bytes] = {}
    object_ids = {object_["id"] for object_ in manifest["objects"]}
    # seL4 is external to the generation-v4 object closure; there is no
    # kernel-object header field or synthetic marker payload.
    # The authenticated C8.2 graph, byte-identical to what an x86 generation
    # carries for the same declaration. `slime-root` does not read it — the
    # fabric is userspace policy and the root knows nothing of routes — but it
    # is part of the object closure the root re-checks, so a graph the builder
    # resolved and then failed to carry would fail admission rather than boot
    # with an unauthenticated one.
    if resolved_profile is not None:
        if "fabric-graph" not in object_ids:
            fail("fabricGraph declared without a fabric-graph resource object")
        payloads["fabric-graph"] = resolved_profile.graph_bytes
    elif "fabric-graph" in object_ids:
        fail("fabric-graph resource object declared without a fabricGraph")
    if "shared-buffer-budget" in object_ids:
        payloads["shared-buffer-budget"] = build_shared_buffer_budget(
            manifest.get("sharedBufferBudget", [])
        )
    # C10.2's private-memory budget. Validated here rather than only encoded:
    # the root refuses an over-declared or over-committed budget at admission,
    # so checking the same two rules on the build side is what makes builder/root
    # drift a build failure instead of a boot failure.
    declared_private_memory = manifest.get("privateMemoryBudget") or []
    if "private-memory-budget" in object_ids:
        validated_private_memory_quotas(declared_private_memory, manifest["target"])
        payloads["private-memory-budget"] = build_private_memory_budget(declared_private_memory)
    elif declared_private_memory:
        # A quota nothing carries is a promise the generation cannot keep: the
        # root reads the ceiling from the resource object, so a manifest
        # declaring holders without the object would boot with every one of
        # them denied and no indication why.
        fail("privateMemoryBudget declared without a private-memory-budget resource object")
    if adaptive_policy is not None:
        payloads["private-memory-policy"] = private_memory_policy.encode(
            adaptive_policy, manifest["instances"]
        )
    declared_io_resources = manifest.get("ioResourceBudget") or []
    if "io-resource-budget" in object_ids:
        payloads["io-resource-budget"] = build_io_resource_budget(declared_io_resources)
    elif declared_io_resources:
        fail("ioResourceBudget declared without an io-resource-budget resource object")
    declared_network_destinations = manifest.get("networkDestinations") or []
    if "network-destinations" in object_ids:
        payloads["network-destinations"] = build_network_destinations(declared_network_destinations)
    elif declared_network_destinations:
        fail("networkDestinations declared without a network-destinations resource object")
    declared_network_interfaces = manifest.get("networkInterfaces") or []
    if "network-interface" in object_ids:
        payloads["network-interface"] = build_network_interfaces(declared_network_interfaces)
    elif declared_network_interfaces:
        fail("networkInterfaces declared without a network-interface resource object")
    declared_network_applications = manifest.get("networkApplications") or []
    if "network-application" in object_ids:
        payloads["network-application"] = build_network_applications(manifest)
    elif declared_network_applications:
        fail("networkApplications declared without a network-application resource object")
    declared_entropy_authority = manifest.get("entropyAuthority") or []
    if "entropy-authority" in object_ids:
        payloads["entropy-authority"] = build_entropy_authority(manifest)
    elif declared_entropy_authority:
        fail("entropyAuthority declared without an entropy-authority resource object")
    declared_zenoh_grants = manifest.get("zenohGrants") or []
    if "zenoh-grants" in object_ids:
        payloads["zenoh-grants"] = build_zenoh_grants_table(manifest)
    elif declared_zenoh_grants:
        fail("zenohGrants declared without a zenoh-grants resource object")
    declared_block_rings = manifest.get("blockRingAuthority") or []
    if "block-ring-authority" in object_ids:
        payloads["block-ring-authority"] = build_block_ring_authority(declared_block_rings)
    elif declared_block_rings:
        fail("blockRingAuthority declared without a block-ring-authority resource object")
    declared_clock_authority = manifest.get("clockAuthority") or []
    if "clock-authority" in object_ids:
        payloads["clock-authority"] = build_clock_authority(manifest)
    elif declared_clock_authority:
        fail("clockAuthority declared without a clock-authority resource object")
    declared_wait_set = manifest.get("waitSet") or []
    if "wait-set" in object_ids:
        payloads["wait-set"] = build_wait_set(manifest)
    elif declared_wait_set:
        fail("waitSet declared without a wait-set resource object")
    if "scheduling-class" in object_ids:
        payloads["scheduling-class"] = build_scheduling_class(manifest)
    elif manifest.get("schedulingClass") is not None:
        # A class policy nothing carries is a policy the root cannot read: it
        # resolves the band mapping from the resource object, so a manifest
        # declaring classes without the object would boot every instance at the
        # default priority while claiming a policy.
        fail("schedulingClass declared without a scheduling-class resource object")
    if "lifecycle-policy" in object_ids:
        payloads["lifecycle-policy"] = build_lifecycle_policy(manifest)
    elif manifest.get("lifecyclePolicy") is not None:
        # A lifecycle policy nothing carries is a policy the root cannot read:
        # every transition would be refused and every restart unadmitted while
        # the manifest claimed a graph, which is exactly the "declared but never
        # applied" shape B71 closed.
        fail("lifecyclePolicy declared without a lifecycle-policy resource object")
    residents = [
        instance["name"]
        for instance in manifest["instances"]
        if instance.get("lifetime", "bounded") == "resident"
    ]
    if "graph-arrival-ceiling" in object_ids:
        payloads["graph-arrival-ceiling"] = build_graph_arrival_ceiling(manifest)
    elif manifest.get("graphArrivalCeiling") is not None:
        # A ceiling nothing carries is one the root cannot read: the plane would
        # stop at the default while the manifest claimed a larger run.
        fail("graphArrivalCeiling declared without a graph-arrival-ceiling resource object")
    if "instance-lifetime" in object_ids:
        payloads["instance-lifetime"] = build_instance_lifetime(manifest)
    elif residents:
        # A resident declaration nothing carries is one the root cannot enforce:
        # it reads lifetimes from the resource object, so every such instance
        # would boot bounded while the manifest claimed otherwise.
        fail(f"resident instances {residents} declared without an instance-lifetime resource object")
    if "recording-policy" in object_ids:
        payloads["recording-policy"] = build_recording_policy(manifest)
    elif manifest.get("recording") is not None:
        # A recording table nothing carries is the same shape one level up: the
        # root reads the determinism declaration from the resource object, so a
        # manifest declaring a deterministic instance without the object would
        # boot with no determinism claim admitted while asserting one, and the
        # unrecorded-source refusal would never run.
        fail("recording declared without a recording-policy resource object")
    # C10.4: a component that cannot run without a private heap must be given
    # one, so the builder refuses the omission rather than shipping a generation
    # that boots into a dead service.
    #
    # `slime-rt/private-heap` makes the task-private region the component's only
    # heap. An instance the budget does not name has no region at all, so its
    # allocator's first request fails and every `try_reserve` after it fails too
    # — for `fabric-service` that is `claim_stream_tables` failing during
    # provisioning, which presents as a named component failure with a correct
    # message and a completely silent build behind it.
    #
    # Keyed on a separate set rather than on `PRIVATE_HEAP_COMPONENTS`, because
    # linking the allocator and *requiring* a quota are different facts. The
    # C10.2/C10.3 probes link it precisely so they can be run both ways: the
    # private-memory plane declares one instance with a quota and one without,
    # and the omitted one proving it is denied is that plane's whole point. A
    # rule keyed on the allocator would make the deny-by-default half
    # unexpressible.
    #
    # The shared-buffer plane has the same guard on its own axis:
    # `resolve_fabric_profile` refuses a graph whose declared fabric holder has
    # no `sharedBufferBudget` entry.
    quota_holders = {entry["holder"] for entry in declared_private_memory}
    if adaptive_policy is not None:
        quota_holders.update(entry["instance"] for entry in adaptive_policy["subjects"])
    for instance in manifest["instances"]:
        if instance["executable"] not in PRIVATE_HEAP_REQUIRED:
            continue
        if instance["name"] not in quota_holders:
            fail(
                f"instance {instance['name']} runs {instance['executable']}, which cannot "
                "provision without a private heap, but privateMemoryBudget declares no quota "
                "for it"
            )
    for executable in manifest["executables"]:
        stack = executable.get("stackBytes", COMPONENT_DEFAULT_STACK_BYTES)
        if (
            not isinstance(stack, int)
            or stack <= 0
            or stack % target_profile.page_bytes
            or stack > COMPONENT_MAX_STACK_BYTES
        ):
            fail(f"executable {executable['name']}: invalid stack")
        specification = component_specs.get(executable["name"])
        if specification is None:
            binary_name = executable["name"]
            provider = "workspace-fixture"
            if built is None:
                fail(f"executable {executable['name']!r}: workspace build was not run")
            elf = component_executable(built, binary_name, target_profile)
        else:
            implementation = specification["implementation"]
            binary_name = implementation["binary"]
            provider = implementation["provider"]
            if provider == component_spec_contract.PROVIDER_WORKSPACE:
                if built is None:
                    fail(f"executable {executable['name']!r}: workspace build was not run")
                elf = component_executable(built, binary_name, target_profile)
            else:
                elf = external_components[binary_name]
                source_path = elf
                try:
                    data = elf.read_bytes()
                except OSError as error:
                    fail(f"external component {binary_name!r}: cannot read {elf}: {error}")
                actual = sha256(data).hex()
                expected = implementation["contentHash"]
                if actual != expected:
                    fail(
                        f"external component {binary_name!r}: SHA-256 {actual} "
                        f"does not match declared {expected}"
                    )
                elf = data
                display_path = source_path
        if provider != component_spec_contract.PROVIDER_EXTERNAL:
            display_path = elf
        print(
            f"Component source: executable={executable['name']} "
            f"implementation={binary_name} provider={provider} path={display_path}"
        )
        payloads[executable["object"]] = component_image(
            executable["name"], elf, stack, target_profile, toolchain=toolchain
        )

    # RP2: qualify one named executable for a *different* admitted target, so a
    # boot gate can observe the root refusing a wrong-target component image
    # before mapping any of its bytes rather than only proving it host-side.
    #
    # Deliberately narrow. The name must be a declared executable and the
    # profile must be an admitted one, so this cannot fabricate a target the
    # contract does not define; only the qualification header changes, and the
    # generation stays otherwise valid so the refusal cannot be an unrelated
    # admission error wearing a wrong-target label. Validation-only, in the same
    # family as `SLIME_BOOT_SELECTION_FAIL`.
    injection = os.environ.get("SLIME_WRONG_TARGET_EXECUTABLE")
    if injection:
        name, _, profile_name = injection.partition("=")
        if not name or not profile_name:
            fail("SLIME_WRONG_TARGET_EXECUTABLE must be <executable>=<target-profile>")
        wrong = TARGET_PROFILES_BY_NAME.get(profile_name)
        if wrong is None:
            fail(f"SLIME_WRONG_TARGET_EXECUTABLE: unknown target {profile_name!r}")
        if wrong.name == target_profile.name:
            fail("SLIME_WRONG_TARGET_EXECUTABLE: the injected target is this generation's own")
        declared = {executable["name"]: executable for executable in manifest["executables"]}
        if name not in declared:
            fail(f"SLIME_WRONG_TARGET_EXECUTABLE: {name!r} is not a declared executable")
        executable = declared[name]
        stack = executable.get("stackBytes", COMPONENT_DEFAULT_STACK_BYTES)
        # The body stays the AArch64 ELF this workspace built; only the
        # qualification header names the other profile. That is exactly the
        # artifact `TargetProfile::admit` must reject, and keeping the body valid
        # means a passing refusal cannot come from a malformed ELF instead.
        header = COMPONENT_IMAGE_HEADER.pack(
            COMPONENT_IMAGE_ELF_MAGIC,
            COMPONENT_IMAGE_ELF_VERSION,
            COMPONENT_IMAGE_ELF_HEADER_LEN,
            COMPONENT_IMAGE_KERNEL_ABI,
            wrong.architecture,
            wrong.abi,
            wrong.page_profile,
            0,
            0,
            0,
            stack,
            wrong.id,
            wrong.required_features,
        )
        body = payloads[executable["object"]][COMPONENT_IMAGE_HEADER.size :]
        payloads[executable["object"]] = header + body
        print(f"Injected wrong-target qualification: {name} as {wrong.name}")

    generation = build_generation(manifest, payloads, None, manifest["generation"], target_profile)
    # Build the compatibility alias independently from the same resolved inputs.
    # Determinism checks can then detect hidden mutable builder state instead of
    # comparing a file copied from the bytes beside it.
    generation_one = build_generation(
        manifest, payloads, None, manifest["generation"], target_profile
    )
    embedded_only = generation_only or len(generation) > SELECTOR_GENERATION_BYTES
    if embedded_only and (output / "boot-store.bin").exists():
        fail("embedded-only output directory contains boot-store.bin; use a fresh output directory")
    bootstore = None if embedded_only else build_bootstore([generation])
    (output / "generation.bin").write_bytes(generation)
    (output / "generation-1.bin").write_bytes(generation_one)
    if bootstore is not None:
        (output / "boot-store.bin").write_bytes(bootstore)
        print(f"Built boot-store.bin ({len(bootstore)} bytes)")
    else:
        print("Embedded generation only: no selector boot-store.bin emitted")
    print(f"Built seL4 generation {generation[24:56].hex()} target={target_profile.name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--external-component",
        action="append",
        default=[],
        metavar="NAME=ELF",
        help="supply one externally built component ELF by implementation name",
    )
    parser.add_argument(
        "--component-spec-root",
        type=Path,
        help="load component specifications from this directory",
    )
    parser.add_argument(
        "--generation-only",
        action="store_true",
        help="omit the selector boot store (also omitted above the selector size ceiling)",
    )
    parser.add_argument("output_dir")
    arguments = parser.parse_args()
    output = Path(arguments.output_dir).resolve()
    external_components = parse_external_components(arguments.external_component)
    component_spec_root = (
        arguments.component_spec_root.resolve()
        if arguments.component_spec_root is not None
        else None
    )
    manifest = load_manifest()
    # The manifest names the profile a generation is built for. The optional
    # override rewrites that declaration before the closed profile lookup, so
    # downstream admission still sees one authoritative target value.
    requested_target = os.environ.get("SLIME_TARGET_PROFILE")
    if requested_target:
        manifest["target"] = requested_target
    requested_generation = os.environ.get("SLIME_GENERATION_NUMBER")
    if requested_generation is not None:
        try:
            generation_number = int(requested_generation)
        except ValueError:
            fail("SLIME_GENERATION_NUMBER must be a positive integer")
        if generation_number <= 0:
            fail("SLIME_GENERATION_NUMBER must be a positive integer")
        manifest["generation"] = generation_number
    # B62: one declared fabric limit, overridden per build variant.
    #
    # `sel4-traffic`, `sel4-fault`, and `sel4-saturation` were three 1882-line
    # fixtures differing in exactly two fields: the generation number (already
    # overridable above) and, for saturation, `inFlightOperations`. Copying an
    # entire manifest to change one integer is how a fixture goes stale against a
    # derivation rule it restates but no longer matches, which is B55's first
    # defect. `.zti` is immediate mode by design — no imports, no composition —
    # so the delta is expressed here rather than in the data.
    #
    # Deliberately narrow: one declared limit by name, validated against the
    # limits the manifest already declares, so this cannot introduce a limit the
    # schema does not know or silently create a graph field.
    requested_limit = os.environ.get("SLIME_FABRIC_LIMIT_OVERRIDE")
    if requested_limit:
        name, _, raw = requested_limit.partition("=")
        if not _ or not name:
            fail("SLIME_FABRIC_LIMIT_OVERRIDE must be <limit>=<value>")
        limits = manifest.get("fabricGraph", {}).get("limits")
        if not isinstance(limits, dict) or name not in limits:
            fail(f"SLIME_FABRIC_LIMIT_OVERRIDE names undeclared limit {name!r}")
        try:
            value = int(raw)
        except ValueError:
            fail("SLIME_FABRIC_LIMIT_OVERRIDE value must be an integer")
        if value <= 0:
            fail("SLIME_FABRIC_LIMIT_OVERRIDE value must be positive")
        limits[name] = value
    # B62: one declared participant QoS field, overridden per build variant.
    #
    # `sel4-matrix-unsatisfiable` was a 1069-line copy of `sel4-matrix` flipping
    # exactly one participant's `reliability` so admission must refuse the
    # resulting incompatible pair. The negative control is that single field, so
    # the copy carried 1068 lines of agreement that nothing checked stayed in
    # agreement.
    #
    # Addressed by route, component, and field so it cannot silently retarget:
    # every part must resolve against what the manifest already declares.
    requested_qos = os.environ.get("SLIME_FABRIC_QOS_OVERRIDE")
    if requested_qos:
        parts = requested_qos.split(":")
        if len(parts) != 4 or not all(parts):
            fail("SLIME_FABRIC_QOS_OVERRIDE must be <route>:<component>:<field>:<value>")
        route_name, component, field, value = parts
        routes = [
            route
            for route in manifest.get("fabricGraph", {}).get("routes", [])
            if route.get("name") == route_name
        ]
        if len(routes) != 1:
            fail(f"SLIME_FABRIC_QOS_OVERRIDE names undeclared route {route_name!r}")
        members = [
            member for member in routes[0]["participants"] if member.get("component") == component
        ]
        if len(members) != 1:
            fail(
                f"SLIME_FABRIC_QOS_OVERRIDE names {component!r}, which is not a "
                f"unique participant of {route_name!r}"
            )
        if field not in members[0]:
            fail(f"SLIME_FABRIC_QOS_OVERRIDE names undeclared field {field!r}")
        members[0][field] = value
    target_profile = resolve_target_profile(manifest.get("target"))
    if manifest["formatVersion"] != 1:
        fail("unsupported source formatVersion")
    if target_profile.name not in SEL4_TARGET_PROFILES:
        fail("custom-kernel generation builds were retired with P5; select a seL4 manifest")
    output.mkdir(parents=True, exist_ok=True)
    build_sel4_generation(
        output,
        manifest,
        target_profile,
        external_components,
        component_spec_root,
        generation_only=arguments.generation_only,
    )


if __name__ == "__main__":
    main()

"""CP1 system-specification compiler and generation derivation.

Decodes `contracts/system-spec/v1/systems/*.zti`, validates it against the
component specs it references, and derives a `contracts/generation-manifest/v1`
`GenerationManifest` from the pair.

The derivation is the point of the milestone, so what it derives rather than
copies is worth stating plainly. Derived:

  - `executables`  — one per referenced component spec: `role` from
    `componentType`, `spawnBudget` and `stackBytes` from `runtime.resource`,
    `commandProfile` from the system's command bindings.
  - `instances`    — `executable`, `health`, and `dependencies` from the
    component spec; `owner` and the thread/priority fields from the system's
    placement; and every `bindings` entry from the grant table, since a grant
    materializes in whichever instance holds it.
  - `objects`      — one per component plus the resource objects the presence of
    a budget or a fabric graph implies.
  - `sharedBufferBudget` — from each component spec's `runtime.resource`.
  - `health.requiredInstances` — the components whose spec says `required`.

Declared, because no component spec can know it: the grant table (authority
between components is a property of the composition), the notification objects,
the fabric graph, the boot profiles, and the persisted state bindings.

Slot numbers are ordinarily assigned by `build-generation.py`'s own
`assign_declared_slots`, which is a function of the manifest alone. A system may
pin individual slots, and does for `valid.zti`, whose numbers
`contracts/boot-layout/v1/fixtures/*.layout` freeze byte for byte.
"""

from __future__ import annotations

import hashlib
import json
import re
import os
import subprocess
import tempfile
from functools import lru_cache
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import private_memory_policy
import system_spec_contract as default_contract
from component_spec import CompiledSpec, admit_specs, interface_catalogue
from harness import GENERATION_COMPOSITIONS, GENERATION_FIXTURES, ROOT, load_script
from zutai_cli import STDLIB, ZutaiError, binary as zutai_binary, evaluate, prefetch
from boot_contracts import (
    GRAPH_ARRIVAL_CEILING_DEFAULT,
    GRAPH_ARRIVAL_CEILING_MAX,
    PRIVATE_MEMORY_CAPACITY_PROFILES,
    PRIVATE_MEMORY_DEFAULT_REGION_PAGES,
    PRIVATE_MEMORY_DEFAULT_TOTAL_PAGES,
)

CONTRACT_ROOT = ROOT / "contracts" / "system-spec" / "v1"
CHECKER = CONTRACT_ROOT / "check.zt"
SYSTEM_ROOT = CONTRACT_ROOT / "systems"
INTERFACE_SCHEMA_ROOT = ROOT / "contracts" / "interface-schema" / "v1" / "interfaces"

# A mapped .zti is an output, never a competing hand-authored source.
COMPUTED_SYSTEM_SOURCES = {
    name: f"sources/{name}.zt"
    for name in (
        "sel4-call",
        "sel4-io-service-fault",
        "sel4-private-memory-adaptive-rv64",
        "sel4-private-memory-matrix-rv64",
        "sel4-private-memory-stress-rv64",
        "sel4-private-memory-heap-stress-rv64",
    )
}
_SOURCE_TOOL = ROOT / "scripts" / "tools" / "system-spec-source" / "Cargo.toml"
_SOURCE_TARGET = ROOT / "build" / "system-spec-source-target"

# Which committed `contracts/generation-manifest/v1` fixture each system spec derives.
#
# An explicit table rather than a glob makes "which fixtures are generated" a
# stated fact and a system spec that derives nothing a gate failure rather
# than a silent no-op. Every composition manifest is derived. Both the gate
# and the generator read the map from here.
DERIVED_GENERATION_FIXTURES = {
    "reference": "valid.zti",
    "sel4": "sel4.zti",
    "sel4-boot": "sel4-boot.zti",
    "sel4-call": "sel4-call.zti",
    "sel4-channel": "sel4-channel.zti",
    "sel4-large-image": "sel4-large-image.zti",
    "sel4-clock-authority": "sel4-clock-authority.zti",
    "sel4-crossing": "sel4-crossing.zti",
    "sel4-demo": "sel4-demo.zti",
    "sel4-entropy": "sel4-entropy.zti",
    "sel4-directory": "sel4-directory.zti",
    "sel4-filesystem": "sel4-filesystem.zti",
    "sel4-generation": "sel4-generation.zti",
    "sel4-input": "sel4-input.zti",
    "sel4-http": "sel4-http.zti",
    "sel4-http-public": "sel4-http-public.zti",
    "sel4-io-block": "sel4-io-block.zti",
    "sel4-io-driver-authority": "sel4-io-driver-authority.zti",
    "sel4-io-link": "sel4-io-link.zti",
    "sel4-io-network": "sel4-io-network.zti",
    "sel4-io-tcp": "sel4-io-tcp.zti",
    "sel4-io-tcp-buffers": "sel4-io-tcp-buffers.zti",
    "sel4-io-tcp-impairment": "sel4-io-tcp-impairment.zti",
    "sel4-io-tcp-listener": "sel4-io-tcp-listener.zti",
    "sel4-io-tcp-options": "sel4-io-tcp-options.zti",
    "sel4-io-local": "sel4-io-local.zti",
    "sel4-io-lifetime": "sel4-io-lifetime.zti",
    "sel4-io-service-fault": "sel4-io-service-fault.zti",
    "sel4-io-driver-reset": "sel4-io-driver-reset.zti",
    "sel4-io-queue": "sel4-io-queue.zti",
    "sel4-lifecycle-restart": "sel4-lifecycle-restart.zti",
    "sel4-lifetime": "sel4-lifetime.zti",
    "sel4-lifetime-exit": "sel4-lifetime-exit.zti",
    "sel4-net": "sel4-net.zti",
    "sel4-zenoh": "sel4-zenoh.zti",
    "sel4-zenoh-external": "sel4-zenoh-external.zti",
    "sel4-loan": "sel4-loan.zti",
    "sel4-mavlink": "sel4-mavlink.zti",
    "sel4-operation": "sel4-operation.zti",
    "sel4-powerbox": "sel4-powerbox.zti",
    "sel4-private-memory": "sel4-private-memory.zti",
    # MEM-ADAPTIVE's declared-policy compositions. The `-rv64` row is a separate
    # spec for the same reason every other private-memory plane's is: a closure's
    # platform follows its system spec's `targetRequirement`, and a spec declares
    # exactly one. `-overcommit` is a negative control that must never boot a
    # graph — it declares a simultaneous guarantee no reference machine can fund,
    # so admission has to fail closed before publication.
    "sel4-private-memory-adaptive": "sel4-private-memory-adaptive.zti",
    "sel4-private-memory-adaptive-rv64": "sel4-private-memory-adaptive-rv64.zti",
    "sel4-private-memory-adaptive-overcommit": "sel4-private-memory-adaptive-overcommit.zti",
    # The inventory matrix: one pool-relative policy, booted unchanged against
    # every pinned kernel-visible RAM row by `private_memory_matrix_check`.
    "sel4-private-memory-matrix": "sel4-private-memory-matrix.zti",
    "sel4-private-memory-matrix-rv64": "sel4-private-memory-matrix-rv64.zti",
    "sel4-private-memory-cycles": "sel4-private-memory-cycles.zti",
    "sel4-private-memory-1g": "sel4-private-memory-1g.zti",
    "sel4-private-memory-isolation": "sel4-private-memory-isolation.zti",
    "sel4-private-memory-stress": "sel4-private-memory-stress.zti",
    "sel4-private-memory-stress-rv64": "sel4-private-memory-stress-rv64.zti",
    "sel4-private-memory-heap-stress": "sel4-private-memory-heap-stress.zti",
    "sel4-private-memory-heap-stress-rv64": "sel4-private-memory-heap-stress-rv64.zti",
    "sel4-pwm": "sel4-pwm.zti",
    "sel4-qos": "sel4-qos.zti",
    "sel4-reclamation": "sel4-reclamation.zti",
    "sel4-recovery": "sel4-recovery.zti",
    "sel4-replay": "sel4-replay.zti",
    "sel4-robot-runtime": "sel4-robot-runtime.zti",
    "sel4-rollback": "sel4-rollback.zti",
    "sel4-sample": "sel4-sample.zti",
    "sel4-scheduling-class": "sel4-scheduling-class.zti",
    "sel4-slisp": "sel4-slisp.zti",
    "sel4-spawn": "sel4-spawn.zti",
    "sel4-storage": "sel4-storage.zti",
    "sel4-store": "sel4-store.zti",
    "sel4-data-volume": "sel4-data-volume.zti",
    "sel4-stream": "sel4-stream.zti",
    "sel4-c-runtime": "sel4-c-runtime.zti",
    "sel4-matrix": "sel4-matrix.zti",
    "sel4-stress": "sel4-stress.zti",
    "sel4-supervision": "sel4-supervision.zti",
    "sel4-traffic": "sel4-traffic.zti",
    "sel4-transfer": "sel4-transfer.zti",
    "sel4-visibility": "sel4-visibility.zti",
    "sel4-wait-set": "sel4-wait-set.zti",
}

def derived_manifest_path(fixture: str) -> Path:
    """Where a derived manifest is committed.

    The two schema-conformance fixtures live in `fixtures/`; every plane
    composition lives in `compositions/`. The derivation table names bare
    filenames because `check-system-spec.py` also uses them to find the frozen
    `contracts/system-spec/v1/baselines/` copy, which is a flat directory.
    """
    root = GENERATION_FIXTURES if fixture in {"valid.zti", "invalid.zti"} else GENERATION_COMPOSITIONS
    return root / fixture

_NAME = re.compile(r"^[a-z][a-z0-9-]*$")

_builder = load_script("system_spec_generation_builder", "build/build-generation.py")
# the builder, which already imports the generated `target_profile` bindings and
# is the module that refuses an unknown target or an unsupported source format.
_TARGET_PROFILES = _builder.TARGET_PROFILES_BY_NAME
# `contracts/generation-manifest/v1/schema.zt` is format 1 and `build-generation.py`
# refuses anything else at load time; a system spec produces that format or it
# produces something the builder will not read.
_GENERATION_SOURCE_FORMAT = 1

_SPEC_FIELDS = {
    "formatVersion",
    "name",
    "generation",
    "targetRequirement",
    "bootAction",
    "bootstrapInstance",
    "bootAttempts",
    "components",
    "placements",
    "grants",
    "slotPins",
    "extraBindings",
    "mintedBindings",
    "commandBindings",
    "defaultImageBytes",
    "imageSizes",
    "sharedBufferBudgetObject",
    "bootLayoutObject",
    "instances",
    "interfaceSchemas",
    "state",
    "notifications",
    "notificationBindings",
    "bootProfiles",
    "fabricGraph",
    "clockAuthority",
    "clockAuthorityObject",
    "ioResourceBudget",
    "ioResourceBudgetObject",
    "networkDestinations",
    "networkDestinationsObject",
    "networkInterfaces",
    "networkInterfacesObject",
    "networkApplications",
    "networkApplicationsObject",
    "entropyAuthority",
    "entropyAuthorityObject",
    "zenohGrants",
    "zenohGrantsObject",
    "blockRingAuthority",
    "blockRingAuthorityObject",
    "waitSet",
    "waitSetObject",
    "schedulingClass",
    "lifecyclePolicy",
    "graphArrivalCeiling",
    "privateMemoryPolicy",
    "recording",
    "recordingObject",
    "deploymentConstraint",
    "acceptanceCriteria",
}


class SystemSpecError(ValueError):
    pass


@dataclass(frozen=True)
class CompiledSystem:
    name: str
    spec: dict
    components: dict[str, dict]
    normalized: bytes
    identity: bytes


def _fail(message: str) -> None:
    raise SystemSpecError(message)


def _run_zutai(path: Path, command: str, *, contract: ModuleType) -> str:
    if not path.is_file():
        _fail(f"system spec not found: {path}")
    if path.stat().st_size > contract.MAX_SOURCE_BYTES:
        _fail(f"{path}: source exceeds bound")
    try:
        return evaluate(
            command,
            CHECKER if command == "run" else path,
            input_path=path,
            env_var="SLIME_SYSTEM_SPEC_PATH",
        )
    except ZutaiError as error:
        _fail(f"{path}: malformed Zutai input: {error}")


def _load(path: Path, contract: ModuleType) -> dict:
    decoded = _run_zutai(path, "run", contract=contract)
    if not decoded.startswith("#valid"):
        _fail(f"{path}: input does not match the system-spec schema")
    raw = _run_zutai(path, "json", contract=contract)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        _fail(f"{path}: invalid Zutai JSON projection: {error}")
    if not isinstance(value, dict):
        _fail(f"{path}: expected a record")
    # `fabricGraph`, `schedulingClass`, `lifecyclePolicy` and
    # `graphArrivalCeiling` are optional; their absence is a legitimate shape.
    _OPTIONAL_FIELDS = {"fabricGraph", "schedulingClass", "lifecyclePolicy", "graphArrivalCeiling", "privateMemoryPolicy"}
    # The IO11 interface table postdates every earlier spec; an absent field is
    # the same declaration as an empty one without an object.
    _DEFAULTED_FIELDS = {"networkInterfaces": [], "networkInterfacesObject": False,
                         "networkApplications": [], "networkApplicationsObject": False,
                         "entropyAuthority": [], "entropyAuthorityObject": False,
                         "zenohGrants": [], "zenohGrantsObject": False}
    unexpected = set(value) - _SPEC_FIELDS
    missing = _SPEC_FIELDS - set(value) - _OPTIONAL_FIELDS - set(_DEFAULTED_FIELDS)
    if unexpected or missing:
        _fail(f"{path}: unexpected {sorted(unexpected)}, missing {sorted(missing)}")
    for field, default in _DEFAULTED_FIELDS.items():
        value.setdefault(field, default)
    return value


def _validate(spec: dict, components: dict[str, dict], contract: ModuleType) -> None:
    """Everything the Zutai type cannot express, checked before anything derives."""
    if spec["formatVersion"] != contract.FORMAT_VERSION:
        _fail(f"unsupported system spec version {spec['formatVersion']}")
    if not _NAME.match(spec["name"]):
        _fail(f"name: {spec['name']!r} is not a system identifier")
    if spec["generation"] <= 0:
        _fail("generation: must be positive")
    if spec["bootAttempts"] <= 0:
        _fail("bootAttempts: must be positive")

    profile = _TARGET_PROFILES.get(spec["targetRequirement"])
    if profile is None:
        _fail(
            f"targetRequirement: {spec['targetRequirement']!r} names no profile in "
            "contracts/target-profile/v1"
        )

    declared = spec["components"]
    if len(declared) > contract.MAX_COMPONENTS:
        _fail("components: exceeds bound")
    if len(set(declared)) != len(declared):
        _fail("components: duplicate entry")
    if declared != sorted(declared):
        _fail("components: must be sorted")
    unknown = [name for name in declared if name not in components]
    if unknown:
        _fail(f"components: no component spec declares {unknown}")

    admitted = set(declared)
    # A component's `runtime.executionEnvironment` is *not* required to equal
    # this system's target, and the attempt to require it is what disproved the
    # assumption: `console`, `init`, and the rest compose into both
    # `valid.zti` (x86_64-qemu-virtio) and `sel4-channel.zti`
    # (aarch64-sel4-qemu-virt) from the same sources. A component spec's
    # environment records the reference generation it was authored against, not
    # an exclusive claim, and CP0's corpus is authored against `valid.zti`.
    #
    # What *is* enforced is that the target exists in the profile table, checked
    # above. Per-image target qualification belongs to immutable selector/root
    # admission and is already gated: `contracts/component/v2`'s header carries
    # architecture, ABI, page profile, and required features, and admission
    # compares them by equality before mapping executable bytes. Restating a
    # weaker version here would be a second authority on it, and a wrong one.

    placements_by_component = {entry["component"]: entry for entry in spec["placements"]}
    # The emitted executable identity per component: its own name unless this
    # composition renames it, which two compositions do because their
    # executable is named for the implementation binary rather than the spec.
    emitted = {
        name: placements_by_component.get(name, {}).get("executableName", name)
        for name in declared
    }
    if len(set(emitted.values())) != len(emitted):
        _fail("placements: two components emit the same executable name")
    emitted_names = set(emitted.values())
    # `admitted` is the component (executable) set; `live` is the instance set
    # grants, notifications, slot pins, and every policy table name. They are
    # equal only when a composition declares no explicit instances.
    declared_instances = spec["instances"]
    if len(declared_instances) > contract.MAX_INSTANCES:
        _fail("instances: exceeds bound")
    instance_owners: dict[str, str] = {}
    for entry in declared_instances:
        if entry["name"] in instance_owners:
            _fail(f"instances: duplicate instance {entry['name']!r}")
        if entry["executable"] not in emitted_names:
            _fail(
                f"instances: {entry['name']}: executable {entry['executable']!r} is not an "
                "admitted component"
            )
        if "health" in entry and entry["health"] not in ("required", "optional"):
            _fail(f"instances: {entry['name']}: unknown health {entry['health']!r}")
        if "lifetime" in entry and entry["lifetime"] not in ("resident", "bounded"):
            _fail(f"instances: {entry['name']}: unknown lifetime {entry['lifetime']!r}")
        instance_owners[entry["name"]] = entry["executable"]
    if declared_instances:
        uncovered = sorted(emitted_names - set(instance_owners.values()))
        if uncovered:
            _fail(
                f"instances: executables {uncovered} are admitted but no instance runs them; "
                "an explicit instance list declares every instance"
            )
    live = instance_names(spec)
    component_of = {value: key for key, value in emitted.items()}

    if spec["bootstrapInstance"] not in live:
        _fail(f"bootstrapInstance: {spec['bootstrapInstance']!r} is not a declared instance")
    bootstrap_executable = instance_owners.get(
        spec["bootstrapInstance"], spec["bootstrapInstance"]
    )
    bootstrap_component = component_of.get(bootstrap_executable, bootstrap_executable)
    bootstrap_role = placements_by_component.get(bootstrap_component, {}).get(
        "role", components[bootstrap_component]["componentType"]
    )
    if bootstrap_role != "init":
        _fail(f"bootstrapInstance: {spec['bootstrapInstance']!r} is not an init component")

    # A dependency must be a live instance, or the derived graph names an
    # instance the generation does not contain. An instance record or a
    # placement may override the component spec's own list, which is the
    # reference generation's answer: `slisp` depends on `console` where both are
    # composed and on nothing in the composition that admits only `slisp`, and
    # `lifecycle-worker` depends on `lifecycle-supervisor`, another instance of
    # its own executable.
    for entry in resolved_instances(spec):
        component_name = component_of.get(entry["executable"], entry["executable"])
        for dependency in entry.get("dependencies", components[component_name]["dependencies"]):
            if dependency not in live:
                _fail(
                    f"{entry['name']}: depends on {dependency!r}, which this system does not admit"
                )

    placements = spec["placements"]
    seen_placements = [entry["component"] for entry in placements]
    if len(set(seen_placements)) != len(seen_placements):
        _fail("placements: duplicate component")
    for entry in placements:
        if entry["component"] not in admitted:
            _fail(f"placements: {entry['component']!r} is not an admitted component")
        if "health" in entry and entry["health"] not in ("required", "optional"):
            _fail(f"placements: {entry['component']}: unknown health {entry['health']!r}")
        if "lifetime" in entry and entry["lifetime"] not in ("resident", "bounded"):
            _fail(f"placements: {entry['component']}: unknown lifetime {entry['lifetime']!r}")
        if "role" in entry and entry["role"] not in ("init", "service", "application"):
            _fail(f"placements: {entry['component']}: unknown role {entry['role']!r}")
        if "stackBytes" in entry and not 0 < entry["stackBytes"] <= _builder.COMPONENT_MAX_STACK_BYTES:
            _fail(f"placements: {entry['component']}: stackBytes outside the declared bound")

    grant_names: set[str] = set()
    for grant in spec["grants"]:
        if grant["name"] in grant_names:
            _fail(f"grants: duplicate grant {grant['name']!r}")
        grant_names.add(grant["name"])
        if grant["capabilityKind"] not in _builder.CAPABILITY_KIND:
            _fail(f"grants: {grant['name']}: unknown capability kind {grant['capabilityKind']!r}")
        if grant["source"] not in live:
            _fail(f"grants: {grant['name']}: source {grant['source']!r} is not admitted")
        if grant["target"] not in live and grant["target"] not in admitted:
            _fail(f"grants: {grant['name']}: target {grant['target']!r} is not admitted")
        # The rights vocabulary and the per-kind mask are the builder's, checked
        # here so a malformed grant is refused before a manifest exists rather
        # than after one is written.
        rights = 0
        for right in grant["rights"]:
            if right not in _builder.RIGHT:
                _fail(f"grants: {grant['name']}: unknown right {right!r}")
            rights |= _builder.RIGHT[right]
        if grant["transferable"]:
            rights |= _builder.RIGHT_TRANSFER
        # The builder raises `SystemExit` on refusal, which would escape a caller
        # catching `SystemSpecError` and abort the process instead of reporting a
        # rejected spec. Reusing its rule is the point; adopting its exit
        # behaviour is not.
        try:
            _builder.validate_capability_rights(
                grant["name"], grant["capabilityKind"], rights
            )
        except SystemExit as error:
            _fail(f"grants: {grant['name']}: {error}")
    if len(grant_names) > contract.MAX_GRANTS:
        _fail("grants: exceeds bound")

    # No capability agreement between a system's grants and a component spec's
    # `provides`/`requires` is enforced here, and that is a finding rather than
    # an omission.
    #
    # Three progressively weaker rules were tried and each was disproved by the
    # two real fixtures:
    #
    #   - per-role equality: `console` *provides* an endpoint under `valid.zti`,
    #     where it owns the edge to `dango`, and *receives* one under the channel
    #     plane, where `init` owns it. Same component, opposite role.
    #   - per-role containment: same counterexample, since the role moved rather
    #     than narrowed.
    #   - kind containment: `init` holds an `endpoint` kind under the channel
    #     plane and none at all under `valid.zti`.
    #
    # The root cause is that CP0's corpus is authored against exactly one
    # generation. A component spec's capability sets record what `valid.zti`
    # grants that component, not what the component supports across every
    # composition, so any cross-system claim built on them is false today. The
    # honest position is to enforce nothing here and say why.
    #
    # `just component_spec_check` keeps the exact per-role match against
    # `valid.zti` itself, where it is true and where it caught a real defect.
    # Making the sets composition-independent — so a system could be checked
    # against them — needs the corpus to describe components rather than one
    # generation's use of them, which is CP3/CP5 work.

    grants_by_name = {grant["name"]: grant for grant in spec["grants"]}
    for pin in spec["slotPins"]:
        grant = grants_by_name.get(pin["grant"])
        # A binding is not restricted to a grant's own source/target: a spawn
        # broker such as `spawn-service` can hold a third-party binding on an
        # `executable` grant it neither issued nor received, delegated spawn
        # authority the command-dispatch table (`commandBindings`) routes
        # through it. `pin["holder"]` need only be admitted and the grant must
        # be real; which instances legitimately hold which grants beyond that
        # is exactly the declared fact a slot pin (and, for the ordinary case,
        # `derive_bindings`) exists to state.
        if grant is None or pin["holder"] not in live:
            _fail(
                f"slotPins: {pin['holder']}/{pin['grant']} pins a slot for a binding the "
                "grant table does not produce"
            )
        if pin["slot"] < 0:
            _fail(f"slotPins: {pin['holder']}/{pin['grant']}: negative slot")
        # Vocabulary only. Whether the stated reason is *true* is a property of
        # the derived manifest, not of this spec, so the generation builder
        # re-derives it and refuses a mislabelled pin (B91).
        if pin["reason"] not in _builder.SLOT_REASONS:
            _fail(
                f"slotPins: {pin['holder']}/{pin['grant']}: unknown reason {pin['reason']!r}; "
                f"expected one of {', '.join(_builder.SLOT_REASONS)}"
            )
    pin_keys = [(pin["holder"], pin["grant"]) for pin in spec["slotPins"]]
    if len(set(pin_keys)) != len(pin_keys):
        _fail("slotPins: duplicate (holder, grant)")
    for holder, pins in _grouped(spec["slotPins"], "holder").items():
        slots = [pin["slot"] for pin in pins]
        if len(set(slots)) != len(slots):
            _fail(f"slotPins: {holder} pins one slot twice")

    # An extra binding is the unpinned half of the same declared fact a slot
    # pin carries: a holder the grant table's structural rule does not reach.
    # Both are refused when the grant is unreal or the holder unadmitted, and a
    # holder the structural rule already reaches needs no entry here — that
    # would be a second way to say one thing.
    extra_keys = [(entry["holder"], entry["grant"]) for entry in spec["extraBindings"]]
    if len(set(extra_keys)) != len(extra_keys):
        _fail("extraBindings: duplicate (holder, grant)")
    structural = derive_bindings(spec["grants"], live)
    for entry in spec["extraBindings"]:
        if entry["grant"] not in grants_by_name or entry["holder"] not in live:
            _fail(
                f"extraBindings: {entry['holder']}/{entry['grant']} names no grant this "
                "system declares for an admitted instance"
            )
        if entry["grant"] in structural.get(entry["holder"], set()):
            _fail(
                f"extraBindings: {entry['holder']}/{entry['grant']} is already produced by "
                "the grant table, so declaring it adds nothing"
            )
    if set(extra_keys) & set(pin_keys):
        _fail("extraBindings: a slot-pinned binding is already declared by its pin")

    # Minted bindings name no grant, so the grant table cannot validate them:
    # what is checkable is that the owner and holder are admitted, the kind and
    # rights are the builder's own vocabulary, and no two entries share a name.
    minted_names = [entry["name"] for entry in spec["mintedBindings"]]
    if len(set(minted_names)) != len(minted_names):
        _fail("mintedBindings: duplicate name")
    for entry in spec["mintedBindings"]:
        for role in ("owner", "holder"):
            if entry[role] not in live:
                _fail(f"mintedBindings: {entry['name']}: {role} is not admitted")
        if entry["capabilityKind"] not in _builder.CAPABILITY_KIND:
            _fail(
                f"mintedBindings: {entry['name']}: unknown capability kind "
                f"{entry['capabilityKind']!r}"
            )
        rights = 0
        for right in entry["rights"]:
            if right not in _builder.RIGHT:
                _fail(f"mintedBindings: {entry['name']}: unknown right {right!r}")
            rights |= _builder.RIGHT[right]
        if entry["transferable"]:
            rights |= _builder.RIGHT_TRANSFER
        try:
            _builder.validate_capability_rights(
                entry["name"], entry["capabilityKind"], rights
            )
        except SystemExit as error:
            _fail(f"mintedBindings: {entry['name']}: {error}")

    for entry in spec["commandBindings"]:
        if entry["component"] not in admitted:
            _fail(f"commandBindings: {entry['component']!r} is not an admitted component")
        if entry["commands"] != sorted(set(entry["commands"])):
            _fail(f"commandBindings: {entry['component']}: commands must be sorted and unique")
        # A command name is not an executable name, and assuming it was is what
        # this rule got wrong first: `dango`'s profile is `["echo", "sysinfo"]`,
        # but `echo` is served by the `echo-agent` executable, reached through
        # `spawn-service`'s exec grant rather than one `dango` holds. The
        # component that runs a command and the component that holds authority
        # over it are routinely different, which is the whole point of a spawn
        # service.
        #
        # What is checkable without inventing a naming convention: some admitted
        # component must hold an exec grant, or the profile advertises commands
        # no one in this system can launch. Binding each command name to its
        # executable is CP2's runtime resolution, not a host-side string rule.
        spawnable = {
            grant["target"]
            for grant in spec["grants"]
            if grant["capabilityKind"] == "executable"
        }
        if entry["commands"] and not spawnable:
            _fail(
                f"commandBindings: {entry['component']} declares commands, but this system "
                "grants no executable authority at all"
            )

    for entry in spec["imageSizes"]:
        if entry["component"] not in admitted:
            _fail(f"imageSizes: {entry['component']!r} is not an admitted component")
        if entry["bytes"] <= 0:
            _fail(f"imageSizes: {entry['component']}: must be positive")
    if spec["defaultImageBytes"] <= 0:
        _fail("defaultImageBytes: must be positive")

    for binding in spec["state"]:
        if binding["owner"] not in admitted:
            _fail(f"state: {binding['name']}: owner {binding['owner']!r} is not admitted")
        if binding["policy"] not in _builder.POLICY:
            _fail(f"state: {binding['name']}: unknown policy {binding['policy']!r}")
    # The builder refuses duplicate state names (`unique_sorted`), so a spec that
    # produced them could never encode; refusing here names the spec instead of
    # the manifest it would have written.
    state_names = [binding["name"] for binding in spec["state"]]
    if len(set(state_names)) != len(state_names):
        _fail("state: duplicate binding name")
    for binding in spec["state"]:
        if binding["schemaVersion"] <= 0:
            _fail(f"state: {binding['name']}: schemaVersion must be positive")
    command_components = [entry["component"] for entry in spec["commandBindings"]]
    if len(set(command_components)) != len(command_components):
        _fail("commandBindings: duplicate component")
    sized = [entry["component"] for entry in spec["imageSizes"]]
    if len(set(sized)) != len(sized):
        _fail("imageSizes: duplicate component")

    _validate_bounds(spec, contract)
    # These four name instances, not components.
    _validate_notifications(spec, live)
    _validate_interfaces(spec, components, admitted, live, contract)
    _validate_boot_profiles(spec, live)
    _validate_authority_sections(spec, live)


def _validate_bounds(spec: dict, contract: ModuleType) -> None:
    """Every ceiling `schema.zt` declares, enforced in one place.

    A bound that is declared and never checked is not a bound. These are
    enforced here rather than scattered through the rules above so the set is
    auditable against the contract: each entry names a list and its declared
    ceiling, and the text bounds cover every field that reaches a manifest
    string.
    """
    for field, ceiling in (
        ("grants", contract.MAX_GRANTS),
        ("slotPins", contract.MAX_SLOT_PINS),
        ("extraBindings", contract.MAX_EXTRA_BINDINGS),
        ("mintedBindings", contract.MAX_MINTED_BINDINGS),
        ("notifications", contract.MAX_NOTIFICATIONS),
        ("notificationBindings", contract.MAX_NOTIFICATION_BINDINGS),
        ("bootProfiles", contract.MAX_BOOT_PROFILES),
        ("state", contract.MAX_STATE_BINDINGS),
        ("commandBindings", contract.MAX_COMMAND_BINDINGS),
        ("imageSizes", contract.MAX_IMAGE_SIZES),
        ("clockAuthority", contract.MAX_CLOCK_AUTHORITY),
        ("ioResourceBudget", contract.MAX_IO_RESOURCE_BUDGET),
        ("networkDestinations", contract.MAX_NETWORK_DESTINATIONS),
        ("networkInterfaces", contract.MAX_NETWORK_INTERFACES),
        ("networkApplications", contract.MAX_NETWORK_APPLICATIONS),
        ("entropyAuthority", contract.MAX_ENTROPY_AUTHORITY),
        ("blockRingAuthority", contract.MAX_BLOCK_RING_AUTHORITY),
        ("waitSet", contract.MAX_WAIT_SET_SOURCES),
        ("recording", contract.MAX_RECORDING_ENTRIES),
    ):
        if len(spec[field]) > ceiling:
            _fail(f"{field}: {len(spec[field])} entries exceeds the declared bound of {ceiling}")

    graph = spec.get("fabricGraph")
    if graph is not None:
        if len(graph["routes"]) > contract.MAX_ROUTES:
            _fail(f"fabricGraph.routes: exceeds the declared bound of {contract.MAX_ROUTES}")
        if len(graph["profiles"]) > contract.MAX_PROFILES:
            _fail(f"fabricGraph.profiles: exceeds the declared bound of {contract.MAX_PROFILES}")
        for route in graph["routes"]:
            if len(route["participants"]) > contract.MAX_PARTICIPANTS_PER_ROUTE:
                _fail(
                    f"fabricGraph: route {route['name']} has more participants than the "
                    f"declared bound of {contract.MAX_PARTICIPANTS_PER_ROUTE}"
                )

    scheduling = spec.get("schedulingClass")
    if scheduling is not None:
        if len(scheduling["bands"]) > contract.MAX_SCHEDULING_CLASS_BANDS:
            _fail("schedulingClass.bands: exceeds the declared bound")
        if len(scheduling["instances"]) > contract.MAX_SCHEDULING_CLASS_ENTRIES:
            _fail("schedulingClass.instances: exceeds the declared bound")
        if len(scheduling["promotions"]) > contract.MAX_SCHEDULING_PROMOTIONS:
            _fail("schedulingClass.promotions: exceeds the declared bound")

    lifecycle = spec.get("lifecyclePolicy")
    if lifecycle is not None:
        if len(lifecycle["transitions"]) > contract.MAX_LIFECYCLE_TRANSITIONS:
            _fail("lifecyclePolicy.transitions: exceeds the declared bound")
        if len(lifecycle["restarts"]) > contract.MAX_LIFECYCLE_RESTARTS:
            _fail("lifecyclePolicy.restarts: exceeds the declared bound")
        if len(lifecycle["dependencies"]) > contract.MAX_LIFECYCLE_HEALTH_DEPENDENCIES:
            _fail("lifecyclePolicy.dependencies: exceeds the declared bound")
        if len(lifecycle["parameters"]) > contract.MAX_LIFECYCLE_PARAMETER_GRANTS:
            _fail("lifecyclePolicy.parameters: exceeds the declared bound")

    # A declared ceiling only raises a finite plane's default, stays finite, and
    # has nothing to bound in a product generation, whose root serves without one.
    ceiling = spec.get("graphArrivalCeiling")
    if ceiling is not None:
        if isinstance(ceiling, bool) or not isinstance(ceiling, int):
            _fail("graphArrivalCeiling: not an integer")
        if not GRAPH_ARRIVAL_CEILING_DEFAULT < ceiling <= GRAPH_ARRIVAL_CEILING_MAX:
            _fail(f"graphArrivalCeiling: {ceiling} is outside {GRAPH_ARRIVAL_CEILING_DEFAULT + 1}..{GRAPH_ARRIVAL_CEILING_MAX}")
        if spec["bootAction"] == "product":
            _fail("graphArrivalCeiling: a product generation has no arrival ceiling")

    # Identifier-shaped fields against `maxNameBytes`, free text against
    # `maxTextBytes`. Both end up in the manifest, which the generation encoder
    # bounds again — but a spec that cannot produce an admissible manifest should
    # be refused here, naming the field, rather than at encode time.
    def bounded(value: str, ceiling: int, label: str) -> None:
        if len(value.encode("utf-8")) > ceiling:
            _fail(f"{label}: exceeds {ceiling} bytes")

    names = contract.MAX_NAME_BYTES
    text = contract.MAX_TEXT_BYTES
    bounded(spec["name"], names, "name")
    bounded(spec["targetRequirement"], names, "targetRequirement")
    bounded(spec["bootAction"], names, "bootAction")
    bounded(spec["bootstrapInstance"], names, "bootstrapInstance")
    bounded(spec["deploymentConstraint"], text, "deploymentConstraint")
    bounded(spec["acceptanceCriteria"], text, "acceptanceCriteria")
    for component in spec["components"]:
        bounded(component, names, f"components[{component}]")
    for grant in spec["grants"]:
        bounded(grant["name"], names, f"grants[{grant['name']}].name")
    for entry in spec["interfaceSchemas"]:
        bounded(entry, text, "interfaceSchemas")
    for binding in spec["state"]:
        bounded(binding["name"], names, f"state[{binding['name']}].name")
    for notification in spec["notifications"]:
        bounded(notification["name"], names, f"notifications[{notification['name']}].name")


def _grouped(entries: list[dict], key: str) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for entry in entries:
        out.setdefault(entry[key], []).append(entry)
    return out


def _validate_notifications(spec: dict, admitted: set[str]) -> None:
    names: set[str] = set()
    for notification in spec["notifications"]:
        if notification["name"] in names:
            _fail(f"notifications: duplicate {notification['name']!r}")
        names.add(notification["name"])
        for role in ("source", "target"):
            if notification[role] not in admitted:
                _fail(f"notifications: {notification['name']}: {role} is not admitted")
        if notification["source"] == notification["target"]:
            _fail(f"notifications: {notification['name']}: source and target are the same")
    by_grant = _grouped(spec["notificationBindings"], "grant")
    notification_by_name = {n["name"]: n for n in spec["notifications"]}
    for name in sorted(names):
        holders = by_grant.get(name, [])
        waiters = [entry for entry in holders if entry["role"] == "wait"]
        signals = [entry for entry in holders if entry["role"] == "signal"]
        notification = notification_by_name[name]
        if len(waiters) != 1 or waiters[0]["holder"] != notification["target"]:
            _fail(f"notifications: {name}: needs exactly one wait binding, held by its target")
        if not signals or notification["source"] not in {entry["holder"] for entry in signals}:
            _fail(f"notifications: {name}: needs a signal binding held by its source")
    for binding in spec["notificationBindings"]:
        if binding["grant"] not in names:
            _fail(f"notificationBindings: {binding['grant']!r} names no declared notification")
        if binding["holder"] not in admitted:
            _fail(f"notificationBindings: {binding['grant']}: holder is not admitted")
        if binding["role"] not in ("signal", "wait"):
            _fail(f"notificationBindings: {binding['grant']}: unknown role {binding['role']!r}")
        # The wait holder is pinned to the notification's declared target — one
        # waiter, unambiguous. A signal holder is not pinned to the source: a
        # notification's whole point can be several signallers waking one
        # waiter (B83-style fan-in), so long as the declared source is one of
        # them, which the corpus-level check above already requires.
        if binding["role"] == "wait":
            notification = notification_by_name[binding["grant"]]
            if binding["holder"] != notification["target"]:
                _fail(
                    f"notificationBindings: {binding['grant']}: the wait holder must be "
                    f"{notification['target']!r}, not {binding['holder']!r}"
                )


def _validate_interfaces(
    spec: dict,
    components: dict[str, dict],
    admitted: set[str],
    live: set[str],
    contract: ModuleType,
) -> None:
    if len(spec["interfaceSchemas"]) > contract.MAX_INTERFACE_SCHEMAS:
        _fail("interfaceSchemas: exceeds bound")
    catalogue: dict[str, str] = {}
    for entry in spec["interfaceSchemas"]:
        path = (ROOT / entry).resolve()
        if not path.is_relative_to(INTERFACE_SCHEMA_ROOT) or not path.is_file():
            _fail(f"interfaceSchemas: {entry!r} is no declared interface schema")
        catalogue[path.stem] = entry

    # A fabric participant is an instance; the component spec whose declared
    # interfaces its role is checked against is the executable that instance
    # runs.
    component_by_executable = {
        entry.get("executableName", entry["component"]): entry["component"]
        for entry in spec["placements"]
    }
    executable_of = {
        entry["name"]: component_by_executable.get(entry["executable"], entry["executable"])
        for entry in resolved_instances(spec)
    }

    graph = spec.get("fabricGraph")
    if graph is None:
        # No graph means no component may hold a route role, or the spec would
        # claim an interface this system never establishes.
        for name in sorted(admitted):
            if components[name]["interfaces"]:
                _fail(
                    f"{name}: declares interface entries, but this system declares no fabric graph"
                )
        return

    if graph["fabricComponent"] not in live:
        _fail("fabricGraph: fabricComponent is not admitted")
    names = [route["name"] for route in graph["routes"]]
    if len(set(names)) != len(names):
        _fail("fabricGraph: duplicate route name")
    declared_interfaces = {
        _interface_name(entry) for entry in spec["interfaceSchemas"]
    }
    for route in graph["routes"]:
        if route["interface"] not in declared_interfaces:
            _fail(
                f"fabricGraph: route {route['name']} names interface {route['interface']!r}, "
                "which this system does not admit"
            )
        for participant in route["participants"]:
            if participant["component"] not in live:
                _fail(f"fabricGraph: {route['name']}: participant is not admitted")
            for hop in participant["interposition"]:
                if hop not in live:
                    _fail(f"fabricGraph: {route['name']}: interposition hop {hop!r} is not admitted")
            # The route role a system gives a component and the role its own
            # spec declares are the same fact; CP0's gate checks it against
            # `valid.zti`, and this checks it against the system that produces a
            # manifest at all.
            tag = _DIRECTION_TAGS[participant["direction"]]
            owner = executable_of[participant["component"]]
            entries = components[owner]["interfaces"]
            if not any(
                item["name"] == route["name"]
                and item["tag"] == tag
                and item["interface"] == route["interface"]
                for item in entries
            ):
                _fail(
                    f"{participant['component']}: this system gives it a {tag} role on route "
                    f"{route['name']}, which its component spec does not declare"
                )
    for profile in graph["profiles"]:
        for interposition in profile["interpositions"]:
            if interposition["route"] not in set(names):
                _fail(f"fabricGraph: profile {profile['name']} interposes an unknown route")
            if not interposition["chain"]:
                _fail(f"fabricGraph: profile {profile['name']} declares an empty chain")
            for hop in interposition["chain"]:
                if hop not in live:
                    _fail(f"fabricGraph: profile {profile['name']}: hop {hop!r} is not admitted")
        for control in profile["streamControls"]:
            if control not in {grant["name"] for grant in spec["grants"]}:
                _fail(
                    f"fabricGraph: profile {profile['name']} indexes control {control!r}, "
                    "which is no declared grant"
                )


def _interface_name(entry: str) -> str:
    """The `InterfaceSchema.name` a declared path resolves to."""
    import interface_schema

    return interface_schema.compile_interface((ROOT / entry).resolve()).name


_DIRECTION_TAGS = {
    "publish": "output",
    "subscribe": "input",
    "client": "command",
    "server": "event",
}


def _validate_boot_profiles(spec: dict, admitted: set[str]) -> None:
    profile_names = [profile["name"] for profile in spec["bootProfiles"]]
    if len(set(profile_names)) != len(profile_names):
        _fail("bootProfiles: duplicate name")
    graph = spec.get("fabricGraph")
    fabric_profiles = {profile["name"] for profile in graph["profiles"]} if graph else set()
    for profile in spec["bootProfiles"]:
        if graph is not None and profile["fabricProfile"] not in fabric_profiles:
            _fail(f"bootProfiles: {profile['name']} names unknown fabric profile")
        for name in profile["instances"] + profile["requiredInstances"]:
            if name not in admitted:
                _fail(f"bootProfiles: {profile['name']} names unadmitted component {name!r}")


def _validate_authority_sections(spec: dict, admitted: set[str]) -> None:
    """Reference-integrity for the eight declared authority/policy sections.

    Each is copied verbatim into the derived manifest, so the closed
    vocabularies (`class`, `role`, `kind`, `transport`, ...) and cross-field
    consistency rules are `build-generation.py`'s own to enforce when the
    derived manifest reaches the real builder. What is checked here is the one
    thing no later stage can recover from silently: every named holder,
    waiter, instance, or subject is an instance this system actually admits.
    """
    for entry in spec["clockAuthority"]:
        if entry["holder"] not in admitted:
            _fail(f"clockAuthority: holder {entry['holder']!r} is not admitted")
    for entry in spec["ioResourceBudget"]:
        if entry["holder"] not in admitted:
            _fail(f"ioResourceBudget: holder {entry['holder']!r} is not admitted")
    for entry in spec["networkDestinations"]:
        if entry["holder"] not in admitted:
            _fail(f"networkDestinations: holder {entry['holder']!r} is not admitted")
    for entry in spec["networkInterfaces"]:
        if entry["holder"] not in admitted:
            _fail(f"networkInterfaces: holder {entry['holder']!r} is not admitted")
    for entry in spec["networkApplications"]:
        if entry["holder"] not in admitted or (entry["admittedPeer"] and entry["admittedPeer"] not in admitted):
            _fail("networkApplications: holder or admitted peer is not admitted")
    for entry in spec["blockRingAuthority"]:
        if entry["holder"] not in admitted:
            _fail(f"blockRingAuthority: holder {entry['holder']!r} is not admitted")
    for entry in spec["entropyAuthority"]:
        if entry["holder"] not in admitted:
            _fail(f"entropyAuthority: holder {entry['holder']!r} is not admitted")
    for entry in spec["zenohGrants"]:
        if entry["holder"] not in admitted:
            _fail(f"zenohGrants: holder {entry['holder']!r} is not admitted")
    for entry in spec["waitSet"]:
        if entry["waiter"] not in admitted:
            _fail(f"waitSet: waiter {entry['waiter']!r} is not admitted")
    scheduling = spec.get("schedulingClass")
    if scheduling is not None:
        for entry in scheduling["instances"]:
            if entry["instance"] not in admitted:
                _fail(f"schedulingClass.instances: {entry['instance']!r} is not admitted")
        for entry in scheduling["promotions"]:
            if entry["holder"] not in admitted or entry["subject"] not in admitted:
                _fail(
                    f"schedulingClass.promotions: {entry['holder']!r}/{entry['subject']!r} "
                    "is not admitted"
                )
            if entry["holder"] == entry["subject"]:
                _fail("schedulingClass.promotions: holder and subject must differ")
    lifecycle = spec.get("lifecyclePolicy")
    if lifecycle is not None:
        for entry in lifecycle["restarts"]:
            if entry["instance"] not in admitted:
                _fail(f"lifecyclePolicy.restarts: {entry['instance']!r} is not admitted")
        for entry in lifecycle["dependencies"]:
            if entry["instance"] not in admitted or entry["dependency"] not in admitted:
                _fail(
                    f"lifecyclePolicy.dependencies: {entry['instance']!r}/"
                    f"{entry['dependency']!r} is not admitted"
                )
        for entry in lifecycle["parameters"]:
            if entry["holder"] not in admitted or entry["subject"] not in admitted:
                _fail(
                    f"lifecyclePolicy.parameters: {entry['holder']!r}/{entry['subject']!r} "
                    "is not admitted"
                )
    for entry in spec["recording"]:
        if entry["instance"] not in admitted:
            _fail(f"recording: instance {entry['instance']!r} is not admitted")


def _capability_sets(
    grants: list[dict], admitted: set[str]
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Which capability kinds each component provides and requires.

    The grant table's own semantics: for every kind but `executable`, `source`
    owns the object and `target` receives it. An `executable` grant's target is
    an executable name rather than an instance, and the `exec`/`spawn` authority
    is held by the spawner, so it is a requirement of the source and a provision
    of nobody. Identical to `check-component-spec.py`'s derivation, because it is
    the same fact read from the same table.
    """
    provided: dict[str, set[str]] = {name: set() for name in admitted}
    required: dict[str, set[str]] = {name: set() for name in admitted}
    for grant in grants:
        kind = grant["capabilityKind"]
        if kind == "executable":
            required[grant["source"]].add(kind)
            continue
        provided[grant["source"]].add(kind)
        required[grant["target"]].add(kind)
    return provided, required


def derive_bindings(
    grants: list[dict],
    admitted: set[str],
    pins: list[dict] | None = None,
    extras: list[dict] | None = None,
) -> dict[str, set[str]]:
    """Which grants each instance binds.

    A grant materializes in whichever instance holds it: an `executable` grant in
    its spawner, an `endpoint` in both ends, and every delegated authority in its
    target. This mirrors `build-generation.py`'s own holder resolution, which
    fails a build when an authority-bearing grant has no concrete binding.

    Two declared sources widen that structural set, and both are declared
    because the grant table genuinely cannot imply them. `slotPins` carries a
    holder whose slot number is frozen elsewhere — `init` retaining a
    `sharedBufferFactory`/`directory`/`device`-kind binding beside its target's,
    which every corpus occurrence pins. `extraBindings` carries the same kind
    of holder without a pinned number: a spawn broker holding the `executable`
    grants for the commands it launches, where neither source nor target names
    it at all.
    """
    bindings: dict[str, set[str]] = {name: set() for name in admitted}
    for grant in grants:
        kind = grant["capabilityKind"]
        if kind == "executable":
            bindings[grant["source"]].add(grant["name"])
            continue
        if kind == "endpoint":
            bindings[grant["source"]].add(grant["name"])
        bindings[grant["target"]].add(grant["name"])
    for declared in list(pins or ()) + list(extras or ()):
        if declared["holder"] in bindings:
            bindings[declared["holder"]].add(declared["grant"])
    return bindings


def resolved_instances(spec: dict) -> list[dict]:
    """Every concrete instance this system declares, in canonical order.

    A composition that declares no `instances` gets the default: one instance
    per admitted component, named for it, carrying that component's
    `Placement`. That is what 22 of the corpus's compositions mean and what CP1
    assumed universally. A composition that declares instances declares all of
    them, and may run one executable under several names.
    """
    declared = spec["instances"]
    if declared:
        return sorted(declared, key=lambda entry: entry["name"])
    placements = {entry["component"]: entry for entry in spec["placements"]}
    return [
        dict(
            placements.get(name, {}),
            name=placements.get(name, {}).get("executableName", name),
            executable=placements.get(name, {}).get("executableName", name),
        )
        for name in spec["components"]
    ]


def instance_names(spec: dict) -> set[str]:
    """The instance identities grants, notifications, and policy tables name."""
    return {entry["name"] for entry in resolved_instances(spec)}


def derive_manifest(system: CompiledSystem) -> dict:
    """The `contracts/generation-manifest/v1` manifest this system spec describes."""
    spec, components = system.spec, system.components
    placements = {entry["component"]: entry for entry in spec["placements"]}
    commands = {entry["component"]: entry["commands"] for entry in spec["commandBindings"]}
    sizes = {entry["component"]: entry["bytes"] for entry in spec["imageSizes"]}
    # Grants, pins, and extra bindings all name *instances*, which is not the
    # component set once one executable runs under several names.
    bindings = derive_bindings(
        spec["grants"], instance_names(spec), spec["slotPins"], spec["extraBindings"]
    )
    pins = {(pin["holder"], pin["grant"]): pin for pin in spec["slotPins"]}

    executables = []
    objects = []
    instances = []
    budget = []
    private_budget = []
    # `Executable` and `Object` are one record per distinct binary, however many
    # instances run it, so they are derived from `components` while the
    # instances below are derived from `resolved_instances`.
    # The emitted executable identity, which is the component's own name unless
    # this composition renames it. Instances reference the emitted name, so the
    # map is built before either loop.
    emitted = {
        name: placements.get(name, {}).get("executableName", name)
        for name in spec["components"]
    }
    component_of = {value: key for key, value in emitted.items()}
    for name in spec["components"]:
        component = components[name]
        resource = component["runtime"]["resource"]
        placement = placements.get(name, {})
        role = placement.get("role", component["componentType"])
        emitted_name = emitted[name]
        executable = {
            "commandProfile": commands.get(name, []),
            "name": emitted_name,
            "object": f"sha256:{emitted_name}",
            "role": role,
            # How many children this composition launches, which varies by
            # system: `init` is 1 under the channel plane and 18 under the
            # reference generation. The component spec's value is the reference
            # default.
            "spawnBudget": placement.get("spawnBudget", resource["spawnBudget"]),
        }
        # Only a non-default stack is carried, matching the manifest's optional
        # field: emitting the default everywhere would change the fixture bytes
        # without changing any admitted image. A placement may raise it for one
        # composition without changing the component's reference stack.
        stack_bytes = placement.get("stackBytes", resource["stackBytes"])
        if stack_bytes != _builder.COMPONENT_DEFAULT_STACK_BYTES:
            executable["stackBytes"] = stack_bytes
        executables.append(executable)
        objects.append(
            {
                "id": f"sha256:{emitted_name}",
                "kind": "bootstrap" if role == "init" else "component",
                "size": sizes.get(name, spec["defaultImageBytes"]),
            }
        )

    for declared in resolved_instances(spec):
        name = declared["name"]
        executable_name = declared["executable"]
        component = components[component_of.get(executable_name, executable_name)]
        resource = component["runtime"]["resource"]
        instance = {
            "autostart": declared.get("autostart", True),
            "bindings": [
                {
                    "grant": grant,
                    "slot": pins[(name, grant)]["slot"],
                    "slotReason": pins[(name, grant)]["reason"],
                }
                if (name, grant) in pins
                else {"grant": grant}
                for grant in sorted(bindings[name])
            ],
            "dependencies": declared.get("dependencies", component["dependencies"]),
            "executable": executable_name,
            "health": declared.get("health", component["health"]),
            "lifetime": declared.get("lifetime", component["lifetime"]),
            "name": name,
            "owner": declared.get("owner", component["owner"]),
        }
        for field in ("priority", "extraThreads", "workerPriority"):
            if field in declared:
                instance[field] = declared[field]
        instances.append(instance)
        # Each ceiling is the component spec's unless this composition declares
        # its own: a quota is how much of *this* generation's budget the
        # instance may hold, and the corpus disagrees per plane. Keyed by
        # instance, because that is what the authenticated budget authenticates.
        quota = {
            field: declared.get(field, resource[field])
            for field in (
                "bufferBytePages",
                "bufferCount",
                "mappingCount",
                "loanCount",
                "privatePageQuota",
            )
        }
        if any(
            (
                quota["bufferBytePages"],
                quota["bufferCount"],
                quota["mappingCount"],
                quota["loanCount"],
            )
        ):
            budget.append(
                {
                    "bufferCount": quota["bufferCount"],
                    "bytePages": quota["bufferBytePages"],
                    "holder": name,
                    "loanCount": quota["loanCount"],
                    "mappingCount": quota["mappingCount"],
                }
            )
        # C10.4: the same derivation, from the same record, for the other memory
        # plane. A separate list rather than a column of the shared-buffer one
        # because the two are separately accounted — a component may hold either,
        # both, or neither — and because a holder with no quota must be *absent*
        # rather than present with a zero, which is what deny-by-default means
        # here.
        if quota["privatePageQuota"]:
            private_budget.append(
                {
                    "holder": name,
                    "pageQuota": quota["privatePageQuota"],
                }
            )
    region_pages, total_pages = PRIVATE_MEMORY_CAPACITY_PROFILES.get(
        spec["targetRequirement"],
        (PRIVATE_MEMORY_DEFAULT_REGION_PAGES, PRIVATE_MEMORY_DEFAULT_TOTAL_PAGES),
    )
    oversized = [entry["holder"] for entry in private_budget if entry["pageQuota"] > region_pages]
    if oversized:
        _fail(
            f"private memory: target {spec['targetRequirement']!r} cannot admit holders {oversized}"
        )
    if sum(entry["pageQuota"] for entry in private_budget) > total_pages:
        _fail(
            f"private memory: target {spec['targetRequirement']!r} aggregate exceeds capacity"
        )
    policy = spec.get("privateMemoryPolicy")
    if policy is not None:
        if private_budget:
            _fail("private memory policy conflicts with effective fixed privatePageQuota")
        try:
            policy = private_memory_policy.validate(policy, instances)
        except ValueError as error:
            _fail(str(error))

    # `fabric-graph`'s presence is strictly derived: the builder refuses a graph
    # without the object and an object without the graph, so there is nothing to
    # choose. `shared-buffer-budget` is declared, because its presence is what
    # makes the builder encode a budget payload independently of whether any
    # component has a quota, and the existing fixtures disagree about the
    # correlation. `boot-layout` is carried by every generation.
    if spec["sharedBufferBudgetObject"]:
        objects.append({"id": "shared-buffer-budget", "kind": "resource", "size": 4096})
    if spec.get("fabricGraph") is not None:
        objects.append({"id": "fabric-graph", "kind": "resource", "size": 4096})
    if spec["bootLayoutObject"]:
        objects.append({"id": "boot-layout", "kind": "resource", "size": 4096})
    # C10.4: strictly derived, unlike `shared-buffer-budget` above. The builder
    # refuses a `privateMemoryBudget` without this object and encodes nothing
    # from an object with no holders, so there is nothing for a spec to choose:
    # the object is present exactly when some component declared a quota.
    if private_budget:
        objects.append({"id": "private-memory-budget", "kind": "resource", "size": 4096})
    if policy is not None:
        objects.append({"id": "private-memory-policy", "kind": "resource", "size": 4096})
    # Strictly derived like `private-memory-budget`: the builder encodes the
    # resident instances and nothing else, so the object is present exactly when
    # one is declared.
    if any(entry["lifetime"] == "resident" for entry in instances):
        objects.append({"id": "instance-lifetime", "kind": "resource", "size": 4096})
    # The remaining eight sections follow `sharedBufferBudgetObject`'s pattern
    # exactly: object presence is a declared fact, independent of whether the
    # accompanying list happens to be empty.
    for field, object_id in (
        ("clockAuthorityObject", "clock-authority"),
        ("ioResourceBudgetObject", "io-resource-budget"),
        ("networkDestinationsObject", "network-destinations"),
        ("networkInterfacesObject", "network-interface"),
        ("networkApplicationsObject", "network-application"),
        ("entropyAuthorityObject", "entropy-authority"),
        ("zenohGrantsObject", "zenoh-grants"),
        ("blockRingAuthorityObject", "block-ring-authority"),
        ("waitSetObject", "wait-set"),
        ("recordingObject", "recording-policy"),
    ):
        if spec[field]:
            objects.append({"id": object_id, "kind": "resource", "size": 4096})
    # `schedulingClass`/`lifecyclePolicy` are optional records rather than
    # declared/derived pairs: presence of the record is presence of the object,
    # on the same terms `fabricGraph` already uses.
    if spec.get("schedulingClass") is not None:
        objects.append({"id": "scheduling-class", "kind": "resource", "size": 4096})
    if spec.get("lifecyclePolicy") is not None:
        objects.append({"id": "lifecycle-policy", "kind": "resource", "size": 4096})
    if spec.get("graphArrivalCeiling") is not None:
        objects.append({"id": "graph-arrival-ceiling", "kind": "resource", "size": 4096})

    # Canonical order throughout. `build-generation.py` sorts `objects`,
    # `executables`, `instances`, `grants`, and `state` before encoding
    # (`unique_sorted`, and grants by name/source/target), so emitting sorted
    # output changes no admitted byte while removing the hand-authored ordering
    # that made two fixtures differing only in list order look like different
    # generations. `just generation_check` compares the built bytes and is the
    # evidence for that claim.
    objects.sort(key=lambda entry: entry["id"])
    executables.sort(key=lambda entry: entry["name"])
    instances.sort(key=lambda entry: entry["name"])
    budget.sort(key=lambda entry: entry["holder"])
    private_budget.sort(key=lambda entry: entry["holder"])

    manifest = {
        "bootAction": spec["bootAction"],
        "bootstrapInstance": spec["bootstrapInstance"],
        "executables": executables,
        "formatVersion": _GENERATION_SOURCE_FORMAT,
        "generation": spec["generation"],
        "grants": [
            {
                "name": grant["name"],
                "capabilityKind": grant["capabilityKind"],
                "rights": grant["rights"],
                "source": grant["source"],
                "target": grant["target"],
                "transferable": grant["transferable"],
            }
            for grant in sorted(
                spec["grants"],
                key=lambda entry: (entry["name"], entry["source"], entry["target"]),
            )
        ],
        "health": {
            "bootAttempts": spec["bootAttempts"],
            # Instance identities, not component names: the health policy names
            # the instances that must be live.
            "requiredInstances": sorted(
                entry["name"] for entry in instances if entry["health"] == "required"
            ),
        },
        "instances": instances,
        # Sorted by name, matching `build-generation.py`, which sorts this
        # section before encoding so the output is canonical.
        "mintedBindings": sorted(spec["mintedBindings"], key=lambda entry: entry["name"]),
        "interfaceSchemas": spec["interfaceSchemas"],
        "objects": objects,
        "privateMemoryBudget": private_budget,
        "sharedBufferBudget": budget,
        "state": sorted(spec["state"], key=lambda entry: entry["name"]),
        "target": spec["targetRequirement"],
    }
    if policy is not None:
        del manifest["privateMemoryBudget"]
        manifest["privateMemoryPolicy"] = policy
    if spec["bootProfiles"]:
        manifest["bootProfiles"] = spec["bootProfiles"]
    if spec["notifications"]:
        manifest["notificationGrants"] = spec["notifications"]
        manifest["notificationBindings"] = spec["notificationBindings"]
    graph = spec.get("fabricGraph")
    if graph is not None:
        manifest["fabricGraph"] = graph
    if spec["clockAuthorityObject"]:
        manifest["clockAuthority"] = spec["clockAuthority"]
    if spec["ioResourceBudgetObject"]:
        manifest["ioResourceBudget"] = spec["ioResourceBudget"]
    if spec["networkDestinationsObject"]:
        manifest["networkDestinations"] = spec["networkDestinations"]
    if spec["networkInterfacesObject"]:
        manifest["networkInterfaces"] = spec["networkInterfaces"]
    if spec["networkApplicationsObject"]:
        manifest["networkApplications"] = spec["networkApplications"]
    elif spec["networkApplications"]:
        _fail("networkApplications: populated authority requires its resource object")
    if spec["entropyAuthorityObject"]:
        manifest["entropyAuthority"] = spec["entropyAuthority"]
        # The encoder judges the rows together with the grants they draw
        # through; running it here refuses a bad table at spec admission rather
        # than only when an image is built.
        try:
            _builder.build_entropy_authority(manifest)
        except SystemExit as error:
            _fail(f"entropyAuthority: {error}")
    elif spec["entropyAuthority"]:
        _fail("entropyAuthority: populated authority requires its resource object")
    if spec["zenohGrantsObject"]:
        manifest["zenohGrants"] = spec["zenohGrants"]
        # The encoder judges the rows together with the instances; running it here refuses a bad table at spec
        # admission rather than only when an image is built.
        try:
            _builder.build_zenoh_grants_table(manifest)
        except SystemExit as error:
            _fail(f"zenohGrants: {error}")
    elif spec["zenohGrants"]:
        _fail("zenohGrants: populated grants require their resource object")
    if spec["blockRingAuthorityObject"]:
        manifest["blockRingAuthority"] = spec["blockRingAuthority"]
    if spec["waitSetObject"]:
        manifest["waitSet"] = spec["waitSet"]
    scheduling = spec.get("schedulingClass")
    if scheduling is not None:
        manifest["schedulingClass"] = scheduling
    lifecycle = spec.get("lifecyclePolicy")
    if lifecycle is not None:
        manifest["lifecyclePolicy"] = lifecycle
    if spec.get("graphArrivalCeiling") is not None:
        manifest["graphArrivalCeiling"] = spec["graphArrivalCeiling"]
    if spec["recordingObject"]:
        manifest["recording"] = spec["recording"]
    return manifest


@lru_cache(maxsize=1)
def source_tool() -> Path:
    """Build the pinned semantic/evaluator adapter outside identity-bearing trees."""
    # Building the pinned compiler also obtains the registry dependencies shared
    # by this adapter's lockfile, so a clean checkout needs no second resolution.
    zutai_binary()
    process = subprocess.run(
        ["cargo", "build", "--locked", "--offline", "--release", "--manifest-path",
         str(_SOURCE_TOOL), "--target-dir", str(_SOURCE_TARGET)],
        cwd=ROOT, text=True, capture_output=True,
    )
    if process.returncode:
        _fail(f"computed system-spec adapter build failed: {process.stderr.strip()}")
    return _SOURCE_TARGET / "release" / "system-spec-source"


def validate_source_mapping(root: Path = CONTRACT_ROOT) -> None:
    """Refuse orphan, competing or missing authoring sources before derivation."""
    sources = root / "sources"
    declared = {root / path for path in COMPUTED_SYSTEM_SOURCES.values()}
    for name, relative in COMPUTED_SYSTEM_SOURCES.items():
        source = root / relative
        if (root / "systems" / f"{name}.zti").is_symlink():
            _fail(f"{name}: derived system output must not be a symlink")
        if not source.is_file():
            _fail(f"{name}: computed source missing: {source}")
    for path in sorted(sources.glob("*")):
        if path.suffix in {".zt", ".zti"} and path not in declared:
            _fail(f"{path.stem}: ambiguous or undeclared system authoring source: {path}")
    for path in sorted((root / "systems").glob("*.zt")):
        _fail(f"{path.stem}: ambiguous system source; computed sources belong in sources/")


def render_computed_system(name: str, root: Path = CONTRACT_ROOT) -> str:
    """Evaluate a confined, pure source; callers admit the rendered inert record."""
    if name not in COMPUTED_SYSTEM_SOURCES:
        _fail(f"{name}: no computed source declared")
    source = root / COMPUTED_SYSTEM_SOURCES[name]
    if not source.is_file():
        _fail(f"{name}: computed source missing: {source}")
    environment = dict(os.environ, ZUTAI_STDLIB_ROOT=str(STDLIB))
    try:
        process = subprocess.run(
            [str(source_tool()), str(root.parents[1]), str(source),
             *(str(root / "systems" / f"{entry}.zti") for entry in COMPUTED_SYSTEM_SOURCES)],
            cwd=ROOT, env=environment, text=True, capture_output=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        _fail(f"{name}: computed source evaluation exceeded 120 seconds")
    except OSError as error:
        _fail(f"{name}: cannot execute computed source adapter: {error}")
    if process.returncode:
        _fail(f"{name}: computed source refused: {process.stderr.strip()}")
    rendered = process.stdout
    if len(rendered.encode("utf-8")) > default_contract.MAX_SOURCE_BYTES:
        _fail(f"{name}: computed output exceeds source bound")
    return rendered


def computed_system_outputs(root: Path = CONTRACT_ROOT) -> dict[Path, str]:
    validate_source_mapping(root)
    return {root / "systems" / f"{name}.zti": render_computed_system(name, root)
            for name in COMPUTED_SYSTEM_SOURCES}


def compile_rendered_system(
    name: str, contents: str, *, components: dict[str, dict],
) -> CompiledSystem:
    with tempfile.TemporaryDirectory(prefix="slime-computed-system-") as scope:
        path = Path(scope) / f"{name}.zti"
        path.write_text(contents, encoding="utf-8")
        try:
            return compile_system(path, components=components)
        except SystemSpecError as error:
            _fail(f"{name}: computed result refused: {error}")


def check_computed_systems(
    *, components: dict[str, dict], root: Path = CONTRACT_ROOT,
) -> dict[Path, str]:
    outputs = computed_system_outputs(root)
    for path, contents in outputs.items():
        compile_rendered_system(path.stem, contents, components=components)
        if not path.is_file() or path.read_bytes() != contents.encode("utf-8"):
            _fail(f"{path.stem}: derived system spec drift; run "
                  "python3 scripts/generate/generate-generation-from-spec.py")
    return outputs


def compile_system(
    path: Path,
    *,
    components: dict[str, dict] | None = None,
    contract: ModuleType = default_contract,
) -> CompiledSystem:
    table = components
    if table is None:
        catalogue = interface_catalogue()
        table = {entry.name: entry.spec for entry in admit_specs(catalogue=catalogue)}
    if path.parent.resolve() == SYSTEM_ROOT.resolve() and path.stem in COMPUTED_SYSTEM_SOURCES:
        validate_source_mapping()
        contents = render_computed_system(path.stem)
        if not path.is_file() or path.read_bytes() != contents.encode("utf-8"):
            _fail(f"{path.stem}: derived system spec drift; run "
                  "python3 scripts/generate/generate-generation-from-spec.py")
    spec = _load(path.resolve(), contract)
    if spec["name"] != path.stem:
        _fail(f"{path}: declares system {spec['name']!r}, so its file name must match")
    _validate(spec, table, contract)
    normalized = (
        json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    identity = hashlib.sha256(contract.IDENTITY_DOMAIN + normalized).digest()
    return CompiledSystem(
        name=spec["name"],
        spec=spec,
        components={name: table[name] for name in spec["components"]},
        normalized=normalized,
        identity=identity,
    )


def system_paths(root: Path = SYSTEM_ROOT) -> list[Path]:
    if root.resolve() == SYSTEM_ROOT.resolve():
        validate_source_mapping()
        return sorted(set(root.glob("*.zti")) | {
            root / f"{name}.zti" for name in COMPUTED_SYSTEM_SOURCES
        })
    return sorted(root.glob("*.zti"))


def prefetch_systems(paths: list[Path], *, contract: ModuleType = default_contract) -> None:
    """Warm the evaluation cache for `paths` in parallel; `compile_system` then hits it."""
    prefetch(
        ("run", CHECKER, path.resolve(), "SLIME_SYSTEM_SPEC_PATH")
        for path in paths
        if path.is_file() and path.stat().st_size <= contract.MAX_SOURCE_BYTES
    )


def compiled_specs() -> dict[str, CompiledSpec]:
    return {entry.name: entry for entry in admit_specs(catalogue=interface_catalogue())}

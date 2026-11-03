#!/usr/bin/env python3

"""CP1 system-specification and generation-derivation gate.

Validates every `contracts/system-spec/v1/systems/*.zti` against the component
specs it references, derives a `contracts/generation-manifest/v1` manifest from each, and
requires the derived manifest to be semantically identical to the committed
fixture it replaces — same components, same authority, same graph, same resolved
slots, same admitted bytes.

"Semantically identical" rather than "byte-identical" is deliberate and is
checked rather than asserted: the derived manifest is emitted in canonical
order, while the hand-authored fixtures carry the order they were typed in. Every
one of those sections is sorted by `build-generation.py` before it is encoded, so
the comparison below normalizes exactly what the builder normalizes and nothing
else. Any other divergence is a real one and fails.
"""

from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import copy
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import system_spec_contract as CONTRACT
import private_memory_policy
from component_spec import admit_specs, interface_catalogue
from harness import ROOT, load_script
import zenoh_grants_builder_exam
from system_spec import (
    DERIVED_GENERATION_FIXTURES,
    COMPUTED_SYSTEM_SOURCES,
    check_computed_systems,
    computed_system_outputs,
    render_computed_system,
    validate_source_mapping,
    _validate_authority_sections as validate_authority_sections,
    SystemSpecError,
    compile_system,
    derive_manifest,
    derived_manifest_path,
    instance_names,
    prefetch_systems,
    resolved_instances,
    system_paths,
)
from zutai_cli import STDLIB, binary


# The pre-CP1 hand-authored fixtures, frozen. They are the derivation's
# reference: once a fixture became this generator's output, comparing the
# derivation against it would only assert the generator agrees with itself.
# These files are never regenerated and never edited.
BASELINE_FIXTURES = ROOT / "contracts" / "system-spec" / "v1" / "baselines"
BUILDER = load_script("system_spec_check_builder", "build/build-generation.py")

# Which committed generation fixture each system spec derives. Declared in
# `scripts/lib/system_spec.py` so the gate and
# `scripts/generate/generate-generation-from-spec.py` cannot disagree about what
# is converted, and so importing one does not run the other.
DERIVED_FIXTURES = DERIVED_GENERATION_FIXTURES

# Sections `build-generation.py` sorts before encoding, and the key it sorts by.
# Normalizing exactly these is what makes the comparison below a real equality
# test rather than a lenient one: anything outside this set must match as-is.
SORTED_SECTIONS = {
    "objects": lambda entry: entry["id"],
    "executables": lambda entry: entry["name"],
    "instances": lambda entry: entry["name"],
    "state": lambda entry: entry["name"],
    "grants": lambda entry: (entry["name"], entry["source"], entry["target"]),
    "sharedBufferBudget": lambda entry: entry["holder"],
    "privateMemoryBudget": lambda entry: entry["holder"],
    "mintedBindings": lambda entry: entry["name"],
}

# Sections no system's frozen baseline could ever have, because the baseline is
# the pre-CP1 hand-authored `valid.zti` and the feature postdates every system
# it covers. Excused globally is safe here specifically because there is no
# pre-existing populated content in any baseline for it to hide: C10.4's
# `privateMemoryBudget`, and the `private-memory-budget` resource object that
# carries it, are the first section of this shape.
#
# Excused for the baseline comparison, never unchecked. `check_post_baseline`
# below asserts the derived content equals what the component specs declare,
# independently of the baseline, so the excusal is "the baseline cannot speak to
# this" rather than "this is unverified". A blanket ignore here would let any
# future divergence hide inside these names, which is exactly the failure
# `KNOWN_DEAD_BINDINGS` is written to avoid on its own axis.
POST_BASELINE_SECTIONS = ("privateMemoryBudget",)
POST_BASELINE_OBJECTS = ("private-memory-budget", "instance-lifetime")
# Every baseline predates declared instance lifetime; `check_post_baseline`
# asserts each instance's resolved value and the object's presence instead.
POST_BASELINE_EVERY_INSTANCE_FIELDS = ("lifetime",)

# Sections one *specific* system's frozen baseline predates, unlike the ones
# above. Keyed per system, on the same terms as
# `POST_BASELINE_INSTANCE_FIELDS`/`POST_BASELINE_GRANTS` below: an equivalent
# fact in another system stays baseline-visible, because other systems carry
# real `notificationGrants`/`notificationBindings` content their baselines can
# still compare. `check_post_baseline` independently checks the live notification
# declarations and exact application authority behind these exceptions.
POST_BASELINE_SYSTEM_SECTIONS: dict[str, frozenset[str]] = {
    "sel4-private-memory": frozenset({"notificationGrants", "notificationBindings"}),
    "sel4-io-tcp": frozenset({"networkApplications", "lifecyclePolicy"}),
}
POST_BASELINE_SYSTEM_OBJECTS = {
    "sel4-io-tcp": frozenset({"network-application", "lifecycle-policy"}),
}

# Instance fields and capability edges added after a system's frozen pre-CP1
# baseline. Keep these system-scoped: equivalent facts in another system remain
# baseline-visible. They are lifted only from the frozen comparison; the live
# system contract and builder validation still own their contents.
POST_BASELINE_INSTANCE_FIELDS = {
    "sel4-private-memory": frozenset({"priority", "extraThreads", "workerPriority"}),
}
POST_BASELINE_GRANTS = {
    "sel4-private-memory": frozenset({"private-memory-worker-rpc"}),
    "sel4-io-tcp": frozenset({"network-tcp-probe-provision"}),
}

# Executable-level exceptions are scoped by both system and executable name.
POST_BASELINE_EXECUTABLE_FIELDS = {
    name: {"network-service": frozenset({"stackBytes"})}
    for name in ("sel4-io-network", "sel4-io-tcp")
}
# This holder had no budget row in the baseline. Every field is checked below.
POST_BASELINE_SHARED_BUFFER_HOLDERS = {"sel4-io-tcp": frozenset({"io-tcp-probe"})}

# Lift only these ceilings; every other budget field and holder stays visible
# to the frozen comparison. Each lifted ceiling must match its live declaration.
POST_BASELINE_SHARED_BUFFER_FIELDS = {
    "sel4-io-tcp": {
        "network-service": frozenset({"bytePages", "bufferCount", "loanCount"}),
    },
    "sel4-private-memory-isolation": {
        "private-memory-1g-holder-c": frozenset({"loanCount"}),
    },
}

# `InstanceBinding.slotReason` postdates the frozen baseline too, on the same
# terms (B91): the baseline's pinned bindings carry a number and no reason, so it
# has nothing to compare a label against. Lifted out of the comparison and
# asserted separately below against the generation builder's own re-derivation,
# which is stricter than a frozen copy would have been — a wrong label fails even
# though the baseline could not have caught it.
POST_BASELINE_BINDING_FIELDS = ("slotReason",)

# Bindings the committed `valid.zti` declares that name no grant at all. They are
# dead text: `resolve_boot_profile` drops any binding whose grant is absent, so
# every profile — `default`, `test`, `visibility`, `unified` — already boots
# without them, and no generation byte carries them. The derivation cannot
# reproduce them because it builds bindings from the grant table, which is the
# point; listing them here records that the divergence is a removal of dead text
# rather than a lost fact.
KNOWN_DEAD_BINDINGS = {
    ("filesystem-service", "filesystem-store"),
    ("generation-manager", "generation-boot-update"),
    ("generation-manager", "health-confirmation"),
    ("storage-store-probe", "store-access"),
}

# Grants the frozen baseline declares in a capability kind the contract has
# since retired, and the slots they pinned. They are not dead text the way
# `KNOWN_DEAD_BINDINGS` is — they named real grants when the baseline froze —
# but the vocabulary that made them expressible is gone, so the derivation
# cannot reproduce them and re-blessing the baseline is not an option: it is
# evidence precisely because it is never regenerated.
#
# B90 retired `block`. Its three grants were the only holders. The removal is
# not an unexamined skip: `RETIRED_KINDS_COVERED` below refuses an entry that
# covers no real grant, `check_retired_kinds` refuses a kind that has become
# spellable again, and the per-system `unexplained`/`live` sets refuse a
# stripped binding that names a live grant. A future retirement adds its kind
# here and inherits all three rather than widening a blanket ignore.
RETIRED_CAPABILITY_KINDS = {"block"}


def fail(message: str) -> None:
    raise SystemExit(f"system spec check: {message}")


def zti(value: object, indent: int = 0) -> str:
    padding = " " * indent
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, list):
        if not value:
            return "[]"
        rows = "".join(f"{padding}  {zti(item, indent + 2)};\n" for item in value)
        return "[\n" + rows + padding + "]"
    if isinstance(value, dict):
        rows = "".join(
            f"{padding}  {key} = {zti(item, indent + 2)};\n" for key, item in value.items()
        )
        return "{\n" + rows + padding + "}"
    raise TypeError(type(value))


def _decode(path: Path, label: str) -> dict:
    environment = os.environ.copy()
    environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
    process = subprocess.run(
        [str(binary()), "json", str(path)],
        cwd=ROOT,
        check=False,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        fail(f"cannot read {label}: {process.stderr.strip()}")
    return json.loads(process.stdout)


# These compositions were authored as system specs, not migrated from a
# hand-authored manifest. Their contracts and derived-byte drift remain checked.
SPEC_NATIVE_SYSTEMS = frozenset({
    "sel4-data-volume",
    "sel4-lidar-external",
    "sel4-entropy",
    "sel4-http",
    "sel4-http-public",
    "sel4-io-local",
    "sel4-io-lifetime",
    "sel4-io-service-fault",
    "sel4-io-driver-reset",
    "sel4-io-tcp-impairment",
    "sel4-io-tcp-buffers",
    "sel4-io-tcp-listener",
    "sel4-io-tcp-options",
    "sel4-large-image",
    "sel4-lifetime",
    "sel4-lifetime-exit",
    "sel4-net",
    "sel4-zenoh",
    "sel4-zenoh-external",
    "sel4-private-memory-stress",
    "sel4-private-memory-stress-rv64",
    "sel4-private-memory-heap-stress",
    "sel4-private-memory-heap-stress-rv64",
    # MEM-ADAPTIVE's three compositions. They declare `privateMemoryPolicy`,
    # which no pre-CP1 hand-authored manifest could express at all, so there is
    # nothing for a frozen baseline to have been migrated from.
    "sel4-private-memory-adaptive",
    "sel4-private-memory-adaptive-rv64",
    "sel4-private-memory-adaptive-overcommit",
    "sel4-private-memory-matrix",
    "sel4-private-memory-matrix-rv64",
})


def load_baseline(name: str) -> dict:
    """The frozen pre-CP1 hand-authored fixture this derivation must reproduce."""
    path = BASELINE_FIXTURES / name
    if not path.is_file():
        fail(f"no frozen baseline for {name}; it is what the derivation is checked against")
    return _decode(path, f"baseline {name}")


def normalized(manifest: dict) -> dict:
    """The manifest as the builder will see it: sorted sections, resolved slots."""
    value = copy.deepcopy(manifest)
    for section, key in SORTED_SECTIONS.items():
        if section in value:
            value[section] = sorted(value[section], key=key)
    if "health" in value:
        value["health"] = dict(
            value["health"], requiredInstances=sorted(value["health"]["requiredInstances"])
        )
    # One instance's binding list is order-independent to the builder, so it is
    # normalized on the same terms as the sections above rather than compared
    # in the order a fixture was typed in. `assign_declared_slots` reserves
    # explicit slots first and then takes omitted ones in grant-name order;
    # `build_sel4_plan` emits capability records by grant index and looks each
    # holder's binding up by name; `declared_services` accumulates a set. No
    # encoded byte is a function of the position of a binding within its list,
    # and `just generation_check` compares the built bytes.
    resolved = BUILDER.assign_declared_slots(value)
    for instance in resolved.get("instances", []):
        instance["bindings"] = sorted(
            instance.get("bindings", []), key=lambda entry: entry["grant"]
        )
    # An absent `streamControls` and an empty one are the same build:
    # `generation_fabric.py`'s `declared_stream_controls or
    # FABRIC_STREAM_CONTROL_GRANTS` falls back to the single-broker default for
    # both. The derivation emits the field the contract declares, so the
    # baseline's omission is normalized rather than treated as a divergence.
    graph = resolved.get("fabricGraph")
    if graph is not None:
        for profile in graph.get("profiles", []):
            profile.setdefault("streamControls", [])
    # `bootProfiles` is likewise absent in some baselines and an empty list in
    # others; `resolve_boot_profile` falls back to `health.requiredInstances`
    # for both, so the two are one build and the derivation emits the field the
    # manifest contract declares. The optional authority/policy tables below
    # read the same way: `build-generation.py` reaches each through
    # `manifest.get(field) or []`, so absence and emptiness are one deny-by-
    # default answer. `sel4-io-network` is the case that requires it — it
    # carries a `wait-set` resource object with no declared source at all.
    resolved.setdefault("bootProfiles", [])
    for field in (
        "clockAuthority",
        "ioResourceBudget",
        "networkDestinations",
        "networkInterfaces",
        "entropyAuthority",
        "blockRingAuthority",
        "waitSet",
        "recording",
        "privateMemoryBudget",
        "notificationGrants",
        "notificationBindings",
        "mintedBindings",
        "interfaceSchemas",
        "sharedBufferBudget",
        "state",
    ):
        resolved.setdefault(field, [])
    return resolved


def strip_dead_bindings(manifest: dict) -> dict:
    value = copy.deepcopy(manifest)
    for instance in value["instances"]:
        instance["bindings"] = [
            binding
            for binding in instance["bindings"]
            if (instance["name"], binding["grant"]) not in KNOWN_DEAD_BINDINGS
        ]
    return value


def strip_retired_kinds(manifest: dict) -> tuple[dict, list[dict]]:
    """Drop grants in a retired capability kind, and the bindings naming them.

    Returns `(comparable, removed)`. `removed` is not discarded: the caller
    compares it against the unmodified fixture, and the module-level
    `RETIRED_KINDS_COVERED` guard proves each listed kind covers a real grant, so
    the removal is evidence rather than an unexamined skip.
    """
    value = copy.deepcopy(manifest)
    removed = [
        grant for grant in value["grants"] if grant["capabilityKind"] in RETIRED_CAPABILITY_KINDS
    ]
    retired_names = {grant["name"] for grant in removed}
    value["grants"] = [grant for grant in value["grants"] if grant["name"] not in retired_names]
    for instance in value["instances"]:
        instance["bindings"] = [
            binding for binding in instance["bindings"] if binding["grant"] not in retired_names
        ]
    return value, removed


def check_retired_kinds() -> None:
    """A kind listed as retired must really be unspellable.

    One assertion, deliberately. An earlier version of this helper also re-read
    each stripped grant's `capabilityKind` and refused a "live" one, but that
    could not fire: `strip_retired_kinds` selects on exactly that field, so the
    check was its own filter's complement. Rewriting it to read the untouched
    fixture did not help either — `declared` is built from the same grant list
    the stripped entries were selected out of, so it only fires on a duplicated
    grant name, which `scripts/lib/system_spec.py` refuses independently.

    The two properties that assertion was reaching for are checked where they
    can actually fail: the caller's `unexplained`/`live` sets compare the
    stripped bindings against the *unmodified* fixture, and the module-level
    `RETIRED_KINDS_COVERED` guard refuses an entry that covers nothing. What is
    left here is the one thing neither of those sees — a retired kind quietly
    becoming spellable again while this comparison still skips its grants.
    """
    for kind in sorted(RETIRED_CAPABILITY_KINDS):
        if kind in BUILDER.CAPABILITY_KIND:
            fail(
                f"{kind!r} is listed as a retired capability kind but the builder "
                "still admits it; either the retirement was reverted or the "
                "exemption is stale"
            )


def split_post_baseline(manifest: dict, name: str) -> tuple[dict, dict]:
    """Separate facts the frozen baseline predates from the comparison.

    Returns `(comparable, added)`. `comparable` is what the baseline can be
    compared against; `added` is what `check_post_baseline` asserts on its own
    terms.
    """
    value = copy.deepcopy(manifest)
    added = {section: value.pop(section) for section in POST_BASELINE_SECTIONS if section in value}
    for section in POST_BASELINE_SYSTEM_SECTIONS.get(name, frozenset()):
        if section in value:
            added[section] = value.pop(section)
    if "objects" in value:
        kept, removed = [], []
        for entry in value["objects"]:
            post_objects = (*POST_BASELINE_OBJECTS, *POST_BASELINE_SYSTEM_OBJECTS.get(name, ()))
            (removed if entry["id"] in post_objects else kept).append(entry)
        value["objects"] = kept
        added["objects"] = removed
    post_grants = POST_BASELINE_GRANTS.get(name, frozenset())
    if post_grants:
        added["grants"] = [
            grant for grant in value.get("grants", []) if grant["name"] in post_grants
        ]
        value["grants"] = [
            grant for grant in value.get("grants", []) if grant["name"] not in post_grants
        ]
        added["bindings"] = []
        for instance in value.get("instances", []):
            kept = []
            for binding in instance.get("bindings", []):
                if binding["grant"] in post_grants:
                    added["bindings"].append({"holder": instance["name"], **binding})
                else:
                    kept.append(binding)
            instance["bindings"] = kept
    for executable in value.get("executables", []):
        for field in POST_BASELINE_EXECUTABLE_FIELDS.get(name, {}).get(executable["name"], ()):
            executable.pop(field, None)
    new_holders = POST_BASELINE_SHARED_BUFFER_HOLDERS.get(name, frozenset())
    value["sharedBufferBudget"] = [
        entry for entry in value.get("sharedBufferBudget", []) if entry["holder"] not in new_holders
    ]
    post_budget_fields = POST_BASELINE_SHARED_BUFFER_FIELDS.get(name, {})
    added_budget = []
    for entry in value.get("sharedBufferBudget", []):
        fields = post_budget_fields.get(entry["holder"], frozenset())
        if fields:
            added_budget.append(
                {
                    "holder": entry["holder"],
                    **{field: entry.pop(field) for field in fields if field in entry},
                }
            )
    if added_budget:
        added["sharedBufferBudget"] = added_budget
    for instance in value.get("instances", []):
        for field in POST_BASELINE_INSTANCE_FIELDS.get(name, frozenset()):
            instance.pop(field, None)
        for field in POST_BASELINE_EVERY_INSTANCE_FIELDS:
            instance.pop(field, None)
    for instance in value.get("instances", []):
        for binding in instance.get("bindings", []):
            for field in POST_BASELINE_BINDING_FIELDS:
                binding.pop(field, None)
    return value, added


def check_post_baseline(name: str, derived: dict, system, source: dict) -> None:
    """The post-baseline sections say exactly what the system declares.

    The baseline predates these, so it cannot check them — and an excusal with
    nothing behind it would let a wrong budget through under a name the
    comparison skips. This is the replacement assertion, and it is stricter than
    the baseline's would have been: it compares the derived budget against the
    quota each *instance* is composed with, which is the component spec's value
    unless the instance record or the component's placement declares its own.
    An authenticated budget is keyed by instance, so this is too.
    """
    placements = {entry["component"]: entry for entry in system.spec["placements"]}
    component_by_executable = {
        entry.get("executableName", entry["component"]): entry["component"]
        for entry in system.spec["placements"]
    }
    # Each instance's lifetime is the instance record's, else its component's
    # placement, else the component spec's; the object exists exactly when one
    # is resident.
    lifetimes = {}
    for instance in resolved_instances(system.spec):
        component = component_by_executable.get(instance["executable"], instance["executable"])
        lifetimes[instance["name"]] = instance.get(
            "lifetime", placements.get(component, {}).get("lifetime", COMPONENTS[component]["lifetime"])
        )
    derived_lifetimes = {entry["name"]: entry.get("lifetime") for entry in derived["instances"]}
    if derived_lifetimes != lifetimes:
        fail(f"{name}: derived instance lifetimes {derived_lifetimes} do not match the spec {lifetimes}")
    has_object = any(entry["id"] == "instance-lifetime" for entry in derived["objects"])
    if has_object != ("resident" in lifetimes.values()):
        fail(f"{name}: instance-lifetime object present={has_object} disagrees with its resident instances")
    expected = {}
    for instance in resolved_instances(system.spec):
        component = component_by_executable.get(instance["executable"], instance["executable"])
        default = COMPONENTS[component]["runtime"]["resource"]["privatePageQuota"]
        quota = instance.get(
            "privatePageQuota", placements.get(component, {}).get("privatePageQuota", default)
        )
        if quota:
            expected[instance["name"]] = quota
    budget = {
        entry["holder"]: entry["pageQuota"] for entry in derived.get("privateMemoryBudget", [])
    }
    if budget != expected:
        fail(
            f"{name}: derived privateMemoryBudget {sorted(budget.items())} does not match "
            f"the declared privatePageQuota of the components it composes "
            f"{sorted(expected.items())}"
        )
    # And the resource object is present exactly when the section has holders:
    # the builder refuses a budget without the object and encodes nothing from an
    # object with no holders, so either half alone is a generation that boots
    # with every declared quota silently denied.
    objects = {entry["id"] for entry in derived["objects"]}
    carried = "private-memory-budget" in objects
    if carried != bool(budget):
        fail(
            f"{name}: privateMemoryBudget has {len(budget)} holder(s) but the "
            f"private-memory-budget resource object is {'present' if carried else 'absent'}"
        )
    post_grants = POST_BASELINE_GRANTS.get(name, frozenset())
    declared_post_grants = sorted(
        (grant for grant in system.spec["grants"] if grant["name"] in post_grants),
        key=SORTED_SECTIONS["grants"],
    )
    derived_post_grants = sorted(
        (grant for grant in derived.get("grants", []) if grant["name"] in post_grants),
        key=SORTED_SECTIONS["grants"],
    )
    if {grant["name"] for grant in declared_post_grants} != post_grants:
        fail(
            f"{name}: post-baseline grant exemption {sorted(post_grants)} does not "
            "name exactly the live system declarations"
        )
    if derived_post_grants != declared_post_grants:
        fail(
            f"{name}: derived post-baseline grants do not match the live system "
            f"declarations: {first_difference(derived_post_grants, declared_post_grants, 'grants')}"
        )
    # The notification sections split off by `POST_BASELINE_SYSTEM_SECTIONS`
    # get the same independent treatment as the post-baseline grants above:
    # `derive_manifest` assigns these directly from the system spec, so a
    # divergence here means the derivation or normalization mutated them, not
    # a fact the baseline itself could have disagreed with.
    post_notification_sections = POST_BASELINE_SYSTEM_SECTIONS.get(name, frozenset())
    if "notificationGrants" in post_notification_sections:
        declared_notifications = system.spec["notifications"]
        derived_notifications = derived.get("notificationGrants", [])
        if derived_notifications != declared_notifications:
            fail(
                f"{name}: derived notificationGrants do not match the live system "
                "declarations: "
                f"{first_difference(derived_notifications, declared_notifications, 'notificationGrants')}"
            )
    if "notificationBindings" in post_notification_sections:
        declared_bindings = system.spec["notificationBindings"]
        derived_bindings = derived.get("notificationBindings", [])
        if derived_bindings != declared_bindings:
            fail(
                f"{name}: derived notificationBindings do not match the live system "
                "declarations: "
                f"{first_difference(derived_bindings, declared_bindings, 'notificationBindings')}"
            )
    # Instance fields split off by `POST_BASELINE_INSTANCE_FIELDS` are checked
    # against the live system declaration by holder. Omitting a field is a
    # different statement from assigning its default, so compare only the
    # exempted keys and preserve absence on both sides.
    post_instance_fields = POST_BASELINE_INSTANCE_FIELDS.get(name, frozenset())
    if post_instance_fields:
        declared_instances = {
            instance["name"]: {
                field: instance[field] for field in post_instance_fields if field in instance
            }
            for instance in resolved_instances(system.spec)
        }
        derived_instances = {
            instance["name"]: {
                field: instance[field] for field in post_instance_fields if field in instance
            }
            for instance in derived.get("instances", [])
        }
        if derived_instances != declared_instances:
            fail(
                f"{name}: derived post-baseline instance fields do not match the live "
                "system declarations: "
                f"{first_difference(derived_instances, declared_instances, 'instances')}"
            )
    for holder, fields in POST_BASELINE_SHARED_BUFFER_FIELDS.get(name, {}).items():
        declarations = [
            instance for instance in resolved_instances(system.spec) if instance["name"] == holder
        ]
        budgets = [
            entry for entry in derived.get("sharedBufferBudget", []) if entry["holder"] == holder
        ]
        if len(declarations) != 1 or len(budgets) != 1:
            fail(f"{name}: post-baseline sharedBufferBudget requires exactly one live holder {holder}")
        for field in fields:
            declared_field = "bufferBytePages" if field == "bytePages" else field
            if (
                declared_field not in declarations[0]
                or field not in budgets[0]
                or budgets[0][field] != declarations[0][declared_field]
            ):
                fail(
                    f"{name}: post-baseline sharedBufferBudget {holder}.{field} "
                    "does not match the live instance declaration"
                )
    check_network_post_baseline(name, derived, system)
    # B91: every pin the derivation emits carries the reason its system spec
    # declared, and that reason is what the derived manifest itself implies. The
    # builder's own predicate is reused rather than restated, so this gate cannot
    # disagree with the product build about which label is correct.
    BUILDER.validate_slot_reasons(source, f"{name} derived manifest")


def check_network_post_baseline(name: str, derived: dict, system) -> None:
    """Only the enumerated network stack and IO0 provisioning changes are lifted."""
    if name not in POST_BASELINE_EXECUTABLE_FIELDS:
        return

    def exact(label: str, actual: object, expected: object) -> None:
        if actual != expected:
            fail(f"{name}: network post-baseline {label}: {actual!r} != {expected!r}")

    placements = [entry for entry in system.spec["placements"]
                  if entry["component"] == "network-service"]
    exact("network-service placement count", len(placements), 1)
    resource = COMPONENTS["network-service"]["runtime"]["resource"]
    stack = placements[0].get("stackBytes", resource["stackBytes"])
    exact("derived stackBytes", [entry.get("stackBytes", BUILDER.COMPONENT_DEFAULT_STACK_BYTES)
                                for entry in derived["executables"]
                                if entry["name"] == "network-service"], [stack])
    if name != "sel4-io-tcp":
        return
    exact("derived lifecycle policy", derived.get("lifecyclePolicy"), system.spec.get("lifecyclePolicy"))
    exact("derived lifecycle resource", [entry for entry in derived["objects"]
          if entry["id"] == "lifecycle-policy"],
          [{"id": "lifecycle-policy", "kind": "resource", "size": 4096}]
          if system.spec.get("lifecyclePolicy") is not None else [])
    applications = system.spec.get("networkApplications", [])
    exact("derived applications", derived.get("networkApplications", []), applications)
    exact("derived application resource", [entry for entry in derived["objects"]
          if entry["id"] == "network-application"],
          [{"id": "network-application", "kind": "resource", "size": 4096}]
          if system.spec.get("networkApplicationsObject") else [])
    for application in applications:
        for field, transferable in (("controlBinding", False), ("provisionBinding", True)):
            grant_name = application[field]
            declared = [entry for entry in system.spec["grants"] if entry["name"] == grant_name]
            exact(f"declared {field} grant count", len(declared), 1)
            grant = declared[0]
            exact(f"declared {field} kind", grant["capabilityKind"], "endpoint")
            exact(f"declared {field} rights", sorted(grant["rights"]), ["recv", "send"])
            exact(f"declared {field} transfer", grant["transferable"], transferable)
            exact(f"declared {field} peers", {grant["source"], grant["target"]},
                  {application["holder"], "network-service"})
            exact(f"derived {field} grant",
                  [entry for entry in derived["grants"] if entry["name"] == grant_name], declared)
    for grant_name in POST_BASELINE_GRANTS.get(name, frozenset()):
        pins = sorted((entry["holder"], entry["slot"], entry["reason"])
                      for entry in system.spec["slotPins"] if entry["grant"] == grant_name)
        exact("derived provisioning bindings", sorted(
            (instance["name"], binding["slot"], binding.get("slotReason"))
            for instance in derived["instances"] for binding in instance["bindings"]
            if binding["grant"] == grant_name), pins)
    budget_fields = {"bytePages": "bufferBytePages", "bufferCount": "bufferCount",
                     "mappingCount": "mappingCount", "loanCount": "loanCount"}
    instances = resolved_instances(system.spec)
    component_by_executable = {
        entry.get("executableName", entry["component"]): entry["component"]
        for entry in system.spec["placements"]
    }
    holders = (POST_BASELINE_SHARED_BUFFER_HOLDERS.get(name, frozenset())
               | POST_BASELINE_SHARED_BUFFER_FIELDS.get(name, {}).keys())
    for holder in sorted(holders):
        declarations = [entry for entry in instances if entry["name"] == holder]
        exact(f"declared budget holder {holder}", len(declarations), 1)
        instance = declarations[0]
        component = component_by_executable.get(instance["executable"], instance["executable"])
        defaults = COMPONENTS[component]["runtime"]["resource"]
        declared = {"holder": holder, **{field: instance.get(key, defaults[key])
                                        for field, key in budget_fields.items()}}
        exact(f"derived buffer budget {holder}",
              [entry for entry in derived["sharedBufferBudget"] if entry["holder"] == holder],
              [declared] if any(declared[field] for field in budget_fields) else [])
    # The production encoder owns endpoint exclusivity and listener bounds.
    try:
        BUILDER.build_network_applications(derived)
    except SystemExit as error:
        fail(f"{name}: network post-baseline authority: {error}")


def first_difference(left: object, right: object, label: str) -> str:
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return f"{label}: {len(left)} entries vs {len(right)}"
        for index, (a, b) in enumerate(zip(left, right, strict=True)):
            if a != b:
                return first_difference(a, b, f"{label}[{index}]")
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            if left.get(key) != right.get(key):
                return first_difference(left.get(key), right.get(key), f"{label}.{key}")
    return f"{label}: {left!r} != {right!r}"


def network_application_controls(source: dict) -> int:
    """Exercise the production application encoder independently of fixtures."""
    import boot_contracts as wire

    manifest = copy.deepcopy(source)
    client = {
        "holder": "io-tcp-probe", "controlBinding": "network-tcp-probe-service",
        "provisionBinding": "network-tcp-probe-provision", "supervisionBinding": "",
        "requestNotification": "", "completionNotification": "", "role": "client",
        "backend": "loopback", "localAddress": "0.0.0.0", "localPort": 0,
        "admittedPeer": "", "admittedPeerAddress": "", "rights": [], "backlog": 0, "acceptedSocketLimit": 0,
        "byteBudget": 0, "timerBudget": 0, "queueDepth": 0, "retryLimit": 0,
        "reconnectLimit": 0, "keepaliveMs": 0, "idleTimeoutMs": 10000, "hopLimit": 64, "nagle": True,
        "rxBufferBytes": 2048, "txBufferBytes": 2048,
    }
    listener = dict(client, holder="io-network-intruder", controlBinding="local-control",
                    provisionBinding="local-provision", role="listener", localAddress="127.0.0.1",
                    localPort=8080, admittedPeer="io-tcp-probe", rights=["listen", "send", "recv"],
                    backlog=1, acceptedSocketLimit=1, byteBudget=4096, timerBudget=1, queueDepth=4)
    manifest["networkApplications"] = [client, listener]
    for name, transferable in (("local-control", False), ("local-provision", True)):
        manifest["grants"].append({"name": name, "capabilityKind": "endpoint",
                                   "source": "network-service", "target": "io-network-intruder",
                                   "rights": ["send", "recv"], "transferable": transferable})
    encoded = BUILDER.build_network_applications(manifest)
    expected_length = wire.NETWORK_APPLICATION_HEADER_BYTES + 2 * wire.NETWORK_APPLICATION_ENTRY_BYTES
    header = wire.NETWORK_APPLICATION_HEADER.unpack_from(encoded)
    if header != (wire.NETWORK_APPLICATION_MAGIC, wire.NETWORK_APPLICATION_FORMAT_VERSION,
                  wire.NETWORK_APPLICATION_HEADER_BYTES, 0, 2, expected_length) or len(encoded) != expected_length:
        fail("network application encoder changed exact generated header or entry bounds")
    identities = [wire.NETWORK_APPLICATION_ENTRY.unpack_from(
        encoded, wire.NETWORK_APPLICATION_HEADER_BYTES + index * wire.NETWORK_APPLICATION_ENTRY_BYTES)[0]
        for index in range(2)]
    if identities != sorted(set(identities)):
        fail("network application encoder did not emit strictly ordered holders")
    # Each row's declared options land in its own entry, bounds inclusive.
    tuned = copy.deepcopy(manifest)
    tuned["networkApplications"][0].update(keepaliveMs=60000, idleTimeoutMs=1000, hopLimit=1, nagle=False)
    tuned["networkApplications"][1].update(keepaliveMs=100, idleTimeoutMs=60000, hopLimit=255)
    tuned_bytes = BUILDER.build_network_applications(tuned)
    options = {
        row[10]: row[22:26]
        for row in (wire.NETWORK_APPLICATION_ENTRY.unpack_from(
            tuned_bytes, wire.NETWORK_APPLICATION_HEADER_BYTES + index * wire.NETWORK_APPLICATION_ENTRY_BYTES)
            for index in range(2))
    }
    if options != {
        wire.NETWORK_APPLICATION_ROLE_CLIENT: (60000, 1000, 1, 0),
        wire.NETWORK_APPLICATION_ROLE_LISTENER: (100, 60000, 255, 1),
    }:
        fail(f"network application encoder misplaced declared socket options: {options}")
    # Each row's declared buffer sizes land in its own entry, bounds inclusive.
    sized = copy.deepcopy(manifest)
    sized["networkApplications"][0].update(rxBufferBytes=65536, txBufferBytes=2048)
    sized["networkApplications"][1].update(rxBufferBytes=2048, txBufferBytes=65536, byteBudget=67584)
    buffers = {
        row[10]: row[26:28]
        for row in (wire.NETWORK_APPLICATION_ENTRY.unpack_from(
            BUILDER.build_network_applications(sized),
            wire.NETWORK_APPLICATION_HEADER_BYTES + index * wire.NETWORK_APPLICATION_ENTRY_BYTES)
            for index in range(2))
    }
    if buffers != {
        wire.NETWORK_APPLICATION_ROLE_CLIENT: (65536, 2048),
        wire.NETWORK_APPLICATION_ROLE_LISTENER: (2048, 65536),
    }:
        fail(f"network application encoder misplaced declared buffer sizes: {buffers}")
    reverse = copy.deepcopy(manifest)
    reverse["networkApplications"].reverse()
    if BUILDER.build_network_applications(reverse) != encoded:
        fail("network application encoding depends on authoring row order")

    refused = 0

    def reject(label: str, mutate, reason: str) -> None:
        nonlocal refused
        altered = copy.deepcopy(manifest)
        mutate(altered)
        try:
            BUILDER.build_network_applications(altered)
        except SystemExit as error:
            if reason not in str(error):
                fail(f"network application {label} refused at wrong boundary: {error}")
        else:
            fail(f"network application accepted {label}")
        refused += 1

    for field, value, reason in (
        ("holder", "missing", "holder is not a distinct admitted instance"),
        ("controlBinding", "missing", "controlBinding is not an exclusive"),
        ("provisionBinding", "missing", "provisionBinding is not an exclusive"),
        ("controlBinding", "", "invalid controlBinding"),
        ("provisionBinding", "A", "invalid provisionBinding"),
        ("controlBinding", "x" * (wire.NETWORK_APPLICATION_BINDING_BYTES + 1), "invalid controlBinding"),
        ("supervisionBinding", "missing", "supervision is not a declared"),
        ("requestNotification", "request", "notification bindings must be paired"),
        ("role", "unknown", "unknown role or backend"),
        ("backend", "unknown", "unknown role or backend"),
        ("rights", ["listen"], "client row carries listener authority"),
        ("localPort", True, "invalid numeric bound"),
        ("byteBudget", 1, "client row carries listener authority"),
        ("admittedPeerAddress", "10.0.0.2", "client row carries listener authority"),
        ("keepaliveMs", 99, "socket options exceed contract"),
        ("keepaliveMs", 60001, "socket options exceed contract"),
        ("idleTimeoutMs", 999, "socket options exceed contract"),
        ("idleTimeoutMs", 60001, "socket options exceed contract"),
        ("hopLimit", 0, "socket options exceed contract"),
        ("hopLimit", 256, "socket options exceed contract"),
        ("hopLimit", True, "invalid socket option"),
        ("nagle", 1, "invalid socket option"),
        ("keepaliveMs", "500", "invalid socket option"),
        ("rxBufferBytes", 0, "buffer sizes exceed contract"),
        ("rxBufferBytes", 1024, "buffer sizes exceed contract"),
        ("rxBufferBytes", 3072, "buffer sizes exceed contract"),
        ("rxBufferBytes", 131072, "buffer sizes exceed contract"),
        ("txBufferBytes", 0, "buffer sizes exceed contract"),
        ("txBufferBytes", 1024, "buffer sizes exceed contract"),
        ("txBufferBytes", 3072, "buffer sizes exceed contract"),
        ("txBufferBytes", 131072, "buffer sizes exceed contract"),
        ("rxBufferBytes", True, "invalid buffer size"),
        ("txBufferBytes", "2048", "invalid buffer size"),
    ):
        reject(f"client {field}={value!r}",
               lambda value_manifest, field=field, value=value: value_manifest["networkApplications"][0].update({field: value}), reason)
    for grant_name in ("network-tcp-probe-service", "network-tcp-probe-provision"):
        for field, value in (("target", "init"), ("capabilityKind", "supervision"),
                             ("rights", ["send"]), ("transferable", grant_name.endswith("service"))):
            reject(f"{grant_name}.{field}",
                   lambda value_manifest, field=field, value=value, grant_name=grant_name:
                   next(entry for entry in value_manifest["grants"] if entry["name"] == grant_name).update({field: value}),
                   "is not an exclusive declared endpoint with exact rights")
    reject("duplicate application holder", lambda value: value["networkApplications"].append(
        copy.deepcopy(value["networkApplications"][0])), "duplicate holder")
    reject("reused control grant", lambda value: value["networkApplications"][1].update(
        controlBinding="network-tcp-probe-service"), "controlBinding is not an exclusive")
    reject("missing service", lambda value: value.update(instances=[entry for entry in value["instances"]
           if entry["name"] != "network-service"]), "missing service instance")
    reject("unbound notifications", lambda value: value["networkApplications"][0].update(
        requestNotification="request", completionNotification="complete"), "requestNotification is not the declared")
    for field, value, reason in (
        ("admittedPeer", "missing", "admitted peer is not a distinct declared local client"),
        ("admittedPeer", "io-network-intruder", "admitted peer is not a distinct declared local client"),
        ("localAddress", "0.0.0.0", "not an exact authorized loopback endpoint"),
        ("localAddress", "127.0.0.2", "not an exact authorized loopback endpoint"),
        ("localAddress", "127.*", "invalid local IPv4 address"),
        ("localPort", 0, "not an exact authorized endpoint"),
        ("localPort", 65536, "not an exact authorized endpoint"),
        ("backend", "external", "not on a declared service interface address"),
        ("admittedPeerAddress", "10.0.0.2", "not an exact authorized loopback endpoint"),
        ("rights", ["send"], "not an exact authorized endpoint"),
        ("rights", ["listen", "listen"], "unknown or duplicate right"),
        ("rights", ["connect"], "unknown or duplicate right"),
        ("backlog", 2, "listener bounds exceed contract"),
        ("acceptedSocketLimit", 0, "listener bounds exceed contract"),
        ("acceptedSocketLimit", 5, "listener bounds exceed contract"),
        ("byteBudget", 4095, "listener bounds exceed contract"),
        ("byteBudget", wire.NETWORK_APPLICATION_MAX_BYTE_BUDGET + 1, "listener bounds exceed contract"),
        ("timerBudget", 0, "listener bounds exceed contract"),
        ("timerBudget", 5, "listener bounds exceed contract"),
        ("queueDepth", 1, "listener bounds exceed contract"),
        ("queueDepth", 3, "listener bounds exceed contract"),
        ("retryLimit", 17, "listener bounds exceed contract"),
        ("reconnectLimit", 17, "listener bounds exceed contract"),
        ("idleTimeoutMs", 0, "socket options exceed contract"),
        ("hopLimit", 0, "socket options exceed contract"),
    ):
        reject(f"listener {field}={value!r}",
               lambda value_manifest, field=field, value=value: value_manifest["networkApplications"][1].update({field: value}), reason)
    # A listener's budget covers both buffers of every socket it may accept.
    reject("listener budget below its buffers", lambda value: value["networkApplications"][1].update(
        rxBufferBytes=65536, txBufferBytes=65536, byteBudget=131071), "listener bounds exceed contract")
    wide_listener = copy.deepcopy(manifest)
    wide_listener["networkApplications"][1].update(rxBufferBytes=65536, txBufferBytes=65536, byteBudget=131072)
    BUILDER.build_network_applications(wide_listener)
    reject("unsupported pending backlog", lambda value: value["networkApplications"][1].update(
        backlog=2, acceptedSocketLimit=2, byteBudget=8192), "listener bounds exceed contract")
    retained_sockets = copy.deepcopy(manifest)
    retained_sockets["networkApplications"][1].update(acceptedSocketLimit=2, byteBudget=8192)
    BUILDER.build_network_applications(retained_sockets)
    fan_in = copy.deepcopy(manifest)
    fan_in["networkApplications"][0].update(requestNotification="app-requests", completionNotification="client-complete")
    fan_in["notificationGrants"] = [
        {"name": "app-requests", "source": "io-network-intruder", "target": "network-service"},
        {"name": "client-complete", "source": "network-service", "target": "io-tcp-probe"},
    ]
    fan_in["notificationBindings"] = [
        {"grant": "app-requests", "holder": "io-network-intruder", "role": "signal"},
        {"grant": "app-requests", "holder": "io-tcp-probe", "role": "signal"},
        {"grant": "app-requests", "holder": "network-service", "role": "wait"},
        {"grant": "client-complete", "holder": "network-service", "role": "signal"},
        {"grant": "client-complete", "holder": "io-tcp-probe", "role": "wait"},
    ]
    BUILDER.build_network_applications(fan_in)
    for binding_index in range(1, len(fan_in["notificationBindings"])):
        altered = copy.deepcopy(fan_in)
        del altered["notificationBindings"][binding_index]
        try:
            BUILDER.build_network_applications(altered)
        except SystemExit as error:
            if "is not the declared notification edge" not in str(error):
                fail(f"network application fan-in refused at wrong boundary: {error}")
        else:
            fail(f"network application accepted missing fan-in binding {binding_index}")
        refused += 1
    duplicate_listener = copy.deepcopy(manifest)
    duplicate_listener["instances"].append({"name": "local-second-listener"})
    duplicate_listener["networkApplications"].append(dict(
        listener, holder="local-second-listener", controlBinding="second-control", provisionBinding="second-provision"))
    for name, transferable in (("second-control", False), ("second-provision", True)):
        duplicate_listener["grants"].append({"name": name, "capabilityKind": "endpoint",
                                            "source": "network-service", "target": "local-second-listener",
                                            "rights": ["send", "recv"], "transferable": transferable})
    try:
        BUILDER.build_network_applications(duplicate_listener)
    except SystemExit as error:
        if "duplicate listener endpoint" not in str(error):
            fail(f"network application duplicate endpoint refused at wrong boundary: {error}")
    else:
        fail("network application accepted two holders with the same listener endpoint")
    refused += 1
    duplicate_listener["networkApplications"][-1]["localPort"] += 1
    BUILDER.build_network_applications(duplicate_listener)

    # An external listener listens on the service's declared interface address
    # and admits one exact remote unicast address, never a holder.
    interface = next(entry["address"] for entry in manifest["networkInterfaces"] if entry["holder"] == "network-service")
    external = copy.deepcopy(manifest)
    external["networkApplications"][1].update(backend="external", localAddress=interface, admittedPeer="",
                                               admittedPeerAddress="10.0.0.2")
    encoded = BUILDER.build_network_applications(external)
    row = next(wire.NETWORK_APPLICATION_ENTRY.unpack_from(encoded, wire.NETWORK_APPLICATION_HEADER_BYTES + index * wire.NETWORK_APPLICATION_ENTRY_BYTES)
               for index in range(2)
               if wire.NETWORK_APPLICATION_ENTRY.unpack_from(encoded, wire.NETWORK_APPLICATION_HEADER_BYTES + index * wire.NETWORK_APPLICATION_ENTRY_BYTES)[10] == wire.NETWORK_APPLICATION_ROLE_LISTENER)
    if (row[12], row[21], row[6]) != (wire.NETWORK_APPLICATION_PEER_IPV4, bytes([10, 0, 0, 2]), bytes(32)):
        fail("external listener encoding lost its peer kind, admitted address or empty holder")
    for field, value, reason in (
        ("admittedPeerAddress", "", "admits no exact remote IPv4 address"),
        ("admittedPeerAddress", "10.0.0.0/24", "admits no exact remote IPv4 address"),
        ("admittedPeerAddress", "0.0.0.0", "admits no exact remote IPv4 address"),
        ("admittedPeerAddress", "127.0.0.1", "admits no exact remote IPv4 address"),
        ("admittedPeerAddress", "224.0.0.1", "admits no exact remote IPv4 address"),
        ("admittedPeerAddress", "255.255.255.255", "admits no exact remote IPv4 address"),
        ("admittedPeerAddress", interface, "admits no exact remote IPv4 address"),
        ("admittedPeer", "io-tcp-probe", "not on a declared service interface address"),
        ("localAddress", "10.0.0.9", "not on a declared service interface address"),
        ("localAddress", "0.0.0.0", "not on a declared service interface address"),
        ("backlog", 2, "listener bounds exceed contract"),
    ):
        altered = copy.deepcopy(external)
        altered["networkApplications"][1].update({field: value})
        try:
            BUILDER.build_network_applications(altered)
        except SystemExit as error:
            if reason not in str(error):
                fail(f"external listener {field}={value!r} refused at wrong boundary: {error}")
        else:
            fail(f"network application accepted external listener {field}={value!r}")
        refused += 1
    return refused


def computed_source_controls(components: dict[str, dict]) -> int:
    """Mutation controls exercise authoring admission independently of output drift."""
    refused = 0
    name = "sel4-call"
    with tempfile.TemporaryDirectory(prefix="slime-system-source-") as directory:
        contracts = Path(directory) / "contracts"
        shutil.copytree(ROOT / "contracts", contracts)
        root = contracts / "system-spec" / "v1"
        source = root / COMPUTED_SYSTEM_SOURCES[name]
        original = source.read_text()
        output = root / "systems" / f"{name}.zti"
        output_bytes = output.read_bytes()

        def reject(label: str, operation, reason: str = "") -> None:
            nonlocal refused
            try:
                operation()
            except SystemSpecError as error:
                if name not in str(error) or reason not in str(error):
                    fail(f"computed source {label}: diagnostic does not name {name}: {error}")
                refused += 1
            else:
                fail(f"computed source {label}: was accepted")

        output.write_bytes(output_bytes + b"\n")
        reject("derived output drift", lambda: check_computed_systems(components=components, root=root))
        output.write_bytes(output_bytes.replace(b"\n", b"\r\n"))
        reject("derived output newline drift", lambda: check_computed_systems(components=components, root=root))
        output.unlink()
        alias = root / "systems" / "alias.zti"
        alias.write_bytes(output_bytes + b"\n")
        output.symlink_to(alias)
        reject("symlinked output drift", lambda: check_computed_systems(components=components, root=root))
        output.unlink()
        alias.unlink()
        output.write_bytes(output_bytes)
        competing = source.with_suffix(".zti")
        competing.write_bytes(output_bytes)
        reject("competing hand-authored source", lambda: validate_source_mapping(root))
        competing.unlink()
        source.unlink()
        reject("missing source", lambda: validate_source_mapping(root))
        source.write_text(original)
        external = contracts.parent / "outside.zti"
        external.write_text('{ value = 1; }')
        for label, text in (
            ("type error", 'value :: Int = "wrong"; value'),
            ("function result", 'value :: Int -> Int = x => x; value'),
            ("runtime Type result", '{ value = Int; }'),
            ("invalid record", '{ formatVersion = 999; }'),
            ("explicit stdlib", 'prelude ::= import stdlib.prelude; { value = 1; }'),
            ("derived output import", 'import "../systems/sel4-call.zti"'),
            ("escaping import", 'import "../../../../outside.zti"'),
        ):
            source.write_text(text)
            reject(label, lambda: check_computed_systems(components=components, root=root))
        source.write_text(original)
        link = source.parent / "outside.zti"
        link.symlink_to(external)
        source.write_text('import "outside.zti"')
        reject("symlink import escape", lambda: render_computed_system(name, root))
        link.unlink()
        source.write_text(original.replace('generation = 18;', 'generation = 0;'))
        reject("semantic validation", lambda: check_computed_systems(components=components, root=root),
               "generation: must be positive")
        effect_module = source.parent / "effect-lib.zt"
        effect_module.write_text(
            'run :: Text -> Text ! { io.print : Text -> Text; } = x => print x; { run = run; }'
        )
        source.write_text('unused ::= import "effect-lib.zt"; { value = 1; }')
        reject("unused imported effect", lambda: render_computed_system(name, root), "effects")
        effect_module.unlink()
        source.write_text('askValue :: Unit -> Text ! { ask : Unit -> Text; } '
                          '= _ => perform ask (); askValue')
        reject("direct effect", lambda: render_computed_system(name, root), "effects")
        external_package = contracts.parent / "outside-package"
        external_package.mkdir()
        (external_package / "api.zt").write_text('{ value = 1; }')
        (external_package / "zutai.zti").write_text(
            '{ formatVersion = 1; name = "external"; compilerCompatibility = "0.1.0"; '
            'modules = [{ name = "api"; path = "api.zt"; };]; dependencies = []; }'
        )
        package = source.parent / "zutai.zti"
        package.write_text(
            '{ formatVersion = 1; name = "source"; compilerCompatibility = "0.1.0"; '
            'modules = []; dependencies = [{ alias = "external"; '
            'path = "../../../../outside-package"; };]; }'
        )
        source.write_text('import external.api')
        reject("package import escape", lambda: render_computed_system(name, root), "escapes")
        package.unlink()
        source.write_text(original)
        import system_spec as owner
        saved_root = owner.SYSTEM_ROOT
        try:
            owner.SYSTEM_ROOT = root / "systems"
            output.write_bytes(output_bytes + b"\n")
            reject("equivalent output path drift", lambda: compile_system(
                root / "systems" / ".." / "systems" / f"{name}.zti", components=components,
            ))
        finally:
            owner.SYSTEM_ROOT = saved_root
            output.write_bytes(output_bytes)
        before = computed_system_outputs(root)
        after = computed_system_outputs(root)
        if before != after:
            fail("computed system output is not deterministic")
        lifetime = root / "systems" / "sel4-io-lifetime.zti"
        fault = root / "systems" / "sel4-io-service-fault.zti"
        lifetime.write_text(lifetime.read_text().replace(
            "defaultImageBytes = 65536;", "defaultImageBytes = 131072;"))
        inherited = render_computed_system("sel4-io-service-fault", root)
        if inherited != before[fault].replace("defaultImageBytes = 65536;", "defaultImageBytes = 131072;"):
            fail("service-fault variant did not inherit the lifetime declaration exactly")
    return refused


CATALOGUE = interface_catalogue()
COMPONENTS = {entry.name: entry.spec for entry in admit_specs(catalogue=CATALOGUE)}

computed_refusals = computed_source_controls(COMPONENTS)
paths = system_paths()
if not paths:
    fail("no system specs declared")
if {path.stem for path in paths} != set(DERIVED_FIXTURES):
    fail(
        f"system specs {sorted(path.stem for path in paths)} do not match the declared "
        f"derivation table {sorted(DERIVED_FIXTURES)}"
    )

prefetch_systems(paths)
systems = {}
for path in paths:
    try:
        systems[path.stem] = compile_system(path, components=COMPONENTS)
    except SystemSpecError as error:
        fail(f"{path.name}: {error}")

identities = {entry.identity for entry in systems.values()}
if len(identities) != len(systems):
    fail("two system specs computed the same identity")

# Every retired-kind entry must cover at least one real grant, asserted BEFORE
# any baseline comparison. Ordering matters for diagnosis: the divergence check
# below raises first, and an engineer who mistyped or emptied this set would be
# pointed at the frozen fixture and tempted to re-bless it — the one action the
# exemption exists to avoid. Per-kind rather than per-set, so a set that covers
# three grants through one entry cannot let a second entry skip nothing.
RETIRED_KINDS_COVERED = {
    grant["capabilityKind"]
    for name in sorted(systems)
    if name not in SPEC_NATIVE_SYSTEMS
    for grant in strip_retired_kinds(load_baseline(DERIVED_FIXTURES[name]))[1]
}
if RETIRED_CAPABILITY_KINDS - RETIRED_KINDS_COVERED:
    fail(
        "no frozen baseline declares a grant in "
        f"{sorted(RETIRED_CAPABILITY_KINDS - RETIRED_KINDS_COVERED)}, so those "
        "RETIRED_CAPABILITY_KINDS entries cover nothing and must be removed"
    )

# 1. Each system derives the fixture it replaces.
if not SPEC_NATIVE_SYSTEMS <= systems.keys():
    fail("spec-native system allowlist names a missing system")
for name, system in sorted(systems.items()):
    if name in SPEC_NATIVE_SYSTEMS:
        if (BASELINE_FIXTURES / DERIVED_FIXTURES[name]).exists():
            fail(f"{name}: spec-native system unexpectedly has a historical baseline")
        source_manifest = derive_manifest(system)
        check_post_baseline(name, normalized(source_manifest), system, source_manifest)
        continue
    # The pre-CP1 hand-authored fixture, frozen under
    # `contracts/system-spec/v1/baselines/`. Comparing against the *committed*
    # fixture would be circular now that the fixture is this generator's own
    # output: it would assert the generator agrees with itself. The baseline is
    # what the derivation has to reproduce, and it never changes again.
    fixture = load_baseline(DERIVED_FIXTURES[name])
    derived = normalized(derive_manifest(system))
    # Grants whose capability kind the contract has retired are lifted out
    # before the dead-binding strip, so the two exemptions stay separable: one
    # is text that never named a grant, the other named a grant in a vocabulary
    # that no longer exists.
    without_retired, retired_grants = strip_retired_kinds(fixture)
    check_retired_kinds()
    committed = normalized(strip_dead_bindings(without_retired))
    # Sections the baseline predates are lifted out and asserted separately: it
    # was frozen before they existed, so it has no opinion to compare against.
    derived, _added = split_post_baseline(derived, name)
    committed, _ = split_post_baseline(committed, name)
    if derived != committed:
        fail(
            f"{name}: derived manifest diverges from {DERIVED_FIXTURES[name]}: "
            f"{first_difference(derived, committed, 'manifest')}"
        )
    # One derivation, passed twice: normalized for the budget comparison, and
    # unnormalized because `validate_slot_reasons` needs unresolved slots to tell
    # an omitted pin from an allocated one.
    source_manifest = derive_manifest(system)
    check_post_baseline(name, normalized(source_manifest), system, source_manifest)
    # And the removal above must be exactly the dead bindings and the
    # retired-kind ones, never a live grant in a live kind: comparing against
    # the unmodified fixture must fail for those reasons alone.
    untouched = normalized(fixture)
    if untouched != committed:
        retired_names = {grant["name"] for grant in retired_grants}
        removed = {
            (instance["name"], binding["grant"])
            for instance in fixture["instances"]
            for binding in instance["bindings"]
        } - {
            (instance["name"], binding["grant"])
            for instance in committed["instances"]
            for binding in instance["bindings"]
        }
        unexplained = {
            entry
            for entry in removed
            if entry not in KNOWN_DEAD_BINDINGS and entry[1] not in retired_names
        }
        if unexplained:
            fail(
                f"{name}: stripped a binding that is neither declared dead nor "
                f"retired-kind: {sorted(unexplained)}"
            )
        grants = {grant["name"] for grant in fixture["grants"]}
        live = [entry for entry in removed if entry[1] in grants and entry[1] not in retired_names]
        if live:
            fail(f"{name}: a stripped binding names a real grant: {sorted(live)}")

    # Every surviving binding must keep the exact slot the *unstripped* fixture
    # resolved for it.
    #
    # This is the check whose absence let a real defect through. Removing the
    # four dead bindings frees the slots they occupied, and
    # `assign_declared_slots` then hands those numbers to the next binding in
    # grant-name order: `generation-manager`'s rollback/select/stage bindings
    # silently moved 2->1, 3->2, 4->3. The comparison above could not see it,
    # because it strips first and resolves second, so both sides shifted
    # together. Resolving the untouched fixture independently is what makes the
    # slot a checked fact rather than a coincidence, and the system spec pins
    # those three numbers to hold it.
    resolved_fixture = BUILDER.assign_declared_slots(copy.deepcopy(fixture))
    original_slots = {
        (instance["name"], binding["grant"]): binding["slot"]
        for instance in resolved_fixture["instances"]
        for binding in instance["bindings"]
    }
    derived_slots = {
        (instance["name"], binding["grant"]): binding["slot"]
        for instance in derived["instances"]
        for binding in instance["bindings"]
    }
    moved = {
        key: (original_slots[key], slot)
        for key, slot in derived_slots.items()
        if key in original_slots and original_slots[key] != slot
    }
    if moved:
        fail(
            f"{name}: derivation moved capability slot(s) the committed fixture pinned: "
            + ", ".join(
                f"{holder}/{grant} {was}->{now}"
                for (holder, grant), (was, now) in sorted(moved.items())
            )
            + "; pin them in the system spec"
        )

# 1b. Byte-level drift. The committed fixtures are now this generator's output,
#     so regenerating them must reproduce the committed bytes exactly — the same
#     `--check` discipline every other generated artifact in this repository is
#     held to. Without this, the semantic comparison above would be trivially
#     true against a fixture nobody could reproduce, and the fixtures would drift
#     back into hand-edited text one edit at a time.
for name, system in sorted(systems.items()):
    fixture = derived_manifest_path(DERIVED_FIXTURES[name])
    rendered = zti(derive_manifest(system)) + "\n"
    if fixture.read_text(encoding="utf-8") != rendered:
        fail(
            f"{DERIVED_FIXTURES[name]} is stale: regenerate it with "
            f"python3 scripts/generate/generate-generation-from-spec.py"
        )

# 2. The derivation is a function of its inputs alone.
for name, system in sorted(systems.items()):
    if normalized(derive_manifest(system)) != normalized(derive_manifest(system)):
        fail(f"{name}: two derivations of one system spec disagree")

# 3. Every derived manifest is a real `contracts/generation-manifest/v1` record: written
#    out, it decodes under the generation schema. A derivation that produced a
#    shape the manifest contract rejects would pass every check above.
with tempfile.TemporaryDirectory(prefix="slime-system-spec-check-") as temporary:
    root = Path(temporary)
    environment = os.environ.copy()
    environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
    for name, system in sorted(systems.items()):
        path = root / f"{name}.zti"
        path.write_text(zti(derive_manifest(system)) + "\n", encoding="utf-8")
        process = subprocess.run(
            [str(binary()), "json", str(path)],
            cwd=ROOT,
            check=False,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.returncode != 0:
            fail(f"{name}: derived manifest is not valid Zutai: {process.stderr.strip()}")

    # 4. Named refusals. Each mutation is applied to a compiled system and must
    #    be refused by the rule it names, with the unmutated baseline admitted
    #    first so no arm can pass by tripping an unrelated guard (B67).
    baseline = systems["sel4-channel"]

    def write_system(directory: Path, spec: dict) -> Path:
        path = directory / f"{spec['name']}.zti"
        path.write_text(zti(spec) + "\n", encoding="utf-8")
        return path

    def source() -> dict:
        return copy.deepcopy(baseline.spec)

    arms = root / "arms"
    arms.mkdir()
    compile_system(write_system(arms, source()), components=COMPONENTS)

    def rejected(label: str, mutate) -> None:
        spec = source()
        mutate(spec)
        try:
            compile_system(write_system(arms, spec), components=COMPONENTS)
        except SystemSpecError:
            return
        fail(f"{label} was accepted")

    def undeclared_component(spec: dict) -> None:
        spec["components"] = sorted(spec["components"] + ["no-such-component"])

    def unknown_target(spec: dict) -> None:
        spec["targetRequirement"] = "aarch64-imaginary"

    def negative_slot_pin(spec: dict) -> None:
        spec["slotPins"] = [
            {
                "holder": "init",
                "grant": "dango-output",
                "slot": -1,
                "reason": "componentAbi",
            }
        ]

    def grant_to_unadmitted(spec: dict) -> None:
        spec["grants"][0]["target"] = "dango"

    def unknown_capability_kind(spec: dict) -> None:
        spec["grants"][0]["capabilityKind"] = "pciFunction"

    def rights_outside_kind(spec: dict) -> None:
        # A *live* right the first grant's kind forbids. That grant is
        # `dango-output`, an `endpoint`, and `directoryRead` is valid vocabulary
        # on another kind — so the refusal is `validate_capability_rights`
        # rejecting a right for this kind. Naming a retired right would be
        # refused as unknown vocabulary before that check ran, leaving this rule
        # uncovered (B90).
        spec["grants"][0]["rights"] = ["directoryRead"]

    def stale_slot_pin(spec: dict) -> None:
        spec["slotPins"] = [
            {
                "holder": "console",
                "grant": "no-such-grant",
                "slot": 3,
                "reason": "componentAbi",
            }
        ]

    def duplicate_slot_pin(spec: dict) -> None:
        spec["slotPins"] = [
            {
                "holder": "init",
                "grant": "dango-output",
                "slot": 4,
                "reason": "componentAbi",
            },
            {
                "holder": "init",
                "grant": "init-console",
                "slot": 4,
                "reason": "componentAbi",
            },
        ]

    def unknown_slot_pin_reason(spec: dict) -> None:
        # B91: the reason vocabulary is closed. A pin claiming a reason outside
        # it cannot be checked against the manifest at all, so it is refused
        # here rather than reaching the generation builder.
        spec["slotPins"] = [
            {
                "holder": "init",
                "grant": "dango-output",
                "slot": 4,
                "reason": "becauseISaidSo",
            }
        ]

    def bootstrap_not_init(spec: dict) -> None:
        spec["bootstrapInstance"] = "console"

    def bootstrap_unadmitted(spec: dict) -> None:
        spec["bootstrapInstance"] = "dango"

    def duplicate_grant_name(spec: dict) -> None:
        spec["grants"].append(copy.deepcopy(spec["grants"][0]))

    def commands_without_executables(spec: dict) -> None:
        # A command profile in a system granting no executable authority: the
        # profile advertises commands nothing in this generation can launch.
        spec["commandBindings"] = [{"component": "console", "commands": ["init"]}]
        spec["grants"] = [
            grant for grant in spec["grants"] if grant["capabilityKind"] != "executable"
        ]
        spec["slotPins"] = []

    def state_owner_unadmitted(spec: dict) -> None:
        spec["state"] = [
            {"name": "orphan", "owner": "dango", "policy": "preserve", "schemaVersion": 1}
        ]

    def unknown_state_policy(spec: dict) -> None:
        spec["state"] = [
            {"name": "orphan", "owner": "console", "policy": "forever", "schemaVersion": 1}
        ]

    def unsorted_components(spec: dict) -> None:
        spec["components"] = list(reversed(spec["components"]))

    def over_bounded_slot_pins(spec: dict) -> None:
        # One more pin than the contract's `maxSlotPins` admits. Every pin names
        # a real binding, so only the bound can refuse this.
        spec["slotPins"] = [
            {
                "holder": "init",
                "grant": "dango-output",
                "slot": index,
                "reason": "componentAbi",
            }
            for index in range(CONTRACT.MAX_SLOT_PINS + 1)
        ]

    def over_bounded_text(spec: dict) -> None:
        spec["acceptanceCriteria"] = "x" * (CONTRACT.MAX_TEXT_BYTES + 1)

    def duplicate_state_name(spec: dict) -> None:
        spec["state"] = [
            {"name": "twice", "owner": "console", "policy": "preserve", "schemaVersion": 1},
            {"name": "twice", "owner": "init", "policy": "preserve", "schemaVersion": 1},
        ]

    def dependency_unadmitted(spec: dict) -> None:
        # A component whose declared dependency the system does not admit.
        #
        # `bootstrapInstance` must stay an admitted init component or the
        # bootstrap rules fire first and this arm proves nothing — which is what
        # it did before, in both directions. So `init` stays, and `dango` is
        # added instead: its component spec depends on `console`, which this
        # mutation removes, leaving the dependency rule as the only reason to
        # refuse. Verified by neutralizing that rule and observing the arm
        # falsely pass.
        spec["components"] = sorted(
            name for name in spec["components"] + ["dango"] if name != "console"
        )
        spec["placements"] = [
            entry for entry in spec["placements"] if entry["component"] != "console"
        ]
        spec["grants"] = []
        spec["slotPins"] = []

    def interface_without_graph(spec: dict) -> None:
        # A component declaring route roles, in a system with no fabric graph.
        #
        # `fabric-publisher` depends on `fabric-service`, so adding it alone was
        # refused by the dependency rule rather than the graph rule. Admitting
        # both, and clearing the dependency that would fire first, leaves the
        # missing graph as the only reason to refuse.
        spec["components"] = sorted(spec["components"] + ["fabric-publisher", "fabric-service"])
        spec["placements"] = spec["placements"] + [
            {"component": "fabric-publisher", "owner": "init"},
            {"component": "fabric-service", "owner": "init"},
        ]
        spec["placements"].sort(key=lambda entry: entry["component"])

    refusals = 0
    for label, mutate in (
        ("a component no component spec declares", undeclared_component),
        ("a target profile the table does not name", unknown_target),
        ("a negative slot pin", negative_slot_pin),
        ("a grant naming an unadmitted target", grant_to_unadmitted),
        ("a grant with an unknown capability kind", unknown_capability_kind),
        ("a grant carrying rights its kind forbids", rights_outside_kind),
        ("a slot pin for a binding the grants do not produce", stale_slot_pin),
        ("two slot pins on one holder slot", duplicate_slot_pin),
        ("a slot pin whose reason is outside the vocabulary", unknown_slot_pin_reason),
        ("a bootstrap instance that is not an init component", bootstrap_not_init),
        ("a bootstrap instance the system does not admit", bootstrap_unadmitted),
        ("a duplicate grant name", duplicate_grant_name),
        ("commands with no executable authority anywhere", commands_without_executables),
        ("a state binding owned by an unadmitted component", state_owner_unadmitted),
        ("an unknown state policy", unknown_state_policy),
        ("an unsorted component list", unsorted_components),
        ("more slot pins than the declared bound", over_bounded_slot_pins),
        ("text beyond the declared byte bound", over_bounded_text),
        ("a duplicate state binding name", duplicate_state_name),
        ("a dependency the system does not admit", dependency_unadmitted),
        ("a route role declared with no fabric graph", interface_without_graph),
    ):
        rejected(label, mutate)
        refusals += 1

    # Exercise target-bound memory admission at the exact published edges.
    # Derivation owns these checks; structural compilation alone is insufficient.
    for target, region, total in (
        ("aarch64-sel4-qemu-virt", 65536, 262144),
        ("riscv64-sel4-qemu-virt", 65536, 262144),
        ("aarch64-rpi5", 512, 2048),
    ):
        memory_spec = copy.deepcopy(systems["sel4-private-memory-1g"].spec)
        memory_spec["targetRequirement"] = target
        for instance in memory_spec["instances"]:
            instance["privatePageQuota"] = (
                region if instance["name"].startswith("private-memory-1g-holder-") else 0
            )

        def memory_manifest(spec: dict) -> dict:
            return derive_manifest(compile_system(write_system(arms, spec), components=COMPONENTS))

        admitted = memory_manifest(memory_spec)
        quotas = [entry["pageQuota"] for entry in admitted["privateMemoryBudget"]]
        if quotas != [region] * 4 or sum(quotas) != total:
            fail(f"{target}: exact private-memory boundary was not admitted")

        for label, holder, pages, reason in (
            ("holder", "private-memory-1g-holder-a", region + 1, "cannot admit holders"),
            ("aggregate", "private-memory-1g-probe", 1, "aggregate exceeds capacity"),
        ):
            altered = copy.deepcopy(memory_spec)
            next(entry for entry in altered["instances"] if entry["name"] == holder)[
                "privatePageQuota"
            ] = pages
            try:
                memory_manifest(altered)
            except SystemSpecError as error:
                expected = f"private memory: target {target!r} {reason}"
                if expected not in str(error):
                    fail(f"{target}: {label} private-memory boundary refused for wrong reason: {error}")
            else:
                fail(f"{target}: {label} private-memory boundary overflow was accepted")
            refusals += 1

    adaptive_spec = copy.deepcopy(systems["sel4-private-memory-1g"].spec)
    for instance in adaptive_spec["instances"]:
        instance["privatePageQuota"] = 0
    adaptive_spec["privateMemoryPolicy"] = {
        "formatVersion": 2,
        "reserve": dict.fromkeys(private_memory_policy.RESOURCES, 1),
        "entitlements": [{"name": "workers", "subtreeRoot": "private-memory-1g-probe",
                          "guaranteePages": 2, "maximumMode": "pool", "maximumPages": 0}],
        "subjects": [{"instance": f"private-memory-1g-holder-{name}", "entitlement": "workers",
                      "maximumMode": "pool", "maximumPages": 0} for name in "abcd"],
    }
    adaptive_manifest = memory_manifest(adaptive_spec)
    if "privateMemoryBudget" in adaptive_manifest:
        fail("adaptive derivation retained a fixed budget")
    if [entry["id"] for entry in adaptive_manifest["objects"] if entry["id"].startswith("private-memory-")] != ["private-memory-policy"]:
        fail("adaptive policy resource was not derived exactly once")
    adaptive = private_memory_policy.manifest_policy(adaptive_manifest)
    if adaptive != adaptive_spec["privateMemoryPolicy"]:
        fail("adaptive policy changed during system derivation")
    encoded = private_memory_policy.encode(adaptive, adaptive_manifest["instances"])
    policy_blob = root / "private-memory-policy.bin"
    policy_blob.write_bytes(encoded)
    decoded_policy = subprocess.run(
        ["cargo", "run", "--quiet", "-p", "boot-contracts", "--example", "admit_generation",
         "--", "--private-memory-policy", str(policy_blob)],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    if decoded_policy.stdout.strip() != "policy 1 4":
        fail(f"host policy encoder disagrees with native decoder: {decoded_policy.stdout}")
    if encoded != private_memory_policy.encode(adaptive, adaptive_manifest["instances"]):
        fail("adaptive encoding is not deterministic")

    def policy_mutation(spec: dict, case: str) -> None:
        policy = spec["privateMemoryPolicy"]
        if case == "fixed-conflict":
            spec["instances"][0]["privatePageQuota"] = 1
        elif case == "duplicate-subject":
            policy["subjects"].append(copy.deepcopy(policy["subjects"][0]))
        elif case == "unknown-entitlement":
            policy["subjects"][0]["entitlement"] = "missing"
        elif case == "outside-subtree":
            policy["subjects"][0]["instance"] = "init"
        elif case == "maximum-below-guarantee":
            policy["entitlements"][0].update(maximumMode="fixed", maximumPages=1)
        elif case == "unknown-version":
            policy["formatVersion"] = 3
        elif case == "overflow":
            policy["entitlements"][0]["guaranteePages"] = private_memory_policy.MAX_PAGES + 1
        elif case == "implicit-pool-value":
            policy["subjects"][0]["maximumPages"] = 1

    for case, reason in (
        ("fixed-conflict", "conflicts with effective fixed privatePageQuota"),
        ("duplicate-subject", "unknown or duplicate subject"),
        ("unknown-entitlement", "unknown entitlement"),
        ("outside-subtree", "subject outside declared subtree"),
        ("maximum-below-guarantee", "guarantee exceeds maximum"),
        ("unknown-version", "unsupported version"),
        ("overflow", "invalid guaranteePages"),
        ("implicit-pool-value", "invalid maximum mode/value"),
    ):
        altered = copy.deepcopy(adaptive_spec)
        policy_mutation(altered, case)
        try:
            memory_manifest(altered)
        except SystemSpecError as error:
            if reason not in str(error):
                fail(f"adaptive policy {case} refused at the wrong boundary: {error}")
            refusals += 1
        else:
            fail(f"adaptive policy accepted {case}")

    for case in ("dual-declaration", "dual-resource", "missing-resource", "orphan-resource"):
        altered = copy.deepcopy(adaptive_manifest)
        if case == "dual-declaration":
            altered["privateMemoryBudget"] = []
        elif case == "dual-resource":
            altered["objects"].append({"id": "private-memory-budget", "kind": "resource", "size": 4096})
        elif case == "missing-resource":
            altered["objects"] = [entry for entry in altered["objects"] if entry["id"] != "private-memory-policy"]
        else:
            del altered["privateMemoryPolicy"]
        try:
            private_memory_policy.manifest_policy(altered)
        except ValueError:
            refusals += 1
        else:
            fail(f"adaptive manifest accepted {case}")

    narrowed_instances = [entry for entry in adaptive_manifest["instances"]
                          if not entry["name"].endswith(("-b", "-c", "-d"))]
    narrowed_policy = private_memory_policy.narrow(adaptive, narrowed_instances)
    if len(narrowed_policy["subjects"]) != 1 or narrowed_policy["entitlements"][0]["guaranteePages"] != 2:
        fail("profile narrowing changed a shared guarantee or retained removed members")

# The loan-field exception must refuse drift independently of the frozen
# comparison, and must not conceal changes outside its exact scope.
loan_system_name = "sel4-private-memory-isolation"
loan_system = systems[loan_system_name]
loan_source = derive_manifest(loan_system)
loan_manifest = normalized(loan_source)
check_post_baseline(loan_system_name, loan_manifest, loan_system, loan_source)
loan_holder = "private-memory-1g-holder-c"
for mutation in ("changed", "missing", "duplicate"):
    altered = copy.deepcopy(loan_manifest)
    budget = next(entry for entry in altered["sharedBufferBudget"] if entry["holder"] == loan_holder)
    if mutation == "changed":
        budget["loanCount"] += 1
    elif mutation == "missing":
        del budget["loanCount"]
    else:
        altered["sharedBufferBudget"].append(copy.deepcopy(budget))
    try:
        check_post_baseline(loan_system_name, altered, loan_system, loan_source)
    except SystemExit as error:
        if "post-baseline sharedBufferBudget" not in str(error):
            raise
    else:
        fail(f"{mutation} post-baseline loan budget was accepted")
    refusals += 1

for name, holder, field in (
    (loan_system_name, loan_holder, "bufferCount"),
    (loan_system_name, "private-memory-1g-holder-b", "loanCount"),
    ("sel4-private-memory", loan_holder, "loanCount"),
):
    altered = copy.deepcopy(loan_manifest)
    budget = next(entry for entry in altered["sharedBufferBudget"] if entry["holder"] == holder)
    budget[field] += 1
    if split_post_baseline(altered, name)[0] == split_post_baseline(loan_manifest, name)[0]:
        fail(f"post-baseline exception concealed unrelated {name}/{holder}.{field} drift")
    refusals += 1

# Network exceptions reject derivation drift and invalid authority, while
# allowing the owning declarations to evolve without a second policy copy.
network_name = "sel4-io-tcp"
network_system = systems[network_name]
network_manifest = normalized(derive_manifest(network_system))
# Coherent changes to live policy are not frozen-baseline drift.
for mutation in ("stack", "budget", "lifecycle", "application", "pin"):
    changed = copy.deepcopy(network_system)
    if mutation == "stack":
        next(entry for entry in changed.spec["placements"]
             if entry["component"] == "network-service")["stackBytes"] = 262144
    elif mutation == "budget":
        next(entry for entry in changed.spec["placements"]
             if entry["component"] == "io-tcp-probe")["loanCount"] += 1
    elif mutation == "lifecycle":
        changed.spec["lifecyclePolicy"]["parameters"][0]["write"] = False
    elif mutation == "application":
        changed.spec["networkApplications"][0]["backend"] = "loopback"
    else:
        next(entry for entry in changed.spec["slotPins"]
             if entry["holder"] == "network-service"
             and entry["grant"] == "network-tcp-probe-provision")["slot"] = 29
    check_network_post_baseline(network_name, normalized(derive_manifest(changed)), changed)

# Coherent derivation cannot legitimize invalid authority in a live spec.
for grant_name, field, value in (
    ("network-tcp-probe-service", "transferable", True),
    ("network-tcp-probe-provision", "transferable", False),
    ("network-tcp-probe-provision", "rights", ["send"]),
):
    changed = copy.deepcopy(network_system)
    next(entry for entry in changed.spec["grants"] if entry["name"] == grant_name)[field] = value
    try:
        check_network_post_baseline(network_name, normalized(derive_manifest(changed)), changed)
    except SystemExit as error:
        if "network post-baseline" not in str(error):
            raise
    else:
        fail(f"network post-baseline accepted invalid live {grant_name}.{field}")
    refusals += 1

network_cases = (
    ("stack", "executables", "name", "network-service", "stackBytes", 262144),
    ("provision rights", "grants", "name", "network-tcp-probe-provision", "rights", ["send"]),
    ("control transfer", "grants", "name", "network-tcp-probe-service", "transferable", True),
    ("service pages", "sharedBufferBudget", "holder", "network-service", "bytePages", 13),
    ("client mapping", "sharedBufferBudget", "holder", "io-tcp-probe", "mappingCount", 3),
)
for label, section, key, identity, field, value in network_cases:
    altered = copy.deepcopy(network_manifest)
    next(entry for entry in altered[section] if entry[key] == identity)[field] = value
    try:
        check_network_post_baseline(network_name, altered, network_system)
    except SystemExit as error:
        if "network post-baseline" not in str(error):
            raise
    else:
        fail(f"network post-baseline accepted {label} drift")
    refusals += 1

for mutation in ("missing grant", "missing budget", "duplicate budget", "pin", "live grant", "live budget"):
    altered = copy.deepcopy(network_manifest)
    altered_system = copy.deepcopy(network_system)
    if mutation == "missing grant":
        altered["grants"] = [entry for entry in altered["grants"]
                             if entry["name"] != "network-tcp-probe-provision"]
    elif mutation == "missing budget":
        altered["sharedBufferBudget"] = [entry for entry in altered["sharedBufferBudget"]
                                         if entry["holder"] != "io-tcp-probe"]
    elif mutation == "duplicate budget":
        altered["sharedBufferBudget"].append(copy.deepcopy(next(
            entry for entry in altered["sharedBufferBudget"] if entry["holder"] == "io-tcp-probe")))
    elif mutation == "pin":
        next(binding for instance in altered["instances"] if instance["name"] == "network-service"
             for binding in instance["bindings"] if binding["grant"] == "network-tcp-probe-provision")["slot"] = 29
    elif mutation == "live grant":
        next(entry for entry in altered_system.spec["grants"]
             if entry["name"] == "network-tcp-probe-provision")["transferable"] = False
    else:
        next(entry for entry in altered_system.spec["placements"]
             if entry["component"] == "io-tcp-probe")["loanCount"] = 3
    try:
        check_network_post_baseline(network_name, altered, altered_system)
    except SystemExit as error:
        if "network post-baseline" not in str(error):
            raise
    else:
        fail(f"network post-baseline accepted {mutation}")
    refusals += 1

for name, section, key, identity, field in (
    (network_name, "executables", "name", "io-tcp-probe", "stackBytes"),
    (network_name, "executables", "name", "network-service", "spawnBudget"),
    (network_name, "sharedBufferBudget", "holder", "network-service", "mappingCount"),
    (network_name, "grants", "name", "network-tcp-probe-service", "transferable"),
    ("sel4-io-network", "sharedBufferBudget", "holder", "network-service", "loanCount"),
    ("sel4-product", "executables", "name", "network-service", "stackBytes"),
):
    altered = copy.deepcopy(network_manifest)
    entry = next(entry for entry in altered[section] if entry[key] == identity)
    entry[field] = 999
    if split_post_baseline(altered, name)[0] == split_post_baseline(network_manifest, name)[0]:
        fail(f"network post-baseline concealed unrelated {name}/{identity}.{field} drift")
    refusals += 1

for mutation in ("missing application", "changed application", "missing object", "changed object", "live resource"):
    altered = copy.deepcopy(network_manifest)
    altered_system = copy.deepcopy(network_system)
    if mutation == "missing application":
        del altered["networkApplications"]
    elif mutation == "changed application":
        altered["networkApplications"][0]["backend"] = "loopback"
    elif mutation == "missing object":
        altered["objects"] = [entry for entry in altered["objects"] if entry["id"] != "network-application"]
    elif mutation == "changed object":
        next(entry for entry in altered["objects"] if entry["id"] == "network-application")["size"] = 8192
    else:
        altered_system.spec["networkApplicationsObject"] = False
    try:
        check_network_post_baseline(network_name, altered, altered_system)
    except SystemExit as error:
        if "network post-baseline" not in str(error):
            raise
    else:
        fail(f"network post-baseline accepted {mutation}")
    refusals += 1
for section in ("networkApplications", "objects"):
    altered = copy.deepcopy(network_manifest)
    if section == "networkApplications":
        altered[section][0]["backend"] = "loopback"
    else:
        next(entry for entry in altered[section] if entry["id"] == "network-application")["size"] = 8192
    if split_post_baseline(altered, "sel4-io-network")[0] == split_post_baseline(network_manifest, "sel4-io-network")[0]:
        fail(f"network application exception concealed another system's {section}")
    refusals += 1

for mutation in ("foreign holder", "foreign subject", "read-only", "added dependency", "missing policy", "missing lifecycle object"):
    altered = copy.deepcopy(network_manifest)
    if mutation == "missing policy":
        del altered["lifecyclePolicy"]
    elif mutation == "missing lifecycle object":
        altered["objects"] = [entry for entry in altered["objects"] if entry["id"] != "lifecycle-policy"]
    elif mutation == "added dependency":
        altered["lifecyclePolicy"]["dependencies"].append({"subject": "init", "dependsOn": "network-service"})
    else:
        key, value = {"foreign holder": ("holder", "io-tcp-probe"),
                      "foreign subject": ("subject", "io-tcp-probe"), "read-only": ("write", False)}[mutation]
        altered["lifecyclePolicy"]["parameters"][0][key] = value
    try:
        check_network_post_baseline(network_name, altered, network_system)
    except SystemExit as error:
        if "network post-baseline" not in str(error):
            raise
    else:
        fail(f"network post-baseline accepted lifecycle {mutation}")
    refusals += 1
for section in ("lifecyclePolicy", "objects"):
    altered = copy.deepcopy(network_manifest)
    if section == "lifecyclePolicy":
        altered[section]["parameters"][0]["write"] = False
    else:
        next(entry for entry in altered[section] if entry["id"] == "lifecycle-policy")["size"] = 8192
    if split_post_baseline(altered, "sel4-io-network")[0] == split_post_baseline(network_manifest, "sel4-io-network")[0]:
        fail(f"network lifecycle exception concealed another system's {section}")
    refusals += 1

refusals += network_application_controls(derive_manifest(systems["sel4-io-tcp"]))


def instance_lifetime_controls(source: dict) -> int:
    """The lifetime encoder names exactly the resident instances, and refuses the rest."""
    import boot_contracts as wire

    manifest = copy.deepcopy(source)
    encoded = BUILDER.build_instance_lifetime(manifest)
    residents = sorted(
        BUILDER.instance_lifetime_identity(entry["name"])
        for entry in manifest["instances"]
        if entry["lifetime"] == "resident"
    )
    rows = [
        encoded[offset : offset + 32]
        for offset in range(
            wire.INSTANCE_LIFETIME_HEADER_BYTES, len(encoded), wire.INSTANCE_LIFETIME_ENTRY_BYTES
        )
    ]
    if not residents or rows != residents:
        fail("instance lifetime encoder did not emit exactly the sorted resident instances")
    reverse = copy.deepcopy(manifest)
    reverse["instances"].reverse()
    if BUILDER.build_instance_lifetime(reverse) != encoded:
        fail("instance lifetime encoding depends on authoring order")
    refused = 0
    for label, mutate, reason in (
        ("an unknown lifetime", lambda altered: altered["instances"][0].update(lifetime="forever"), "invalid lifetime"),
        (
            "a table naming nobody",
            lambda altered: [entry.update(lifetime="bounded") for entry in altered["instances"]],
            "without a resident instance",
        ),
    ):
        altered = copy.deepcopy(manifest)
        mutate(altered)
        try:
            BUILDER.build_instance_lifetime(altered)
        except SystemExit as error:
            if reason not in str(error):
                fail(f"instance lifetime {label} refused at wrong boundary: {error}")
        else:
            fail(f"instance lifetime encoder accepted {label}")
        refused += 1
    return refused


refusals += instance_lifetime_controls(derive_manifest(systems["sel4-lifetime"]))


def entropy_authority_controls(system) -> int:
    """The entropy encoder emits exactly the declared rows and refuses every malformed table or grant."""
    import boot_contracts as wire

    manifest = derive_manifest(system)
    encoded = BUILDER.build_entropy_authority(manifest)
    rows = manifest["entropyAuthority"]
    expected_length = wire.ENTROPY_AUTHORITY_HEADER_BYTES + len(rows) * wire.ENTROPY_AUTHORITY_ENTRY_BYTES
    if not rows or len(encoded) != expected_length or wire.ENTROPY_AUTHORITY_HEADER.unpack_from(encoded) != (
        wire.ENTROPY_AUTHORITY_MAGIC, wire.ENTROPY_AUTHORITY_VERSION, wire.ENTROPY_AUTHORITY_HEADER_BYTES, 0,
        len(rows), expected_length,
    ):
        fail("entropy authority encoder changed the generated header or entry bounds")
    decoded = [
        wire.ENTROPY_AUTHORITY_ENTRY.unpack_from(
            encoded, wire.ENTROPY_AUTHORITY_HEADER_BYTES + index * wire.ENTROPY_AUTHORITY_ENTRY_BYTES
        )
        for index in range(len(rows))
    ]
    if [entry[0] for entry in decoded] != sorted({entry[0] for entry in decoded}):
        fail("entropy authority encoder did not emit strictly ordered holders")
    by_name = {entry[1][: entry[2]].decode("ascii"): entry for entry in decoded}
    for row in rows:
        identity, _, _, source, reserved, budget, seed = by_name[row["holder"]]
        if (
            identity != BUILDER.entropy_authority_holder_identity(row["holder"])
            or source != BUILDER.ENTROPY_SOURCES[row["source"]]
            or reserved != bytes(2)
            or budget != row["byteBudget"]
            or seed != bytes.fromhex(row.get("seed", "00" * wire.ENTROPY_AUTHORITY_SEED_BYTES))
        ):
            fail(f"entropy authority encoder misplaced {row['holder']}'s declared row")
    reverse = copy.deepcopy(manifest)
    reverse["entropyAuthority"].reverse()
    reverse["grants"].reverse()
    if BUILDER.build_entropy_authority(reverse) != encoded:
        fail("entropy authority encoding depends on authoring order")

    def row(altered: dict, holder: str) -> dict:
        return next(entry for entry in altered["entropyAuthority"] if entry["holder"] == holder)

    def grant(altered: dict, name: str) -> dict:
        return next(entry for entry in altered["grants"] if entry["name"] == name)

    def endpoint(name: str, source: str, **fields) -> dict:
        return dict({"name": name, "capabilityKind": "endpoint", "source": source, "target": "entropy-service",
                     "rights": ["send", "recv"], "transferable": False}, **fields)

    seed = row(manifest, "entropy-seeded")["seed"]
    refused = 0
    for label, mutate, reason in (
        ("an unknown source", lambda value: row(value, "entropy-hw-a").update(source="device"), "unknown source"),
        ("a zero budget", lambda value: row(value, "entropy-hw-a").update(byteBudget=0), "byteBudget outside"),
        ("a budget above the bound", lambda value: row(value, "entropy-seeded").update(
            byteBudget=wire.ENTROPY_AUTHORITY_MAX_BYTE_BUDGET + 1), "byteBudget outside"),
        ("a boolean budget", lambda value: row(value, "entropy-hw-a").update(byteBudget=True), "byteBudget outside"),
        ("a seed on a hardware row", lambda value: row(value, "entropy-hw-a").update(seed=seed), "declares a seed"),
        ("an empty seed on a hardware row", lambda value: row(value, "entropy-hw-b").update(seed=""), "declares a seed"),
        ("a seeded row without a seed", lambda value: row(value, "entropy-seeded").pop("seed"), "64 lowercase hex"),
        ("an uppercase seed", lambda value: row(value, "entropy-seeded").update(seed=seed.upper()), "64 lowercase hex"),
        ("a short seed", lambda value: row(value, "entropy-seeded").update(seed=seed[:-2]), "64 lowercase hex"),
        ("a non-hex seed", lambda value: row(value, "entropy-seeded").update(seed="g" + seed[1:]), "64 lowercase hex"),
        ("a duplicate holder", lambda value: value["entropyAuthority"].append(
            copy.deepcopy(row(value, "entropy-hw-a"))), "duplicate holder"),
        ("an undeclared holder", lambda value: value["entropyAuthority"].append(
            {"holder": "entropy-ghost", "source": "hardware", "byteBudget": 96}), "not a declared instance"),
        ("the service as holder", lambda value: (
            value["entropyAuthority"].append({"holder": "entropy-service", "source": "hardware", "byteBudget": 96}),
            value["grants"].append(endpoint("entropy-service-entropy", "entropy-service"))), "may not hold"),
        ("the driver as holder", lambda value: (
            value["entropyAuthority"].append({"holder": "virtio-rng-driver", "source": "hardware", "byteBudget": 96}),
            value["grants"].append(endpoint("virtio-rng-driver-entropy", "virtio-rng-driver"))), "may not hold"),
        ("a missing service instance", lambda value: value.update(
            instances=[entry for entry in value["instances"] if entry["name"] != "entropy-service"]), "no entropy-service"),
        ("a transferable holder endpoint", lambda value: grant(value, "entropy-hw-a-entropy").update(
            transferable=True), "is transferable"),
        ("a misnamed holder endpoint", lambda value: grant(value, "entropy-hw-a-entropy").update(
            name="entropy-hw-a-draw"), "is not named"),
        ("a send-only holder endpoint", lambda value: grant(value, "entropy-hw-b-entropy").update(
            rights=["send"]), "exactly send and recv"),
        ("a widened holder endpoint", lambda value: grant(value, "entropy-hw-b-entropy").update(
            rights=["send", "recv", "grant"]), "exactly send and recv"),
        ("an endpoint from a holder with no row", lambda value: value["grants"].append(
            endpoint("entropy-intruder-entropy", "entropy-intruder")), "with no row"),
        ("a row without its endpoint", lambda value: value.update(
            grants=[entry for entry in value["grants"] if entry["name"] != "entropy-seeded-entropy"]), "not exactly one"),
        ("a row with two endpoints", lambda value: value["grants"].append(
            endpoint("entropy-seeded-entropy", "entropy-seeded")), "not exactly one"),
        ("a holder name above the entry field", lambda value: (
            value["instances"].append(dict(next(entry for entry in value["instances"] if entry["name"] == "entropy-hw-a"),
                                           name="h" * (wire.ENTROPY_AUTHORITY_HOLDER_NAME_BYTES + 1))),
            value["entropyAuthority"].append({"holder": "h" * (wire.ENTROPY_AUTHORITY_HOLDER_NAME_BYTES + 1),
                                              "source": "hardware", "byteBudget": 96})), "printable ASCII"),
        ("rows above the holder bound", lambda value: value["entropyAuthority"].extend(
            {"holder": f"entropy-extra-{index}", "source": "hardware", "byteBudget": 96}
            for index in range(wire.MAX_ENTROPY_AUTHORITY_HOLDERS)), "holder bound"),
    ):
        altered = copy.deepcopy(manifest)
        mutate(altered)
        try:
            BUILDER.build_entropy_authority(altered)
        except SystemExit as error:
            if reason not in str(error):
                fail(f"entropy authority {label} refused at wrong boundary: {error}")
        else:
            fail(f"entropy authority encoder accepted {label}")
        refused += 1
    # The spec-admission half: a populated table needs its object, and a row
    # must name an admitted instance before anything is encoded.
    for label, mutate, reason in (
        ("a table without its resource object", lambda spec: spec.update(entropyAuthorityObject=False),
         "requires its resource object"),
        ("an unadmitted holder", lambda spec: spec["entropyAuthority"].append(
            {"holder": "entropy-ghost", "source": "hardware", "byteBudget": 96}), "is not admitted"),
        ("an encoder refusal at admission", lambda spec: spec["entropyAuthority"][0].update(source="device"),
         "unknown source"),
    ):
        altered_system = copy.deepcopy(system)
        mutate(altered_system.spec)
        try:
            validate_authority_sections(altered_system.spec, set(instance_names(altered_system.spec)))
            derive_manifest(altered_system)
        except SystemSpecError as error:
            if reason not in str(error):
                fail(f"entropy authority spec {label} refused at wrong boundary: {error}")
        else:
            fail(f"system spec admitted entropy authority with {label}")
        refused += 1
    return refused


refusals += entropy_authority_controls(systems["sel4-entropy"])
refusals += zenoh_grants_builder_exam.controls(systems["sel4-zenoh"])[1]

parameter_instance = {"name": "network-service", "bindings": []}
parameter_executable = {"role": "service", "spawnBudget": 0}
base_services = {BUILDER.SERVICE_LIFECYCLE, BUILDER.SERVICE_CONSOLE}
for parameter_holders, expected in (
    (frozenset(), base_services),
    (frozenset({"other"}), base_services),
    (frozenset({"network-service"}), base_services | {BUILDER.SERVICE_SUPERVISION}),
):
    actual = BUILDER.declared_services(parameter_instance, parameter_executable, {}, [], set(), set(), parameter_holders)
    if actual != expected:
        fail(f"parameter transport declaration widened or omitted services: {actual} != {expected}")
    refusals += 1
if BUILDER.declared_services(parameter_instance, parameter_executable, {}, [], set(), set()) != base_services:
    fail("absent parameter declarations implicitly granted supervision transport")

print(
    f"system spec derivation: {len(systems)} systems compiled and "
    f"{len(DERIVED_FIXTURES)} generation manifests derived semantically identical to "
    f"their committed fixtures; {refusals} named mutations and "
    f"{computed_refusals} computed-source controls refused"
)

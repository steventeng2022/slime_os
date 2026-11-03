#!/usr/bin/env python3

from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from zutai_cli import STDLIB, binary

from harness import ROOT

OUTPUT = ROOT / "scripts" / "lib" / "boot_contracts.py"
RUST_OUTPUT_DIR = ROOT / "boot-contracts" / "src" / "generated"
GENERATORS = (
    (ROOT / "contracts" / "generation" / "v5" / "schema.zt", "generation.py", "generation.rs"),
    (ROOT / "contracts" / "kernel-image" / "v2" / "schema.zt", "kernel_image.py", "kernel_image.rs"),
    (
        ROOT / "contracts" / "target-profile" / "v1" / "schema.zt",
        "target_profile.py",
        "target_profile.rs",
    ),
    (
        ROOT / "contracts" / "component" / "v2" / "schema.zt",
        "component_image.py",
        "component_image.rs",
    ),
    (ROOT / "contracts" / "bootstate" / "v1" / "schema.zt", "bootstate.py", "bootstate.rs"),
    (
        ROOT / "contracts" / "bootstate" / "trace" / "v1" / "schema.zt",
        "bootstate_trace.py",
        "bootstate_trace.rs",
    ),
    (ROOT / "contracts" / "release" / "v1" / "schema.zt", "release.py", "release.rs"),
    (ROOT / "contracts" / "recovery" / "v1" / "schema.zt", "recovery.py", "recovery.rs"),
    (ROOT / "contracts" / "transfer" / "v1" / "schema.zt", "transfer.py", "transfer.rs"),
    (ROOT / "contracts" / "store" / "disk" / "v1" / "schema.zt", "store_disk.py", "store_disk.rs"),
    (
        ROOT / "contracts" / "shared-buffer-budget" / "v1" / "schema.zt",
        "shared_buffer_budget.py",
        "shared_buffer_budget.rs",
    ),
    (
        ROOT / "contracts" / "private-memory-budget" / "v1" / "schema.zt",
        "private_memory_budget.py",
        "private_memory_budget.rs",
    ),
    (
        ROOT / "contracts" / "private-memory-budget" / "v2" / "schema.zt",
        "private_memory_policy.py",
        "private_memory_policy.rs",
    ),
    (
        ROOT / "contracts" / "clock-authority" / "v2" / "schema.zt",
        "clock_authority.py",
        "clock_authority.rs",
    ),
    (
        ROOT / "contracts" / "wait-set" / "v2" / "schema.zt",
        "wait_set.py",
        "wait_set.rs",
    ),
    (
        ROOT / "contracts" / "scheduling-class" / "v1" / "schema.zt",
        "scheduling_class.py",
        "scheduling_class.rs",
    ),
    (
        ROOT / "contracts" / "lifecycle-policy" / "v1" / "schema.zt",
        "lifecycle_policy.py",
        "lifecycle_policy.rs",
    ),
    (
        ROOT / "contracts" / "recording-policy" / "v1" / "schema.zt",
        "recording_policy.py",
        "recording_policy.rs",
    ),
    (
        ROOT / "contracts" / "fabric-graph" / "v1" / "schema.zt",
        "fabric_graph.py",
        "fabric_graph.rs",
    ),
    (
        ROOT / "contracts" / "boot-layout" / "v1" / "schema.zt",
        "boot_layout.py",
        "boot_layout.rs",
    ),
    (
        ROOT / "contracts" / "normalized-interface-schemas" / "v1" / "schema.zt",
        "normalized_interface_schemas.py",
        "normalized_interface_schemas.rs",
    ),
    (
        ROOT / "contracts" / "io-resource" / "v1" / "schema.zt",
        "io_resource.py",
        "io_resource.rs",
    ),
    (
        ROOT / "contracts" / "network-application" / "v4" / "schema.zt",
        "network_application.py",
        "network_application.rs",
    ),
    (
        ROOT / "contracts" / "network-destination" / "v1" / "schema.zt",
        "network_destination.py",
        "network_destination.rs",
    ),
    (
        ROOT / "contracts" / "block-authority" / "v1" / "schema.zt",
        "block_authority.py",
        "block_authority.rs",
    ),
    (
        ROOT / "contracts" / "network-interface" / "v1" / "schema.zt",
        "network_interface.py",
        "network_interface.rs",
    ),
    (
        ROOT / "contracts" / "instance-lifetime" / "v1" / "schema.zt",
        "instance_lifetime.py",
        "instance_lifetime.rs",
    ),
    (
        ROOT / "contracts" / "entropy-authority" / "v1" / "schema.zt",
        "entropy_authority.py",
        "entropy_authority.rs",
    ),
    (
        ROOT / "contracts" / "graph-arrival-ceiling" / "v1" / "schema.zt",
        "graph_arrival_ceiling.py",
        "graph_arrival_ceiling.rs",
    ),
)
INVALID_SCHEMA = "INVALID_"
HEADER = """# @generated from boot contract schemas; do not edit.
from __future__ import annotations

import hashlib
import struct
import typing

"""
HELPERS = """def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def generation_identity(data: bytes) -> bytes:
    return sha256(
        data[:GENERATION_HEADER_IDENTITY_OFFSET]
        + bytes(GENERATION_HEADER_IDENTITY_END - GENERATION_HEADER_IDENTITY_OFFSET)
        + data[GENERATION_HEADER_IDENTITY_END:]
    )


def bootstate_checksum(slot: bytes) -> bytes:
    return sha256(
        slot[:BOOTSTATE_CHECKSUM_OFFSET]
        + bytes(BOOTSTATE_CHECKSUM_END - BOOTSTATE_CHECKSUM_OFFSET)
        + slot[BOOTSTATE_CHECKSUM_END:]
    )


def bootstore_checksum(data: bytes) -> bytes:
    offset = BOOTSTORE_DIRECTORY_OFFSET + BOOTSTORE_HEADER_CHECKSUM_OFFSET
    end = BOOTSTORE_DIRECTORY_OFFSET + BOOTSTORE_HEADER_CHECKSUM_END
    return sha256(data[BOOTSTATE_SLOT_BYTES * BOOTSTATE_SLOT_COUNT : offset] + bytes(end - offset) + data[end:])
"""


def run_generator(generator: Path, staging: Path) -> None:
    environment = os.environ.copy()
    environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
    environment["SLIME_BOOT_BINDINGS_ROOT"] = str(staging)
    # The component schema renders for two consumers and defaults this root to
    # the working directory, which would let a staging run overwrite the real
    # proto binding with unformatted output. Every generator output stays staged.
    environment["SLIME_COMPONENT_BINDINGS_ROOT"] = str(staging)
    process = subprocess.run(
        [str(binary()), "run", str(generator)],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        sys.stderr.write(process.stdout)
        sys.stderr.write(process.stderr)
        raise SystemExit(process.returncode)


def format_rust(source: str) -> str:
    process = subprocess.run(
        ["rustfmt", "--edition", "2024", "--emit", "stdout"],
        cwd=ROOT,
        input=source,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        sys.stderr.write(process.stderr)
        raise SystemExit(process.returncode)
    return process.stdout


def render() -> tuple[str, dict[Path, str]]:
    with tempfile.TemporaryDirectory(prefix="slime-boot-bindings-") as temporary:
        staging = Path(temporary)
        # The component schema also renders the proto binding at its own nested
        # path; stage that tree so a boot run never writes outside `staging`.
        (staging / "components" / "proto" / "src").mkdir(parents=True)
        for generator, _, _ in GENERATORS:
            run_generator(generator, staging)

        fragments = []
        rust_outputs: dict[Path, str] = {}
        for _, python_name, rust_name in GENERATORS:
            path = staging / python_name
            if not path.exists():
                raise SystemExit(f"boot generator did not write {python_name}")
            fragment = path.read_text(encoding="utf-8")
            if INVALID_SCHEMA in fragment:
                raise SystemExit(f"boot schema reflection/layout validation failed in {python_name}")
            fragments.append(fragment.rstrip() + "\n\n")

            rust_path = staging / rust_name
            if not rust_path.exists():
                raise SystemExit(f"boot generator did not write {rust_name}")
            rust_fragment = rust_path.read_text(encoding="utf-8")
            if INVALID_SCHEMA in rust_fragment:
                raise SystemExit(f"boot schema reflection/layout validation failed in {rust_name}")
            rust_outputs[RUST_OUTPUT_DIR / rust_name] = format_rust(rust_fragment)

        return HEADER + "".join(fragments) + HELPERS, rust_outputs


def write_atomic(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(contents, encoding="utf-8")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the checked-in bindings are stale",
    )
    arguments = parser.parse_args()
    generated, rust_outputs = render()
    if arguments.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != generated:
            raise SystemExit("generated boot bindings are stale; run `just boot_gen`")
        for path, contents in rust_outputs.items():
            if not path.exists() or path.read_text(encoding="utf-8") != contents:
                raise SystemExit(
                    f"generated {path.relative_to(ROOT)} is stale; run `just boot_gen`"
                )
        print("Boot contract bindings are current")
        return
    write_atomic(OUTPUT, generated)
    print(f"Generated {OUTPUT.relative_to(ROOT)}")
    for path, contents in rust_outputs.items():
        write_atomic(path, contents)
        print(f"Generated {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

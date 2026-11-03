from __future__ import annotations

import struct
import ipaddress
import boot_contracts as wire_contracts

from boot_contracts import (
    BLOCK_AUTHORITY_ENTRY,
    BLOCK_AUTHORITY_ENTRY_BYTES,
    BLOCK_AUTHORITY_HEADER,
    BLOCK_AUTHORITY_HEADER_BYTES,
    BLOCK_AUTHORITY_MAGIC,
    BLOCK_AUTHORITY_VERSION,
    BLOCK_RIGHT_READ,
    BLOCK_RIGHT_WRITE,
    CLOCK_AUTHORITY_ENTRY,
    CLOCK_AUTHORITY_ENTRY_BYTES,
    CLOCK_AUTHORITY_HEADER,
    CLOCK_AUTHORITY_HEADER_BYTES,
    CLOCK_AUTHORITY_MAGIC,
    CLOCK_AUTHORITY_MAX_HOLDERS,
    CLOCK_AUTHORITY_MAX_LIVE_TIMERS,
    CLOCK_AUTHORITY_MAX_LIVE_TIMERS_PER_HOLDER,
    CLOCK_AUTHORITY_VERSION,
    FABRIC_GRAPH_KERNEL_LOANS,
    FABRIC_GRAPH_KERNEL_MAPPINGS,
    FABRIC_GRAPH_KERNEL_SHARED_BUFFERS,
    FABRIC_GRAPH_KERNEL_TOTAL_PAGES,
    GENERATION_RIGHT_BY_MANIFEST_NAME,
    GENERATION_RIGHT_UNRECORDED,
    LIFECYCLE_CAUSE_ID_BY_MANIFEST_NAME,
    LIFECYCLE_DEPENDENCY,
    LIFECYCLE_DEPENDENCY_BYTES,
    LIFECYCLE_PARAMETER_GRANT,
    LIFECYCLE_PARAMETER_GRANT_BYTES,
    LIFECYCLE_PARAMETER_READ,
    LIFECYCLE_PARAMETER_WRITE,
    LIFECYCLE_POLICY_BACKOFF_FACTOR_SCALE,
    LIFECYCLE_POLICY_HEADER,
    LIFECYCLE_POLICY_HEADER_BYTES,
    LIFECYCLE_POLICY_MAGIC,
    LIFECYCLE_POLICY_MAX_BACKOFF_FACTOR,
    LIFECYCLE_POLICY_MAX_BACKOFF_NS,
    LIFECYCLE_POLICY_MAX_DEPENDENCIES,
    LIFECYCLE_POLICY_MAX_INSTANCES,
    LIFECYCLE_POLICY_MAX_PARAMETER_GRANTS,
    LIFECYCLE_POLICY_MAX_RESTART_ATTEMPTS,
    LIFECYCLE_POLICY_MAX_TRANSITIONS,
    LIFECYCLE_POLICY_VERSION,
    LIFECYCLE_RESTART,
    LIFECYCLE_RESTART_BYTES,
    LIFECYCLE_STATE_ID_BY_MANIFEST_NAME,
    LIFECYCLE_TRANSITION,
    LIFECYCLE_TRANSITION_BYTES,
    IO_RESOURCE_ENTRY,
    IO_RESOURCE_HEADER,
    IO_RESOURCE_HEADER_BYTES,
    IO_RESOURCE_MAGIC,
    IO_RESOURCE_VERSION,
    MAX_BLOCK_RINGS,
    MAX_BLOCK_RINGS_PER_HOLDER,
    MAX_IO_RESOURCE_DRIVERS,
    MAX_PRIVATE_MEMORY_BUDGET_HOLDERS,
    MAX_SHARED_BUFFER_BUDGET_HOLDERS,
    MAX_NETWORK_DESTINATIONS,
    MAX_NETWORK_DESTINATIONS_PER_HOLDER,
    MAX_NETWORK_NAME_BYTES,
    NETWORK_DESTINATION_ENTRY,
    NETWORK_DESTINATION_ENTRY_BYTES,
    NETWORK_DESTINATION_HEADER,
    NETWORK_DESTINATION_HEADER_BYTES,
    NETWORK_DESTINATION_MAGIC,
    NETWORK_DESTINATION_VERSION,
    NETWORK_INTERFACE_ENTRY,
    NETWORK_INTERFACE_ENTRY_BYTES,
    NETWORK_INTERFACE_HEADER,
    NETWORK_INTERFACE_HEADER_BYTES,
    NETWORK_INTERFACE_MAGIC,
    NETWORK_INTERFACE_MAX_PREFIX_LEN,
    NETWORK_INTERFACE_MIN_PREFIX_LEN,
    NETWORK_INTERFACE_VERSION,
    MAX_NETWORK_INTERFACES,
    PRIVATE_MEMORY_BUDGET_ENTRY,
    PRIVATE_MEMORY_BUDGET_ENTRY_BYTES,
    PRIVATE_MEMORY_BUDGET_HEADER,
    PRIVATE_MEMORY_BUDGET_HEADER_BYTES,
    PRIVATE_MEMORY_BUDGET_MAGIC,
    PRIVATE_MEMORY_BUDGET_VERSION,
    PRIVATE_MEMORY_CAPACITY_PROFILES,
    PRIVATE_MEMORY_DEFAULT_REGION_PAGES,
    PRIVATE_MEMORY_DEFAULT_TOTAL_PAGES,
    RECORDING_POLICY_ENTRY,
    RECORDING_POLICY_ENTRY_BYTES,
    RECORDING_POLICY_FLAG_DETERMINISTIC,
    RECORDING_POLICY_HEADER,
    RECORDING_POLICY_HEADER_BYTES,
    RECORDING_POLICY_MAGIC,
    RECORDING_POLICY_MAX_INSTANCES,
    RECORDING_POLICY_MAX_RECORD_CAPACITY,
    RECORDING_POLICY_ROLE_BY_MANIFEST_NAME,
    RECORDING_POLICY_ROLE_RECORD,
    RECORDING_POLICY_ROLE_REPLAY,
    RECORDING_POLICY_VERSION,
    SCHEDULING_CLASS_BAND,
    SCHEDULING_CLASS_BAND_BYTES,
    SCHEDULING_CLASS_ENTRY,
    SCHEDULING_CLASS_ENTRY_BYTES,
    SCHEDULING_CLASS_HEADER,
    SCHEDULING_CLASS_HEADER_BYTES,
    SCHEDULING_CLASS_ID_BY_MANIFEST_NAME,
    SCHEDULING_CLASS_MAGIC,
    SCHEDULING_CLASS_MAX_CLASSES,
    SCHEDULING_CLASS_MAX_INSTANCES,
    SCHEDULING_CLASS_MAX_PROMOTIONS,
    SCHEDULING_CLASS_VERSION,
    SCHEDULING_PROMOTION_ENTRY,
    SCHEDULING_PROMOTION_ENTRY_BYTES,
    SHARED_BUFFER_BUDGET_ENTRY,
    SHARED_BUFFER_BUDGET_ENTRY_BYTES,
    SHARED_BUFFER_BUDGET_HEADER,
    SHARED_BUFFER_BUDGET_HEADER_BYTES,
    SHARED_BUFFER_BUDGET_MAGIC,
    SHARED_BUFFER_BUDGET_VERSION,
    WAIT_SET_DRAIN_SLOT_ABSENT,
    WAIT_SET_ENTRY,
    WAIT_SET_ENTRY_BYTES,
    WAIT_SET_HEADER,
    WAIT_SET_HEADER_BYTES,
    WAIT_SET_KIND_CALL,
    WAIT_SET_KIND_DEVICE,
    WAIT_SET_KIND_OPERATION,
    WAIT_SET_KIND_QOS_EVENT,
    WAIT_SET_KIND_STREAM,
    WAIT_SET_KIND_SUPERVISION,
    WAIT_SET_KIND_TIMER,
    WAIT_SET_MAGIC,
    WAIT_SET_MAX_ENTRIES,
    WAIT_SET_MAX_SOURCES_PER_WAITER,
    WAIT_SET_VERSION,
    sha256,
)

NETWORK_SERVICE_MAX_NAME_BYTES = 24

RIGHT = GENERATION_RIGHT_BY_MANIFEST_NAME
DEFAULT_CHILD_PRIORITY = 254


def io_resource_driver_identity(name: str) -> bytes:
    encoded = name.encode("utf-8")
    return sha256(b"slime-io-resource-driver-v1" + struct.pack("<H", len(encoded)) + encoded)


def build_io_resource_budget(holders: list[dict]) -> bytes:
    if len(holders) > MAX_IO_RESOURCE_DRIVERS:
        fail("ioResourceBudget exceeds driver ceiling")
    names = [entry["holder"] for entry in holders]
    if len(names) != len(set(names)):
        fail("ioResourceBudget holder must be unique")
    # A device is exclusive: two driver instances programming one transport's
    # queue would each observe the other's completions (B84). The decoder
    # refuses this too; catching it here names the offending holder.
    devices = [entry.get("device", 0) for entry in holders]
    if len(devices) != len(set(devices)):
        fail("ioResourceBudget device must be unique per driver")
    rows = []
    for entry in sorted(holders, key=lambda item: io_resource_driver_identity(item["holder"])):
        values = [entry[name] for name in ("mmioBytes", "mmioMappings", "dmaPages", "dmaMappings", "irqSources", "outstandingRequests", "bufferLoans")]
        # Zero-based ordinal into the platform's stable device order. Optional in
        # the manifest because a single-device plane has nothing to choose, and
        # requiring it would make every existing composition restate a default.
        values.append(entry.get("device", 0))
        if any(value < 0 or value > 0xFFFFFFFF for value in values):
            fail(f"ioResourceBudget holder {entry['holder']}: quota out of range")
        rows.append(IO_RESOURCE_ENTRY.pack(io_resource_driver_identity(entry["holder"]), *values))
    total = IO_RESOURCE_HEADER_BYTES + len(rows) * IO_RESOURCE_ENTRY.size
    return IO_RESOURCE_HEADER.pack(IO_RESOURCE_MAGIC, IO_RESOURCE_VERSION, IO_RESOURCE_HEADER_BYTES, 0, len(rows), total) + b"".join(rows)


def fail(message: str) -> None:
    raise SystemExit(message)


# The one instance the grants table is served to. The root's reader gates by the caller's instance name, as it does for
# the entropy table, so the builder requires that instance to exist before it emits a table.
ZENOH_GRANTS_READER_INSTANCE = "zenoh-service"


def build_zenoh_grants_table(manifest: dict) -> bytes:
    """Encode the Zenoh service grants table (zenoh-service-grants-table/v1) from the manifest's `zenohGrants` rows.

    Each row is `{holder, key, publish, subscribe}`, as in the grants record. The encoder refuses a row the grants
    record refuses, a row that grants nothing and a repeated pair, and it sorts the rows. This function adds what only
    the manifest knows: the reader instance exists, and every holder is a declared instance other than the reader.
    """
    import zenoh_grants_table

    declarations = manifest.get("zenohGrants") or []
    if not declarations:
        fail("zenoh grants: the table has no rows")
    instances = {entry["name"] for entry in manifest["instances"]}
    if ZENOH_GRANTS_READER_INSTANCE not in instances:
        fail(f"zenoh grants: no {ZENOH_GRANTS_READER_INSTANCE} instance reads the table")
    for row in declarations:
        holder = row.get("holder") if isinstance(row, dict) else None
        if holder not in instances:
            fail(f"zenoh grants: holder {holder!r} is not a declared instance")
        if holder == ZENOH_GRANTS_READER_INSTANCE:
            fail(f"zenoh grants: {holder} reads the table and may not hold a row")
    try:
        return zenoh_grants_table.encode(declarations)
    except zenoh_grants_table.GrantsTableError as error:
        fail(str(error))


def holder_identity(name: str) -> bytes:
    """Stable per-holder identity, matching `boot_contracts::shared_buffer_budget`."""
    encoded = name.encode("utf-8")
    return sha256(
        b"slime-shared-buffer-holder-v1" + struct.pack("<H", len(encoded)) + encoded
    )


def build_shared_buffer_budget(holders: list[dict]) -> bytes:
    """Encode the C7.3 shared-buffer budget resource object.

    Entries are sorted by holder identity and must be unique: the decoder
    rejects an unsorted or duplicated table, so the sort here is part of the
    format rather than a convenience. A component absent from the table gets no
    quota at all (deny by default), so omission is meaningful, not a default.
    """
    if len(holders) > MAX_SHARED_BUFFER_BUDGET_HOLDERS:
        fail("shared-buffer budget exceeds holder bound")
    entries = []
    for holder in holders:
        identity = holder_identity(holder["holder"])
        limits = (
            holder["bytePages"],
            holder["bufferCount"],
            holder["mappingCount"],
            holder["loanCount"],
        )
        for limit in limits:
            if not isinstance(limit, int) or not 0 <= limit <= 0xFFFFFFFF:
                fail(f"shared-buffer budget: invalid limit for {holder['holder']}")
        entries.append((identity, *limits))
    entries.sort(key=lambda entry: entry[0])
    identities = {entry[0] for entry in entries}
    if len(identities) != len(entries):
        fail("shared-buffer budget: duplicate holder")
    total_len = SHARED_BUFFER_BUDGET_HEADER_BYTES + len(entries) * SHARED_BUFFER_BUDGET_ENTRY_BYTES
    header = SHARED_BUFFER_BUDGET_HEADER.pack(
        SHARED_BUFFER_BUDGET_MAGIC,
        SHARED_BUFFER_BUDGET_VERSION,
        SHARED_BUFFER_BUDGET_HEADER_BYTES,
        0,
        len(entries),
        total_len,
    )
    return header + b"".join(SHARED_BUFFER_BUDGET_ENTRY.pack(*entry) for entry in entries)

def validated_shared_buffer_quotas(holders: list[dict]) -> dict[str, dict]:
    if len(holders) > MAX_SHARED_BUFFER_BUDGET_HOLDERS:
        fail("shared-buffer budget exceeds holder bound")
    by_name: dict[str, dict] = {}
    totals = {"bytePages": 0, "bufferCount": 0, "mappingCount": 0, "loanCount": 0}
    ceilings = {
        "bytePages": FABRIC_GRAPH_KERNEL_TOTAL_PAGES,
        "bufferCount": FABRIC_GRAPH_KERNEL_SHARED_BUFFERS,
        "mappingCount": FABRIC_GRAPH_KERNEL_MAPPINGS,
        "loanCount": FABRIC_GRAPH_KERNEL_LOANS,
    }
    for holder in holders:
        name = holder["holder"]
        if name in by_name:
            fail(f"shared-buffer budget: duplicate holder {name}")
        for key, ceiling in ceilings.items():
            value = holder[key]
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= ceiling:
                fail(f"shared-buffer budget: invalid {key} for {name}")
            totals[key] += value
        if holder["bufferCount"] > holder["bytePages"]:
            fail(f"shared-buffer budget: {name} buffers exceed its page quota")
        if holder["mappingCount"] > holder["bytePages"]:
            fail(f"shared-buffer budget: {name} mappings exceed its page quota")
        if holder["loanCount"] > holder["bufferCount"]:
            fail(f"shared-buffer budget: {name} loans exceed its buffer quota")
        by_name[name] = holder
    for key, ceiling in ceilings.items():
        if totals[key] > ceiling:
            fail(f"shared-buffer budget: aggregate {key} exceeds the kernel ceiling")
    return by_name

def network_destination_holder_identity(name: str) -> bytes:
    encoded = name.encode("utf-8")
    return sha256(b"slime-network-destination-holder-v1" + struct.pack("<H", len(encoded)) + encoded)


def build_network_destinations(declarations: list[dict]) -> bytes:
    """Encode IO4's exact, wildcard-free destination authority table."""
    if len(declarations) > MAX_NETWORK_DESTINATIONS:
        fail("network destinations exceed entry bound")
    transports = {"tcp": 1, "udp": 2}
    address_kinds = {"ipv4": 1, "ipv6": 2, "dns": 3}
    right_bits = {"connect": 1, "send": 2, "recv": 4, "listen": 8}
    entries = []
    holder_counts: dict[bytes, int] = {}
    for declaration in declarations:
        holder = network_destination_holder_identity(declaration["holder"])
        transport = transports.get(declaration["transport"])
        kind = address_kinds.get(declaration["addressKind"])
        if transport is None or kind is None:
            fail("network destination: unknown transport or address kind")
        rights = 0
        for right in declaration["rights"]:
            bit = right_bits.get(right)
            if bit is None or rights & bit:
                fail("network destination: unknown or duplicate right")
            rights |= bit
        port = declaration["port"]
        if rights == 0 or not 1 <= port <= 65535 or (rights & 8 and transport != 1):
            fail("network destination: invalid rights or port")
        raw_address = bytes(16)
        raw_name = bytes(64)
        address = declaration["address"]
        if kind == 1:
            try:
                raw_address = ipaddress.IPv4Address(address).packed + bytes(12)
            except ipaddress.AddressValueError:
                fail("network destination: invalid IPv4 address")
        elif kind == 2:
            try:
                raw_address = ipaddress.IPv6Address(address).packed
            except ipaddress.AddressValueError:
                fail("network destination: invalid IPv6 address")
        else:
            try:
                encoded = address.encode("ascii")
            except UnicodeEncodeError:
                fail("network destination: non-ASCII DNS name")
            if not encoded or len(encoded) > MAX_NETWORK_NAME_BYTES or encoded.startswith(b".") or encoded.endswith(b".") or b".." in encoded or any(not (byte in b".-" or chr(byte).isalnum()) for byte in encoded):
                fail("network destination: invalid exact DNS name")
            if len(encoded) > NETWORK_SERVICE_MAX_NAME_BYTES:
                fail(
                    "network destination contract permits this DNS name, but "
                    "network-service/v1 maxNameBytes is 24; destination is unreachable"
                )
            raw_name = encoded + bytes(64 - len(encoded))
        keys = ("queueDepth", "byteBudget", "timerBudget", "retryLimit", "reconnectLimit", "socketLimit", "listenerLimit", "dnsRecordLimit")
        limits = tuple(declaration[key] for key in keys)
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in limits):
            fail("network destination: invalid bound")
        queue_depth, byte_budget, timer_budget, retry_limit, reconnect_limit, socket_limit, listener_limit, dns_record_limit = limits
        if not (1 <= queue_depth <= 256 and 1 <= byte_budget <= 16_777_216 and timer_budget <= 256 and retry_limit <= 16 and reconnect_limit <= 16 and 1 <= socket_limit <= 64 and listener_limit <= min(socket_limit, 16) and dns_record_limit <= 64):
            fail("network destination: bound exceeds contract")
        holder_counts[holder] = holder_counts.get(holder, 0) + 1
        if holder_counts[holder] > MAX_NETWORK_DESTINATIONS_PER_HOLDER:
            fail("network destinations exceed per-holder bound")
        packed = NETWORK_DESTINATION_ENTRY.pack(holder, transport, kind, rights, port, len(address.encode("ascii")) if kind == 3 else 0, raw_address, raw_name, *limits)
        key_address = raw_address + raw_name
        entries.append(((holder, transport, kind, key_address, port), packed))
    entries.sort(key=lambda value: value[0])
    # Adjacent pairs over a sorted list, so the second sequence is deliberately
    # one shorter: `strict=False` is the intent, not an oversight.
    if any(left[0] == right[0] for left, right in zip(entries, entries[1:], strict=False)):
        fail("network destination: duplicate exact tuple")
    total_len = NETWORK_DESTINATION_HEADER_BYTES + len(entries) * NETWORK_DESTINATION_ENTRY_BYTES
    header = NETWORK_DESTINATION_HEADER.pack(NETWORK_DESTINATION_MAGIC, NETWORK_DESTINATION_VERSION, NETWORK_DESTINATION_HEADER_BYTES, 0, len(entries), total_len)
    return header + b"".join(entry for _, entry in entries)


def network_interface_holder_identity(name: str) -> bytes:
    """Stable per-holder identity, matching `boot_contracts::network_interface`.

    Its own domain tag, for the reason `block_ring_holder_identity` gives.
    """
    encoded = name.encode("utf-8")
    return sha256(b"slime-network-interface-holder-v1" + struct.pack("<H", len(encoded)) + encoded)


def _unicast_host(address: ipaddress.IPv4Address, network: ipaddress.IPv4Network) -> bool:
    return (
        address in network
        and address != network.network_address
        and address != network.broadcast_address
        and not address.is_multicast
        and int(address) >> 24 != 0
    )


def build_network_interfaces(declarations: list[dict]) -> bytes:
    """Encode IO11's static interface table: one IPv4 interface per holder."""
    if len(declarations) > MAX_NETWORK_INTERFACES:
        fail("network interfaces exceed entry bound")
    entries = []
    for declaration in declarations:
        holder = network_interface_holder_identity(declaration["holder"])
        prefix_len = declaration["prefixLen"]
        if not isinstance(prefix_len, int) or isinstance(prefix_len, bool) or not (
            NETWORK_INTERFACE_MIN_PREFIX_LEN <= prefix_len <= NETWORK_INTERFACE_MAX_PREFIX_LEN
        ):
            fail("network interface: prefix length outside the contract's range")
        try:
            address = ipaddress.IPv4Address(declaration["address"])
            gateway = ipaddress.IPv4Address(declaration["gateway"])
        except ipaddress.AddressValueError:
            fail("network interface: invalid IPv4 address or gateway")
        network = ipaddress.IPv4Network((address, prefix_len), strict=False)
        if not _unicast_host(address, network):
            fail("network interface: address is not a unicast host on its prefix")
        if int(gateway) != 0 and (gateway == address or not _unicast_host(gateway, network)):
            fail("network interface: gateway is not a distinct unicast host on the prefix")
        try:
            mac = bytes.fromhex(declaration["mac"].replace(":", ""))
        except ValueError:
            fail("network interface: malformed MAC")
        if len(mac) != 6 or mac == bytes(6) or mac[0] & 1:
            fail("network interface: MAC is not a unicast hardware address")
        entries.append(
            (holder, NETWORK_INTERFACE_ENTRY.pack(holder, address.packed, gateway.packed, mac, prefix_len, 0))
        )
    entries.sort(key=lambda value: value[0])
    if any(left[0] == right[0] for left, right in zip(entries, entries[1:], strict=False)):
        fail("network interface: one holder declares two interfaces")
    total_len = NETWORK_INTERFACE_HEADER_BYTES + len(entries) * NETWORK_INTERFACE_ENTRY_BYTES
    header = NETWORK_INTERFACE_HEADER.pack(
        NETWORK_INTERFACE_MAGIC, NETWORK_INTERFACE_VERSION, NETWORK_INTERFACE_HEADER_BYTES, 0, len(entries), total_len
    )
    return header + b"".join(entry for _, entry in entries)


def build_network_applications(manifest: dict) -> bytes:
    """Encode exact application bindings, listener policy, TCP options and buffer sizes (network-application/v4).

    A loopback listener admits one declared local client holder; an external
    listener listens on an address the service's declared interface owns and
    admits one exact remote unicast IPv4 address, any source port. Every row,
    client or listener, declares the TCP options and the receive and transmit
    buffer sizes the service applies to each socket it opens or accepts for
    that holder. A listener's byte budget covers both buffers of every socket
    it may accept.
    """
    c = wire_contracts
    declarations = manifest.get("networkApplications") or []
    if len(declarations) > c.NETWORK_APPLICATION_MAX_APPLICATIONS:
        fail("network applications exceed entry bound")
    instances = {entry["name"]: entry for entry in manifest["instances"]}
    grants = {entry["name"]: entry for entry in manifest["grants"]}
    rows = {entry["holder"]: entry for entry in declarations}
    if len(rows) != len(declarations):
        fail("network application: duplicate holder")
    if declarations and "network-service" not in instances:
        fail("network application: missing service instance")
    bindings_used: set[str] = set()
    listener_endpoints: set[tuple[bytes, int]] = set()
    interface_addresses = {
        ipaddress.IPv4Address(entry["address"]).packed
        for entry in manifest.get("networkInterfaces") or []
        if entry.get("holder") == "network-service"
    }
    entries = []
    name_fields = ("controlBinding", "provisionBinding", "supervisionBinding", "requestNotification", "completionNotification")
    limit_fields = ("backlog", "acceptedSocketLimit", "byteBudget", "timerBudget", "queueDepth", "retryLimit", "reconnectLimit")
    for declaration in declarations:
        holder = declaration["holder"]
        if holder not in instances or holder == "network-service":
            fail("network application: holder is not a distinct admitted instance")
        encoded_names = []
        for field in name_fields:
            value = declaration[field]
            if not isinstance(value, str) or len(value) > c.NETWORK_APPLICATION_BINDING_BYTES or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for character in value
            ) or (field in name_fields[:2] and not value):
                fail(f"network application: invalid {field}")
            encoded_names.append(value.encode().ljust(c.NETWORK_APPLICATION_BINDING_BYTES, b"\0"))
        for field, transferable in (("controlBinding", False), ("provisionBinding", True)):
            name = declaration[field]
            grant = grants.get(name)
            if name in bindings_used or grant is None or grant["capabilityKind"] != "endpoint" or set(grant["rights"]) != {"send", "recv"} or grant["transferable"] != transferable or {grant["source"], grant["target"]} != {holder, "network-service"}:
                fail(f"network application: {field} is not an exclusive declared endpoint with exact rights")
            bindings_used.add(name)
        if bool(declaration["requestNotification"]) != bool(declaration["completionNotification"]):
            fail("network application: notification bindings must be paired")
        for field, source, target in (("requestNotification", holder, "network-service"), ("completionNotification", "network-service", holder)):
            if declaration[field]:
                name = declaration[field]
                declared = any(entry["name"] == name and entry["target"] == target for entry in manifest.get("notificationGrants", []))
                signaller = any(entry["grant"] == name and entry["holder"] == source and entry["role"] == "signal" for entry in manifest.get("notificationBindings", []))
                waiter = any(entry["grant"] == name and entry["holder"] == target and entry["role"] == "wait" for entry in manifest.get("notificationBindings", []))
                if not declared or not signaller or not waiter:
                    fail(f"network application: {field} is not the declared notification edge")
        if declaration["supervisionBinding"] and not any(
            entry.get("name") == declaration["supervisionBinding"] == f"{holder}-supervision" and entry.get("holder") == "network-service" and entry.get("capabilityKind") == "supervision" and set(entry.get("rights", [])) == {"supervise"} and not entry.get("transferable", True)
            for entry in manifest.get("mintedBindings", [])
        ):
            fail("network application: supervision is not a declared nontransferable service capability")
        role = {"client": c.NETWORK_APPLICATION_ROLE_CLIENT, "listener": c.NETWORK_APPLICATION_ROLE_LISTENER}.get(declaration["role"])
        backend = {"external": c.NETWORK_APPLICATION_BACKEND_EXTERNAL, "loopback": c.NETWORK_APPLICATION_BACKEND_LOOPBACK}.get(declaration["backend"])
        if role is None or backend is None:
            fail("network application: unknown role or backend")
        rights = 0
        bits = {"listen": c.NETWORK_APPLICATION_RIGHT_LISTEN, "send": c.NETWORK_APPLICATION_RIGHT_SEND, "recv": c.NETWORK_APPLICATION_RIGHT_RECV}
        for right in declaration["rights"]:
            bit = bits.get(right)
            if bit is None or rights & bit:
                fail("network application: unknown or duplicate right")
            rights |= bit
        try:
            address = ipaddress.IPv4Address(declaration["localAddress"]).packed
        except ipaddress.AddressValueError:
            fail("network application: invalid local IPv4 address")
        port = declaration["localPort"]
        limits = tuple(declaration[field] for field in limit_fields)
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in (port, *limits)):
            fail("network application: invalid numeric bound")
        keepalive, idle_timeout, hop_limit, nagle = (declaration[field] for field in ("keepaliveMs", "idleTimeoutMs", "hopLimit", "nagle"))
        if any(not isinstance(value, int) or isinstance(value, bool) for value in (keepalive, idle_timeout, hop_limit)) or not isinstance(nagle, bool):
            fail("network application: invalid socket option")
        if not (
            (keepalive == 0 or c.NETWORK_APPLICATION_MIN_KEEPALIVE_MS <= keepalive <= c.NETWORK_APPLICATION_MAX_KEEPALIVE_MS)
            and c.NETWORK_APPLICATION_MIN_IDLE_TIMEOUT_MS <= idle_timeout <= c.NETWORK_APPLICATION_MAX_IDLE_TIMEOUT_MS
            and c.NETWORK_APPLICATION_MIN_HOP_LIMIT <= hop_limit <= c.NETWORK_APPLICATION_MAX_HOP_LIMIT
        ):
            fail("network application: socket options exceed contract")
        rx_buffer, tx_buffer = (declaration[field] for field in ("rxBufferBytes", "txBufferBytes"))
        if any(not isinstance(value, int) or isinstance(value, bool) for value in (rx_buffer, tx_buffer)):
            fail("network application: invalid buffer size")
        if not all(
            c.NETWORK_APPLICATION_MIN_BUFFER_BYTES <= value <= c.NETWORK_APPLICATION_MAX_BUFFER_BYTES and value & (value - 1) == 0
            for value in (rx_buffer, tx_buffer)
        ):
            fail("network application: buffer sizes exceed contract")
        peer = declaration["admittedPeer"]
        peer_address_text = declaration["admittedPeerAddress"]
        peer_kind = c.NETWORK_APPLICATION_PEER_NONE
        peer_address = bytes(4)
        if role == c.NETWORK_APPLICATION_ROLE_CLIENT:
            if address != bytes(4) or port or peer or peer_address_text or rights or any(limits):
                fail("network application: client row carries listener authority")
        else:
            backlog, sockets, byte_budget, timers, queue, retries, reconnects = limits
            if not 1 <= port <= 65535 or not rights & c.NETWORK_APPLICATION_RIGHT_LISTEN:
                fail("network application: listener is not an exact authorized endpoint")
            if backend == c.NETWORK_APPLICATION_BACKEND_LOOPBACK:
                if address != ipaddress.IPv4Address("127.0.0.1").packed or peer_address_text:
                    fail("network application: listener is not an exact authorized loopback endpoint")
                peer_kind = c.NETWORK_APPLICATION_PEER_HOLDER
            else:
                if peer or address not in interface_addresses:
                    fail("network application: external listener is not on a declared service interface address")
                try:
                    remote = ipaddress.IPv4Address(peer_address_text)
                except ipaddress.AddressValueError:
                    fail("network application: external listener admits no exact remote IPv4 address")
                if remote.packed == address or remote.packed[0] in (0, 127) or remote.packed[0] >= 224:
                    fail("network application: external listener admits no exact remote IPv4 address")
                peer_kind = c.NETWORK_APPLICATION_PEER_IPV4
                peer_address = remote.packed
            if not (backlog == 1 and 1 <= sockets <= c.NETWORK_APPLICATION_MAX_ACCEPTED_SOCKETS and sockets * (rx_buffer + tx_buffer) <= byte_budget <= c.NETWORK_APPLICATION_MAX_BYTE_BUDGET and 1 <= timers <= c.NETWORK_APPLICATION_MAX_TIMER_BUDGET and c.NETWORK_APPLICATION_MIN_QUEUE_DEPTH <= queue <= c.NETWORK_APPLICATION_MAX_QUEUE_DEPTH and queue & (queue - 1) == 0 and retries <= c.NETWORK_APPLICATION_MAX_RETRY_LIMIT and reconnects <= c.NETWORK_APPLICATION_MAX_RECONNECT_LIMIT):
                fail("network application: listener bounds exceed contract")
            endpoint = (address, port)
            if endpoint in listener_endpoints:
                fail("network application: duplicate listener endpoint")
            listener_endpoints.add(endpoint)
            if backend == c.NETWORK_APPLICATION_BACKEND_LOOPBACK:
                admitted = rows.get(peer)
                if peer == holder or admitted is None or admitted["role"] != "client" or admitted["backend"] != "loopback":
                    fail("network application: admitted peer is not a distinct declared local client")
        identity = network_destination_holder_identity(holder)
        peer_identity = network_destination_holder_identity(peer) if peer else bytes(32)
        packed = c.NETWORK_APPLICATION_ENTRY.pack(identity, *encoded_names, peer_identity, address, port, rights, role, backend, peer_kind, bytes(1), *limits, peer_address, keepalive, idle_timeout, hop_limit, int(nagle), rx_buffer, tx_buffer, bytes(34))
        entries.append((identity, packed))
    entries.sort(key=lambda entry: entry[0])
    total = c.NETWORK_APPLICATION_HEADER_BYTES + len(entries) * c.NETWORK_APPLICATION_ENTRY_BYTES
    return c.NETWORK_APPLICATION_HEADER.pack(c.NETWORK_APPLICATION_MAGIC, c.NETWORK_APPLICATION_FORMAT_VERSION, c.NETWORK_APPLICATION_HEADER_BYTES, 0, len(entries), total) + b"".join(entry for _, entry in entries)


def block_ring_holder_identity(name: str) -> bytes:
    """Stable per-holder identity, matching `boot_contracts::block_authority`.

    Its own domain tag: an identity computed for a network destination must not
    be replayable as a block-ring identity, or a grant in either table would be
    forgeable from the other.
    """
    encoded = name.encode("utf-8")
    return sha256(
        b"slime-block-authority-holder-v1" + struct.pack("<H", len(encoded)) + encoded
    )


def build_block_ring_authority(declarations: list[dict]) -> bytes:
    """Encode B83's exact per-ring block authority table.

    Rights are a property of the `(holder, device, ring)` triple, not of a
    submission: an IO0 ring is shared memory carrying no rights identity, so a
    driver reading this table is the only place a read-only ring's write can be
    refused. Two clients whose rights differ therefore declare two rings, and
    the strictly ascending sort makes a duplicate triple unrepresentable rather
    than resolved by whichever row a lookup reaches first.
    """
    if len(declarations) > MAX_BLOCK_RINGS:
        fail("block ring authority exceeds entry bound")
    right_bits = {"blockRead": BLOCK_RIGHT_READ, "blockWrite": BLOCK_RIGHT_WRITE}
    entries = []
    holder_counts: dict[bytes, int] = {}
    for declaration in declarations:
        holder = block_ring_holder_identity(declaration["holder"])
        rights = 0
        for right in declaration["rights"]:
            bit = right_bits.get(right)
            if bit is None or rights & bit:
                fail("block ring authority: unknown or duplicate right")
            rights |= bit
        numbers = (declaration["device"], declaration["ring"], declaration["sectorLimit"])
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in numbers
        ):
            fail("block ring authority: invalid device, ring, or sector limit")
        device, ring, sector_limit = numbers
        if rights == 0 or sector_limit == 0:
            fail("block ring authority: a ring must carry a right and a nonzero limit")
        if device > 0xFFFFFFFF or ring > 0xFFFFFFFF or sector_limit > 0xFFFFFFFFFFFFFFFF:
            fail("block ring authority: field exceeds contract width")
        holder_counts[holder] = holder_counts.get(holder, 0) + 1
        if holder_counts[holder] > MAX_BLOCK_RINGS_PER_HOLDER:
            fail("block ring authority exceeds per-holder bound")
        packed = BLOCK_AUTHORITY_ENTRY.pack(
            holder, device, ring, rights, sector_limit, bytes(14)
        )
        entries.append(((device, ring), packed))
    entries.sort(key=lambda value: value[0])
    # Adjacent pairs over a sorted list, so the second sequence is deliberately
    # one shorter: `strict=False` is the intent, not an oversight.
    #
    # Keyed on `(device, ring)` without the holder, matching the decoder: one
    # ring may carry exactly one row, even for two different holders. A ring
    # shared by two holders would leave the driver unable to say whose rights a
    # submission carries, which is the defect this table closes.
    if any(left[0] == right[0] for left, right in zip(entries, entries[1:], strict=False)):
        fail("block ring authority: two holders named one device and ring")
    total_len = BLOCK_AUTHORITY_HEADER_BYTES + len(entries) * BLOCK_AUTHORITY_ENTRY_BYTES
    header = BLOCK_AUTHORITY_HEADER.pack(
        BLOCK_AUTHORITY_MAGIC,
        BLOCK_AUTHORITY_VERSION,
        BLOCK_AUTHORITY_HEADER_BYTES,
        0,
        len(entries),
        total_len,
    )
    return header + b"".join(entry for _, entry in entries)


def private_memory_holder_identity(name: str) -> bytes:
    """Stable per-holder identity, matching `boot_contracts::private_memory_budget`.

    Its domain tag is this contract's own, not `holder_identity`'s: an identity
    computed for one budget must never be replayable as a valid identity in the
    other, since the two bound unrelated mechanisms.
    """
    encoded = name.encode("utf-8")
    return sha256(
        b"slime-private-memory-holder-v1" + struct.pack("<H", len(encoded)) + encoded
    )


def build_private_memory_budget(holders: list[dict]) -> bytes:
    """Encode the C10.2 private-memory budget resource object.

    Entries are sorted by holder identity and must be unique: the decoder
    rejects an unsorted or duplicated table, so the sort here is part of the
    format rather than a convenience. A component absent from the table gets no
    quota at all (deny by default), so omission is meaningful, not a default.
    """
    if len(holders) > MAX_PRIVATE_MEMORY_BUDGET_HOLDERS:
        fail("private-memory budget exceeds holder bound")
    entries = []
    for holder in holders:
        identity = private_memory_holder_identity(holder["holder"])
        quota = holder["pageQuota"]
        if not isinstance(quota, int) or isinstance(quota, bool) or not 0 <= quota <= 0xFFFFFFFF:
            fail(f"private-memory budget: invalid pageQuota for {holder['holder']}")
        entries.append((identity, quota))
    entries.sort(key=lambda entry: entry[0])
    identities = {entry[0] for entry in entries}
    if len(identities) != len(entries):
        fail("private-memory budget: duplicate holder")
    total_len = (
        PRIVATE_MEMORY_BUDGET_HEADER_BYTES + len(entries) * PRIVATE_MEMORY_BUDGET_ENTRY_BYTES
    )
    header = PRIVATE_MEMORY_BUDGET_HEADER.pack(
        PRIVATE_MEMORY_BUDGET_MAGIC,
        PRIVATE_MEMORY_BUDGET_VERSION,
        PRIVATE_MEMORY_BUDGET_HEADER_BYTES,
        0,
        len(entries),
        total_len,
    )
    return header + b"".join(PRIVATE_MEMORY_BUDGET_ENTRY.pack(*entry) for entry in entries)


def validated_private_memory_quotas(holders: list[dict], target: str) -> dict[str, dict]:
    """Mirror target-qualified `PrivateMemoryBudget::validate_against`."""
    region_pages, total_pages = PRIVATE_MEMORY_CAPACITY_PROFILES.get(
        target,
        (PRIVATE_MEMORY_DEFAULT_REGION_PAGES, PRIVATE_MEMORY_DEFAULT_TOTAL_PAGES),
    )
    if len(holders) > MAX_PRIVATE_MEMORY_BUDGET_HOLDERS:
        fail("private-memory budget exceeds holder bound")
    by_name: dict[str, dict] = {}
    total = 0
    for holder in holders:
        name = holder["holder"]
        if name in by_name:
            fail(f"private-memory budget: duplicate holder {name}")
        quota = holder["pageQuota"]
        if (
            not isinstance(quota, int)
            or isinstance(quota, bool)
            or not 0 <= quota <= region_pages
        ):
            fail(f"private-memory budget: invalid pageQuota for {name}")
        total += quota
        by_name[name] = holder
    if total > total_pages:
        fail("private-memory budget: aggregate pageQuota exceeds the target ceiling")
    return by_name


def clock_authority_holder_identity(name: str) -> bytes:
    """Stable per-holder identity, matching boot_contracts::clock_authority."""
    encoded = name.encode("utf-8")
    return sha256(
        b"slime-clock-authority-holder-v1" + struct.pack("<H", len(encoded)) + encoded
    )


def clock_notification_grant_identity(name: str) -> int:
    """Stable notification-grant identity used by the clock resource."""
    encoded = name.encode("utf-8")
    digest = sha256(
        b"slime-clock-notification-grant-v1" + struct.pack("<H", len(encoded)) + encoded
    )
    return int.from_bytes(digest[:8], "little")


def validated_clock_authorities(
    manifest: dict,
) -> list[tuple[bytes, int, int, int, int, int]]:
    declarations = manifest.get("clockAuthority") or []
    if len(declarations) > CLOCK_AUTHORITY_MAX_HOLDERS:
        fail("clock authority exceeds holder bound")
    instances = {entry["name"] for entry in manifest["instances"]}
    grants = {entry["name"]: entry for entry in manifest.get("notificationGrants", [])}
    bindings = manifest.get("notificationBindings", [])
    entries: list[tuple[bytes, int, int, int, int, int]] = []
    names: set[str] = set()
    timer_total = 0
    for declaration in declarations:
        holder = declaration["holder"]
        if holder in names:
            fail(f"clock authority: duplicate holder {holder}")
        names.add(holder)
        if holder not in instances:
            fail(f"clock authority: unknown holder {holder}")
        if "monotonicRead" in declaration:
            fail(
                f"clock authority: holder {holder} declares monotonicRead, which "
                "clock-authority/v2 retired; a monotonic read needs no authority"
            )
        flags = 0
        for field, right in (
            ("timerUse", RIGHT["clockTimerUse"]),
            ("simulatedRead", RIGHT["clockSimulatedRead"]),
            ("simulatedAdvance", RIGHT["clockSimulatedAdvance"]),
        ):
            if declaration[field]:
                flags |= right
        if flags == 0:
            fail(f"clock authority: holder {holder} declares no authority")
        quota = declaration["timerQuota"]
        if (
            not isinstance(quota, int)
            or isinstance(quota, bool)
            or not 0 <= quota <= CLOCK_AUTHORITY_MAX_LIVE_TIMERS_PER_HOLDER
        ):
            fail(f"clock authority: invalid timerQuota for {holder}")
        timer_use = bool(flags & RIGHT["clockTimerUse"])
        notification = declaration.get("timerNotification")
        badge_bit = declaration.get("timerBadgeBit")
        grant_identity = 0
        badge = 0
        if timer_use:
            if quota == 0 or not isinstance(notification, str):
                fail(f"clock authority: timer holder {holder} lacks quota or notification")
            if (
                not isinstance(badge_bit, int)
                or isinstance(badge_bit, bool)
                or not 0 <= badge_bit < 63
            ):
                fail(f"clock authority: invalid timerBadgeBit for {holder}")
            grant = grants.get(notification)
            if grant is None or grant["target"] != holder:
                fail(f"clock authority: timer notification for {holder} is not its wait grant")
            wait_binding = any(
                binding["grant"] == notification
                and binding["holder"] == holder
                and binding["role"] == "wait"
                for binding in bindings
            )
            if not wait_binding:
                fail(f"clock authority: timer notification for {holder} has no wait binding")
            colliding_signallers = [
                binding
                for binding in bindings
                if binding["grant"] == notification
                and binding["role"] == "signal"
                and binding["slot"] % 63 == badge_bit
            ]
            if colliding_signallers:
                fail(
                    f"clock authority: timer badge for {holder} "
                    "collides with a declared signaller"
                )
            grant_identity = clock_notification_grant_identity(notification)
            badge = 1 << badge_bit
        elif quota != 0 or notification is not None or badge_bit is not None:
            fail(f"clock authority: non-timer holder {holder} declares timer delivery")
        timer_total += quota
        entries.append(
            (
                clock_authority_holder_identity(holder),
                flags,
                quota,
                0,
                grant_identity,
                badge,
            )
        )
    if timer_total > CLOCK_AUTHORITY_MAX_LIVE_TIMERS:
        fail("clock authority: aggregate timer quota exceeds root ceiling")
    entries.sort(key=lambda entry: entry[0])
    return entries


def build_clock_authority(manifest: dict) -> bytes:
    entries = validated_clock_authorities(manifest)
    total_len = CLOCK_AUTHORITY_HEADER_BYTES + len(entries) * CLOCK_AUTHORITY_ENTRY_BYTES
    header = CLOCK_AUTHORITY_HEADER.pack(
        CLOCK_AUTHORITY_MAGIC,
        CLOCK_AUTHORITY_VERSION,
        CLOCK_AUTHORITY_HEADER_BYTES,
        0,
        len(entries),
        total_len,
    )
    return header + b"".join(CLOCK_AUTHORITY_ENTRY.pack(*entry) for entry in entries)


def wait_set_waiter_identity(name: str) -> bytes:
    """Stable per-waiter identity, matching boot_contracts::wait_set."""
    encoded = name.encode("utf-8")
    return sha256(b"slime-wait-set-waiter-v1" + struct.pack("<H", len(encoded)) + encoded)


def wait_set_notification_grant_identity(name: str) -> int:
    """Stable notification-grant identity used by the wait-set resource.

    A different domain tag from the clock resource's, so an identity minted for a
    timer entry cannot be lifted verbatim into a wait-set entry naming another
    object's badge.
    """
    encoded = name.encode("utf-8")
    digest = sha256(
        b"slime-wait-set-notification-grant-v1" + struct.pack("<H", len(encoded)) + encoded
    )
    return int.from_bytes(digest[:8], "little")


WAIT_SET_KIND = {
    "stream": WAIT_SET_KIND_STREAM,
    "call": WAIT_SET_KIND_CALL,
    "operation": WAIT_SET_KIND_OPERATION,
    "timer": WAIT_SET_KIND_TIMER,
    "supervision": WAIT_SET_KIND_SUPERVISION,
    "qosEvent": WAIT_SET_KIND_QOS_EVENT,
    "device": WAIT_SET_KIND_DEVICE,
}


def validated_wait_set(manifest: dict) -> list[tuple[bytes, int, int, int, int, int]]:
    """Every declared wake source, checked against the topology it names.

    Each entry must resolve to a badge the generation already produces on a
    Notification the waiter already waits on: a declared signaller's
    `1 << (slot % 63)`, or the C9.1 timer badge for this same holder. That is what
    keeps the resource from granting anything — it renames facts the notification
    and clock tables already fix, so an entry cannot invent a wake source.
    """
    declarations = manifest.get("waitSet") or []
    if len(declarations) > WAIT_SET_MAX_ENTRIES:
        fail("wait set exceeds source bound")
    instances = {entry["name"] for entry in manifest["instances"]}
    grants = {entry["name"]: entry for entry in manifest.get("notificationGrants", [])}
    bindings = manifest.get("notificationBindings", [])
    clocks = {entry["holder"]: entry for entry in manifest.get("clockAuthority") or []}
    entries: list[tuple[bytes, int, int, int, int, int]] = []
    seen: set[tuple[str, int]] = set()
    per_waiter: dict[str, int] = {}
    for declaration in declarations:
        waiter = declaration["waiter"]
        if waiter not in instances:
            fail(f"wait set: unknown waiter {waiter}")
        notification = declaration["notification"]
        badge_bit = declaration["badgeBit"]
        if (
            not isinstance(badge_bit, int)
            or isinstance(badge_bit, bool)
            or not 0 <= badge_bit < 63
        ):
            fail(f"wait set: invalid badgeBit for {waiter}")
        if (waiter, badge_bit) in seen:
            fail(f"wait set: duplicate badge bit {badge_bit} for {waiter}")
        seen.add((waiter, badge_bit))
        per_waiter[waiter] = per_waiter.get(waiter, 0) + 1
        if per_waiter[waiter] > WAIT_SET_MAX_SOURCES_PER_WAITER:
            fail(f"wait set: {waiter} declares more sources than one wait set may hold")
        kind = WAIT_SET_KIND.get(declaration["kind"])
        if kind is None:
            fail(f"wait set: unknown source kind {declaration['kind']!r} for {waiter}")
        grant = grants.get(notification)
        if grant is None or grant["target"] != waiter:
            fail(f"wait set: {notification} is not a wait grant targeting {waiter}")
        if not any(
            binding["grant"] == notification
            and binding["holder"] == waiter
            and binding["role"] == "wait"
            for binding in bindings
        ):
            fail(f"wait set: {waiter} has no wait binding on {notification}")
        # The badge must be one the generation actually produces on this object,
        # and there are exactly three producers. A peer signals its declared
        # `1 << (slot % 63)`; the root signals a C9.1 timer badge; and the root
        # signals a supervision badge when a task the waiter supervises ends. A
        # badge matching none of the three names a bit nothing can ever set,
        # which is a source that would look registered and never fire.
        signalled = any(
            binding["grant"] == notification
            and binding["role"] == "signal"
            and binding["slot"] % 63 == badge_bit
            for binding in bindings
        )
        clock = clocks.get(waiter)
        timer_badge = (
            clock is not None
            and clock.get("timerNotification") == notification
            and clock.get("timerBadgeBit") == badge_bit
        )
        if kind == WAIT_SET_KIND_TIMER:
            if not timer_badge:
                fail(
                    f"wait set: {waiter}'s timer source does not name its declared "
                    "C9.1 expiry badge"
                )
            if signalled:
                fail(
                    f"wait set: {waiter}'s timer badge collides with a declared "
                    "signaller on the same notification"
                )
        elif kind == WAIT_SET_KIND_SUPERVISION:
            # Root-signalled, like the timer, because the peer whose death it
            # reports is the thing that died. So it must *not* collide with a
            # declared signaller or with the timer badge: all three producers
            # write the same word, and two of them on one bit would make a wake
            # ambiguous.
            if signalled or timer_badge:
                fail(
                    f"wait set: {waiter}'s supervision badge collides with a "
                    "declared signaller or its timer badge"
                )
        elif not signalled:
            fail(
                f"wait set: badge bit {badge_bit} on {notification} is signalled by "
                f"no declared peer of {waiter}"
            )
        elif timer_badge:
            fail(f"wait set: {waiter}'s timer badge is declared as a {declaration['kind']} source")
        drain_slot = declaration.get("drainSlot")
        # A timer and a device completion carry no payload, so neither drains.
        if kind in (WAIT_SET_KIND_TIMER, WAIT_SET_KIND_DEVICE):
            if drain_slot is not None:
                fail(f"wait set: {waiter}'s {declaration['kind']} source declares a drain slot")
            drain_slot = WAIT_SET_DRAIN_SLOT_ABSENT
        else:
            if (
                not isinstance(drain_slot, int)
                or isinstance(drain_slot, bool)
                or not 0 <= drain_slot < WAIT_SET_DRAIN_SLOT_ABSENT
            ):
                fail(f"wait set: {waiter}'s {declaration['kind']} source needs a drain slot")
        entries.append(
            (
                wait_set_waiter_identity(waiter),
                1 << badge_bit,
                wait_set_notification_grant_identity(notification),
                kind,
                drain_slot,
                0,
            )
        )
    # `(identity, badge)` ascending is both the canonical encoding and the
    # contract's dispatch tie rule, so the sort here is what makes a waiter's
    # ready set drain in a documented order without sorting at runtime.
    entries.sort(key=lambda entry: (entry[0], entry[1]))
    return entries


def build_wait_set(manifest: dict) -> bytes:
    entries = validated_wait_set(manifest)
    total_len = WAIT_SET_HEADER_BYTES + len(entries) * WAIT_SET_ENTRY_BYTES
    header = WAIT_SET_HEADER.pack(
        WAIT_SET_MAGIC,
        WAIT_SET_VERSION,
        WAIT_SET_HEADER_BYTES,
        0,
        len(entries),
        total_len,
    )
    return header + b"".join(WAIT_SET_ENTRY.pack(*entry) for entry in entries)


def build_graph_arrival_ceiling(manifest: dict) -> bytes:
    """Encode the graph-arrival-ceiling resource object (graph-arrival-ceiling/v1).

    The object raises a finite plane's arrival ceiling and exists only when one
    is declared, so an object without a value, a value that does not raise the
    default, and a product generation carrying one are refused.
    """
    ceiling = manifest.get("graphArrivalCeiling")
    if ceiling is None:
        fail("graph-arrival-ceiling resource object declared without a graphArrivalCeiling")
    if isinstance(ceiling, bool) or not isinstance(ceiling, int):
        fail("graphArrivalCeiling is not an integer")
    if not wire_contracts.GRAPH_ARRIVAL_CEILING_DEFAULT < ceiling <= wire_contracts.GRAPH_ARRIVAL_CEILING_MAX:
        fail(
            f"graphArrivalCeiling {ceiling} is outside "
            f"{wire_contracts.GRAPH_ARRIVAL_CEILING_DEFAULT + 1}..{wire_contracts.GRAPH_ARRIVAL_CEILING_MAX}"
        )
    if manifest["bootAction"] == "product":
        fail("graphArrivalCeiling: a product generation has no arrival ceiling")
    return wire_contracts.GRAPH_ARRIVAL_CEILING_HEADER.pack(
        wire_contracts.GRAPH_ARRIVAL_CEILING_MAGIC,
        wire_contracts.GRAPH_ARRIVAL_CEILING_VERSION,
        wire_contracts.GRAPH_ARRIVAL_CEILING_HEADER_BYTES,
        0,
        ceiling,
    )


def instance_lifetime_identity(name: str) -> bytes:
    """Stable per-instance identity, matching boot_contracts::instance_lifetime."""
    encoded = name.encode("utf-8")
    return sha256(b"slime-instance-lifetime-v1" + struct.pack("<H", len(encoded)) + encoded)


def build_instance_lifetime(manifest: dict) -> bytes:
    """Encode the instance-lifetime resource object: one row per resident instance.

    A bounded instance is expressed by its absence, so a table naming nobody is
    refused rather than encoded: the object exists exactly when some instance is
    resident.
    """
    residents = []
    for instance in manifest["instances"]:
        lifetime = instance.get("lifetime", "bounded")
        if lifetime not in ("resident", "bounded"):
            fail(f"instance {instance['name']}: invalid lifetime {lifetime!r}")
        if lifetime == "resident":
            residents.append(instance_lifetime_identity(instance["name"]))
    if not residents:
        fail("instance-lifetime resource object declared without a resident instance")
    if len(residents) > wire_contracts.MAX_INSTANCE_LIFETIME_ROWS:
        fail("instance-lifetime exceeds its row bound")
    residents.sort()
    total_len = (
        wire_contracts.INSTANCE_LIFETIME_HEADER_BYTES
        + len(residents) * wire_contracts.INSTANCE_LIFETIME_ENTRY_BYTES
    )
    header = wire_contracts.INSTANCE_LIFETIME_HEADER.pack(
        wire_contracts.INSTANCE_LIFETIME_MAGIC,
        wire_contracts.INSTANCE_LIFETIME_VERSION,
        wire_contracts.INSTANCE_LIFETIME_HEADER_BYTES,
        0,
        len(residents),
        total_len,
    )
    return header + b"".join(
        wire_contracts.INSTANCE_LIFETIME_ENTRY.pack(
            identity, wire_contracts.INSTANCE_LIFETIME_RESIDENT, bytes(3)
        )
        for identity in residents
    )


ENTROPY_SERVICE_INSTANCE = "entropy-service"
ENTROPY_DRIVER_INSTANCE = "virtio-rng-driver"
ENTROPY_SOURCES = {
    "hardware": wire_contracts.ENTROPY_AUTHORITY_SOURCE_HARDWARE,
    "seeded": wire_contracts.ENTROPY_AUTHORITY_SOURCE_SEEDED,
}


def entropy_authority_holder_identity(name: str) -> bytes:
    """Stable per-holder identity, matching `boot_contracts::entropy_authority`."""
    encoded = name.encode("utf-8")
    return sha256(b"slime-entropy-authority-holder-v1" + struct.pack("<H", len(encoded)) + encoded)


def entropy_holder_grant(holder: str) -> str:
    """The one endpoint a holder draws through, named for it."""
    return f"{holder}-entropy"


def build_entropy_authority(manifest: dict) -> bytes:
    """Encode the entropy-authority resource object (entropy-authority/v1).

    A row is only meaningful together with the endpoint it draws through, so
    the grant table is judged here as well: every endpoint the service receives
    is exactly one row's non-transferable send/recv channel, and every row has
    exactly one.
    """
    c = wire_contracts
    declarations = manifest.get("entropyAuthority") or []
    if len(declarations) > c.MAX_ENTROPY_AUTHORITY_HOLDERS:
        fail("entropy authority exceeds its holder bound")
    instances = {entry["name"] for entry in manifest["instances"]}
    if declarations and ENTROPY_SERVICE_INSTANCE not in instances:
        fail("entropy authority: no entropy-service instance reads the table")
    holders = [entry.get("holder") for entry in declarations]
    if len(set(holders)) != len(holders):
        fail("entropy authority: duplicate holder")
    channels: dict[str, int] = {holder: 0 for holder in holders}
    for grant in manifest["grants"]:
        # The service's own `entropy-source` channel runs service -> driver, so
        # every endpoint *received* by the service is a holder's draw channel.
        if grant["capabilityKind"] != "endpoint" or grant["target"] != ENTROPY_SERVICE_INSTANCE:
            continue
        source = grant["source"]
        if source not in channels:
            fail(f"entropy authority: endpoint {grant['name']} reaches the service from a holder with no row")
        if grant["name"] != entropy_holder_grant(source):
            fail(f"entropy authority: endpoint {grant['name']} is not named {entropy_holder_grant(source)}")
        if grant["transferable"] is not False:
            fail(f"entropy authority: endpoint {grant['name']} is transferable")
        if not isinstance(grant["rights"], list) or sorted(grant["rights"]) != ["recv", "send"]:
            fail(f"entropy authority: endpoint {grant['name']} rights are not exactly send and recv")
        channels[source] += 1
    entries = []
    for declaration in declarations:
        holder = declaration.get("holder")
        if not isinstance(holder, str) or holder not in instances:
            fail(f"entropy authority: holder {holder!r} is not a declared instance")
        if holder in (ENTROPY_SERVICE_INSTANCE, ENTROPY_DRIVER_INSTANCE):
            fail(f"entropy authority: {holder} may not hold an entropy row")
        encoded = holder.encode("utf-8")
        if not 1 <= len(encoded) <= c.ENTROPY_AUTHORITY_HOLDER_NAME_BYTES or not all(0x21 <= byte <= 0x7E for byte in encoded):
            fail(f"entropy authority: holder name {holder!r} is not 1..32 printable ASCII bytes")
        source = declaration.get("source")
        if source not in ENTROPY_SOURCES:
            fail(f"entropy authority: {holder} has unknown source {source!r}")
        budget = declaration.get("byteBudget")
        if not isinstance(budget, int) or isinstance(budget, bool) or not 1 <= budget <= c.ENTROPY_AUTHORITY_MAX_BYTE_BUDGET:
            fail(f"entropy authority: {holder} byteBudget outside 1..{c.ENTROPY_AUTHORITY_MAX_BYTE_BUDGET}")
        if source == "hardware":
            if "seed" in declaration:
                fail(f"entropy authority: hardware row {holder} declares a seed")
            seed = bytes(c.ENTROPY_AUTHORITY_SEED_BYTES)
        else:
            text = declaration.get("seed")
            if not isinstance(text, str) or len(text) != 2 * c.ENTROPY_AUTHORITY_SEED_BYTES or any(
                character not in "0123456789abcdef" for character in text
            ):
                fail(f"entropy authority: seeded row {holder} seed is not 64 lowercase hex digits")
            seed = bytes.fromhex(text)
        if channels[holder] != 1:
            fail(f"entropy authority: {holder} has {channels[holder]} entropy endpoints, not exactly one")
        identity = entropy_authority_holder_identity(holder)
        entries.append((identity, c.ENTROPY_AUTHORITY_ENTRY.pack(
            identity, encoded.ljust(c.ENTROPY_AUTHORITY_HOLDER_NAME_BYTES, b"\0"), len(encoded),
            ENTROPY_SOURCES[source], bytes(2), budget, seed,
        )))
    entries.sort(key=lambda value: value[0])
    total_len = c.ENTROPY_AUTHORITY_HEADER_BYTES + len(entries) * c.ENTROPY_AUTHORITY_ENTRY_BYTES
    header = c.ENTROPY_AUTHORITY_HEADER.pack(
        c.ENTROPY_AUTHORITY_MAGIC, c.ENTROPY_AUTHORITY_VERSION, c.ENTROPY_AUTHORITY_HEADER_BYTES, 0, len(entries), total_len
    )
    return header + b"".join(entry for _, entry in entries)


def scheduling_class_instance_identity(name: str) -> bytes:
    """Stable per-instance identity, matching boot_contracts::scheduling_class.

    A distinct domain tag from the clock and wait-set folds, so an identity
    minted for a clock holder or a wait-set waiter cannot be read as a
    scheduling subject.
    """
    encoded = name.encode("utf-8")
    return sha256(
        b"slime-scheduling-class-instance-v1" + struct.pack("<H", len(encoded)) + encoded
    )


def validated_scheduling_class(manifest: dict) -> dict | None:
    """Resolve the C9.3 class policy, refusing every contradiction here.

    Returns `None` when the manifest declares no policy, and otherwise a
    resolved view carrying the serialized wire records plus the per-instance
    priorities `build_sel4_plan` writes into its `ScheduleRecord`s. The
    priorities are returned rather than recomputed there so the band mapping is
    read once: two readers of one mapping is how a class and a priority come to
    disagree.

    The contradiction rule is the milestone's, and it is refused at *build*
    rather than resolved by precedence. An instance may declare a class, or a
    priority, or both when they agree; declaring both when they disagree is a
    manifest that states two different intentions, and silently preferring
    either one would make the other authenticated fiction.
    """
    policy = manifest.get("schedulingClass")
    if policy is None:
        return None
    bands = policy["bands"]
    if not bands or len(bands) > SCHEDULING_CLASS_MAX_CLASSES:
        fail("scheduling class: band count outside the declared bound")
    priority_by_class: dict[int, int] = {}
    seen_priorities: dict[int, str] = {}
    for band in bands:
        spelling = band["class"]
        class_id = SCHEDULING_CLASS_ID_BY_MANIFEST_NAME.get(spelling)
        if class_id is None:
            fail(f"scheduling class: unknown class {spelling!r}")
        if class_id in priority_by_class:
            fail(f"scheduling class: duplicate band for {spelling}")
        priority = band["priority"]
        if (
            not isinstance(priority, int)
            or isinstance(priority, bool)
            or not 0 <= priority <= DEFAULT_CHILD_PRIORITY
        ):
            fail(
                f"scheduling class: band {spelling} priority outside "
                f"0..={DEFAULT_CHILD_PRIORITY}; a child at or above the root's "
                "priority can stall the service loop"
            )
        if priority in seen_priorities:
            fail(
                f"scheduling class: bands {seen_priorities[priority]} and {spelling} "
                "share one priority, so their ordering cannot be observed"
            )
        seen_priorities[priority] = spelling
        priority_by_class[class_id] = priority
    instances = {entry["name"]: entry for entry in manifest["instances"]}
    declared = policy["instances"]
    if len(declared) > SCHEDULING_CLASS_MAX_INSTANCES:
        fail("scheduling class: instance count exceeds the declared bound")
    resolved: dict[str, dict] = {}
    entries: list[tuple[bytes, int, int, int]] = []
    for entry in declared:
        name = entry["instance"]
        if name in resolved:
            fail(f"scheduling class: duplicate instance {name}")
        if name not in instances:
            fail(f"scheduling class: unknown instance {name}")
        class_id = SCHEDULING_CLASS_ID_BY_MANIFEST_NAME.get(entry["class"])
        if class_id is None:
            fail(f"scheduling class: unknown class {entry['class']!r} for {name}")
        worker_spelling = entry.get("workerClass", entry["class"])
        worker_class_id = SCHEDULING_CLASS_ID_BY_MANIFEST_NAME.get(worker_spelling)
        if worker_class_id is None:
            fail(f"scheduling class: unknown workerClass {worker_spelling!r} for {name}")
        for spelling, resolved_id in ((entry["class"], class_id), (worker_spelling, worker_class_id)):
            if resolved_id not in priority_by_class:
                fail(f"scheduling class: {name} names class {spelling} with no declared band")
        priority = priority_by_class[class_id]
        worker_priority = priority_by_class[worker_class_id]
        # The contradiction check, on both threads. A manifest that declares a
        # class *and* a priority states one intention twice; when the two
        # numbers differ it states two, and no precedence rule makes that
        # correct.
        #
        # `workerPriority` is compared against its *resolved* value, not the raw
        # field: an absent `workerPriority` inherits the instance's `priority`
        # (B48), so a manifest declaring `priority: 100` and `workerClass:
        # foreground` does state a worker priority — by inheritance — and the
        # class would otherwise silently override it (found by review).
        instance = instances[name]
        explicit_priority = instance.get("priority")
        for field, explicit, declared_class, band_priority in (
            ("priority", explicit_priority, entry["class"], priority),
            (
                "workerPriority",
                instance.get("workerPriority", explicit_priority),
                worker_spelling,
                worker_priority,
            ),
        ):
            if explicit is not None and explicit != band_priority:
                fail(
                    f"scheduling class: instance {name} declares {field}={explicit} and "
                    f"class {declared_class} whose band is {band_priority}; a class and a "
                    "priority that disagree are refused rather than resolved by precedence"
                )
        resolved[name] = {
            "class_id": class_id,
            "worker_class_id": worker_class_id,
            "priority": priority,
            "worker_priority": worker_priority,
        }
        entries.append(
            (
                scheduling_class_instance_identity(name),
                class_id,
                worker_class_id,
                0,
            )
        )
    promotions = policy["promotions"]
    if len(promotions) > SCHEDULING_CLASS_MAX_PROMOTIONS:
        fail("scheduling class: promotion count exceeds the declared bound")
    promotion_records: list[tuple[bytes, bytes, int, int]] = []
    seen_edges: set[tuple[str, str]] = set()
    for promotion in promotions:
        holder = promotion["holder"]
        subject = promotion["subject"]
        if holder not in instances:
            fail(f"scheduling class: promotion holder {holder} is not an instance")
        if subject not in instances:
            fail(f"scheduling class: promotion subject {subject} is not an instance")
        # "Never its own" is the milestone's exact wording, and this is where it
        # becomes unrepresentable rather than merely refused at runtime.
        if holder == subject:
            fail(
                f"scheduling class: {holder} may not hold promotion authority over itself; "
                "no component can widen its own class"
            )
        if (holder, subject) in seen_edges:
            fail(f"scheduling class: duplicate promotion edge {holder} -> {subject}")
        seen_edges.add((holder, subject))
        ceiling_id = SCHEDULING_CLASS_ID_BY_MANIFEST_NAME.get(promotion["ceiling"])
        if ceiling_id is None or ceiling_id not in priority_by_class:
            fail(
                f"scheduling class: promotion {holder} -> {subject} names ceiling "
                f"{promotion['ceiling']!r} with no declared band"
            )
        # The edge *is* the authority statement, so nothing further is required
        # of the holder here. `slime-root` sets `RIGHT_SCHEDULING_PROMOTE` on the
        # supervision handle it mints for a spawner exactly where this table
        # declares an edge from that spawner to that child, so the right on the
        # capability and the edge in this resource are one fact with one source.
        # Requiring a separate `schedulingPromote` grant as well would make them
        # two statements that can disagree, which is the shape B71 closed.
        promotion_records.append(
            (
                scheduling_class_instance_identity(holder),
                scheduling_class_instance_identity(subject),
                priority_by_class[ceiling_id],
                0,
            )
        )
    entries.sort(key=lambda entry: entry[0])
    promotion_records.sort(key=lambda entry: (entry[0], entry[1]))
    return {
        "bands": sorted(priority_by_class.items()),
        "entries": entries,
        "promotions": promotion_records,
        "resolved": resolved,
    }


def build_scheduling_class(manifest: dict) -> bytes:
    policy = validated_scheduling_class(manifest)
    if policy is None:
        fail("scheduling-class resource object declared without a schedulingClass policy")
    bands = policy["bands"]
    entries = policy["entries"]
    promotions = policy["promotions"]
    total_len = (
        SCHEDULING_CLASS_HEADER_BYTES
        + len(bands) * SCHEDULING_CLASS_BAND_BYTES
        + len(entries) * SCHEDULING_CLASS_ENTRY_BYTES
        + len(promotions) * SCHEDULING_PROMOTION_ENTRY_BYTES
    )
    header = SCHEDULING_CLASS_HEADER.pack(
        SCHEDULING_CLASS_MAGIC,
        SCHEDULING_CLASS_VERSION,
        SCHEDULING_CLASS_HEADER_BYTES,
        0,
        len(bands),
        len(entries),
        len(promotions),
        total_len,
    )
    return (
        header
        + b"".join(
            SCHEDULING_CLASS_BAND.pack(class_id, priority, 0) for class_id, priority in bands
        )
        + b"".join(SCHEDULING_CLASS_ENTRY.pack(*entry) for entry in entries)
        + b"".join(SCHEDULING_PROMOTION_ENTRY.pack(*entry) for entry in promotions)
    )


def lifecycle_instance_identity(name: str) -> bytes:
    """Stable per-instance identity, matching boot_contracts::lifecycle_policy.

    A distinct domain tag from the clock, wait-set, and scheduling folds, so an
    identity minted for one of those cannot be read as a lifecycle subject.
    """
    encoded = name.encode("utf-8")
    return sha256(
        b"slime-lifecycle-policy-instance-v1" + struct.pack("<H", len(encoded)) + encoded
    )


def lifecycle_cause_mask(causes: list[str], where: str) -> int:
    """Fold declared cause spellings into the contract's mask.

    An empty list is refused rather than folded to zero: a restart policy that
    can never fire reads as supervision while providing none, which is the same
    dead-guard shape B76 removed.
    """
    if not causes:
        fail(f"lifecycle policy: {where} declares no restart cause")
    mask = 0
    for spelling in causes:
        cause_id = LIFECYCLE_CAUSE_ID_BY_MANIFEST_NAME.get(spelling)
        if cause_id is None:
            fail(f"lifecycle policy: {where} names unknown cause {spelling!r}")
        bit = 1 << (cause_id - 1)
        if mask & bit:
            fail(f"lifecycle policy: {where} names cause {spelling} twice")
        mask |= bit
    return mask


def validated_lifecycle_policy(manifest: dict) -> dict | None:
    """Resolve the C9.4 lifecycle policy, refusing every contradiction here.

    Returns `None` when the manifest declares no policy, and otherwise the
    serialized wire rows. Every rule the decoder enforces on bytes is enforced
    here on names, so a malformed policy fails with a manifest-level diagnostic
    naming the instance rather than as a `DecodeError` on a boot.

    Three refusals are the milestone's, rather than tidiness:

    * A restart policy on an instance the manifest does not declare would name a
      subject the root can never resolve, so the policy would read as supervision
      that silently never applies.
    * A restart policy without an admitted edge into the declared terminal state
      makes "exhaustion leaves the graph in a declared terminal state" a claim
      about a state the graph cannot reach.
    * A health dependency whose dependency is not a declared instance, or which
      names the subject itself, is a start condition that can never be satisfied.
    """
    policy = manifest.get("lifecyclePolicy")
    if policy is None:
        return None
    instances = {entry["name"]: entry for entry in manifest["instances"]}

    def state_id(spelling: str, where: str) -> int:
        resolved = LIFECYCLE_STATE_ID_BY_MANIFEST_NAME.get(spelling)
        if resolved is None:
            fail(f"lifecycle policy: {where} names unknown state {spelling!r}")
        return resolved

    initial_state = state_id(policy["initialState"], "initialState")
    terminal_state = state_id(policy["terminalState"], "terminalState")
    if initial_state == terminal_state:
        fail(
            "lifecycle policy: initialState and terminalState are the same state, so "
            "an exhausted instance would be indistinguishable from a fresh one"
        )

    declared_transitions = policy["transitions"]
    if len(declared_transitions) > LIFECYCLE_POLICY_MAX_TRANSITIONS:
        fail("lifecycle policy: transition count exceeds the declared bound")
    transitions: list[tuple[int, int]] = []
    seen_edges: set[tuple[int, int]] = set()
    for edge in declared_transitions:
        source = state_id(edge["from"], "a transition")
        target = state_id(edge["to"], "a transition")
        if source == target:
            fail(
                f"lifecycle policy: transition {edge['from']} -> {edge['to']} is a "
                "self-edge, which would make an observed advance indistinguishable "
                "from a no-op"
            )
        if (source, target) in seen_edges:
            fail(f"lifecycle policy: duplicate transition {edge['from']} -> {edge['to']}")
        seen_edges.add((source, target))
        transitions.append((source, target))

    declared_restarts = policy["restarts"]
    if len(declared_restarts) > LIFECYCLE_POLICY_MAX_INSTANCES:
        fail("lifecycle policy: restart policy count exceeds the declared bound")
    restarts: list[tuple[bytes, int, int, int, int]] = []
    seen_subjects: set[str] = set()
    for entry in declared_restarts:
        name = entry["instance"]
        if name not in instances:
            fail(f"lifecycle policy: restart policy names unknown instance {name}")
        if name in seen_subjects:
            fail(f"lifecycle policy: duplicate restart policy for {name}")
        seen_subjects.add(name)
        attempts = entry["attempts"]
        if (
            not isinstance(attempts, int)
            or isinstance(attempts, bool)
            or not 0 <= attempts <= LIFECYCLE_POLICY_MAX_RESTART_ATTEMPTS
        ):
            fail(
                f"lifecycle policy: {name} declares attempts={attempts} outside "
                f"0..={LIFECYCLE_POLICY_MAX_RESTART_ATTEMPTS}"
            )
        backoff_ns = entry["backoffNs"]
        if (
            not isinstance(backoff_ns, int)
            or isinstance(backoff_ns, bool)
            or not 0 <= backoff_ns <= LIFECYCLE_POLICY_MAX_BACKOFF_NS
        ):
            fail(
                f"lifecycle policy: {name} declares backoffNs={backoff_ns} outside "
                f"0..={LIFECYCLE_POLICY_MAX_BACKOFF_NS}"
            )
        factor = entry.get("backoffFactor", LIFECYCLE_POLICY_BACKOFF_FACTOR_SCALE)
        if (
            not isinstance(factor, int)
            or isinstance(factor, bool)
            or not LIFECYCLE_POLICY_BACKOFF_FACTOR_SCALE
            <= factor
            <= LIFECYCLE_POLICY_MAX_BACKOFF_FACTOR
        ):
            fail(
                f"lifecycle policy: {name} declares backoffFactor={factor} outside "
                f"{LIFECYCLE_POLICY_BACKOFF_FACTOR_SCALE}.."
                f"={LIFECYCLE_POLICY_MAX_BACKOFF_FACTOR}; a factor below the scale "
                "would shrink each successive delay"
            )
        restarts.append(
            (
                lifecycle_instance_identity(name),
                attempts,
                lifecycle_cause_mask(entry["causes"], name),
                backoff_ns,
                factor,
            )
        )
    # The terminal state must be reachable, or exhaustion moves an instance
    # somewhere the graph says it cannot go.
    if restarts and not any(target == terminal_state for _, target in transitions):
        fail(
            f"lifecycle policy: {policy['terminalState']} is the declared terminal "
            "state but no transition reaches it, so an exhausted instance could not "
            "enter it"
        )

    declared_dependencies = policy["dependencies"]
    if len(declared_dependencies) > LIFECYCLE_POLICY_MAX_DEPENDENCIES:
        fail("lifecycle policy: dependency count exceeds the declared bound")
    dependencies: list[tuple[bytes, bytes, int]] = []
    seen_dependencies: set[tuple[str, str]] = set()
    for entry in declared_dependencies:
        subject = entry["instance"]
        dependency = entry["dependency"]
        for name in (subject, dependency):
            if name not in instances:
                fail(f"lifecycle policy: health dependency names unknown instance {name}")
        if subject == dependency:
            fail(
                f"lifecycle policy: {subject} declares a health dependency on itself, "
                "which is a start condition that can never be satisfied"
            )
        if (subject, dependency) in seen_dependencies:
            fail(f"lifecycle policy: duplicate health dependency {subject} -> {dependency}")
        seen_dependencies.add((subject, dependency))
        dependencies.append(
            (
                lifecycle_instance_identity(subject),
                lifecycle_instance_identity(dependency),
                state_id(entry["requiredState"], f"{subject}'s health dependency"),
            )
        )

    declared_parameters = policy["parameters"]
    if len(declared_parameters) > LIFECYCLE_POLICY_MAX_PARAMETER_GRANTS:
        fail("lifecycle policy: parameter grant count exceeds the declared bound")
    parameters: list[tuple[bytes, bytes, int]] = []
    seen_parameters: set[tuple[str, str]] = set()
    for entry in declared_parameters:
        holder = entry["holder"]
        subject = entry["subject"]
        for name in (holder, subject):
            if name not in instances:
                fail(f"lifecycle policy: parameter grant names unknown instance {name}")
        if (holder, subject) in seen_parameters:
            fail(f"lifecycle policy: duplicate parameter grant {holder} -> {subject}")
        seen_parameters.add((holder, subject))
        flags = 0
        if entry["read"]:
            flags |= LIFECYCLE_PARAMETER_READ
        if entry["write"]:
            flags |= LIFECYCLE_PARAMETER_WRITE
        if flags == 0:
            fail(
                f"lifecycle policy: parameter grant {holder} -> {subject} carries "
                "neither read nor write, so it declares authority with no content"
            )
        parameters.append(
            (
                lifecycle_instance_identity(holder),
                lifecycle_instance_identity(subject),
                flags,
            )
        )

    transitions.sort()
    restarts.sort(key=lambda entry: entry[0])
    dependencies.sort(key=lambda entry: (entry[0], entry[1]))
    parameters.sort(key=lambda entry: (entry[0], entry[1]))
    return {
        "initial_state": initial_state,
        "terminal_state": terminal_state,
        "transitions": transitions,
        "restarts": restarts,
        "dependencies": dependencies,
        "parameters": parameters,
    }


def build_lifecycle_policy(manifest: dict) -> bytes:
    policy = validated_lifecycle_policy(manifest)
    if policy is None:
        fail("lifecycle-policy resource object declared without a lifecyclePolicy")
    transitions = policy["transitions"]
    restarts = policy["restarts"]
    dependencies = policy["dependencies"]
    parameters = policy["parameters"]
    total_len = (
        LIFECYCLE_POLICY_HEADER_BYTES
        + len(transitions) * LIFECYCLE_TRANSITION_BYTES
        + len(restarts) * LIFECYCLE_RESTART_BYTES
        + len(dependencies) * LIFECYCLE_DEPENDENCY_BYTES
        + len(parameters) * LIFECYCLE_PARAMETER_GRANT_BYTES
    )
    header = LIFECYCLE_POLICY_HEADER.pack(
        LIFECYCLE_POLICY_MAGIC,
        LIFECYCLE_POLICY_VERSION,
        LIFECYCLE_POLICY_HEADER_BYTES,
        0,
        policy["initial_state"],
        policy["terminal_state"],
        len(transitions),
        len(restarts),
        len(dependencies),
        len(parameters),
        total_len,
    )
    return (
        header
        + b"".join(
            LIFECYCLE_TRANSITION.pack(source, target, 0) for source, target in transitions
        )
        + b"".join(
            LIFECYCLE_RESTART.pack(identity, attempts, causes, backoff, factor, b"\0" * 12)
            for identity, attempts, causes, backoff, factor in restarts
        )
        + b"".join(
            LIFECYCLE_DEPENDENCY.pack(subject, dependency, state, 0)
            for subject, dependency, state in dependencies
        )
        + b"".join(
            LIFECYCLE_PARAMETER_GRANT.pack(holder, subject, flags, 0)
            for holder, subject, flags in parameters
        )
    )

def recording_instance_identity(name: str) -> bytes:
    """Stable per-instance identity, matching boot_contracts::recording_policy.

    Its own domain tag, so an identity minted for a clock holder, a wait-set
    waiter, a scheduling subject, or a lifecycle instance cannot authenticate as
    a recording participant.
    """
    encoded = name.encode("utf-8")
    return sha256(
        b"slime-recording-policy-instance-v1" + struct.pack("<H", len(encoded)) + encoded
    )


def recording_stream_identity(name: str) -> int:
    """Stable per-stream identity, matching boot_contracts::recording_policy.

    A separate fold from the instance identity because a stream name and an
    instance name may coincide, and folding both the same way would let one
    authenticate as the other.
    """
    encoded = name.encode("utf-8")
    digest = sha256(b"slime-recording-policy-stream-v1" + struct.pack("<H", len(encoded)) + encoded)
    return int.from_bytes(digest[:8], "little")


def recording_stream_grant_identity(name: str) -> int:
    """Stable per-grant identity, matching boot_contracts::recording_policy.

    Its own domain tag for the stream fold's reason, and it matters more here:
    this identity names a *grant* whose rights the determinism check subtracts, so
    a stream name folding to the same eight bytes would exempt whichever grant
    collided with it.
    """
    encoded = name.encode("utf-8")
    digest = sha256(
        b"slime-recording-policy-stream-grant-v1" + struct.pack("<H", len(encoded)) + encoded
    )
    return int.from_bytes(digest[:8], "little")


def instance_held_rights(manifest: dict) -> dict[str, dict[str, int]]:
    """The rights each instance holds, per grant name, from the generation's own
    tables.

    Keyed by grant name rather than summed, because the C9.5 determinism check
    subtracts one *named* grant — the one a replayer's recording arrives over —
    and a pre-summed mask could not express that exception.

    Read from each instance's own `bindings` rather than by comparing a grant's
    `target` to the instance. The two differ: an executable capability's target is
    an executable, so a target comparison drops every executable grant a component
    is bound, and a deterministic instance bound `spawn` would pass unexamined
    (found by review). `slime-root` derives the same set from the encoded bindings
    under `grant_applies_to_instance`, so both readers ask the same question.

    Minted bindings are included because the root installs those as authority too.
    """
    grants = {grant["name"]: grant for grant in manifest["grants"]}
    held: dict[str, dict[str, int]] = {entry["name"]: {} for entry in manifest["instances"]}
    for instance in manifest["instances"]:
        name = instance["name"]
        for binding in instance.get("bindings") or []:
            grant = grants.get(binding["grant"])
            if grant is None:
                fail(f"recording policy: {name} binds unknown grant {binding['grant']}")
            mask = 0
            for right in grant["rights"]:
                if right not in RIGHT:
                    fail(f"recording policy: grant {grant['name']} names unknown right {right}")
                mask |= RIGHT[right]
            held[name][grant["name"]] = held[name].get(grant["name"], 0) | mask
    for minted in manifest.get("mintedBindings", []):
        holder = minted.get("holder")
        if holder not in held:
            continue
        mask = 0
        for right in minted["rights"]:
            if right not in RIGHT:
                fail(
                    f"recording policy: minted binding {minted['name']} names unknown "
                    f"right {right}"
                )
            mask |= RIGHT[right]
        held[holder][minted["name"]] = held[holder].get(minted["name"], 0) | mask
    return held


def unrecorded_right_names(mask: int) -> list[str]:
    """The manifest spellings of every unrecorded right in `mask`.

    Used only for the refusal message. The decision is the mask test; this turns
    it back into names so a build failure says which authority made the
    determinism claim inadmissible rather than printing a bit pattern.
    """
    return sorted(
        name for name, bit in RIGHT.items() if bit & mask & GENERATION_RIGHT_UNRECORDED
    )


def validated_recording(manifest: dict) -> list[tuple[bytes, int, int, int, int, bytes]] | None:
    """Resolve the C9.5 recording table, refusing every contradiction here.

    Returns `None` when the manifest declares no table, and otherwise the wire
    rows in the contract's canonical order. Every rule the decoder enforces on
    bytes is enforced here on names, so a malformed table fails naming the
    instance rather than as a `DecodeError` on a boot.

    The refusal C9.5 asks for is the last one below, and it is a *join*: the
    determinism claim comes from this table, the grants come from the generation's
    own grant and minted-binding tables, and the verdict comes from the
    `determinism` classification each right carries in
    `contracts/generation/v5`, folded there into `GENERATION_RIGHT_UNRECORDED`.
    No single one of the three could refuse it.

    The classification needs no completeness check here: it is a required field
    on every right rather than a list beside them, so a right added without one
    fails to type-check and its bit lands in exactly one class by construction.
    """
    declarations = manifest.get("recording")
    if declarations is None:
        return None
    if len(declarations) > RECORDING_POLICY_MAX_INSTANCES:
        fail("recording policy: entry count exceeds the declared bound")
    instances = {entry["name"] for entry in manifest["instances"]}
    held = instance_held_rights(manifest)
    entries: list[tuple[bytes, int, int, int, int, bytes]] = []
    seen_instances: set[str] = set()
    streams: dict[str, dict[str, object]] = {}
    for declaration in declarations:
        name = declaration["instance"]
        if name not in instances:
            fail(f"recording policy: unknown instance {name}")
        if name in seen_instances:
            fail(
                f"recording policy: {name} is declared twice; an instance recording "
                "and replaying at once has no meaning"
            )
        seen_instances.add(name)
        stream = declaration["stream"]
        role = RECORDING_POLICY_ROLE_BY_MANIFEST_NAME.get(declaration["role"])
        if role is None:
            fail(f"recording policy: {name} declares unknown role {declaration['role']!r}")
        capacity = declaration["recordCapacity"]
        if (
            not isinstance(capacity, int)
            or isinstance(capacity, bool)
            or not 1 <= capacity <= RECORDING_POLICY_MAX_RECORD_CAPACITY
        ):
            fail(
                f"recording policy: {name} declares recordCapacity={capacity} outside "
                f"1..={RECORDING_POLICY_MAX_RECORD_CAPACITY}"
            )
        tracked = streams.setdefault(stream, {"capacity": capacity, "roles": []})
        if tracked["capacity"] != capacity:
            fail(
                f"recording policy: stream {stream} is declared with two record "
                "capacities; one recording has one length"
            )
        tracked["roles"].append((name, role))
        # `streamGrant` is the declared exception to the determinism join, so it
        # is validated as strictly as the claim it excuses: only a replayer may
        # name one, it must be a grant this instance is actually bound, and its
        # rights are subtracted from nothing else.
        stream_grant = declaration.get("streamGrant")
        if stream_grant is not None and role != RECORDING_POLICY_ROLE_REPLAY:
            fail(
                f"recording policy: {name} declares a streamGrant without replaying; a "
                "recorder writes its stream, and writing is not an unrecorded source"
            )
        if stream_grant is not None and stream_grant not in held[name]:
            fail(
                f"recording policy: {name} declares streamGrant {stream_grant}, which it "
                "is not bound; an exemption naming nothing would excuse whichever "
                "authority the composition meant it to cover"
            )
        deterministic = declaration["deterministic"]
        if not isinstance(deterministic, bool):
            fail(f"recording policy: {name} declares a non-boolean deterministic flag")
        if deterministic:
            examined = 0
            for grant_name, mask in held[name].items():
                if grant_name == stream_grant:
                    continue
                examined |= mask
            unrecorded = unrecorded_right_names(examined)
            if unrecorded:
                fail(
                    f"recording policy: {name} is declared deterministic while holding "
                    + ", ".join(unrecorded)
                    + ", which contracts/generation/v5 classifies as an unrecorded "
                    "nondeterminism source; a replay of this component would read live "
                    "state no recording captured"
                )
        entries.append(
            (
                recording_instance_identity(name),
                recording_stream_identity(stream),
                recording_stream_grant_identity(stream_grant) if stream_grant else 0,
                role,
                RECORDING_POLICY_FLAG_DETERMINISTIC if deterministic else 0,
                capacity,
                b"\0" * 4,
            )
        )
    for stream, tracked in streams.items():
        roles = tracked["roles"]
        recorders = [name for name, role in roles if role == RECORDING_POLICY_ROLE_RECORD]
        replayers = [name for name, role in roles if role == RECORDING_POLICY_ROLE_REPLAY]
        if len(recorders) != 1 or len(replayers) != 1:
            fail(
                f"recording policy: stream {stream} declares {len(recorders)} recorders "
                f"and {len(replayers)} replayers; a stream is exactly one of each, or "
                "the artifact has two writers or is compared against itself"
            )
    # `instance_identity` strictly ascending is the canonical encoding the decoder
    # requires — strictly, because one entry per instance is the API's promise —
    # so a reordered or duplicated resource fails structurally.
    entries.sort(key=lambda entry: entry[0])
    return entries


def build_recording_policy(manifest: dict) -> bytes:
    entries = validated_recording(manifest)
    if entries is None:
        fail("recording-policy resource object declared without a recording table")
    total_len = RECORDING_POLICY_HEADER_BYTES + len(entries) * RECORDING_POLICY_ENTRY_BYTES
    header = RECORDING_POLICY_HEADER.pack(
        RECORDING_POLICY_MAGIC,
        RECORDING_POLICY_VERSION,
        RECORDING_POLICY_HEADER_BYTES,
        0,
        len(entries),
        total_len,
    )
    return header + b"".join(RECORDING_POLICY_ENTRY.pack(*entry) for entry in entries)

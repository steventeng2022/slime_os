# Zenoh Profile 0 transport

The bounded Zenoh subset two ROS 2 demo nodes use to exchange one topic: the
wire codec, a pure session machine, a runtime that carries a session over a byte
stream, and the two node components that run it on `sel4-zenoh`. It is a
userspace consumer of the [network service](network-service.md): the service
carries bytes and parses nothing, and every Zenoh concept lives in these
modules.

Owners:

- wire vocabulary and bounds: `contracts/zenoh-profile/v1/` (generated
  `components/proto/src/zenoh_profile.rs`); the wire records themselves belong
  to eclipse-zenoh wire version `0x09` and are not declared here;
- decoder and `StreamFramerOf`: `components/lib/src/zenoh_profile0.rs`; encoder:
  `zenoh_profile0/encode.rs`; session machine: `zenoh_profile0/session.rs`;
- link configurations: `contracts/zenoh-link-limits/v1/` judges a named configuration, and
  `zenoh_profile0/limits.rs` states the same arithmetic in Rust; FRAGMENT:
  `zenoh_profile0/fragment.rs`; reassembly into storage the component lends:
  `zenoh_profile0/reassembly.rs`; slot tables: `zenoh_profile0/tables.rs`;
- classic CDR for `Counter`: `components/lib/src/ros_cdr.rs`;
- transport runtime: `components/lib/src/zenoh_link.rs`;
- the nodes' shared exchange logic: `components/lib/src/zenoh_node.rs`;
- nodes: `components/applications/ros2-demo-publisher` and
  `components/applications/ros2-demo-subscriber`;
- composition: `contracts/system-spec/v1/systems/sel4-zenoh.zti` (generation 168),
  from which `contracts/generation-manifest/v1/compositions/sel4-zenoh.zti` is
  derived;
- the external variant: `contracts/system-spec/v1/systems/sel4-zenoh-external.zti`
  (generation 169) and the nodes `components/applications/ros2-demo-publisher-external`
  and `ros2-demo-subscriber-external` (see [External listener](#external-listener));
- the demo it serves: [`contracts/rpi5-ros2-demo/v2`](../../contracts/rpi5-ros2-demo/v2/README.md);
- plan and decision: [`../plans/ros2-wire-compatibility.md`](../plans/ros2-wire-compatibility.md),
  [`../decisions/zenoh-profile0-transport.md`](../decisions/zenoh-profile0-transport.md).

## Boundary

Profile 0 admits one static peer link over one TCP connection: the
`INIT`/`OPEN` handshake as connector or listener, reliable `FRAME` batches
carrying `DECLARE_SUBSCRIBER`, `UNDECLARE_SUBSCRIBER` and a `PUSH` with a `Put`
body and the 33-byte `rmw_zenoh` attachment, `KEEP_ALIVE`, and `CLOSE`. A stock
eclipse-zenoh 1.0.0 peer on the plain demo topic is also taken
([decision](../decisions/zenoh-stock-peer.md)): the optional QoS extension on
`INIT_SYN` and, only where it was observed, on `OAM` and on the outer `DECLARE`; an
`OAM` and a `DeclareFinal` after `OPEN`; and one numeric key-expression alias for the
demo key, in the declaring peer's mapping only (a reference in the receiver's mapping
names an alias this side declared, and it declares none, so it is `invalid-keyexpr`); and its
`UndeclareSubscriber`, which names the subscriber by id alone behind the network QoS extension
(`9e 21 08 03 <id>`, [decision](../decisions/zenoh-stock-undeclare.md)). The session removes the
remote subscriber it holds under that id, and an id it does not hold is `unknown-subscriber`; the
full form still matches on id and key, and the bare form without the QoS extension stays
`malformed-message`. Everything else is refused with a class from the closed vocabulary in
`contracts/zenoh-profile/v1`, never tolerated: routers and clients, wildcard key
expressions, other resolutions, unknown extensions and messages. A second alias is
refused as over-bound and an undeclared one as `invalid-keyexpr`.

Bounds are enforced before any byte is taken. The first release's are the demo
contract's: a 512-byte batch, 129-byte key expression, 33-byte attachment, 12-byte
payload, 64-byte cookie, one subscriber, four outstanding samples and three retries,
and `Link`, `Session` and `decode_batch` still mean exactly that. A link may instead
be built from a named configuration that `contracts/zenoh-link-limits/v1` judges
(batch, key, payload, key and subscriber counts, outstanding samples, stack and heap),
in one of two modes. The arrays of a link and its session equal what the configuration
declares: storage larger or smaller than that is refused at construction as
`InvalidConfig`.

- **fixed**: no heap, every buffer an array sized from the configuration, and a message
  must fit one batch. A Put that does not fit is refused as `over-bound`, and a
  FRAGMENT is refused as `unsupported-message` whatever its form;
- **heap**: the owning component lends the storage a fragmented message is joined into
  (`LinkOf::pump_with`), and a Put larger than a batch is sent and received as reliable
  `FRAGMENT`s. One message is reassembled at a time, a run's first fragment must be the
  session's next expected sequence number, a gap is `fragment-sequence`, a run that
  outlives its declared timeout is `reassembly-timeout`, and the joined message is held
  to what a whole-frame Put is held to. Best-effort fragments and fragments with
  extensions are still refused.

What a link sends is bounded by the smaller of its own batch and the one the peer
announced in its `INIT`. Nothing in these modules allocates.

`limits::LIDAR` is the heap configuration `lidar-publisher` uses. Its batch is 4096
bytes including the stream length, one network-service data operation. It admits a
payload of 512 KiB, so a 494,889-byte PointCloud2 frame crosses as 121 fragments.

## Layers

| Layer | What it owns | What it does not own |
| --- | --- | --- |
| Decoder, encoder | Bytes to and from `Message`, under the `Bounds` they are given; every length checked against its bound first; decoded values borrow from the batch | Session state, time, the link |
| Fragment codec, reassembly | Cutting a message into FRAGMENT bodies, reading one, joining a run into lent storage with a deadline measured from its first fragment | The session's sequence number, any clock, any memory of its own |
| Session machine | Handshake, cookie, frame sequence numbers, lease, subscriber and alias tables, delivery, the effective batch; time is an argument | I/O, allocation, any clock capability |
| `Link` over `ByteLink` | One framed batch awaiting send, partial writes, backpressure, the retry limit, reassembly, notices, generation-checked handles | A socket or a capability: the node passes it the connection the generation granted |
| Node exchange (`zenoh_node`) | The publisher and subscriber control flow as steppable state machines, the console lines, the service-reply-to-error mapping, the denied requests | Bindings, the connection, the console: those are the component's |
| Node components | Their bindings, the service connection, the clock and the console, handed to `zenoh_node` through two small traits | Any control flow worth testing |
| Service core (`zenoh_service`) | The grant rows, one ring of samples for each holder, the subscriptions it declares to the peer, and the routing of a publication and of a peer's sample by the rows | A session of its own (the caller lends one on each call), a link, a clock, network authority |

The session keeps slot tables of the sizes its type states (`SessionOf<K, S, B, E>`:
`K` key aliases, `S` subscribers of both sides, keys of up to `B` bytes, and `E`
events one batch can yield; `Session` is the first release's one alias and one
subscriber of each side). A subscriber *this side* declared is delivered to: a
received `PUSH` reaches only its key. A subscriber *the peer* declared is published
to: a `Put` this side sends must name its key. A `FRAME`'s changes to the tables are
journaled and undone if a later message in it is refused, and a frame that changes
more than the journal holds is refused before it changes anything. A publisher therefore learns the subscriber's key from its
declaration before it may publish, and a subscriber never accepts a `Put` for a
key it did not declare. Frames the session sends use the sender key mapping,
as the upstream encoder writes them.

`Params::local` is the number of subscriptions this side may declare, and the table
holds `per_side + local` slots. `Params::DEMO` and `Params::from_limits` set it to 1, so
the first release and every link built from `contracts/zenoh-link-limits/v1` keep one.
A side that declares a subscription beyond `local`, or one under an id it already
holds, is refused as `subscriber-limit`. A `local` below 1, or a table of any other
size, is refused at construction as `InvalidConfig`. Two subscriptions on one key
deliver a `Put` once, and the `Put` is refused as `undeclared-key` once the last
subscription on that key is undeclared. A link configuration cannot yet declare more
than one; that needs a new version of the limits contract.

An open session sends a one-byte `KEEP_ALIVE` (message id 4) every quarter of the
lease this side announced when it has sent nothing else, floored at one millisecond,
and takes the peer's as traffic that renews the lease. Before `OPEN` a `KEEP_ALIVE`
is `unexpected-message` and changes nothing, and it is exactly the one byte: a
trailing byte is `trailing-bytes`. The peer expires a link on the lease announced to it,
so that lease sets the send cadence; the lease the peer announced bounds the silence
tolerated from it. A link quiet for longer than the peer's lease is
closed by `tick` with the expiry reason. The demo exchanges its samples well inside
the 2 s lease. A link whose send slot is occupied runs only the expiry half
(`tick_lease`), so a keep-alive never collides with a batch waiting there.

A refused call leaves the session unchanged. The only transitions into
`Closed` are a received `CLOSE`, a local `close()` and lease expiry; a caller
that wants the link gone after a refusal says so.

## Service core

The service core (`components/lib/src/zenoh_service.rs`) serves one session to several local holders by
the rows of `contracts/zenoh-service-grants/v1`. A row names a holder, one exact key and the rights to
publish and to subscribe, and a key in a request grants nothing. The core is declared with its rows and
the session's parameters. It does not own the session. The caller lends one on each call, and the core
refuses a session declared with other parameters, so its size is its own and stays under the overheads
the contract states.

After the session opens, the core declares one subscription for each distinct subscribe key, numbered
from 1 in the order the keys first appear in the rows. A publication needs a row that grants the holder
the right to publish the key. It reaches every holder with a subscribe row on the key, the publisher
included, and it is written to the peer only if the peer declared a subscriber on the key. Otherwise the
core reports the peer's copy as not subscribed and the local copies still arrive. A refused publication
reaches no ring and writes nothing. A peer's sample reaches every holder with a subscribe row on the
subscription that matched, and `Event::SampleDelivered` names that subscription. A Put for a key no
subscription holds is refused as `undeclared-key`.

Each holder has a ring of fixed slots. A holder that does not take never blocks another. A full ring
keeps its newest samples and counts what it dropped, and the next take reports the count once. The core
serves whole-frame samples only, so a session that reassembles fragments is refused. A component that
wraps the core, the client interface and the path of the grants from the system spec are later items.

## Link behaviour

- `Link::pump` flushes the pending send, reads, decodes and replies, then checks
  the lease. A send that accepts nothing counts as a stall; more than
  `MAX_RETRIES` consecutive stalls end the link with `RetryLimit`, and any
  progress resets the count.
- Reassembly takes a length prefix as soon as both bytes arrive, so a zero or
  oversized prefix is refused before its body. A received batch is never dropped:
  while the send slot or the notice queue is full the batch stays in the
  framer, and a full buffer with no complete batch is `ReceiveQueueFull`.
- A heap link takes its storage on every `pump_with`, cut into cells of one message
  each. A sample, whole or fragmented, stays in its cell until its notice is taken, so
  a batch waits until the queue has room for every notice it can raise and, for each
  sample, a free cell. `LinkOf` sizes its buffers and notice queue from its type; a Put
  larger than one frame is sent a fragment per `publish_part`, resuming where the last
  call left off.
- A pass that raised notices ends there, so `last_received_batch` names the batch
  behind the notices the owner is about to take; `last_sent_batch` names the
  batch most recently queued. Nodes print both as evidence.
- A `LinkHandle` carries the generation of the link that issued it. A restart
  builds a new link under the next generation, and an operation through an old
  handle is `StaleHandle`.

## Node exchange

The nodes are thin. Everything that decides what a node does lives in
`components/lib/src/zenoh_node.rs`, which builds on the host: `Publisher` and
`Subscriber` are steppable state machines over a `Link`, and a component supplies
only a `Host` (clock, yield, console) and a `Connection` (non-blocking send and
receive on one service connection). The host tests run the real publisher and
subscriber against each other over a scripted stream, so the order a node acts in
and every line it prints are judged without QEMU.

`Line` collects a console line in a fixed buffer and emits it by a single write. A
line that does not fit is refused whole and never truncated, so a clipped hex line
cannot reach the judge. The demo's frames are 184 bytes (368 hex digits); a full
512-byte batch would clip and is refused.

## Node authority

`sel4-zenoh` contains `init`, `network-service` and the two nodes over the
loopback backend. The publisher holds one destination, exact IPv4 TCP to
`127.0.0.1:7447` with `connect`, `send` and `recv` and no listener or DNS
authority. The subscriber is the one loopback listener on that endpoint with
`listen`, `send` and `recv`, admitting exactly the publisher's holder. Each
node attempts requests it was not granted, checks that each reply is a denial
(status `denied`, nothing moved, no capability), and only then reports it by name.
The publisher attempts an undeclared host, a port the endpoint does not name, a
listen, and a *scouting* request: a well-formed UDP connect to Zenoh's multicast
scouting group, which no destination row names. The subscriber attempts a connect.
Profile 0 has no scouting message, so the denial is the service refusing the
request, not the codec; a refusal of a malformed request would prove nothing about
authority.
Each console line is written in one `debug_write`, because the two nodes run
concurrently and a line built from several writes can be interleaved.

## External listener

`sel4-zenoh-external` (generation 169) is the same demo with the publisher dialling a
stock `eclipse-zenoh` 1.0.0 listener on the host through a virtio NIC, so a packet
leaves the VM and can be captured. It contains `init`, `network-service`,
`virtio-net-driver`, `ros2-demo-publisher` and `ros2-demo-subscriber` and one network
interface (`10.0.2.15/24`, gateway `10.0.2.2`, MAC `52:54:00:53:4c:01`). The publisher
holds one destination, exact IPv4 TCP to `10.0.2.2:17447` with `connect`, `send` and
`recv`, and is a rightless client on the `external` backend. The subscriber holds no
network authority and its executable exits at once.

The instance names stay `ros2-demo-publisher` and `ros2-demo-subscriber`, which the exam
pins; only their `executable` differs (`ros2-demo-publisher-external`,
`ros2-demo-subscriber-external`). The publisher reuses `zenoh_node` and `zenoh_link`
unchanged; the subscriber links only `slime-rt` and exits at once, so no Zenoh code runs
on its side. The publisher's endpoint is a compile-time constant; the network service enforces the real
destination row, so a wrong constant is refused there and grants nothing. The publisher
still sends its four refused requests. The scouting probe, a UDP connect, is refused by
the external backend as `unsupported` and not `denied`, because its TCP-only engine
checks the transport before the destination table; the publisher accepts that reply for
that probe only and prints the same `denial class=scouting` line.

`just zenoh_external_check` judges one run from three witnesses held against each other:
the derived composition, a QEMU `filter-dump` capture at the virtio-net device (one TCP
connection to `10.0.2.2:17447`, ARP only besides it), and the record the stock listener
wrote of what its own subscriber delivered. The guest's batches are held to
`scripts/lib/zenoh_wire.py`. The listener is a hash-pinned wheel from a registry, so the
recipe is explicit and in no aggregate. See the
[decision](../decisions/zenoh-external-listener.md).

## Limitations

- `sel4-zenoh` crosses the loopback backend, so there is no packet capture there. The
  nodes' reported batches observe their codecs and session at the service's
  application boundary, not the stack's wire, and the guest chooses what it
  prints. `sel4-zenoh-external` is the composition with a capture.
- `sel4-zenoh`'s evidence is the nodes' own reports at the service boundary. Under
  QEMU the corrected exam accepts the booted guest; see the plan for what was
  observed and on which image.
- The external exam runs on QEMU user networking, not a physical NIC. Its translation
  of the guest's connection to the host's loopback is not the wire a real network
  shows. It covers one peer: `eclipse-zenoh` 1.0.0, peer mode, scouting and gossip off.
- A Zenoh ID ending in `0x00`, or all zero, is refused: upstream holds it as a
  little-endian integer, drops trailing zero bytes and refuses zero, so the bytes
  would not round-trip.
- No `rmw_zenoh` interoperability, liveliness, queryables, router, scouting or
  transport security, and no Raspberry Pi 5 claim. The ROSIDL importer and RIHS01
  generator are not here: the demo contract's checker derives those values.

## Verification

- `just zenoh_encoder_check` — all 17 upstream-encoded corpus batches
  reproduced byte for byte, after the host reference `scripts/lib/zenoh_wire.py`
  reproduces them; 7 named refusals;
- `just zenoh_session_check` — 5 scenarios and 7 refusals;
- `just zenoh_cdr_check` — the demo fixture's 4 samples and 7 malformed inputs;
- `just zenoh_transport_check` — 6 scenarios and 7 refusals over a scripted link;
- `just zenoh_composition_check` — 15 authority facts on the derived manifest;
- `just zenoh_stock_check` — the session against the batches a stock eclipse-zenoh
  1.0.0 peer put on a TCP stream;
- `just zenoh_links_check` — a link built from each named configuration: the stock
  peer's fragments reproduced byte for byte, payloads up to 256 MiB reassembled, the
  tables and notice queue filled to their limits at 9, 256, 65535 and 65536, and 94
  refusals by name and class, each judged on a link and on its session;
- `just zenoh_undeclare_check` — the whole session a stock eclipse-zenoh 1.0.0 peer sent,
  including its `UndeclareSubscriber` that names the subscriber by id alone behind the
  network QoS extension, which the host reference reproduces byte for byte, and ten
  variants of it refused by name and class;
- `just zenoh_xcheck_check` — the codec and session against the real eclipse-zenoh 1.0.0
  crates: the 17 corpus batches as upstream's encoder produces them, a 6000-case sweep
  (5993 compared, 7 refused as a non-canonical Zenoh ID, none differing), our decoder
  reading what upstream encodes, upstream reading and re-encoding ours, one 11-batch
  session, and eight Zenoh ID probes; 17 mutations of an honest transcript refused first.
  The harness is `verification/zenoh-xcheck`, a standalone crate outside the root
  workspace, so the upstream crates stay out of `Cargo.lock`, `just deny` and the
  closures. It fetches them from a registry, so the recipe is explicit and not in CI;
  `cargo deny` run on that crate reports `paste` as unmaintained (RUSTSEC-2024-0436) and
  Zlib-licensed transitive crates, which the root `deny.toml` does not allow;
- `just rpi5_ros2_zenoh_check` — the QEMU exchange; explicit, not part of `all`;
- `just zenoh_external_check` — the guest connecting out to a stock listener, judged
  from the composition, a packet capture and the listener's record; explicit, not part
  of `all`.

#![no_std]
#![no_main]

//! The publisher of the `sel4-lidar-external` composition: reads a LiDAR frame store from a
//! read-only data volume and publishes every frame, in index order, as one Zenoh Profile 0 Put to the
//! stock peer on the host.
//!
//! The volume and its store are validated with `slime_components::data_volume` before any frame is
//! sent, and each frame is then read back from the disk into one heap buffer of the frame's size, so
//! the store is never held whole. The link is the `lidar` heap configuration, whose batch is one
//! network-service operation with its stream length. A frame is handed to the link no sooner than
//! [`PERIOD_MS`] after the previous one; a frame that is ready later than that goes at once and is
//! counted late. The component prints exactly three lines on success: the store, the summary and the
//! closed session. Every failure prints one `fail:` line and exits nonzero.

extern crate alloc;

use alloc::vec::Vec;

use slime_components::block_io::BlockIo;
use slime_components::data_volume::{self, DeviceError, Disk, Error as VolumeError, FrameError};
use slime_components::network_io::{
    Connection as ServiceConnection, NetworkError, NetworkIo, NetworkNotifications, NetworkReply,
};
use slime_components::zenoh_link::{ByteLink, Error as LinkFault, LinkError, LinkOf, Notice};
use slime_components::zenoh_node::{Connection, GID, Reply, Stream};
use slime_components::zenoh_profile0::encode;
use slime_components::zenoh_profile0::limits::LIDAR;
use slime_components::zenoh_profile0::session::{Config, Params, Role};
use slime_proto::block_v2::SECTOR_BYTES;
use slime_proto::network_service as net;
use slime_rt::console_line::Line;
use slime_rt::{
    exit, monotonic_frequency, monotonic_read, notification_wait, resolve_binding, timer_arm,
    timer_cancel,
};

slime_rt::entry!(main);

const TAG: &[u8] = b"[lidar-publisher] ";

/// The publish period, a property of this component and not of the composition or the store.
const PERIOD_MS: u64 = 500;
/// Passes over the store.
const PASSES: usize = 1;

/// The ROS 2 data key of `/velodyne_points`, named in full in every Put.
const KEY: &str = "0/velodyne_points/sensor_msgs::msg::dds_::PointCloud2_/RIHS01_9198cabf7da3796ae6fe19c4cb3bdd3525492988c70522628af5daa124bae2b5";

/// The one destination the composition grants: the host as QEMU's user networking names it. The
/// network service enforces the row; a wrong constant is refused there, not trusted.
const ENDPOINT: [u8; 4] = [10, 0, 2, 2];
const PORT: u16 = 17447;

const ZID: [u8; 8] = [0xa3; 8];
/// The silence after which the peer may drop this side. Longer than any wait between two frames.
const LEASE_MS: u64 = 10_000;

/// Page-aligned addresses in this component's free VSpace range: the network ring and payload, then
/// the block ring and payload window.
const NET_RING_BASE: u64 = 0x0000_001c_0000_0000;
const NET_DATA_BASE: u64 = NET_RING_BASE + 4096;
const BLOCK_RING_BASE: u64 = 0x0000_001f_0000_0000;
const BLOCK_DATA_BASE: u64 = 0x0000_001f_0001_0000;

/// How long one network-service request may wait for its completion, in seconds.
const REQUEST_TIMEOUT_S: u64 = 10;
/// How long the session may take to open and see the peer's subscriber.
const HANDSHAKE_MS: u64 = 30_000;
/// How long the peer may take to end its stream after this side's CLOSE.
const CLOSE_MS: u64 = 30_000;
/// The wait between two polls that found nothing to do.
const POLL_MS: u64 = 2;
const CONNECT_ATTEMPTS: u32 = 200;
const CONNECT_RETRY_MS: u64 = 50;

/// The heap link `LIDAR` declares: a 4096-byte framed batch, its keys and subscribers of each side and
/// this side's one subscription, no payload copied into notices, and two notices per sample.
type LidarLink<'a, 'b> = LinkOf<
    Stream<Wire<'a, 'b>>,
    { LIDAR.batch_bytes },
    { LIDAR.max_keys },
    { LIDAR.max_subscribers + 1 },
    { LIDAR.key_bytes },
    0,
    { 2 * LIDAR.outstanding_samples },
    { LIDAR.events_per_batch() },
>;

/// The volume's block device: the block ring, read whole sectors at a time. It never writes.
struct Ring {
    io: BlockIo<'static>,
    capacity: u64,
}

impl Disk for Ring {
    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn read(&mut self, lba: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        let sectors = (out.len() / SECTOR_BYTES) as u32;
        match self.io.read(lba, out) {
            Ok(reply) if reply.sectors_done == sectors => Ok(()),
            _ => Err(DeviceError),
        }
    }
}

/// One connection of the network service. A send waits in the service for room in the transmit
/// buffer, so a batch larger than the buffer is accepted in parts instead of stalling the link; a
/// receive answers at once, so the link polls the peer without blocking.
struct Wire<'a, 'b> {
    io: &'a mut NetworkIo<'b>,
    connection: &'a ServiceConnection,
}

fn reply_of(reply: &NetworkReply) -> Reply {
    Reply {
        success: reply.is_success(),
        status: reply.status_detail,
        transferred: reply.transferred,
        end_of_stream: reply.flags == net::FLAG_END_OF_STREAM,
    }
}

impl Connection for Wire<'_, '_> {
    fn send(&mut self, bytes: &[u8]) -> Result<Reply, LinkError> {
        self.io
            .send(self.connection, bytes)
            .map(|reply| reply_of(&reply))
            .map_err(|_| LinkError::Reset)
    }

    fn recv(&mut self, bytes: &mut [u8]) -> Result<Reply, LinkError> {
        self.io
            .recv_nonblocking(self.connection, bytes)
            .map(|reply| reply_of(&reply))
            .map_err(|_| LinkError::Reset)
    }
}

/// The monotonic counter and the one Notification its timers and the network service signal.
struct Clock {
    rate: u64,
    wake: u32,
}

impl Clock {
    fn now(&self) -> u64 {
        monotonic_read().unwrap_or_else(|_| fail(b"clock read"))
    }

    fn ticks(&self, ms: u64) -> u64 {
        (u128::from(self.rate) * u128::from(ms) / 1000).min(u128::from(u64::MAX)) as u64
    }

    fn millis(&self, ticks: u64) -> u64 {
        (u128::from(ticks) * 1000 / u128::from(self.rate)) as u64
    }

    fn now_ms(&self) -> u64 {
        self.millis(self.now())
    }

    /// Blocks until the counter reaches `deadline`. Each wait is bounded by a timer on the shared
    /// Notification; a wake from any other source re-reads the counter and waits again. No request
    /// is outstanding while this runs, so the timer is the only one live, and it is cancelled before
    /// the next wait whether it fired or not.
    fn sleep_until(&self, deadline: u64) {
        loop {
            let now = self.now();
            if now >= deadline {
                return;
            }
            let timer = timer_arm(deadline - now).unwrap_or_else(|_| fail(b"timer arm"));
            let woke = notification_wait(self.wake);
            let _ = timer_cancel(timer);
            if woke.is_err() {
                fail(b"timer wait");
            }
        }
    }

    fn sleep_ms(&self, ms: u64) {
        let deadline = self.now().saturating_add(self.ticks(ms));
        self.sleep_until(deadline);
    }
}

fn main(_: u32) {
    let rate = monotonic_frequency().unwrap_or_else(|_| fail(b"clock rate"));
    if rate < 1000 {
        fail(b"clock rate too slow");
    }
    let clock = Clock {
        rate,
        wake: binding(b"notification:lidar-publisher-done+wait"),
    };
    if LIDAR.check().is_err() {
        fail(b"link limits");
    }

    // SAFETY: both bases are page-aligned addresses in this component's free VSpace range, do not
    // alias each other or the network regions, and nothing else maps them.
    let io = unsafe {
        BlockIo::attach(
            binding(b"lidar-publisher-buffer-factory"),
            binding(b"lidar-block-peer"),
            binding(b"notification:lidar-block-request-ready+signal"),
            binding(b"notification:lidar-block-completion-ready+wait"),
            BLOCK_RING_BASE,
            BLOCK_DATA_BASE,
        )
    }
    .unwrap_or_else(|_| fail(b"block attach"));
    let capacity = io.capacity();
    let mut ring = Ring { io, capacity };

    let volume = data_volume::open(&mut ring).unwrap_or_else(|error| fail_volume(error));
    let mut store =
        data_volume::open_store(&mut ring, &volume).unwrap_or_else(|error| fail_volume(error));
    let summary = *store.summary();
    Line::<256>::new()
        .bytes(TAG)
        .bytes(b"store frames=")
        .decimal(summary.frame_count as u64)
        .bytes(b" period=")
        .decimal(summary.frame_period_ns)
        .bytes(b" digest=")
        .hex_bytes(&summary.payload_digest)
        .bytes(b"\n")
        .emit();

    let mut heap: Vec<u8> = Vec::new();
    let heap_bytes = usize::try_from(LIDAR.heap_bytes).unwrap_or_else(|_| fail(b"heap size"));
    if heap.try_reserve_exact(heap_bytes).is_err() {
        fail(b"link heap");
    }
    heap.resize(heap_bytes, 0);
    let mut frame: Vec<u8> = Vec::new();

    let notifications = NetworkNotifications {
        request_signal: binding(b"notification:lidar-network-request+signal"),
        completion_wait: clock.wake,
        timeout_ticks: rate
            .checked_mul(REQUEST_TIMEOUT_S)
            .unwrap_or_else(|| fail(b"timer range")),
    };
    // SAFETY: these distinct page-aligned regions are reserved solely for this adapter, and the two
    // declared endpoints belong to the same service.
    let mut io = unsafe {
        NetworkIo::attach_with_notifications(
            binding(b"lidar-publisher-control"),
            binding(b"lidar-publisher-provision"),
            NET_RING_BASE,
            NET_DATA_BASE,
            notifications,
        )
    }
    .unwrap_or_else(|error| fail(attach_reason(error)));
    let connection = connect(&mut io, &clock);

    let config = Config {
        zid: &ZID,
        lease_ms: LEASE_MS,
        initial_sn: 0,
        cookie: b"",
    };
    {
        let wire = Wire {
            io: &mut io,
            connection: &connection,
        };
        let mut link = LidarLink::with_params(
            Stream::new(wire),
            Role::Connector,
            &config,
            Params::from_limits(&LIDAR),
            1,
        )
        .unwrap_or_else(|_| fail(b"session config"));
        let handle = link.handle();
        link.open(handle, clock.now_ms())
            .unwrap_or_else(|error| fail_link(error));
        let opened = clock.now_ms();
        let mut declared = false;
        while !(link.is_open() && declared) {
            if clock.now_ms().saturating_sub(opened) > HANDSHAKE_MS {
                fail(b"handshake deadline");
            }
            if !pump(&mut link, &mut heap, &clock, &mut declared) {
                clock.sleep_ms(POLL_MS);
            }
        }

        let period = clock.ticks(PERIOD_MS);
        let mut sent = 0u64;
        let mut bytes = 0u64;
        let mut late = 0u64;
        let mut first: Option<u64> = None;
        let mut previous: Option<u64> = None;
        for _pass in 0..PASSES {
            for index in 0..summary.frame_count {
                let extent = store.frame(index).unwrap_or_else(|error| fail_frame(error));
                if extent.len() as u64 > LIDAR.payload_bytes {
                    fail(b"frame larger than the link's payload bound");
                }
                frame.clear();
                if frame.try_reserve_exact(extent.len()).is_err() {
                    fail(b"frame buffer");
                }
                frame.resize(extent.len(), 0);
                store
                    .read(&extent, 0, &mut frame)
                    .unwrap_or_else(|error| fail_frame(error));
                let sequence = i64::try_from(sent + 1).unwrap_or_else(|_| fail(b"sequence"));
                let timestamp =
                    i64::try_from(extent.log_time_ns()).unwrap_or_else(|_| fail(b"log time"));
                let attachment = encode::attachment(sequence, timestamp, &GID)
                    .unwrap_or_else(|_| fail(b"attachment"));

                // The previous frame is wholly queued, so this one is ready; it waits out the rest
                // of the period, or goes at once and counts late if the period has already passed.
                if let Some(previous) = previous {
                    let due = previous.saturating_add(period);
                    if clock.now() > due {
                        late += 1;
                    } else {
                        clock.sleep_until(due);
                    }
                }
                let handed = clock.now();
                first.get_or_insert(handed);
                previous = Some(handed);
                publish(
                    &mut link,
                    &mut heap,
                    &clock,
                    &mut declared,
                    &attachment,
                    &frame,
                );
                sent += 1;
                bytes += extent.len() as u64;
            }
        }
        while link.send_pending() {
            if !pump(&mut link, &mut heap, &clock, &mut declared) {
                clock.sleep_ms(POLL_MS);
            }
        }
        let elapsed = match (first, previous) {
            (Some(first), Some(last)) => clock.millis(last - first),
            _ => 0,
        };
        Line::<256>::new()
            .bytes(TAG)
            .bytes(b"summary frames=")
            .decimal(sent)
            .bytes(b" bytes=")
            .decimal(bytes)
            .bytes(b" late=")
            .decimal(late)
            .bytes(b" elapsed_ms=")
            .decimal(elapsed)
            .bytes(b"\n")
            .emit();

        link.close(handle, 0)
            .unwrap_or_else(|error| fail_link(error));
        while link.send_pending() {
            if link.pump_with(handle, clock.now_ms(), &mut heap).is_err() {
                fail(b"close flush");
            }
            if link.send_pending() {
                clock.sleep_ms(POLL_MS);
            }
        }
        await_end_of_stream(link.io_mut(), &clock);
    }
    ring.io
        .shutdown()
        .unwrap_or_else(|_| fail(b"block shutdown"));

    if !io
        .close(connection)
        .unwrap_or_else(|_| fail(b"close request"))
        .is_success()
    {
        fail(b"close");
    }
    io.finish().unwrap_or_else(|_| fail(b"finish"));
    Line::<64>::new()
        .bytes(TAG)
        .bytes(b"session closed\n")
        .emit();
    exit(0)
}

/// Drives the link once and takes its notices. Returns whether bytes moved either way, so an idle
/// caller waits before the next poll. A peer that closes, or a sample sent to this side, which
/// declares no subscription, ends the run.
fn pump(link: &mut LidarLink<'_, '_>, heap: &mut [u8], clock: &Clock, declared: &mut bool) -> bool {
    let handle = link.handle();
    let report = link
        .pump_with(handle, clock.now_ms(), heap)
        .unwrap_or_else(|error| fail_link(error));
    while let Some(notice) = link.next_notice() {
        match notice {
            Notice::HandshakeComplete | Notice::SubscriberUndeclared { .. } => {}
            Notice::SubscriberDeclared { .. } => *declared = true,
            Notice::Closed { .. } => fail(b"peer closed the session"),
            Notice::SampleDelivered(_) | Notice::SampleStored(_) => fail(b"unexpected sample"),
        }
    }
    report.sent_bytes != 0 || report.received_bytes != 0
}

/// Queues one Put as its run of fragments, pumping between them so each goes out before the next is
/// cut. The key, attachment and payload are the same throughout, as the splitter requires.
fn publish(
    link: &mut LidarLink<'_, '_>,
    heap: &mut [u8],
    clock: &Clock,
    declared: &mut bool,
    attachment: &[u8],
    payload: &[u8],
) {
    let handle = link.handle();
    let mut at = 0;
    loop {
        while link.send_pending() {
            if !pump(link, heap, clock, declared) {
                clock.sleep_ms(POLL_MS);
            }
        }
        match link.publish_part(handle, KEY, attachment, payload, at) {
            Ok(Some(next)) => at = next,
            Ok(None) => break,
            Err(error) => fail_link(error),
        }
        pump(link, heap, clock, declared);
    }
}

/// Reads and discards what the peer still sends after this side's CLOSE until it ends its stream,
/// so the connection is closed by both sides and never reset over unread bytes.
fn await_end_of_stream(stream: &mut Stream<Wire<'_, '_>>, clock: &Clock) {
    let started = clock.now_ms();
    let mut chunk = [0u8; 512];
    loop {
        match stream.recv(&mut chunk) {
            Ok(0) if stream.eof() => return,
            Ok(0) => {
                if clock.now_ms().saturating_sub(started) > CLOSE_MS {
                    fail(b"peer did not end its stream");
                }
                clock.sleep_ms(POLL_MS);
            }
            Ok(_) => {}
            Err(_) => fail(b"stream after close"),
        }
    }
}

fn connect(io: &mut NetworkIo<'_>, clock: &Clock) -> ServiceConnection {
    for _ in 0..CONNECT_ATTEMPTS {
        let mut reply = io
            .connect_ipv4(ENDPOINT, PORT)
            .unwrap_or_else(|_| fail(b"connect request"));
        if let Some(connection) = reply.take_connection() {
            return connection;
        }
        if !matches!(
            reply.status_detail,
            net::STATUS_REFUSED | net::STATUS_WOULD_BLOCK
        ) {
            fail(b"connect refused");
        }
        clock.sleep_ms(CONNECT_RETRY_MS);
    }
    fail(b"connect attempts")
}

fn binding(name: &[u8]) -> u32 {
    resolve_binding(name).unwrap_or_else(|_| fail(b"binding"))
}

/// Names the attach failure so a boot that stops here says why, not only where.
fn attach_reason(error: NetworkError) -> &'static [u8] {
    match error {
        NetworkError::Setup => b"attach: setup",
        NetworkError::BadRequest => b"attach: bad request",
        NetworkError::Malformed => b"attach: malformed",
        NetworkError::Lost => b"attach: lost",
    }
}

fn fail_volume(error: VolumeError) -> ! {
    match error {
        VolumeError::Refused(refusal) => {
            Line::<128>::new()
                .bytes(TAG)
                .bytes(b"fail: volume refused ")
                .bytes(refusal.class().as_bytes())
                .bytes(b"\n")
                .emit();
            exit(1)
        }
        VolumeError::Device => fail(b"block read"),
    }
}

fn fail_frame(error: FrameError) -> ! {
    match error {
        FrameError::Range => fail(b"frame range"),
        FrameError::Refused => fail(b"frame entry changed"),
        FrameError::Device => fail(b"block read"),
    }
}

fn fail_link(error: LinkFault) -> ! {
    match error {
        LinkFault::Link(LinkError::Reset) => fail(b"link reset"),
        LinkFault::Link(LinkError::Closed) => fail(b"link closed"),
        LinkFault::Stream(_) => fail(b"link stream refused"),
        LinkFault::Session(_) => fail(b"link session refused"),
        LinkFault::Encode(_) => fail(b"link encode"),
        LinkFault::RetryLimit => fail(b"link retry limit"),
        LinkFault::SendBusy => fail(b"link send busy"),
        LinkFault::ReceiveQueueFull => fail(b"link receive queue full"),
        LinkFault::SendAfterClose => fail(b"link send after close"),
        LinkFault::StaleHandle => fail(b"link stale handle"),
        LinkFault::NeedsFragments => fail(b"link needs fragments"),
    }
}

fn fail(reason: &[u8]) -> ! {
    Line::<128>::new()
        .bytes(TAG)
        .bytes(b"fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    exit(1)
}

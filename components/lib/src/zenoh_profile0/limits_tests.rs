//! Host tests for the link configuration: the three pinned configurations and the boundaries
//! `contracts/zenoh-link-limits/v1` states, each on both sides.

use super::*;

fn with(base: Limits, change: impl FnOnce(&mut Limits)) -> Limits {
    let mut limits = base;
    change(&mut limits);
    limits.stack_bytes = limits.required_stack();
    if limits.mode == Mode::Heap {
        limits.heap_bytes = limits.heap_needed();
    }
    limits
}

#[test]
fn the_pinned_configurations_are_accepted() {
    for limits in [DEMO, LARGE, HEAP] {
        assert_eq!(limits.check(), Ok(()), "{}", limits.name);
    }
}

#[test]
fn the_pinned_figures_are_the_arithmetic() {
    assert_eq!(HEAP.message_bytes(), 16_556);
    assert_eq!(HEAP.heap_needed(), 149_004);
    assert_eq!(DEMO.required_stack(), 5442);
    assert_eq!(LARGE.required_stack(), 26_696);
    assert_eq!(HEAP.required_stack(), 18_504);
    assert!(DEMO.required_stack() <= DEMO.stack_bytes);
    assert!(LARGE.required_stack() <= LARGE.stack_bytes);
    assert!(HEAP.required_stack() <= HEAP.stack_bytes);
}

#[test]
fn a_batch_holds_the_handshake_and_one_operation() {
    let smallest = HANDSHAKE_BYTES + STREAM_LENGTH_BYTES;
    let heap = |batch: usize| {
        with(HEAP, |l| {
            l.batch_bytes = batch;
            l.key_bytes = 1;
        })
    };
    assert_eq!(heap(smallest - 1).check(), Err(LimitsError::Batch));
    assert_eq!(heap(smallest).check(), Ok(()));
    assert_eq!(heap(DATA_BYTES).check(), Ok(()));
    assert_eq!(heap(DATA_BYTES + 1).check(), Err(LimitsError::Batch));
    assert_eq!(heap(0).check(), Err(LimitsError::Batch));
}

#[test]
fn a_declaration_fits_the_batch_to_the_byte() {
    let key = |batch: usize, key: usize| {
        with(HEAP, |l| {
            l.batch_bytes = batch;
            l.key_bytes = key;
        })
    };
    // 19 bytes around a key below 126, 20 from 126, 21 from 16382; the batch holds all of it.
    assert_eq!(key(144, 125).declaration_bytes(), 144);
    assert_eq!(key(144, 125).check(), Ok(()));
    assert_eq!(key(143, 125).check(), Err(LimitsError::Batch));
    assert_eq!(key(146, 126).declaration_bytes(), 146);
    assert_eq!(key(146, 126).check(), Ok(()));
    assert_eq!(key(145, 126).check(), Err(LimitsError::Batch));
    assert_eq!(key(4096, 4076).check(), Ok(()));
    assert_eq!(key(4096, 4077).check(), Err(LimitsError::Batch));
    assert_eq!(key(2048, 2028).check(), Ok(()));
    assert_eq!(key(2048, 2029).check(), Err(LimitsError::Batch));
    assert_eq!(key(89, 70).check(), Ok(()));
    assert_eq!(key(89, 71).check(), Err(LimitsError::Batch));
}

#[test]
fn a_fixed_message_and_its_frame_fill_the_batch_exactly() {
    let payload = |payload: u64| with(LARGE, |l| l.payload_bytes = payload);
    assert_eq!(payload(1869).fixed_need(), 2048);
    assert_eq!(payload(1869).check(), Ok(()));
    assert_eq!(payload(1870).check(), Err(LimitsError::Fixed));
    // The step in the width of the payload length, at 127 and 128 bytes.
    let narrow = with(LARGE, |l| {
        l.payload_bytes = 127;
        l.batch_bytes = 89 + 400;
    });
    assert_eq!(narrow.check(), Ok(()));
    let batch = |payload: u64, batch: usize| {
        with(LARGE, |l| {
            l.payload_bytes = payload;
            l.batch_bytes = batch;
        })
    };
    assert_eq!(
        batch(127, 127 + 129 + 33 + 5 + 2 + 1 + 6 + 2).check(),
        Ok(())
    );
    assert_eq!(
        batch(127, 127 + 129 + 33 + 5 + 2 + 1 + 6 + 2 - 1).check(),
        Err(LimitsError::Fixed)
    );
    assert_eq!(
        batch(128, 128 + 129 + 33 + 5 + 2 + 2 + 6 + 2).check(),
        Ok(())
    );
    assert_eq!(
        batch(128, 128 + 129 + 33 + 5 + 2 + 2 + 6 + 2 - 1).check(),
        Err(LimitsError::Fixed)
    );
}

#[test]
fn a_fixed_link_has_no_timeout_or_heap_and_a_heap_link_needs_both() {
    let mut fixed = LARGE;
    fixed.reassembly_timeout_ms = 1000;
    assert_eq!(fixed.check(), Err(LimitsError::Fixed));
    let mut fixed = LARGE;
    fixed.heap_bytes = 1;
    assert_eq!(fixed.check(), Err(LimitsError::Fixed));
    let mut heap = HEAP;
    heap.reassembly_timeout_ms = 0;
    assert_eq!(heap.check(), Err(LimitsError::Heap));
    let mut heap = HEAP;
    heap.heap_bytes = heap.heap_needed() - 1;
    assert_eq!(heap.check(), Err(LimitsError::Heap));
    let mut heap = HEAP;
    heap.heap_bytes = heap.heap_needed();
    assert_eq!(heap.check(), Ok(()));
    // One message of heap is not enough for four outstanding samples, and two are not for one.
    heap.heap_bytes = heap.message_bytes();
    assert_eq!(heap.check(), Err(LimitsError::Heap));
    let one = with(HEAP, |l| l.outstanding_samples = 1);
    assert_eq!(one.heap_bytes, 3 * one.message_bytes());
    let mut short = one;
    short.heap_bytes = 2 * one.message_bytes();
    assert_eq!(short.check(), Err(LimitsError::Heap));
}

#[test]
fn any_positive_timeout_is_accepted() {
    for timeout in [1u64, 250, 5000, 65_536, 1 << 32, (1 << 63) - 1] {
        let limits = with(HEAP, |l| l.reassembly_timeout_ms = timeout);
        assert_eq!(limits.check(), Ok(()), "{timeout}");
    }
}

#[test]
fn counts_are_bounded_at_what_the_wire_and_the_arithmetic_hold() {
    let counts = |keys: usize, subscribers: usize, samples: usize| {
        with(HEAP, |l| {
            l.max_keys = keys;
            l.max_subscribers = subscribers;
            l.outstanding_samples = samples;
            l.payload_bytes = 4;
        })
    };
    assert_eq!(counts(0, 0, 4).check(), Err(LimitsError::Count));
    assert_eq!(counts(4, 0, 4).check(), Err(LimitsError::Count));
    assert_eq!(counts(2, 3, 4).check(), Err(LimitsError::Count));
    assert_eq!(counts(4, 4, 0).check(), Err(LimitsError::Count));
    assert_eq!(counts(65_535, 65_535, 1).check(), Ok(()));
    assert_eq!(counts(65_536, 65_536, 1).check(), Err(LimitsError::Count));
    assert_eq!(counts(256, 256, 256).check(), Ok(()));
    assert_eq!(counts(1, 1, 65_536).check(), Ok(()));
    assert_eq!(counts(1, 1, MAX_OUTSTANDING_SAMPLES).check(), Ok(()));
    assert_eq!(
        counts(1, 1, MAX_OUTSTANDING_SAMPLES + 1).check(),
        Err(LimitsError::Count)
    );
}

#[test]
fn sizes_are_bounded_at_what_the_wire_carries() {
    let key = |key: usize| {
        with(HEAP, |l| {
            l.key_bytes = key;
            l.batch_bytes = DATA_BYTES;
        })
    };
    assert_eq!(key(0).check(), Err(LimitsError::Size));
    assert_eq!(key(1).check(), Ok(()));
    let mut attachment = HEAP;
    attachment.attachment_bytes = 32;
    assert_eq!(attachment.check(), Err(LimitsError::Size));
    attachment.attachment_bytes = 34;
    assert_eq!(attachment.check(), Err(LimitsError::Size));
    let payload = |payload: u64| with(HEAP, |l| l.payload_bytes = payload);
    assert_eq!(payload(0).check(), Err(LimitsError::Size));
    assert_eq!(payload(1).check(), Ok(()));
    assert_eq!(payload(MAX_PAYLOAD_LENGTH_BYTES).check(), Ok(()));
    assert_eq!(
        payload(MAX_PAYLOAD_LENGTH_BYTES + 1).check(),
        Err(LimitsError::Size)
    );
}

#[test]
fn the_stack_must_cover_the_arithmetic_to_the_byte() {
    let mut limits = LARGE;
    limits.stack_bytes = limits.required_stack();
    assert_eq!(limits.check(), Ok(()));
    limits.stack_bytes -= 1;
    assert_eq!(limits.check(), Err(LimitsError::Stack));
}

#[test]
fn a_name_is_one_to_sixteen_bytes() {
    let mut limits = LARGE;
    limits.name = "";
    assert_eq!(limits.check(), Err(LimitsError::Name));
    limits.name = "0123456789abcdef";
    assert_eq!(limits.check(), Ok(()));
    limits.name = "0123456789abcdefg";
    assert_eq!(limits.check(), Err(LimitsError::Name));
}

#[test]
fn a_variable_length_integer_widens_at_each_seven_bits() {
    for (value, width) in [
        (0u64, 1usize),
        (127, 1),
        (128, 2),
        (16_383, 2),
        (16_384, 3),
        (2_097_151, 3),
        (2_097_152, 4),
        (268_435_455, 4),
        (268_435_456, 5),
        (4_294_967_295, 5),
    ] {
        assert_eq!(leb_bytes(value), width, "{value}");
    }
}

/// The PointCloud2 key the LiDAR publisher names in full, and the size of one frame of the pinned bag.
const LIDAR_KEY: &str = "0/velodyne_points/sensor_msgs::msg::dds_::PointCloud2_/RIHS01_9198cabf7da3796ae6fe19c4cb3bdd3525492988c70522628af5daa124bae2b5";
const LIDAR_FRAME_BYTES: usize = 494_889;

#[test]
fn the_lidar_configuration_is_accepted_and_holds_one_frame() {
    assert_eq!(LIDAR.check(), Ok(()));
    assert_eq!(LIDAR.mode, Mode::Heap);
    // A batch is one network-service operation with its stream length.
    assert_eq!(LIDAR.batch_bytes, DATA_BYTES);
    assert!(LIDAR.payload_bytes >= LIDAR_FRAME_BYTES as u64);
    assert_eq!(LIDAR_KEY.len(), 126);
    assert!(LIDAR.key_bytes >= LIDAR_KEY.len());
    assert_eq!(LIDAR.attachment_bytes, REQUIRED_ATTACHMENT_BYTES);
    assert_ne!(LIDAR.reassembly_timeout_ms, 0);
    assert_eq!(LIDAR.message_bytes(), 524_460);
    assert_eq!(
        LIDAR.heap_bytes,
        (2 * LIDAR.outstanding_samples as u64 + 1) * LIDAR.message_bytes()
    );
    assert_eq!(LIDAR.heap_bytes, LIDAR.heap_needed());
    assert_eq!(LIDAR.required_stack(), 34_888);
    assert!(LIDAR.required_stack() <= LIDAR.stack_bytes);
}

/// One frame under the full key, cut as the session cuts it for the batch the configuration
/// announces: every fragment fits one operation with its stream length, and they join to the Put.
#[test]
fn a_lidar_frame_crosses_in_batches_of_one_operation() {
    use crate::zenoh_profile0::fragment::{PutMessage, Source, Splitter, decode_fragment};
    use crate::zenoh_profile0::session::Params;

    let params = Params::from_limits(&LIDAR);
    assert_eq!(usize::from(params.announced), DATA_BYTES);
    assert_eq!(params.bounds.batch + STREAM_LENGTH_BYTES, DATA_BYTES);
    assert!(params.fragments);
    let payload: std::vec::Vec<u8> = (0..LIDAR_FRAME_BYTES).map(|i| (i * 7) as u8).collect();
    let attachment = [0x5a; REQUIRED_ATTACHMENT_BYTES];
    let message = PutMessage::new(LIDAR_KEY.as_bytes(), &attachment, &payload);
    assert!(message.len() as u64 <= LIDAR.message_bytes());
    assert!(message.len() <= params.message_limit);
    let mut whole = std::vec![0u8; message.len()];
    message.read(0, &mut whole);
    // Start below the wrap so the sequence number's width changes inside the run.
    let first = u32::MAX - 3;
    let mut splitter = Splitter::new(message, DATA_BYTES, first).expect("splitter");
    let mut joined = std::vec::Vec::new();
    let mut out = [0u8; DATA_BYTES];
    let mut count = 0u32;
    while let Some(len) = splitter.next_body(&mut out).expect("fragment") {
        assert!(len + STREAM_LENGTH_BYTES <= DATA_BYTES, "fragment {count}");
        let part = decode_fragment(&out[..len], Some(DATA_BYTES)).expect("decodes");
        assert_eq!(part.sn, first.wrapping_add(count));
        assert_eq!(part.more, !splitter.done());
        joined.extend_from_slice(part.data);
        count += 1;
    }
    assert_eq!(joined, whole);
    // Four fragments carry a five-byte sequence number before the wrap, the rest one byte.
    assert_eq!(count, 121);
}

//! The configuration a Zenoh Profile 0 link is declared with.
//!
//! `contracts/zenoh-link-limits/v1` judges a declaration before a link is built from it. This module
//! is the same arithmetic in Rust, so a component can refuse a declaration it could not honour and a
//! test can print the figures the exam pins. It allocates nothing and owns no storage: a [`Limits`]
//! says how large things are, and the component supplies the memory.
//!
//! Two modes. A `fixed` link has no heap: every message must fit one batch and a fragment is refused.
//! A `heap` link reassembles a fragmented message into storage the component supplies from its own
//! allocator, so this library takes no allocator of its own.

use super::STREAM_LENGTH_BYTES;

/// The network service moves at most one data page per operation (`DATA_BYTES`), and a batch is the
/// size of one stream operation, its two-byte length included.
pub const DATA_BYTES: usize = 4096;
/// The longest INIT_ACK the profile permits is 87 bytes, and INIT and OPEN cannot be fragmented.
pub const HANDSHAKE_BYTES: usize = 87;
/// What a key declaration adds around its key, besides the width of its length field.
pub const DECLARATION_FIXED_BYTES: usize = 18;
/// What a full-key Put adds around its key, attachment and payload, besides the widths of the key's
/// and the payload's lengths: the PUSH header, the scope, the Put header, the attachment extension
/// tag and the attachment's one-byte length.
pub const MESSAGE_FIXED_BYTES: usize = 5;
/// What a FRAME adds before the message it carries: its header and a sequence number of up to five
/// bytes.
pub const FRAME_FIXED_BYTES: usize = 6;
/// What a fragment adds around its slice: the header and a sequence number of up to five bytes, with
/// a margin.
pub const FRAGMENT_FRAMING_BYTES: usize = 8;
/// The key-expression alias id and the scope every reference to it carries are 16 bits.
pub const ALIAS_IDS: usize = 65_535;
/// A key's length travels as a 16-bit field.
pub const MAX_KEY_LENGTH_BYTES: usize = 65_535;
/// A payload's length travels as a 32-bit field.
pub const MAX_PAYLOAD_LENGTH_BYTES: u64 = 4_294_967_295;
/// The count past which the contract's own 63-bit arithmetic would overflow.
pub const MAX_OUTSTANDING_SAMPLES: usize = 1_000_000_000;
/// The `rmw_zenoh` attachment is exactly this long.
pub const REQUIRED_ATTACHMENT_BYTES: usize = 33;
/// The notices queued for each outstanding sample (`NOTICES = 2 * MAX_EVENTS` in `zenoh_link.rs`).
pub const NOTICES_PER_SAMPLE: usize = 2;
/// The stack the link's batch-sized arrays need, as a multiple of the batch.
pub const STACK_FACTOR: u64 = 8;
/// One key or subscriber slot beyond its key.
pub const SLOT_OVERHEAD_BYTES: u64 = 16;
/// One queued notice beyond its payload.
pub const NOTICE_OVERHEAD_BYTES: u64 = 40;
/// The session machine's own fixed storage, held with a margin over its measured 608 bytes.
pub const SESSION_FIXED_BYTES: u64 = 640;

/// How a link is declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// No heap: a message must fit one batch and a fragment is refused.
    Fixed,
    /// The component supplies the storage a fragmented message is reassembled into.
    Heap,
}

impl Mode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Heap => "heap",
        }
    }
}

/// Why a declaration is refused. The names are the contract's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitsError {
    /// The name is empty or longer than 16 bytes.
    Name,
    /// The batch cannot hold the largest handshake message or a declaration of the longest key, or
    /// exceeds one network-service operation.
    Batch,
    /// A payload, key or attachment size outside what the wire carries.
    Size,
    /// A count outside what the contract admits.
    Count,
    /// The declared stack does not cover the link's arrays, slots and notices.
    Stack,
    /// A fixed link declared a timeout or a heap, or its message does not fit its batch.
    Fixed,
    /// A heap link declared no timeout, too little heap, or a batch that cannot carry a fragment.
    Heap,
}

/// One declared link configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub name: &'static str,
    pub mode: Mode,
    pub batch_bytes: usize,
    pub payload_bytes: u64,
    pub key_bytes: usize,
    pub attachment_bytes: usize,
    pub max_keys: usize,
    pub max_subscribers: usize,
    pub outstanding_samples: usize,
    pub stack_bytes: u64,
    pub reassembly_timeout_ms: u64,
    pub heap_bytes: u64,
}

/// The width of a variable-length integer, one to five bytes.
pub const fn leb_bytes(value: u64) -> usize {
    if value < 1 << 7 {
        1
    } else if value < 1 << 14 {
        2
    } else if value < 1 << 21 {
        3
    } else if value < 1 << 28 {
        4
    } else {
        5
    }
}

impl Limits {
    /// The whole serialized message a Put becomes: payload, key and attachment, the fixed bytes
    /// around them and the widths of the key's and the payload's lengths.
    pub const fn message_bytes(&self) -> u64 {
        self.payload_bytes
            + self.key_bytes as u64
            + self.attachment_bytes as u64
            + MESSAGE_FIXED_BYTES as u64
            + leb_bytes(self.key_bytes as u64) as u64
            + leb_bytes(self.payload_bytes) as u64
    }

    /// The bytes a key declaration takes on the wire, stream length included: the key, the fixed
    /// bytes around it and the width of the length of its two-byte-longer extension body.
    pub const fn declaration_bytes(&self) -> usize {
        self.key_bytes + DECLARATION_FIXED_BYTES + leb_bytes(self.key_bytes as u64 + 2)
    }

    /// The key and subscriber slots a configuration declares.
    pub const fn slot_bytes(&self) -> u64 {
        (self.max_keys as u64 + self.max_subscribers as u64)
            * (self.key_bytes as u64 + SLOT_OVERHEAD_BYTES)
    }

    /// The queued sample notices. A fixed link copies each payload into its notice; a heap link hands
    /// the sample out as a slice of the reassembly buffer, so its notices carry no payload.
    pub const fn notice_bytes(&self) -> u64 {
        let carried = match self.mode {
            Mode::Fixed => self.payload_bytes,
            Mode::Heap => 0,
        };
        NOTICES_PER_SAMPLE as u64
            * self.outstanding_samples as u64
            * (NOTICE_OVERHEAD_BYTES + carried)
    }

    /// The memory the owning component declares for the link's fixed storage.
    pub const fn required_stack(&self) -> u64 {
        STACK_FACTOR * self.batch_bytes as u64
            + SESSION_FIXED_BYTES
            + self.slot_bytes()
            + self.notice_bytes()
    }

    /// The heap a heap link needs: every queued sample notice holds a whole message until it is
    /// consumed, and one more message is being reassembled.
    pub const fn heap_needed(&self) -> u64 {
        (NOTICES_PER_SAMPLE as u64 * self.outstanding_samples as u64 + 1) * self.message_bytes()
    }

    /// The most events one received batch can yield: one for each outstanding sample, and no more than
    /// the batch has room for. The smallest message that raises an event is four bytes, so a batch of
    /// `n` bytes holds fewer than `n / 4`.
    pub const fn events_per_batch(&self) -> usize {
        let room = self.batch_bytes / 4;
        if self.outstanding_samples < room {
            self.outstanding_samples
        } else {
            room
        }
    }

    /// What a fixed link needs of its batch: the message, a frame header and a five-byte sequence
    /// number, and the two-byte stream length.
    pub const fn fixed_need(&self) -> u64 {
        self.message_bytes() + FRAME_FIXED_BYTES as u64 + STREAM_LENGTH_BYTES as u64
    }

    /// Whether the declaration is consistent with the memory it also declares. This is the contract's
    /// `configOk`, written again.
    pub fn check(&self) -> Result<(), LimitsError> {
        if self.name.is_empty() || self.name.len() > 16 {
            return Err(LimitsError::Name);
        }
        // A size is judged before any sum is made from it, so one that is far past the wire's widths is
        // refused as a size and not as an overflow.
        if self.payload_bytes < 1
            || self.payload_bytes > MAX_PAYLOAD_LENGTH_BYTES
            || self.key_bytes < 1
            || self.key_bytes > MAX_KEY_LENGTH_BYTES
            || self.attachment_bytes != REQUIRED_ATTACHMENT_BYTES
        {
            return Err(LimitsError::Size);
        }
        if self.batch_bytes < HANDSHAKE_BYTES + STREAM_LENGTH_BYTES
            || self.batch_bytes > DATA_BYTES
            || self.declaration_bytes() > self.batch_bytes
        {
            return Err(LimitsError::Batch);
        }
        if self.payload_bytes < 1
            || self.payload_bytes > MAX_PAYLOAD_LENGTH_BYTES
            || self.key_bytes < 1
            || self.key_bytes > MAX_KEY_LENGTH_BYTES
            || self.attachment_bytes != REQUIRED_ATTACHMENT_BYTES
        {
            return Err(LimitsError::Size);
        }
        if self.max_keys < 1
            || self.max_keys > ALIAS_IDS
            || self.max_subscribers < 1
            || self.max_subscribers > self.max_keys
            || self.outstanding_samples < 1
            || self.outstanding_samples > MAX_OUTSTANDING_SAMPLES
        {
            return Err(LimitsError::Count);
        }
        if self.stack_bytes < self.required_stack() {
            return Err(LimitsError::Stack);
        }
        match self.mode {
            Mode::Fixed => {
                if self.fixed_need() > self.batch_bytes as u64
                    || self.reassembly_timeout_ms != 0
                    || self.heap_bytes != 0
                {
                    return Err(LimitsError::Fixed);
                }
            }
            Mode::Heap => {
                if self.batch_bytes <= FRAGMENT_FRAMING_BYTES
                    || self.reassembly_timeout_ms < 1
                    || self.heap_bytes < self.heap_needed()
                {
                    return Err(LimitsError::Heap);
                }
            }
        }
        Ok(())
    }
}

/// The configuration the first release shipped; it does not change.
pub const DEMO: Limits = Limits {
    name: "demo",
    mode: Mode::Fixed,
    batch_bytes: 512,
    payload_bytes: 12,
    key_bytes: 129,
    attachment_bytes: 33,
    max_keys: 1,
    max_subscribers: 1,
    outstanding_samples: 4,
    stack_bytes: 16_384,
    reassembly_timeout_ms: 0,
    heap_bytes: 0,
};

/// A fixed link with room for a 1024-byte payload and four keys and subscribers.
pub const LARGE: Limits = Limits {
    name: "large",
    mode: Mode::Fixed,
    batch_bytes: 2048,
    payload_bytes: 1024,
    key_bytes: 129,
    attachment_bytes: 33,
    max_keys: 4,
    max_subscribers: 4,
    outstanding_samples: 4,
    stack_bytes: 32_768,
    reassembly_timeout_ms: 0,
    heap_bytes: 0,
};

/// A heap link reassembling messages of up to 16384 payload bytes.
pub const HEAP: Limits = Limits {
    name: "heap",
    mode: Mode::Heap,
    batch_bytes: 2048,
    payload_bytes: 16_384,
    key_bytes: 129,
    attachment_bytes: 33,
    max_keys: 4,
    max_subscribers: 4,
    outstanding_samples: 4,
    stack_bytes: 32_768,
    reassembly_timeout_ms: 5000,
    heap_bytes: 149_004,
};

/// The LiDAR publisher's heap link: one PointCloud2 frame of up to 512 KiB as one fragmented Put, in
/// batches of exactly one network-service operation, stream length included. The key and table sizes
/// are the `heap` configuration's, which the stock-peer exchanges already run.
pub const LIDAR: Limits = Limits {
    name: "lidar",
    mode: Mode::Heap,
    batch_bytes: DATA_BYTES,
    payload_bytes: 524_288,
    key_bytes: 129,
    attachment_bytes: 33,
    max_keys: 4,
    max_subscribers: 4,
    outstanding_samples: 4,
    stack_bytes: 65_536,
    reassembly_timeout_ms: 5000,
    heap_bytes: 4_720_140,
};

#[cfg(test)]
#[path = "limits_tests.rs"]
mod tests;

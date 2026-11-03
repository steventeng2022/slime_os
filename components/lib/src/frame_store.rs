//! Reader of `contracts/frame-store/v1`: the recorded messages of one ROS 2 topic.
//!
//! [`FrameStore::parse`] validates the whole store before it exposes any frame, in the order the
//! schema lists its checks, and refuses with the class of the first check that fails. The order is
//! part of the format: the exam compares a refusal's class by name. The reader never panics and
//! never allocates, so it runs over a store mapped into a component's memory.

use slime_proto::frame_store::{
    self as wire, ALIGNMENT, FORMAT_VERSION, FRAME_STORE_MAGIC, HASH_VERSION_RIHS01, HEADER_BYTES,
    INDEX_ENTRY_BYTES, MAX_FRAMES, MAX_PAYLOAD_BYTES, MAX_SCHEMA_BYTES, MAX_STORE_BYTES,
    MAX_TOPIC_BYTES, MAX_TYPE_NAME_BYTES, REFUSAL_CLASSES, TYPE_HASH_BYTES, WireFrameIndexEntry,
    WireFrameStoreHeader,
};

/// Why a store was refused. The discriminant is the class's position in `REFUSAL_CLASSES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    StoreBound = 0,
    Truncated = 1,
    Magic = 2,
    Version = 3,
    Header = 4,
    FrameCount = 5,
    PayloadBound = 6,
    Order = 7,
    Range = 8,
    Overlap = 9,
    Padding = 10,
    Trailing = 11,
}

impl Refusal {
    /// The contract's name for this class.
    pub fn class(self) -> &'static str {
        REFUSAL_CLASSES[self as usize]
    }
}

/// One recorded message: its CDR bytes as recorded and its MCAP log time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub log_time_ns: u64,
    pub payload: &'a [u8],
    /// Where `payload` starts, from the start of the store.
    pub offset: usize,
}

/// A store that passed every check. Its accessors cannot fail.
#[derive(Debug, Clone, Copy)]
pub struct FrameStore<'a> {
    bytes: &'a [u8],
    topic: &'a str,
    type_name: &'a str,
    schema: &'a str,
    type_hash: [u8; TYPE_HASH_BYTES],
    frame_period_ns: u64,
    frame_count: usize,
    index_start: usize,
}

const fn align(value: usize) -> usize {
    value.div_ceil(ALIGNMENT) * ALIGNMENT
}

fn text(raw: &[u8]) -> Result<&str, Refusal> {
    let text = core::str::from_utf8(raw).map_err(|_| Refusal::Header)?;
    if raw.contains(&0) {
        return Err(Refusal::Header);
    }
    Ok(text)
}

fn zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| byte == 0)
}

fn entry(bytes: &[u8], index_start: usize, index: usize) -> Option<WireFrameIndexEntry> {
    let start = index_start + index * INDEX_ENTRY_BYTES;
    WireFrameIndexEntry::decode(bytes.get(start..start + INDEX_ENTRY_BYTES)?)
}

impl<'a> FrameStore<'a> {
    /// Validates the whole store in the contract's order.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let size = bytes.len();
        if size > MAX_STORE_BYTES {
            return Err(Refusal::StoreBound);
        }
        let header = WireFrameStoreHeader::decode(bytes).ok_or(Refusal::Truncated)?;
        if header.magic != FRAME_STORE_MAGIC {
            return Err(Refusal::Magic);
        }
        if header.version != FORMAT_VERSION {
            return Err(Refusal::Version);
        }
        if header.hashVersion != HASH_VERSION_RIHS01
            || !zero(&header.reserved0)
            || !zero(&header.reserved1)
            || header.framePeriodNs == 0
        {
            return Err(Refusal::Header);
        }
        let topic_len = usize::from(header.topicBytes);
        let type_len = usize::from(header.typeNameBytes);
        let schema_len = header.schemaBytes as usize;
        if !(1..=MAX_TOPIC_BYTES).contains(&topic_len)
            || !(1..=MAX_TYPE_NAME_BYTES).contains(&type_len)
            || !(1..=MAX_SCHEMA_BYTES).contains(&schema_len)
        {
            return Err(Refusal::Header);
        }
        let frame_count = header.frameCount as usize;
        if !(1..=MAX_FRAMES).contains(&frame_count) {
            return Err(Refusal::FrameCount);
        }
        // Every term is bounded above, so none of these sums can overflow a 32-bit usize.
        let topic_end = HEADER_BYTES + topic_len;
        let type_end = topic_end + type_len;
        let text_end = type_end + schema_len;
        let index_start = align(text_end);
        let data_start = index_start + frame_count * INDEX_ENTRY_BYTES;
        if size < data_start {
            return Err(Refusal::Truncated);
        }
        let topic = text(&bytes[HEADER_BYTES..topic_end])?;
        let type_name = text(&bytes[topic_end..type_end])?;
        let schema = text(&bytes[type_end..text_end])?;
        if !zero(&bytes[text_end..index_start]) {
            return Err(Refusal::Header);
        }

        // `cursor` is where the next payload must start: the aligned end of the previous payload.
        let mut cursor = data_start;
        let mut previous_end = data_start;
        let mut previous_time: Option<u64> = None;
        for index in 0..frame_count {
            let entry = entry(bytes, index_start, index).ok_or(Refusal::Truncated)?;
            if !zero(&entry.reserved) {
                return Err(Refusal::Header);
            }
            let length = entry.payloadBytes as usize;
            if length > MAX_PAYLOAD_BYTES {
                return Err(Refusal::PayloadBound);
            }
            if previous_time.is_some_and(|previous| entry.logTimeNs < previous) {
                return Err(Refusal::Order);
            }
            let offset = match usize::try_from(entry.payloadOffset) {
                Ok(offset) if offset <= size && length <= size - offset => offset,
                _ => return Err(Refusal::Range),
            };
            if offset < cursor {
                return Err(Refusal::Overlap);
            }
            if offset > cursor || !zero(&bytes[previous_end..offset]) {
                return Err(Refusal::Padding);
            }
            previous_time = Some(entry.logTimeNs);
            previous_end = offset + length;
            cursor = align(previous_end);
        }
        if !zero(&bytes[previous_end..cursor.min(size)]) {
            return Err(Refusal::Padding);
        }
        if size < cursor {
            return Err(Refusal::Range);
        }
        if size > cursor {
            return Err(Refusal::Trailing);
        }
        Ok(Self {
            bytes,
            topic,
            type_name,
            schema,
            type_hash: header.typeHash,
            frame_period_ns: header.framePeriodNs,
            frame_count,
            index_start,
        })
    }

    pub fn topic(&self) -> &'a str {
        self.topic
    }

    pub fn type_name(&self) -> &'a str {
        self.type_name
    }

    /// The ros2msg schema text the messages were recorded with.
    pub fn schema(&self) -> &'a str {
        self.schema
    }

    /// The RIHS01 digest of the message type.
    pub fn type_hash(&self) -> &[u8; TYPE_HASH_BYTES] {
        &self.type_hash
    }

    /// The period a publisher replays the frames at, as the converter declared it.
    pub fn frame_period_ns(&self) -> u64 {
        self.frame_period_ns
    }

    /// The number of frames, at least 1.
    pub fn len(&self) -> usize {
        self.frame_count
    }

    /// Always false: a valid store holds at least one frame.
    pub fn is_empty(&self) -> bool {
        self.frame_count == 0
    }

    /// Frame `index` in log-time order, or `None` past the last frame.
    pub fn frame(&self, index: usize) -> Option<Frame<'a>> {
        if index >= self.frame_count {
            return None;
        }
        let entry = entry(self.bytes, self.index_start, index)?;
        let offset = usize::try_from(entry.payloadOffset).ok()?;
        let payload = self
            .bytes
            .get(offset..offset + entry.payloadBytes as usize)?;
        Some(Frame {
            log_time_ns: entry.logTimeNs,
            payload,
            offset,
        })
    }

    pub fn frames(&self) -> impl Iterator<Item = Frame<'a>> + '_ {
        (0..self.frame_count).filter_map(move |index| self.frame(index))
    }
}

/// A store read where it lies rather than mapped whole, such as a frame store on a block device.
pub trait StoreSource {
    /// Fills `out` with the store's bytes from `offset`. [`validate_streaming`] reads only below the
    /// length it was given.
    fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), SourceError>;
}

/// The source could not supply the bytes asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceError;

/// Why [`validate_streaming`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    /// The store failed a check: the class [`FrameStore::parse`] gives the same bytes.
    Refused(Refusal),
    /// The source failed before the store could be judged.
    Source,
}

impl From<SourceError> for StreamError {
    fn from(_: SourceError) -> Self {
        Self::Source
    }
}

/// What a streamed store holds, for a reader that keeps no frame in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreSummary {
    pub frame_count: usize,
    pub frame_period_ns: u64,
    pub first_log_time_ns: u64,
    pub last_log_time_ns: u64,
    /// SHA-256 of every payload, concatenated in index order.
    pub payload_digest: [u8; 32],
    /// Where the frame index starts, from the start of the store.
    pub index_offset: usize,
}

/// Where one frame's payload lies in a store read through a [`StoreSource`]. Only
/// [`frame_extent`] makes one, from an index entry that passed its checks again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameExtent {
    log_time_ns: u64,
    offset: usize,
    len: usize,
}

impl FrameExtent {
    /// The frame's MCAP log time.
    pub fn log_time_ns(&self) -> u64 {
        self.log_time_ns
    }

    /// Where the payload starts, from the start of the store.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The payload's length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the payload is empty, which the format permits.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Frame `index` of a store of `size` bytes that [`validate_streaming`] summarized as `summary`, or
/// `None` past the last frame. The entry is read again and held to the checks it passed then: zero
/// reserved bytes, the payload bound and a payload inside the store. A source that changed since
/// is refused with the class of the check the entry now fails.
pub fn frame_extent<S: StoreSource>(
    source: &mut S,
    summary: &StoreSummary,
    size: usize,
    index: usize,
) -> Result<Option<FrameExtent>, StreamError> {
    if index >= summary.frame_count {
        return Ok(None);
    }
    // A summary of another store could place the entry past this one's end.
    let at = summary.index_offset + index * INDEX_ENTRY_BYTES;
    if at
        .checked_add(INDEX_ENTRY_BYTES)
        .is_none_or(|end| end > size)
    {
        return Err(refused(Refusal::Truncated));
    }
    let mut raw = [0u8; INDEX_ENTRY_BYTES];
    source.read(at, &mut raw)?;
    let entry = WireFrameIndexEntry::decode(&raw).ok_or(refused(Refusal::Truncated))?;
    if !zero(&entry.reserved) {
        return Err(refused(Refusal::Header));
    }
    let len = entry.payloadBytes as usize;
    if len > MAX_PAYLOAD_BYTES {
        return Err(refused(Refusal::PayloadBound));
    }
    let offset = match usize::try_from(entry.payloadOffset) {
        Ok(offset) if offset <= size && len <= size - offset => offset,
        _ => return Err(refused(Refusal::Range)),
    };
    Ok(Some(FrameExtent {
        log_time_ns: entry.logTimeNs,
        offset,
        len,
    }))
}

/// Why [`read_payload`] read nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    /// The bytes asked for run past the end of the frame's payload.
    Range,
    /// The source could not supply them.
    Source,
}

/// Fills `out` with `frame`'s payload bytes from byte `at` of the payload. A range that runs past the
/// payload is refused before the source is read, so a caller can never read a neighbour's bytes or
/// padding through a frame.
pub fn read_payload<S: StoreSource>(
    source: &mut S,
    frame: &FrameExtent,
    at: usize,
    out: &mut [u8],
) -> Result<(), PayloadError> {
    match at.checked_add(out.len()) {
        Some(end) if end <= frame.len => {}
        _ => return Err(PayloadError::Range),
    }
    if out.is_empty() {
        return Ok(());
    }
    source
        .read(frame.offset + at, out)
        .map_err(|_| PayloadError::Source)
}

/// Bytes read per source call while scanning texts, zero runs and payloads.
const STREAM_CHUNK: usize = 512;

fn refused(refusal: Refusal) -> StreamError {
    StreamError::Refused(refusal)
}

/// UTF-8 without a NUL, read in chunks. A code point split across chunks is carried into the next.
fn stream_text<S: StoreSource>(
    source: &mut S,
    start: usize,
    len: usize,
) -> Result<(), StreamError> {
    let mut buffer = [0u8; STREAM_CHUNK + 3];
    let mut carry = 0;
    let mut done = 0;
    while done < len {
        let take = (len - done).min(STREAM_CHUNK);
        source.read(start + done, &mut buffer[carry..carry + take])?;
        if buffer[carry..carry + take].contains(&0) {
            return Err(refused(Refusal::Header));
        }
        let filled = carry + take;
        carry = match core::str::from_utf8(&buffer[..filled]) {
            Ok(_) => 0,
            Err(error) if error.error_len().is_none() => {
                let valid = error.valid_up_to();
                buffer.copy_within(valid..filled, 0);
                filled - valid
            }
            Err(_) => return Err(refused(Refusal::Header)),
        };
        done += take;
    }
    if carry != 0 {
        return Err(refused(Refusal::Header));
    }
    Ok(())
}

/// Whether every byte in `[from, to)` is zero.
fn stream_zero<S: StoreSource>(
    source: &mut S,
    from: usize,
    to: usize,
) -> Result<bool, StreamError> {
    let mut buffer = [0u8; STREAM_CHUNK];
    let mut at = from;
    while at < to {
        let take = (to - at).min(STREAM_CHUNK);
        source.read(at, &mut buffer[..take])?;
        if !zero(&buffer[..take]) {
            return Ok(false);
        }
        at += take;
    }
    Ok(true)
}

/// Validates a store of `size` bytes read through `source`, in the same order and with the same
/// classes as [`FrameStore::parse`], holding no more than one header, one index entry and one
/// chunk at a time. Payloads are hashed in index order as their entries pass.
pub fn validate_streaming<S: StoreSource>(
    source: &mut S,
    size: usize,
) -> Result<StoreSummary, StreamError> {
    use boot_contracts::sha256::Sha256;

    if size > MAX_STORE_BYTES {
        return Err(refused(Refusal::StoreBound));
    }
    if size < HEADER_BYTES {
        return Err(refused(Refusal::Truncated));
    }
    let mut raw = [0u8; HEADER_BYTES];
    source.read(0, &mut raw)?;
    let header = WireFrameStoreHeader::decode(&raw).ok_or(refused(Refusal::Truncated))?;
    if header.magic != FRAME_STORE_MAGIC {
        return Err(refused(Refusal::Magic));
    }
    if header.version != FORMAT_VERSION {
        return Err(refused(Refusal::Version));
    }
    if header.hashVersion != HASH_VERSION_RIHS01
        || !zero(&header.reserved0)
        || !zero(&header.reserved1)
        || header.framePeriodNs == 0
    {
        return Err(refused(Refusal::Header));
    }
    let topic_len = usize::from(header.topicBytes);
    let type_len = usize::from(header.typeNameBytes);
    let schema_len = header.schemaBytes as usize;
    if !(1..=MAX_TOPIC_BYTES).contains(&topic_len)
        || !(1..=MAX_TYPE_NAME_BYTES).contains(&type_len)
        || !(1..=MAX_SCHEMA_BYTES).contains(&schema_len)
    {
        return Err(refused(Refusal::Header));
    }
    let frame_count = header.frameCount as usize;
    if !(1..=MAX_FRAMES).contains(&frame_count) {
        return Err(refused(Refusal::FrameCount));
    }
    let topic_end = HEADER_BYTES + topic_len;
    let type_end = topic_end + type_len;
    let text_end = type_end + schema_len;
    let index_start = align(text_end);
    let data_start = index_start + frame_count * INDEX_ENTRY_BYTES;
    if size < data_start {
        return Err(refused(Refusal::Truncated));
    }
    stream_text(source, HEADER_BYTES, topic_len)?;
    stream_text(source, topic_end, type_len)?;
    stream_text(source, type_end, schema_len)?;
    if !stream_zero(source, text_end, index_start)? {
        return Err(refused(Refusal::Header));
    }

    let mut digest = Sha256::new();
    let mut chunk = [0u8; STREAM_CHUNK];
    let mut cursor = data_start;
    let mut previous_end = data_start;
    let mut first_time = 0;
    let mut previous_time: Option<u64> = None;
    for index in 0..frame_count {
        let mut raw = [0u8; INDEX_ENTRY_BYTES];
        source.read(index_start + index * INDEX_ENTRY_BYTES, &mut raw)?;
        let entry = WireFrameIndexEntry::decode(&raw).ok_or(refused(Refusal::Truncated))?;
        if !zero(&entry.reserved) {
            return Err(refused(Refusal::Header));
        }
        let length = entry.payloadBytes as usize;
        if length > MAX_PAYLOAD_BYTES {
            return Err(refused(Refusal::PayloadBound));
        }
        if previous_time.is_some_and(|previous| entry.logTimeNs < previous) {
            return Err(refused(Refusal::Order));
        }
        let offset = match usize::try_from(entry.payloadOffset) {
            Ok(offset) if offset <= size && length <= size - offset => offset,
            _ => return Err(refused(Refusal::Range)),
        };
        if offset < cursor {
            return Err(refused(Refusal::Overlap));
        }
        if offset > cursor || !stream_zero(source, previous_end, offset)? {
            return Err(refused(Refusal::Padding));
        }
        let mut at = offset;
        while at < offset + length {
            let take = (offset + length - at).min(STREAM_CHUNK);
            source.read(at, &mut chunk[..take])?;
            digest.update(&chunk[..take]);
            at += take;
        }
        if index == 0 {
            first_time = entry.logTimeNs;
        }
        previous_time = Some(entry.logTimeNs);
        previous_end = offset + length;
        cursor = align(previous_end);
    }
    if !stream_zero(source, previous_end, cursor.min(size))? {
        return Err(refused(Refusal::Padding));
    }
    if size < cursor {
        return Err(refused(Refusal::Range));
    }
    if size > cursor {
        return Err(refused(Refusal::Trailing));
    }
    Ok(StoreSummary {
        frame_count,
        frame_period_ns: header.framePeriodNs,
        first_log_time_ns: first_time,
        last_log_time_ns: previous_time.unwrap_or(first_time),
        payload_digest: digest.finalize(),
        index_offset: index_start,
    })
}

// The class table and the enum must agree; this fails to compile if the table changes length.
const _: [(); 12] = [(); wire::REFUSAL_CLASSES.len()];

#[cfg(test)]
mod tests {
    use super::{FrameStore, Refusal};
    use slime_proto::frame_store::REFUSAL_CLASSES;

    const FIXTURE: &[u8] = include_bytes!("frame_store/fixture.bin");

    const ALL: [Refusal; 12] = [
        Refusal::StoreBound,
        Refusal::Truncated,
        Refusal::Magic,
        Refusal::Version,
        Refusal::Header,
        Refusal::FrameCount,
        Refusal::PayloadBound,
        Refusal::Order,
        Refusal::Range,
        Refusal::Overlap,
        Refusal::Padding,
        Refusal::Trailing,
    ];

    #[test]
    fn classes_follow_the_contract_order() {
        for (index, refusal) in ALL.iter().enumerate() {
            assert_eq!(refusal.class(), REFUSAL_CLASSES[index]);
        }
    }

    #[test]
    fn fixture_reads_as_written() {
        let store = FrameStore::parse(FIXTURE).expect("fixture is valid");
        assert_eq!(store.topic(), "/fixture/chatter");
        assert_eq!(store.type_name(), "std_msgs/msg/String");
        assert_eq!(store.schema(), "string data\n");
        assert_eq!(store.frame_period_ns(), 100_000_000);
        assert_eq!(store.len(), 2);
        let frames: [_; 2] = core::array::from_fn(|index| store.frame(index).expect("frame"));
        assert_eq!(frames[0].log_time_ns, 1_000_000_000);
        assert_eq!(
            frames[0].payload,
            b"\x00\x01\x00\x00\x06\x00\x00\x00hello\x00"
        );
        assert_eq!(frames[1].log_time_ns, 1_100_000_000);
        assert_eq!(
            frames[1].payload,
            b"\x00\x01\x00\x00\x07\x00\x00\x00world!\x00"
        );
        assert!(store.frame(2).is_none());
        assert_eq!(store.frames().count(), 2);
    }

    #[test]
    fn fixture_edits_are_refused_by_class() {
        let refused = |edit: &dyn Fn(&mut Vec<u8>), class: Refusal| {
            let mut bytes = FIXTURE.to_vec();
            edit(&mut bytes);
            assert_eq!(FrameStore::parse(&bytes).err(), Some(class));
        };
        refused(&|bytes| bytes.truncate(63), Refusal::Truncated);
        refused(&|bytes| bytes[0] ^= 1, Refusal::Magic);
        refused(&|bytes| bytes[4] = 2, Refusal::Version);
        refused(&|bytes| bytes[7] = 1, Refusal::Header);
        refused(
            &|bytes| bytes[8..12].copy_from_slice(&0u32.to_le_bytes()),
            Refusal::FrameCount,
        );
        refused(&|bytes| bytes.push(0), Refusal::Trailing);
        let last = FIXTURE.len() - 1;
        refused(&move |bytes| bytes[last] = 1, Refusal::Padding);
    }

    #[test]
    fn offset_near_the_top_of_u64_is_out_of_range() {
        let store = FrameStore::parse(FIXTURE).expect("fixture is valid");
        let entry = store.index_start;
        let mut bytes = FIXTURE.to_vec();
        bytes[entry..entry + 8].copy_from_slice(&(u64::MAX - 7).to_le_bytes());
        assert_eq!(FrameStore::parse(&bytes).err(), Some(Refusal::Range));
    }
}

#[cfg(test)]
mod streaming {
    extern crate std;

    use super::{
        FrameStore, PayloadError, Refusal, SourceError, StoreSource, StreamError, frame_extent,
        read_payload, validate_streaming,
    };
    use std::vec::Vec;

    const FIXTURE: &[u8] = include_bytes!("frame_store/fixture.bin");

    struct Memory<'a>(&'a [u8]);

    impl StoreSource for Memory<'_> {
        fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), SourceError> {
            let bytes = self.0.get(offset..offset + out.len()).ok_or(SourceError)?;
            out.copy_from_slice(bytes);
            Ok(())
        }
    }

    fn streamed(bytes: &[u8]) -> Result<(), Refusal> {
        match validate_streaming(&mut Memory(bytes), bytes.len()) {
            Ok(_) => Ok(()),
            Err(StreamError::Refused(refusal)) => Err(refusal),
            Err(StreamError::Source) => panic!("the source failed inside the store's length"),
        }
    }

    fn parsed(bytes: &[u8]) -> Result<(), Refusal> {
        FrameStore::parse(bytes).map(|_| ())
    }

    /// A store with a schema longer than one chunk whose multi-byte characters straddle chunk ends.
    fn wide() -> Vec<u8> {
        let mut bytes = FIXTURE.to_vec();
        let header = 64;
        let topic = u16::from_le_bytes([bytes[12], bytes[13]]) as usize;
        let type_len = u16::from_le_bytes([bytes[14], bytes[15]]) as usize;
        let schema_len = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let schema_start = header + topic + type_len;
        let tail = bytes[schema_start + schema_len..].to_vec();
        let old_index = (schema_start + schema_len).div_ceil(8) * 8;
        let mut schema = std::string::String::from("string data\n");
        while schema.len() < 1500 {
            schema.push_str("# é𝄞 comment\n");
        }
        let delta = schema.len() as isize - schema_len as isize;
        bytes.truncate(schema_start);
        bytes.extend_from_slice(schema.as_bytes());
        let new_index = bytes.len().div_ceil(8) * 8;
        bytes.resize(new_index, 0);
        bytes.extend_from_slice(&tail[old_index - (schema_start + schema_len)..]);
        bytes[16..20].copy_from_slice(&(schema.len() as u32).to_le_bytes());
        let shift = new_index as isize - old_index as isize;
        let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        for index in 0..count {
            let at = new_index + index * 24;
            let offset = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
            bytes[at..at + 8].copy_from_slice(&((offset as isize + shift) as u64).to_le_bytes());
        }
        let _ = delta;
        assert!(parsed(&bytes).is_ok(), "the widened store is valid");
        bytes
    }

    #[test]
    fn accepted_stores_summarize_their_frames() {
        for bytes in [FIXTURE.to_vec(), wide()] {
            let summary = validate_streaming(&mut Memory(&bytes), bytes.len()).expect("valid");
            let store = FrameStore::parse(&bytes).expect("valid");
            let mut payloads = Vec::new();
            for frame in store.frames() {
                payloads.extend_from_slice(frame.payload);
            }
            assert_eq!(summary.frame_count, store.len());
            assert_eq!(summary.frame_period_ns, store.frame_period_ns());
            assert_eq!(
                summary.first_log_time_ns,
                store.frame(0).unwrap().log_time_ns
            );
            assert_eq!(
                summary.last_log_time_ns,
                store.frame(store.len() - 1).unwrap().log_time_ns
            );
            assert_eq!(
                summary.payload_digest,
                boot_contracts::sha256::digest(&payloads)
            );
        }
    }

    /// Every single-byte edit, every truncation and an extension: the streaming reader gives exactly
    /// the verdict the whole-store reader gives.
    #[test]
    fn every_edit_gets_the_whole_store_verdict() {
        for base in [FIXTURE.to_vec(), wide()] {
            for index in 0..base.len() {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut bytes = base.clone();
                    bytes[index] ^= flip;
                    assert_eq!(streamed(&bytes), parsed(&bytes), "byte {index} ^ {flip:#x}");
                }
            }
            for length in 0..base.len() {
                assert_eq!(
                    streamed(&base[..length]),
                    parsed(&base[..length]),
                    "length {length}"
                );
            }
            let mut longer = base.clone();
            longer.extend_from_slice(&[0; 8]);
            assert_eq!(streamed(&longer), parsed(&longer));
        }
    }

    /// Every frame read back through its extent, in chunks of every size up to past the payload,
    /// is the frame the whole-store reader exposes.
    #[test]
    fn frames_read_back_through_their_extents() {
        for bytes in [FIXTURE.to_vec(), wide()] {
            let summary = validate_streaming(&mut Memory(&bytes), bytes.len()).expect("valid");
            let store = FrameStore::parse(&bytes).expect("valid");
            assert_eq!(summary.index_offset, store.index_start);
            for (index, frame) in store.frames().enumerate() {
                let extent = frame_extent(&mut Memory(&bytes), &summary, bytes.len(), index)
                    .expect("entry")
                    .expect("in range");
                assert_eq!(extent.offset(), frame.offset);
                assert_eq!(extent.len(), frame.payload.len());
                assert_eq!(extent.log_time_ns(), frame.log_time_ns);
                for chunk in 1..=frame.payload.len() + 1 {
                    let mut joined = Vec::new();
                    let mut at = 0;
                    while at < extent.len() {
                        let take = chunk.min(extent.len() - at);
                        let mut part = std::vec![0u8; take];
                        read_payload(&mut Memory(&bytes), &extent, at, &mut part).expect("read");
                        joined.extend_from_slice(&part);
                        at += take;
                    }
                    assert_eq!(joined, frame.payload, "frame {index} in chunks of {chunk}");
                }
            }
            assert_eq!(
                frame_extent(&mut Memory(&bytes), &summary, bytes.len(), store.len()),
                Ok(None)
            );
        }
    }

    #[test]
    fn a_read_past_the_payload_is_refused_before_the_source() {
        struct Untouched;
        impl StoreSource for Untouched {
            fn read(&mut self, _: usize, _: &mut [u8]) -> Result<(), SourceError> {
                panic!("a refused range read the source");
            }
        }
        let summary = validate_streaming(&mut Memory(FIXTURE), FIXTURE.len()).expect("valid");
        let extent = frame_extent(&mut Memory(FIXTURE), &summary, FIXTURE.len(), 0)
            .expect("entry")
            .expect("in range");
        let len = extent.len();
        let mut one = [0u8; 1];
        assert_eq!(
            read_payload(&mut Untouched, &extent, len, &mut one),
            Err(PayloadError::Range)
        );
        let mut whole = std::vec![0u8; len + 1];
        assert_eq!(
            read_payload(&mut Untouched, &extent, 0, &mut whole),
            Err(PayloadError::Range)
        );
        assert_eq!(
            read_payload(&mut Untouched, &extent, usize::MAX, &mut one),
            Err(PayloadError::Range)
        );
        assert_eq!(read_payload(&mut Untouched, &extent, len, &mut []), Ok(()));
    }

    /// An entry that changed after validation is refused with the class it now fails.
    #[test]
    fn a_changed_entry_is_refused_by_class() {
        let summary = validate_streaming(&mut Memory(FIXTURE), FIXTURE.len()).expect("valid");
        let entry = summary.index_offset;
        let changed = |edit: &dyn Fn(&mut Vec<u8>)| {
            let mut bytes = FIXTURE.to_vec();
            edit(&mut bytes);
            frame_extent(&mut Memory(&bytes), &summary, bytes.len(), 0).err()
        };
        assert_eq!(
            changed(&|bytes| bytes[entry + 12] = 1),
            Some(StreamError::Refused(Refusal::Header))
        );
        assert_eq!(
            changed(&|bytes| {
                bytes[entry..entry + 8].copy_from_slice(&(u64::MAX - 7).to_le_bytes())
            }),
            Some(StreamError::Refused(Refusal::Range))
        );
        assert_eq!(
            changed(&|bytes| {
                bytes[entry + 8..entry + 12].copy_from_slice(&u32::MAX.to_le_bytes())
            }),
            Some(StreamError::Refused(Refusal::PayloadBound))
        );
        assert_eq!(
            frame_extent(&mut Memory(&FIXTURE[..entry + 4]), &summary, entry + 4, 0).err(),
            Some(StreamError::Refused(Refusal::Truncated))
        );
    }

    #[test]
    fn a_failing_source_is_not_a_refusal() {
        struct Broken;
        impl StoreSource for Broken {
            fn read(&mut self, _: usize, _: &mut [u8]) -> Result<(), SourceError> {
                Err(SourceError)
            }
        }
        assert_eq!(
            validate_streaming(&mut Broken, FIXTURE.len()),
            Err(StreamError::Source)
        );
    }
}

/// The exam's corpus run. `scripts/check/check-frame-store.py` names a manifest of `<case> <path>`
/// lines in SLIME_FRAME_STORE_CORPUS and a transcript file in SLIME_FRAME_STORE_TRANSCRIPT. Without
/// them the test does nothing.
#[cfg(test)]
mod exam {
    use super::FrameStore;
    use std::fmt::Write as _;

    fn hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            })
    }

    fn report(out: &mut String, case: &str, bytes: &[u8]) {
        let store = match FrameStore::parse(bytes) {
            Ok(store) => store,
            Err(refusal) => {
                let _ = writeln!(out, "[frame-store] {case} refuse {}", refusal.class());
                return;
            }
        };
        let _ = writeln!(
            out,
            "[frame-store] {case} accept frames={} period={} hash={} topic={} type={} schema={}",
            store.len(),
            store.frame_period_ns(),
            hex(store.type_hash()),
            hex(store.topic().as_bytes()),
            hex(store.type_name().as_bytes()),
            hex(store.schema().as_bytes()),
        );
        for (index, frame) in store.frames().enumerate() {
            let digest = boot_contracts::sha256::digest(frame.payload);
            let _ = writeln!(
                out,
                "[frame-store] {case} frame {index} offset={} bytes={} log={} sha256={}",
                frame.offset,
                frame.payload.len(),
                frame.log_time_ns,
                hex(&digest),
            );
        }
        let _ = writeln!(out, "[frame-store] {case} end");
    }

    #[test]
    fn corpus() {
        let (Ok(manifest), Ok(transcript)) = (
            std::env::var("SLIME_FRAME_STORE_CORPUS"),
            std::env::var("SLIME_FRAME_STORE_TRANSCRIPT"),
        ) else {
            return;
        };
        let mut out = String::new();
        for line in std::fs::read_to_string(manifest)
            .expect("read the corpus manifest")
            .lines()
        {
            let (case, path) = line
                .split_once(' ')
                .expect("a manifest line is `<case> <path>`");
            report(
                &mut out,
                case,
                &std::fs::read(path).expect("read a corpus store"),
            );
        }
        std::fs::write(transcript, out).expect("write the transcript");
    }
}

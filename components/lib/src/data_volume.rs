//! Reader of `contracts/data-volume/v1`: one hash-pinned frame store on a disk a run attaches.
//!
//! [`open`] validates the disk in the contract's order — GPT, partition, volume header, length,
//! padding, payload hash — and refuses with the class of the first check that fails.
//! [`frame_store`] then validates the payload as a `contracts/frame-store/v1` store, read where it
//! lies. Neither allocates or holds more than one 4 KiB chunk, so a component reads a store far
//! larger than its memory through its block ring. [`open_store`] validates the same way and keeps
//! the store open, so a component then reads one frame's payload at a time into storage it owns.

use boot_contracts::crc32::Crc32;
use boot_contracts::sha256::Sha256;
use slime_proto::data_volume::{
    FIRST_LBA, FORMAT_VERSION, GPT_ENTRY_BYTES, GPT_ENTRY_COUNT, KIND_FRAME_STORE,
    MAX_PAYLOAD_BYTES, OFF_HEADER_KIND, OFF_HEADER_MAGIC, OFF_HEADER_PAYLOADBYTES,
    OFF_HEADER_PAYLOADSHA256, OFF_HEADER_VERSION, PARTITION_NAME, PARTITION_TYPE_GUID,
    REFUSAL_CLASSES, SECTOR_BYTES, VOLUME_HEADER_BYTES, VOLUME_MAGIC,
};

use crate::frame_store::{
    self, FrameExtent, PayloadError, SourceError, StoreSource, StoreSummary, StreamError,
};

/// Sectors read per call, matching one block request's payload window.
pub const CHUNK_SECTORS: usize = 8;
const CHUNK: usize = SECTOR_BYTES * CHUNK_SECTORS;
const ENTRY_ARRAY_BYTES: usize = GPT_ENTRY_COUNT as usize * GPT_ENTRY_BYTES as usize;
const ENTRY_SECTORS: u64 = (ENTRY_ARRAY_BYTES / SECTOR_BYTES) as u64;
const GPT_HEADER_BYTES: usize = 92;
const PROTECTIVE_TYPE: u8 = 0xEE;
/// The smallest disk the layout fits: MBR, primary header and entries, volume header, one payload
/// sector, backup entries and header.
const MIN_SECTORS: u64 = FIRST_LBA + 2 + ENTRY_SECTORS + 1;

/// A block device, read by whole sectors.
pub trait Disk {
    /// The device's size in sectors.
    fn capacity(&self) -> u64;
    /// Fills `out`, a nonzero multiple of [`SECTOR_BYTES`] of at most one chunk, from `lba`.
    fn read(&mut self, lba: u64, out: &mut [u8]) -> Result<(), DeviceError>;
}

/// The device could not supply the sectors asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceError;

/// Why a volume was refused. The discriminant is the class's position in `REFUSAL_CLASSES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Gpt = 0,
    Partition = 1,
    Header = 2,
    Length = 3,
    Padding = 4,
    Hash = 5,
    FrameStore = 6,
}

impl Refusal {
    /// The contract's name for this class.
    pub fn class(self) -> &'static str {
        REFUSAL_CLASSES[self as usize]
    }
}

// The class table and the enum must agree; this fails to compile if the table changes length.
const _: [(); 7] = [(); REFUSAL_CLASSES.len()];

/// Why reading a volume stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Refused(Refusal),
    Device,
}

impl From<DeviceError> for Error {
    fn from(_: DeviceError) -> Self {
        Self::Device
    }
}

/// A volume whose GPT, header, length, padding and payload hash passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Volume {
    pub payload_bytes: u64,
    pub payload_sha256: [u8; 32],
}

const fn hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("the partition type GUID is lowercase hex"),
    }
}

/// A GUID's text in the GPT mixed-endian encoding: the first three groups little-endian.
const fn guid_bytes(text: &str) -> [u8; 16] {
    let text = text.as_bytes();
    let mut raw = [0u8; 16];
    let mut index = 0;
    let mut at = 0;
    while index < 16 {
        if text[at] == b'-' {
            at += 1;
        }
        raw[index] = hex(text[at]) << 4 | hex(text[at + 1]);
        index += 1;
        at += 2;
    }
    [
        raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10],
        raw[11], raw[12], raw[13], raw[14], raw[15],
    ]
}

const TYPE_GUID: [u8; 16] = guid_bytes(PARTITION_TYPE_GUID);

const fn name_bytes(name: &str) -> [u8; 72] {
    let name = name.as_bytes();
    let mut out = [0u8; 72];
    let mut index = 0;
    while index < name.len() {
        out[index * 2] = name[index];
        index += 1;
    }
    out
}

const NAME: [u8; 72] = name_bytes(PARTITION_NAME);

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(raw)
}

fn require(held: bool, refusal: Refusal) -> Result<(), Error> {
    if held {
        Ok(())
    } else {
        Err(Error::Refused(refusal))
    }
}

fn sector<D: Disk>(disk: &mut D, lba: u64) -> Result<[u8; SECTOR_BYTES], Error> {
    let mut out = [0u8; SECTOR_BYTES];
    disk.read(lba, &mut out)?;
    Ok(out)
}

/// A GPT header that passed its own checks.
struct GptHeader {
    own: u64,
    alternate: u64,
    first_usable: u64,
    last_usable: u64,
    disk_guid: [u8; 16],
    entries_lba: u64,
    entry_count: u32,
    entry_bytes: u32,
    entries_crc: u32,
}

fn gpt_header<D: Disk>(disk: &mut D, lba: u64) -> Result<GptHeader, Error> {
    let mut raw = sector(disk, lba)?;
    require(&raw[0..8] == b"EFI PART", Refusal::Gpt)?;
    require(u32_at(&raw, 8) == 0x0001_0000, Refusal::Gpt)?;
    require(u32_at(&raw, 12) == GPT_HEADER_BYTES as u32, Refusal::Gpt)?;
    require(u32_at(&raw, 20) == 0, Refusal::Gpt)?;
    let stored = u32_at(&raw, 16);
    raw[16..20].fill(0);
    require(
        boot_contracts::crc32::crc32(&raw[..GPT_HEADER_BYTES]) == stored,
        Refusal::Gpt,
    )?;
    require(
        raw[GPT_HEADER_BYTES..].iter().all(|&byte| byte == 0),
        Refusal::Gpt,
    )?;
    let mut disk_guid = [0u8; 16];
    disk_guid.copy_from_slice(&raw[56..72]);
    Ok(GptHeader {
        own: u64_at(&raw, 24),
        alternate: u64_at(&raw, 32),
        first_usable: u64_at(&raw, 40),
        last_usable: u64_at(&raw, 48),
        disk_guid,
        entries_lba: u64_at(&raw, 72),
        entry_count: u32_at(&raw, 80),
        entry_bytes: u32_at(&raw, 84),
        entries_crc: u32_at(&raw, 88),
    })
}

/// The CRC32 of the entry array at `lba`, entry 0, and whether every later entry is zero.
fn entry_array<D: Disk>(disk: &mut D, lba: u64) -> Result<(u32, [u8; 128], bool), Error> {
    let mut crc = Crc32::new();
    let mut first = [0u8; 128];
    let mut others_zero = true;
    let mut chunk = [0u8; CHUNK];
    let mut done = 0;
    while done < ENTRY_SECTORS {
        let count = (ENTRY_SECTORS - done).min(CHUNK_SECTORS as u64) as usize;
        let bytes = &mut chunk[..count * SECTOR_BYTES];
        disk.read(lba + done, bytes)?;
        crc.update(bytes);
        let start = if done == 0 {
            first.copy_from_slice(&bytes[..128]);
            128
        } else {
            0
        };
        others_zero &= bytes[start..].iter().all(|&byte| byte == 0);
        done += count as u64;
    }
    Ok((crc.finish(), first, others_zero))
}

/// Validates a disk in the contract's order through the payload hash.
pub fn open<D: Disk>(disk: &mut D) -> Result<Volume, Error> {
    let total = disk.capacity();
    require(total >= MIN_SECTORS, Refusal::Gpt)?;
    let mbr = sector(disk, 0)?;
    require(mbr[510..512] == [0x55, 0xAA], Refusal::Gpt)?;
    require(mbr[450] == PROTECTIVE_TYPE, Refusal::Gpt)?;
    require(
        u32_at(&mbr, 454) == 1 && u64::from(u32_at(&mbr, 458)) == (total - 1).min(0xFFFF_FFFF),
        Refusal::Gpt,
    )?;
    let primary = gpt_header(disk, 1)?;
    let backup = gpt_header(disk, total - 1)?;
    require(primary.own == 1, Refusal::Gpt)?;
    require(primary.alternate == total - 1, Refusal::Gpt)?;
    require(backup.own == total - 1, Refusal::Gpt)?;
    require(backup.alternate == 1, Refusal::Gpt)?;
    require(primary.entries_lba == 2, Refusal::Gpt)?;
    require(
        backup.entries_lba == total - 1 - ENTRY_SECTORS,
        Refusal::Gpt,
    )?;
    require(primary.first_usable == backup.first_usable, Refusal::Gpt)?;
    require(primary.last_usable == backup.last_usable, Refusal::Gpt)?;
    require(primary.disk_guid == backup.disk_guid, Refusal::Gpt)?;
    require(primary.entry_count == backup.entry_count, Refusal::Gpt)?;
    require(primary.entry_bytes == backup.entry_bytes, Refusal::Gpt)?;
    require(primary.entries_crc == backup.entries_crc, Refusal::Gpt)?;
    require(primary.entry_count == GPT_ENTRY_COUNT, Refusal::Gpt)?;
    require(primary.entry_bytes == GPT_ENTRY_BYTES, Refusal::Gpt)?;
    require(primary.first_usable == ENTRY_SECTORS + 2, Refusal::Gpt)?;
    require(
        primary.last_usable < total - 1 - ENTRY_SECTORS,
        Refusal::Gpt,
    )?;
    let (crc, entry, others_zero) = entry_array(disk, primary.entries_lba)?;
    require(crc == primary.entries_crc, Refusal::Gpt)?;
    let (backup_crc, _, _) = entry_array(disk, backup.entries_lba)?;
    require(backup_crc == backup.entries_crc, Refusal::Gpt)?;

    require(entry[0..16] == TYPE_GUID, Refusal::Partition)?;
    require(others_zero, Refusal::Partition)?;
    require(u64_at(&entry, 32) == FIRST_LBA, Refusal::Partition)?;
    let last = u64_at(&entry, 40);
    require(last == primary.last_usable, Refusal::Partition)?;
    require(u64_at(&entry, 48) == 0, Refusal::Partition)?;
    require(entry[56..128] == NAME, Refusal::Partition)?;

    let header = sector(disk, FIRST_LBA)?;
    require(
        u32_at(&header, OFF_HEADER_MAGIC) == VOLUME_MAGIC,
        Refusal::Header,
    )?;
    require(
        u16_at(&header, OFF_HEADER_VERSION) == FORMAT_VERSION,
        Refusal::Header,
    )?;
    require(
        u16_at(&header, OFF_HEADER_KIND) == KIND_FRAME_STORE,
        Refusal::Header,
    )?;
    require(
        header[VOLUME_HEADER_BYTES..].iter().all(|&byte| byte == 0),
        Refusal::Header,
    )?;
    let size = u64_at(&header, OFF_HEADER_PAYLOADBYTES);
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&header[OFF_HEADER_PAYLOADSHA256..OFF_HEADER_PAYLOADSHA256 + 32]);
    require(size != 0, Refusal::Length)?;
    require(size <= MAX_PAYLOAD_BYTES, Refusal::Length)?;
    let sectors = size.div_ceil(SECTOR_BYTES as u64);
    require(sectors == last - FIRST_LBA, Refusal::Length)?;

    let tail = (size % SECTOR_BYTES as u64) as usize;
    if tail != 0 {
        let final_sector = sector(disk, FIRST_LBA + sectors)?;
        require(
            final_sector[tail..].iter().all(|&byte| byte == 0),
            Refusal::Padding,
        )?;
    }

    let mut digest = Sha256::new();
    let mut chunk = [0u8; CHUNK];
    let mut done = 0u64;
    while done < sectors {
        let count = (sectors - done).min(CHUNK_SECTORS as u64) as usize;
        let bytes = &mut chunk[..count * SECTOR_BYTES];
        disk.read(FIRST_LBA + 1 + done, bytes)?;
        let used = (size - done * SECTOR_BYTES as u64).min(bytes.len() as u64) as usize;
        digest.update(&bytes[..used]);
        done += count as u64;
    }
    require(digest.finalize() == expected, Refusal::Hash)?;
    Ok(Volume {
        payload_bytes: size,
        payload_sha256: expected,
    })
}

/// The payload of an opened volume, read through a one-chunk cache.
struct Payload<'a, D: Disk> {
    disk: &'a mut D,
    sectors: u64,
    chunk: [u8; CHUNK],
    /// The payload-relative sector the chunk starts at, if one is loaded.
    loaded: Option<u64>,
}

impl<D: Disk> StoreSource for Payload<'_, D> {
    fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), SourceError> {
        let mut done = 0;
        while done < out.len() {
            let at = (offset + done) as u64;
            let first = at / SECTOR_BYTES as u64 / CHUNK_SECTORS as u64 * CHUNK_SECTORS as u64;
            if self.loaded != Some(first) {
                let count = (self.sectors - first).min(CHUNK_SECTORS as u64) as usize;
                if count == 0 {
                    return Err(SourceError);
                }
                self.disk
                    .read(
                        FIRST_LBA + 1 + first,
                        &mut self.chunk[..count * SECTOR_BYTES],
                    )
                    .map_err(|_| SourceError)?;
                self.loaded = Some(first);
            }
            let within = (at - first * SECTOR_BYTES as u64) as usize;
            let take = (CHUNK - within).min(out.len() - done);
            out[done..done + take].copy_from_slice(&self.chunk[within..within + take]);
            done += take;
        }
        Ok(())
    }
}

/// Validates an opened volume's payload as a frame store and summarizes it.
pub fn frame_store<D: Disk>(disk: &mut D, volume: &Volume) -> Result<StoreSummary, Error> {
    open_store(disk, volume).map(|store| store.summary)
}

/// A frame store on an opened volume that passed [`frame_store`]'s validation, read one frame at a
/// time through the same one-chunk cache. It holds the disk for as long as it lives.
pub struct StoreReader<'a, D: Disk> {
    payload: Payload<'a, D>,
    size: usize,
    summary: StoreSummary,
}

/// Why a frame was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The frame index or the byte range asked for is outside the store or the frame.
    Range,
    /// The frame's index entry, read again, fails a check it passed in validation.
    Refused,
    /// The device could not supply the sectors.
    Device,
}

/// Validates an opened volume's payload as a frame store, as [`frame_store`] does, and keeps it
/// open for frame reads.
pub fn open_store<'a, D: Disk>(
    disk: &'a mut D,
    volume: &Volume,
) -> Result<StoreReader<'a, D>, Error> {
    let size =
        usize::try_from(volume.payload_bytes).map_err(|_| Error::Refused(Refusal::FrameStore))?;
    let mut payload = Payload {
        disk,
        sectors: volume.payload_bytes.div_ceil(SECTOR_BYTES as u64),
        chunk: [0; CHUNK],
        loaded: None,
    };
    match frame_store::validate_streaming(&mut payload, size) {
        Ok(summary) => Ok(StoreReader {
            payload,
            size,
            summary,
        }),
        Err(StreamError::Refused(_)) => Err(Error::Refused(Refusal::FrameStore)),
        Err(StreamError::Source) => Err(Error::Device),
    }
}

impl<D: Disk> StoreReader<'_, D> {
    /// What validation found: frame count, period, log times and the payload digest.
    pub fn summary(&self) -> &StoreSummary {
        &self.summary
    }

    /// Where frame `index` lies. Its index entry is read from the disk again and held to the checks
    /// it passed, so a payload range always lies inside the volume's payload bytes.
    pub fn frame(&mut self, index: usize) -> Result<FrameExtent, FrameError> {
        match frame_store::frame_extent(&mut self.payload, &self.summary, self.size, index) {
            Ok(Some(extent)) => Ok(extent),
            Ok(None) => Err(FrameError::Range),
            Err(StreamError::Refused(_)) => Err(FrameError::Refused),
            Err(StreamError::Source) => Err(FrameError::Device),
        }
    }

    /// Fills `out` with `frame`'s payload from byte `at` of that payload. The range must lie inside
    /// the payload, so `out` is at most the frame's length and the store is never held whole.
    pub fn read(
        &mut self,
        frame: &FrameExtent,
        at: usize,
        out: &mut [u8],
    ) -> Result<(), FrameError> {
        // An extent of another store could name bytes past this one's payload.
        if frame
            .offset()
            .checked_add(frame.len())
            .is_none_or(|end| end > self.size)
        {
            return Err(FrameError::Range);
        }
        frame_store::read_payload(&mut self.payload, frame, at, out).map_err(|error| match error {
            PayloadError::Range => FrameError::Range,
            PayloadError::Source => FrameError::Device,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    const FIXTURE: &[u8] = include_bytes!("frame_store/fixture.bin");

    struct Memory(Vec<u8>);

    impl Disk for Memory {
        fn capacity(&self) -> u64 {
            (self.0.len() / SECTOR_BYTES) as u64
        }

        fn read(&mut self, lba: u64, out: &mut [u8]) -> Result<(), DeviceError> {
            assert!(
                !out.is_empty() && out.len().is_multiple_of(SECTOR_BYTES) && out.len() <= CHUNK
            );
            let start = lba as usize * SECTOR_BYTES;
            let bytes = self.0.get(start..start + out.len()).ok_or(DeviceError)?;
            out.copy_from_slice(bytes);
            Ok(())
        }
    }

    fn header_crc(disk: &mut [u8], lba: usize) {
        let at = lba * SECTOR_BYTES;
        disk[at + 16..at + 20].fill(0);
        let crc = boot_contracts::crc32::crc32(&disk[at..at + GPT_HEADER_BYTES]);
        disk[at + 16..at + 20].copy_from_slice(&crc.to_le_bytes());
    }

    /// The contract's one disk image of `payload`, written independently of the reader's checks.
    fn encode(payload: &[u8]) -> Vec<u8> {
        let digest = boot_contracts::sha256::digest(payload);
        let sectors = payload.len().div_ceil(SECTOR_BYTES);
        let last_usable = FIRST_LBA as usize + sectors;
        let total = last_usable + 1 + ENTRY_SECTORS as usize + 1;
        let mut disk = std::vec![0u8; total * SECTOR_BYTES];
        disk[446..462]
            .copy_from_slice(&[0, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF, 1, 0, 0, 0, 0, 0, 0, 0]);
        disk[458..462].copy_from_slice(&((total - 1) as u32).to_le_bytes());
        disk[510] = 0x55;
        disk[511] = 0xAA;
        let mut entries = std::vec![0u8; ENTRY_ARRAY_BYTES];
        entries[0..16].copy_from_slice(&TYPE_GUID);
        entries[16..32].copy_from_slice(&digest[..16]);
        entries[32..40].copy_from_slice(&FIRST_LBA.to_le_bytes());
        entries[40..48].copy_from_slice(&(last_usable as u64).to_le_bytes());
        entries[56..128].copy_from_slice(&NAME);
        let crc = boot_contracts::crc32::crc32(&entries);
        let backup_entries = total - 1 - ENTRY_SECTORS as usize;
        for (lba, alternate, array) in [(1, total - 1, 2), (total - 1, 1, backup_entries)] {
            let at = lba * SECTOR_BYTES;
            disk[at..at + 8].copy_from_slice(b"EFI PART");
            disk[at + 8..at + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
            disk[at + 12..at + 16].copy_from_slice(&(GPT_HEADER_BYTES as u32).to_le_bytes());
            disk[at + 24..at + 32].copy_from_slice(&(lba as u64).to_le_bytes());
            disk[at + 32..at + 40].copy_from_slice(&(alternate as u64).to_le_bytes());
            disk[at + 40..at + 48].copy_from_slice(&(ENTRY_SECTORS + 2).to_le_bytes());
            disk[at + 48..at + 56].copy_from_slice(&(last_usable as u64).to_le_bytes());
            disk[at + 56..at + 72].copy_from_slice(&digest[16..32]);
            disk[at + 72..at + 80].copy_from_slice(&(array as u64).to_le_bytes());
            disk[at + 80..at + 84].copy_from_slice(&GPT_ENTRY_COUNT.to_le_bytes());
            disk[at + 84..at + 88].copy_from_slice(&GPT_ENTRY_BYTES.to_le_bytes());
            disk[at + 88..at + 92].copy_from_slice(&crc.to_le_bytes());
            header_crc(&mut disk, lba);
            disk[array * SECTOR_BYTES..array * SECTOR_BYTES + ENTRY_ARRAY_BYTES]
                .copy_from_slice(&entries);
        }
        let header = FIRST_LBA as usize * SECTOR_BYTES;
        disk[header..header + 4].copy_from_slice(&VOLUME_MAGIC.to_le_bytes());
        disk[header + 4..header + 6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        disk[header + 6..header + 8].copy_from_slice(&KIND_FRAME_STORE.to_le_bytes());
        disk[header + 8..header + 16].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        disk[header + 16..header + 48].copy_from_slice(&digest);
        disk[header + SECTOR_BYTES..header + SECTOR_BYTES + payload.len()].copy_from_slice(payload);
        disk
    }

    fn verdict(disk: Vec<u8>) -> Result<StoreSummary, Error> {
        let mut disk = Memory(disk);
        let volume = open(&mut disk)?;
        frame_store(&mut disk, &volume)
    }

    #[test]
    fn classes_follow_the_contract_order() {
        let all = [
            Refusal::Gpt,
            Refusal::Partition,
            Refusal::Header,
            Refusal::Length,
            Refusal::Padding,
            Refusal::Hash,
            Refusal::FrameStore,
        ];
        for (index, refusal) in all.iter().enumerate() {
            assert_eq!(refusal.class(), REFUSAL_CLASSES[index]);
        }
    }

    #[test]
    fn the_fixture_volume_reads_back() {
        let summary = verdict(encode(FIXTURE)).expect("the fixture volume is valid");
        let store = crate::frame_store::FrameStore::parse(FIXTURE).expect("valid");
        assert_eq!(summary.frame_count, store.len());
        let mut payloads = Vec::new();
        for frame in store.frames() {
            payloads.extend_from_slice(frame.payload);
        }
        assert_eq!(
            summary.payload_digest,
            boot_contracts::sha256::digest(&payloads)
        );
    }

    /// Every frame read from the disk one bounded buffer at a time is the frame the whole-store
    /// reader exposes, and the reader refuses an index or range outside the store.
    #[test]
    fn frames_read_back_from_the_volume() {
        let mut disk = Memory(encode(FIXTURE));
        let volume = open(&mut disk).expect("the fixture volume is valid");
        let store = crate::frame_store::FrameStore::parse(FIXTURE).expect("valid");
        let mut reader = open_store(&mut disk, &volume).expect("a valid store");
        assert_eq!(reader.summary().frame_count, store.len());
        let mut payloads = Vec::new();
        for (index, frame) in store.frames().enumerate() {
            let extent = reader.frame(index).expect("frame");
            assert_eq!(extent.log_time_ns(), frame.log_time_ns);
            let mut whole = std::vec![0u8; extent.len()];
            reader.read(&extent, 0, &mut whole).expect("read");
            assert_eq!(whole, frame.payload);
            let mut tail = std::vec![0u8; extent.len() - 3];
            reader.read(&extent, 3, &mut tail).expect("read");
            assert_eq!(tail, frame.payload[3..]);
            let mut past = std::vec![0u8; extent.len() + 1];
            assert_eq!(reader.read(&extent, 0, &mut past), Err(FrameError::Range));
            payloads.extend_from_slice(&whole);
        }
        assert_eq!(reader.frame(store.len()), Err(FrameError::Range));
        assert_eq!(
            reader.summary().payload_digest,
            boot_contracts::sha256::digest(&payloads)
        );
    }

    /// A frame read is held to this store's payload bytes, so an extent taken from a larger store
    /// cannot reach past them into the padding or the backup GPT.
    #[test]
    fn an_extent_of_another_store_is_out_of_range() {
        let mut longer = FIXTURE.to_vec();
        let summary =
            crate::frame_store::validate_streaming(&mut Slice(FIXTURE), FIXTURE.len()).unwrap();
        let entry = summary.index_offset + 24;
        // Grow frame 1 to the end of a store one 8-byte block longer.
        let length = u32::from_le_bytes(longer[entry + 8..entry + 12].try_into().unwrap());
        longer[entry + 8..entry + 12].copy_from_slice(&(length.div_ceil(8) * 8 + 8).to_le_bytes());
        longer.extend_from_slice(&[0; 8]);
        let mut big_disk = Memory(encode(&longer));
        let big_volume = open(&mut big_disk).expect("valid");
        let far = open_store(&mut big_disk, &big_volume)
            .expect("a valid store")
            .frame(1)
            .expect("frame");
        let mut disk = Memory(encode(FIXTURE));
        let volume = open(&mut disk).expect("valid");
        let mut reader = open_store(&mut disk, &volume).expect("a valid store");
        let mut out = std::vec![0u8; far.len()];
        assert_eq!(reader.read(&far, 0, &mut out), Err(FrameError::Range));
    }

    #[test]
    fn a_device_failing_after_validation_is_a_device_error() {
        let mut disk = Flaky {
            inner: Memory(encode(FIXTURE)),
            broken: false,
        };
        let volume = open(&mut disk).expect("valid");
        let mut reader = open_store(&mut disk, &volume).expect("a valid store");
        let extent = reader.frame(1).expect("frame");
        reader.payload.disk.broken = true;
        reader.payload.loaded = None;
        let mut out = std::vec![0u8; extent.len()];
        assert_eq!(reader.read(&extent, 0, &mut out), Err(FrameError::Device));
        assert_eq!(reader.frame(0), Err(FrameError::Device));
    }

    struct Slice<'a>(&'a [u8]);

    impl StoreSource for Slice<'_> {
        fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), SourceError> {
            let bytes = self.0.get(offset..offset + out.len()).ok_or(SourceError)?;
            out.copy_from_slice(bytes);
            Ok(())
        }
    }

    struct Flaky {
        inner: Memory,
        broken: bool,
    }

    impl Disk for Flaky {
        fn capacity(&self) -> u64 {
            self.inner.capacity()
        }

        fn read(&mut self, lba: u64, out: &mut [u8]) -> Result<(), DeviceError> {
            if self.broken {
                return Err(DeviceError);
            }
            self.inner.read(lba, out)
        }
    }

    #[test]
    fn broken_volumes_are_refused_by_class() {
        let honest = encode(FIXTURE);
        let header = FIRST_LBA as usize * SECTOR_BYTES;
        let payload = header + SECTOR_BYTES;
        let refused = |edit: &dyn Fn(&mut Vec<u8>), class: Refusal| {
            let mut disk = honest.clone();
            edit(&mut disk);
            assert_eq!(
                verdict(disk).err(),
                Some(Error::Refused(class)),
                "{class:?}"
            );
        };
        refused(&|disk| disk[510] = 0, Refusal::Gpt);
        refused(&|disk| disk[SECTOR_BYTES + 40] ^= 1, Refusal::Gpt);
        refused(
            &|disk| {
                disk[SECTOR_BYTES + 40] = 0;
                header_crc(disk, 1);
            },
            Refusal::Gpt,
        );
        refused(
            &|disk| {
                let backup = disk.len() / SECTOR_BYTES - 1 - ENTRY_SECTORS as usize;
                disk[backup * SECTOR_BYTES + 200] = 1;
            },
            Refusal::Gpt,
        );
        refused(
            &|disk| {
                let total = disk.len() / SECTOR_BYTES;
                for (lba, array) in [(1, 2), (total - 1, total - 1 - ENTRY_SECTORS as usize)] {
                    disk[array * SECTOR_BYTES] ^= 1;
                    let start = array * SECTOR_BYTES;
                    let crc = boot_contracts::crc32::crc32(&disk[start..start + ENTRY_ARRAY_BYTES]);
                    disk[lba * SECTOR_BYTES + 88..lba * SECTOR_BYTES + 92]
                        .copy_from_slice(&crc.to_le_bytes());
                    header_crc(disk, lba);
                }
            },
            Refusal::Partition,
        );
        refused(&|disk| disk[header] ^= 1, Refusal::Header);
        refused(&|disk| disk[header + 100] = 1, Refusal::Header);
        refused(
            &|disk| disk[header + 8..header + 16].copy_from_slice(&0u64.to_le_bytes()),
            Refusal::Length,
        );
        refused(
            &move |disk| disk[payload + FIXTURE.len()] = 1,
            Refusal::Padding,
        );
        refused(&move |disk| disk[payload + 70] ^= 1, Refusal::Hash);
        let mut not_a_store = FIXTURE.to_vec();
        not_a_store[0] ^= 0xFF;
        assert_eq!(
            verdict(encode(&not_a_store)).err(),
            Some(Error::Refused(Refusal::FrameStore))
        );
    }

    #[test]
    fn a_short_device_is_a_gpt_refusal_and_a_failing_one_is_not_a_refusal() {
        assert_eq!(
            verdict(std::vec![0; 1024]).err(),
            Some(Error::Refused(Refusal::Gpt))
        );
        struct Broken;
        impl Disk for Broken {
            fn capacity(&self) -> u64 {
                1 << 20
            }
            fn read(&mut self, _: u64, _: &mut [u8]) -> Result<(), DeviceError> {
                Err(DeviceError)
            }
        }
        assert_eq!(open(&mut Broken).err(), Some(Error::Device));
    }
}

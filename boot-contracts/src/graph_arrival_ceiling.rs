//! Graph arrival ceiling resource object.
//!
//! A generation resource object declaring how many component arrivals the
//! root's graph service loop handles before a finite plane stops. Without the
//! object a finite plane keeps [`DEFAULT_CEILING`]. A declared ceiling is
//! strictly above that default and at most [`MAX_CEILING`], so it stays a
//! livelock watchdog rather than removing one.
//!
//! It is embedded as a `KIND_RESOURCE` object and authenticated by the
//! generation's per-object digest table. Decoding here assumes integrity has
//! already been verified and enforces only structure and bounds. Whether the
//! generation's boot action may carry a ceiling is the root's admission check.

pub const MAGIC: [u8; 8] = *b"SLIMEGA\0";
include!("generated/graph_arrival_ceiling.rs");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The object is not exactly one header long.
    Truncated,
    BadMagic,
    UnsupportedVersion,
    UnknownRequiredFlags,
    /// The ceiling is not above the default or is above the contract bound.
    OutOfBounds,
}

/// A decoded, bounds-checked arrival ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphArrivalCeiling {
    arrivals: usize,
}

impl GraphArrivalCeiling {
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != HEADER_BYTES {
            return Err(DecodeError::Truncated);
        }
        if bytes[OFF_HEADER_MAGIC..OFF_HEADER_MAGIC_END] != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        if u32_at(bytes, OFF_HEADER_FORMAT_VERSION) != FORMAT_VERSION
            || u32_at(bytes, OFF_HEADER_HEADER_SIZE) as usize != HEADER_BYTES
        {
            return Err(DecodeError::UnsupportedVersion);
        }
        if u64_at(bytes, OFF_HEADER_REQUIRED_FLAGS) != 0 {
            return Err(DecodeError::UnknownRequiredFlags);
        }
        let declared = u64_at(bytes, OFF_HEADER_ARRIVAL_CEILING);
        if declared <= DEFAULT_CEILING as u64 || declared > MAX_CEILING as u64 {
            return Err(DecodeError::OutOfBounds);
        }
        Ok(Self {
            arrivals: declared as usize,
        })
    }

    /// The component arrivals the graph service loop handles.
    pub fn arrivals(&self) -> usize {
        self.arrivals
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn build(ceiling: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&ceiling.to_le_bytes());
        bytes
    }

    #[test]
    fn layout_matches_the_contract() {
        assert_eq!(build(DEFAULT_CEILING as u64 + 1).len(), HEADER_BYTES);
        assert_eq!(OFF_HEADER_ARRIVAL_CEILING_END, HEADER_BYTES);
    }

    #[test]
    fn accepts_every_ceiling_inside_the_bounds() {
        for ceiling in [DEFAULT_CEILING as u64 + 1, 4_194_304, MAX_CEILING as u64] {
            let decoded = GraphArrivalCeiling::decode(&build(ceiling)).unwrap();
            assert_eq!(decoded.arrivals() as u64, ceiling);
        }
    }

    #[test]
    fn refuses_a_ceiling_that_does_not_raise_the_default_or_passes_the_bound() {
        for ceiling in [
            0,
            1,
            DEFAULT_CEILING as u64,
            MAX_CEILING as u64 + 1,
            u64::MAX,
        ] {
            assert_eq!(
                GraphArrivalCeiling::decode(&build(ceiling)),
                Err(DecodeError::OutOfBounds),
                "{ceiling}"
            );
        }
    }

    #[test]
    fn refuses_each_malformed_header() {
        let good = build(4_194_304);
        let mut short = good.clone();
        short.pop();
        let mut long = good.clone();
        long.push(0);
        assert_eq!(
            GraphArrivalCeiling::decode(&short),
            Err(DecodeError::Truncated)
        );
        assert_eq!(
            GraphArrivalCeiling::decode(&long),
            Err(DecodeError::Truncated)
        );
        let mut magic = good.clone();
        magic[0] ^= 1;
        assert_eq!(
            GraphArrivalCeiling::decode(&magic),
            Err(DecodeError::BadMagic)
        );
        let mut version = good.clone();
        version[OFF_HEADER_FORMAT_VERSION] = 2;
        assert_eq!(
            GraphArrivalCeiling::decode(&version),
            Err(DecodeError::UnsupportedVersion)
        );
        let mut header = good.clone();
        header[OFF_HEADER_HEADER_SIZE] = 33;
        assert_eq!(
            GraphArrivalCeiling::decode(&header),
            Err(DecodeError::UnsupportedVersion)
        );
        let mut flags = good;
        flags[OFF_HEADER_REQUIRED_FLAGS] = 1;
        assert_eq!(
            GraphArrivalCeiling::decode(&flags),
            Err(DecodeError::UnknownRequiredFlags)
        );
    }
}

//! A small, explicit binary wire format for exchanging [`VersionReq`].
//!
//! This module encodes a `VersionReq` as a versioned binary frame and decodes
//! such frames back into a `VersionReq`. Unlike a naive fixed-shape encoding,
//! the presence of the optional `minor`, `patch`, and pre-release components is
//! recorded with explicit flag bits. An omitted field stays omitted after a
//! round trip: `^1` is *not* silently widened to `^1.0.0`, which would change
//! how [`VersionReq::matches`] treats pre-releases and wildcards.
//!
//! # Frame layout (protocol version 1)
//!
//! Multi-byte integers are unsigned, big-endian.
//!
//! | offset | size | field | notes |
//! |---|---|---|---|
//! | 0 | 2 | magic | always `SV` (`53 56`) |
//! | 2 | 1 | protocol version | must equal [`PROTOCOL_VERSION`] (`1`) |
//! | 3 | 1 | comparator count | `0..=` [`MAX_COMPARATORS`]; `0` denotes the `*` / [`VersionReq::STAR`] requirement |
//! | 4 | N | comparators | repeated `count` times, see below |
//!
//! Each comparator:
//!
//! | size | field | notes |
//! |---|---|---|
//! | 1 | op | one byte: `0` =, `1` >, `2` >=, `3` <, `4` <=, `5` ~, `6` ^, `7` wildcard; any other value is rejected |
//! | 1 | flags | bit 0 `HAS_MINOR`, bit 1 `HAS_PATCH`, bit 2 `HAS_PRE`; bits 3..=7 are reserved and must be zero |
//! | 8 | major | big-endian u64 |
//! | 8 | minor | present only if `HAS_MINOR` |
//! | 8 | patch | present only if `HAS_PATCH` (implies `HAS_MINOR`) |
//! | 1 | pre-release length | present only if `HAS_PRE`; `1..=` [`MAX_PRERELEASE_LEN`] |
//! | L | pre-release bytes | raw ASCII bytes, validated against the original [`Prerelease`] grammar |
//!
//! # Validation
//!
//! On decode, unknown op codes, illegal flag combinations, and over-long
//! frames are rejected before any value is constructed. Once a `VersionReq`
//! has been constructed, each comparator and the whole requirement are
//! re-serialized to their canonical textual form and re-parsed with this
//! crate's original parser to prove representability. Trailing bytes after the
//! declared frame are never ignored, and any failure yields an `Err` rather
//! than a partially populated `VersionReq`.
//!
//! See `docs/protocol.md` for the prose version of this table.
//!
//! # Example
//!
//! ```
//! use semver::VersionReq;
//!
//! let req = VersionReq::parse("^1.2").unwrap();
//! let bytes = req.to_binary().unwrap();
//! let back = VersionReq::from_binary(&bytes).unwrap();
//!
//! // The omitted patch component is still omitted; it was not padded to zero.
//! assert_eq!(back, req);
//! assert_eq!(back.comparators[0].patch, None);
//! assert_eq!(back.to_string(), "^1.2");
//! ```

use crate::{Comparator, Op, Prerelease, VersionReq};
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt::{self, Display};
use core::str::FromStr;

/// The only wire-protocol version understood by this build.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum number of comparators representable in a frame. Matches the limit
/// enforced by the textual parser (`32`).
pub const MAX_COMPARATORS: usize = 32;

/// Maximum length, in bytes, of an encoded pre-release identifier.
pub const MAX_PRERELEASE_LEN: usize = 255;

const MAGIC: [u8; 2] = *b"SV";
const HEADER_LEN: usize = 4;
const OP_LEN: usize = 1;
const FLAGS_LEN: usize = 1;
const U64_LEN: usize = 8;
const MAX_COMPARATOR_LEN: usize = OP_LEN + FLAGS_LEN + 3 * U64_LEN + 1 + MAX_PRERELEASE_LEN;
const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_COMPARATORS * MAX_COMPARATOR_LEN;

const HAS_MINOR: u8 = 0b0000_0001;
const HAS_PATCH: u8 = 0b0000_0010;
const HAS_PRE: u8 = 0b0000_0100;
const RESERVED_FLAGS: u8 = 0b1111_1000;

/// An error encountered while encoding or decoding a binary [`VersionReq`].
#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum CodecError {
    /// The frame does not begin with the `SV` magic.
    InvalidMagic,
    /// The frame advertises a protocol version this build does not understand.
    UnsupportedVersion(u8),
    /// A comparator carried an op code outside `0..=7`.
    UnknownOp(u8),
    /// The flags byte had a reserved bit set, or its presence bits did not
    /// form a legal combination (for example `HAS_PATCH` without `HAS_MINOR`).
    IllegalFlags(u8),
    /// The decoded fields contradict the invariants of a parsed comparator
    /// (for example a pre-release without a patch number, or a wildcard with a
    /// patch component).
    IllegalCombination(&'static str),
    /// The input ended while more bytes were required.
    UnexpectedEnd,
    /// More comparators than [`MAX_COMPARATORS`] were declared.
    TooManyComparators {
        /// Declared count that exceeded the limit.
        count: usize,
    },
    /// The frame exceeds the maximum size derivable from the declared limits.
    FrameTooLong {
        /// Actual length in bytes.
        len: usize,
        /// Maximum accepted length in bytes.
        max: usize,
    },
    /// A pre-release byte string does not conform to the [`Prerelease`]
    /// grammar.
    InvalidPrerelease,
    /// A pre-release identifier exceeded [`MAX_PRERELEASE_LEN`] bytes.
    PrereleaseTooLong {
        /// Actual length in bytes.
        len: usize,
    },
    /// The decoded bytes formed a [`Comparator`] or [`VersionReq`] that the
    /// original textual parser does not consider representable.
    NotRepresentable,
    /// Bytes remained after the number of declared comparators was consumed.
    TrailingBytes {
        /// Number of unconsumed trailing bytes.
        remaining: usize,
    },
}

impl Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CodecError::InvalidMagic => {
                formatter.write_str("invalid version-requirement frame magic")
            }
            CodecError::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported version-requirement wire protocol version {}",
                    version,
                )
            }
            CodecError::UnknownOp(op) => {
                write!(formatter, "unknown comparison operator code {}", op)
            }
            CodecError::IllegalFlags(flags) => {
                write!(formatter, "illegal comparator flags byte {:#04x}", flags)
            }
            CodecError::IllegalCombination(reason) => {
                write!(
                    formatter,
                    "illegal comparator field combination: {}",
                    reason
                )
            }
            CodecError::UnexpectedEnd => {
                formatter.write_str("unexpected end of version-requirement frame")
            }
            CodecError::TooManyComparators { count } => {
                write!(
                    formatter,
                    "version requirement declares {} comparators but the limit is {}",
                    count, MAX_COMPARATORS,
                )
            }
            CodecError::FrameTooLong { len, max } => {
                write!(
                    formatter,
                    "version-requirement frame is {} bytes but the maximum is {} bytes",
                    len, max,
                )
            }
            CodecError::InvalidPrerelease => {
                formatter.write_str("pre-release identifier fails semver prerelease grammar")
            }
            CodecError::PrereleaseTooLong { len } => {
                write!(
                    formatter,
                    "pre-release identifier is {} bytes but the limit is {}",
                    len, MAX_PRERELEASE_LEN,
                )
            }
            CodecError::NotRepresentable => formatter.write_str(
                "decoded version requirement cannot be represented by the original parser",
            ),
            CodecError::TrailingBytes { remaining } => {
                write!(
                    formatter,
                    "{} trailing bytes after the end of the version-requirement frame",
                    remaining,
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CodecError {}

impl VersionReq {
    /// Encode this requirement into the binary wire format.
    ///
    /// Omitted `minor`/`patch` fields and an empty pre-release are preserved as
    /// omitted rather than padded with zeroes.
    pub fn to_binary(&self) -> Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Decode a requirement previously produced by [`VersionReq::to_binary`].
    pub fn from_binary(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(bytes)
    }
}

/// Encode a [`VersionReq`] into protocol version 1 bytes.
pub fn encode(req: &VersionReq) -> Result<Vec<u8>, CodecError> {
    let count = req.comparators.len();
    if count > MAX_COMPARATORS {
        return Err(CodecError::TooManyComparators { count });
    }

    // Reject illegal op/field combinations before writing a single byte.
    for comparator in &req.comparators {
        validate_comparator(comparator)?;
    }

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(PROTOCOL_VERSION);
    out.push(count as u8);

    for comparator in &req.comparators {
        out.push(op_to_code(comparator.op));

        let mut flags = 0u8;
        if comparator.minor.is_some() {
            flags |= HAS_MINOR;
        }
        if comparator.patch.is_some() {
            flags |= HAS_PATCH;
        }
        if !comparator.pre.is_empty() {
            flags |= HAS_PRE;
        }
        out.push(flags);

        out.extend_from_slice(&comparator.major.to_be_bytes());
        if let Some(minor) = comparator.minor {
            out.extend_from_slice(&minor.to_be_bytes());
        }
        if let Some(patch) = comparator.patch {
            out.extend_from_slice(&patch.to_be_bytes());
        }
        if !comparator.pre.is_empty() {
            let bytes = comparator.pre.as_str().as_bytes();
            // Length was checked by validate_comparator.
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
    }

    Ok(out)
}

/// Decode protocol version 1 bytes into a fully validated [`VersionReq`].
///
/// The returned value is only produced if every comparator and the whole
/// requirement survive a round trip through the original textual parser.
pub fn decode(bytes: &[u8]) -> Result<VersionReq, CodecError> {
    if bytes.len() < HEADER_LEN {
        return Err(CodecError::UnexpectedEnd);
    }
    if bytes[0..2] != MAGIC {
        return Err(CodecError::InvalidMagic);
    }

    let version = bytes[2];
    if version != PROTOCOL_VERSION {
        return Err(CodecError::UnsupportedVersion(version));
    }

    let count = bytes[3] as usize;
    if count > MAX_COMPARATORS {
        return Err(CodecError::TooManyComparators { count });
    }
    if bytes.len() > MAX_FRAME_LEN {
        return Err(CodecError::FrameTooLong {
            len: bytes.len(),
            max: MAX_FRAME_LEN,
        });
    }

    let mut pos = HEADER_LEN;
    let mut comparators: Vec<Comparator> = Vec::with_capacity(count);

    for _ in 0..count {
        // Unknown ops and illegal presence-bit combinations are rejected
        // inside decode_comparator before a Comparator is constructed.
        let comparator = decode_comparator(bytes, &mut pos)?;

        // Construct-then-verify: prove the original parser can represent this
        // exact comparator (including which fields were omitted).
        let canonical = Comparator::from_str(&comparator.to_string())
            .map_err(|_| CodecError::NotRepresentable)?;
        if canonical != comparator {
            return Err(CodecError::NotRepresentable);
        }

        comparators.push(comparator);
    }

    // Trailing bytes are a hard error, never silently ignored.
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes {
            remaining: bytes.len() - pos,
        });
    }

    // The VersionReq itself is only assembled after every prior check passed,
    // so an error never hands back a partially populated requirement.
    let req = VersionReq { comparators };
    let reparsed =
        VersionReq::from_str(&req.to_string()).map_err(|_| CodecError::NotRepresentable)?;
    if reparsed != req {
        return Err(CodecError::NotRepresentable);
    }

    Ok(req)
}

fn validate_comparator(comparator: &Comparator) -> Result<(), CodecError> {
    if comparator.patch.is_some() && comparator.minor.is_none() {
        return Err(CodecError::IllegalCombination(
            "patch component requires a minor component",
        ));
    }
    if !comparator.pre.is_empty() && comparator.patch.is_none() {
        return Err(CodecError::IllegalCombination(
            "non-empty pre-release requires a patch component",
        ));
    }
    if comparator.op == Op::Wildcard && comparator.patch.is_some() {
        return Err(CodecError::IllegalCombination(
            "wildcard comparator cannot carry a patch component",
        ));
    }
    let len = comparator.pre.as_str().len();
    if len > MAX_PRERELEASE_LEN {
        return Err(CodecError::PrereleaseTooLong { len });
    }
    Ok(())
}

fn decode_comparator(bytes: &[u8], pos: &mut usize) -> Result<Comparator, CodecError> {
    let start = *pos;

    if bytes.len() - start < OP_LEN + FLAGS_LEN {
        return Err(CodecError::UnexpectedEnd);
    }

    let op_byte = bytes[start];
    let flags = bytes[start + 1];

    // Op validation comes before any field combination is accepted.
    let op = op_from_code(op_byte)?;

    if flags & RESERVED_FLAGS != 0 {
        return Err(CodecError::IllegalFlags(flags));
    }
    let has_minor = flags & HAS_MINOR != 0;
    let has_patch = flags & HAS_PATCH != 0;
    let has_pre = flags & HAS_PRE != 0;

    if has_patch && !has_minor {
        return Err(CodecError::IllegalCombination(
            "HAS_PATCH flag requires the HAS_MINOR flag",
        ));
    }
    if has_pre && !has_patch {
        return Err(CodecError::IllegalCombination(
            "HAS_PRE flag requires the HAS_PATCH flag",
        ));
    }
    if op == Op::Wildcard && has_patch {
        return Err(CodecError::IllegalCombination(
            "wildcard comparator cannot carry a patch component",
        ));
    }

    let mut cur = start + OP_LEN + FLAGS_LEN;
    let major = read_u64(bytes, &mut cur)?;
    let minor = if has_minor {
        Some(read_u64(bytes, &mut cur)?)
    } else {
        None
    };
    let patch = if has_patch {
        Some(read_u64(bytes, &mut cur)?)
    } else {
        None
    };

    let pre = if has_pre {
        if cur >= bytes.len() {
            return Err(CodecError::UnexpectedEnd);
        }
        let len = bytes[cur] as usize;
        cur += 1;
        if len == 0 {
            return Err(CodecError::IllegalCombination(
                "HAS_PRE flag requires a non-empty pre-release",
            ));
        }
        if cur.saturating_add(len) > bytes.len() {
            return Err(CodecError::UnexpectedEnd);
        }
        let raw = &bytes[cur..cur + len];
        cur += len;

        // Validate the carried bytes against the original prerelease grammar
        // (ASCII alphanumerics and hyphen, dot-separated, no leading zeroes).
        let text = core::str::from_utf8(raw).map_err(|_| CodecError::InvalidPrerelease)?;
        let parsed = Prerelease::new(text).map_err(|_| CodecError::InvalidPrerelease)?;
        if parsed.is_empty() {
            return Err(CodecError::InvalidPrerelease);
        }
        parsed
    } else {
        Prerelease::EMPTY
    };

    *pos = cur;
    Ok(Comparator {
        op,
        major,
        minor,
        patch,
        pre,
    })
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, CodecError> {
    let start = *pos;
    let end = start
        .checked_add(U64_LEN)
        .ok_or(CodecError::UnexpectedEnd)?;
    if end > bytes.len() {
        return Err(CodecError::UnexpectedEnd);
    }
    let mut buf = [0u8; U64_LEN];
    buf.copy_from_slice(&bytes[start..end]);
    *pos = end;
    Ok(u64::from_be_bytes(buf))
}

fn op_to_code(op: Op) -> u8 {
    match op {
        Op::Exact => 0,
        Op::Greater => 1,
        Op::GreaterEq => 2,
        Op::Less => 3,
        Op::LessEq => 4,
        Op::Tilde => 5,
        Op::Caret => 6,
        Op::Wildcard => 7,
    }
}

fn op_from_code(code: u8) -> Result<Op, CodecError> {
    match code {
        0 => Ok(Op::Exact),
        1 => Ok(Op::Greater),
        2 => Ok(Op::GreaterEq),
        3 => Ok(Op::Less),
        4 => Ok(Op::LessEq),
        5 => Ok(Op::Tilde),
        6 => Ok(Op::Caret),
        7 => Ok(Op::Wildcard),
        other => Err(CodecError::UnknownOp(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(text: &str) -> VersionReq {
        let req = VersionReq::parse(text).unwrap();
        let bytes = encode(&req).unwrap();
        let decoded = decode(&bytes).unwrap_or_else(|err| panic!("decode {}: {}", text, err));
        assert_eq!(decoded, req, "structural round trip for {}", text);
        assert_eq!(encode(&decoded).unwrap(), bytes, "deterministic re-encode");
        decoded
    }

    #[test]
    fn test_caret_preserves_omitted_fields() {
        // ^1 has no minor and no patch.
        let req = round_trip("^1");
        let cmp = &req.comparators[0];
        assert_eq!(cmp.op, Op::Caret);
        assert_eq!(cmp.major, 1);
        assert_eq!(cmp.minor, None);
        assert_eq!(cmp.patch, None);
        assert!(cmp.pre.is_empty());

        // ^1.2 carries a minor but still no patch.
        let req = round_trip("^1.2");
        let cmp = &req.comparators[0];
        assert_eq!(cmp.minor, Some(2));
        assert_eq!(cmp.patch, None);

        // ^1.2.0 carries all three; the explicit zero patch is not dropped.
        let req = round_trip("^1.2.0");
        let cmp = &req.comparators[0];
        assert_eq!(cmp.minor, Some(2));
        assert_eq!(cmp.patch, Some(0));
    }

    #[test]
    fn test_various_requirements_round_trip() {
        for text in [
            "*",
            "=1.2.3",
            ">=1.0.0, <2.0.0",
            "~1.2.3-beta.2",
            "^0.0.2",
            ">=2.1.0-alpha2",
            "1.*",
            "1.2.*",
            "=0.1.0-beta2.a",
            ">=1.2.3-rc.1, <2",
        ] {
            round_trip(text);
        }
    }

    #[test]
    fn test_unknown_op_rejected() {
        let req = VersionReq::parse("^1").unwrap();
        let mut bytes = encode(&req).unwrap();
        bytes[4] = 8; // not a legal op code
        assert_eq!(decode(&bytes).unwrap_err(), CodecError::UnknownOp(8));
        bytes[4] = 255;
        assert_eq!(decode(&bytes).unwrap_err(), CodecError::UnknownOp(255));
    }

    #[test]
    fn test_illegal_flags_rejected() {
        let req = VersionReq::parse("^1.2.0").unwrap();
        let bytes = encode(&req).unwrap();

        // Reserved bit set.
        let mut reserved = bytes.clone();
        reserved[5] |= 0b0000_1000;
        assert!(matches!(
            decode(&reserved).unwrap_err(),
            CodecError::IllegalFlags(_),
        ));

        // HAS_PATCH without HAS_MINOR.
        let mut patch_only = bytes.clone();
        patch_only[5] = HAS_PATCH;
        assert!(matches!(
            decode(&patch_only).unwrap_err(),
            CodecError::IllegalCombination(_),
        ));

        // HAS_PRE without HAS_PATCH.
        let mut pre_only = bytes.clone();
        pre_only[5] = HAS_MINOR | HAS_PRE;
        assert!(matches!(
            decode(&pre_only).unwrap_err(),
            CodecError::IllegalCombination(_),
        ));

        // Wildcard op together with a patch component.
        let mut wildcard_patch = bytes.clone();
        wildcard_patch[4] = op_to_code(Op::Wildcard);
        wildcard_patch[5] = HAS_MINOR | HAS_PATCH;
        assert!(matches!(
            decode(&wildcard_patch).unwrap_err(),
            CodecError::IllegalCombination(_),
        ));
    }

    #[test]
    fn test_trailing_and_truncated_bytes_rejected() {
        let req = VersionReq::parse("^1.2.0").unwrap();
        let bytes = encode(&req).unwrap();

        let mut padded = bytes.clone();
        padded.push(0);
        assert!(matches!(
            decode(&padded).unwrap_err(),
            CodecError::TrailingBytes { remaining: 1 },
        ));

        for cut in 1..bytes.len() {
            assert!(matches!(
                decode(&bytes[..cut]).unwrap_err(),
                CodecError::UnexpectedEnd
                    | CodecError::InvalidMagic
                    | CodecError::IllegalCombination(_),
            ));
        }
    }

    #[test]
    fn test_header_validation() {
        let req = VersionReq::parse("^1").unwrap();
        let bytes = encode(&req).unwrap();

        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert_eq!(decode(&bad_magic).unwrap_err(), CodecError::InvalidMagic);

        let mut future = bytes.clone();
        future[2] = 2;
        assert_eq!(
            decode(&future).unwrap_err(),
            CodecError::UnsupportedVersion(2)
        );

        let mut too_many = bytes.clone();
        too_many[3] = (MAX_COMPARATORS + 1) as u8;
        assert!(matches!(
            decode(&too_many).unwrap_err(),
            CodecError::TooManyComparators { count } if count == MAX_COMPARATORS + 1,
        ));

        assert_eq!(decode(b"").unwrap_err(), CodecError::UnexpectedEnd);
        assert_eq!(decode(b"SV").unwrap_err(), CodecError::UnexpectedEnd);
    }

    #[test]
    fn test_invalid_prerelease_rejected() {
        let req = VersionReq::parse("^1.2.3-alpha").unwrap();
        let bytes = encode(&req).unwrap();
        let pre_offset = bytes.len() - "alpha".len() - 1;
        assert_eq!(bytes[pre_offset], "alpha".len() as u8);

        for bad in ["01", "a..b", ".a", "a.", "a b"] {
            // Rewrite the length byte and payload while keeping the frame
            // otherwise well-formed, so only the prerelease grammar is at fault.
            let mut tampered = bytes.clone();
            tampered[pre_offset] = bad.len() as u8;
            tampered.truncate(pre_offset + 1);
            tampered.extend_from_slice(bad.as_bytes());
            assert!(
                matches!(
                    decode(&tampered).unwrap_err(),
                    CodecError::InvalidPrerelease,
                ),
                "prerelease {:?} was wrongly accepted",
                bad,
            );
        }

        // HAS_PRE with an explicit zero length is an illegal combination.
        let mut zero_len = bytes.clone();
        zero_len[pre_offset] = 0;
        zero_len.truncate(pre_offset + 1);
        assert!(matches!(
            decode(&zero_len).unwrap_err(),
            CodecError::IllegalCombination(_),
        ));

        // Non-ASCII byte in the prerelease region.
        let mut non_ascii = bytes.clone();
        *non_ascii.last_mut().unwrap() = 0xff;
        assert!(matches!(
            decode(&non_ascii).unwrap_err(),
            CodecError::InvalidPrerelease,
        ));
    }

    #[test]
    fn test_prerelease_length_limit() {
        let too_long = "a".repeat(MAX_PRERELEASE_LEN + 1);
        let req = VersionReq::parse(&alloc::format!("^1.2.3-{}", too_long)).unwrap();
        assert!(matches!(
            encode(&req).unwrap_err(),
            CodecError::PrereleaseTooLong { len } if len == MAX_PRERELEASE_LEN + 1,
        ));

        let at_limit = "a".repeat(MAX_PRERELEASE_LEN);
        let req = VersionReq::parse(&alloc::format!("^1.2.3-{}", at_limit)).unwrap();
        let bytes = encode(&req).unwrap();
        assert_eq!(decode(&bytes).unwrap(), req);
    }

    #[test]
    fn test_comparator_count_limit() {
        let text = (1..=32)
            .map(|i| format!(">={}.0.0", i))
            .collect::<Vec<_>>()
            .join(", ");
        round_trip(&text);

        let req = VersionReq::parse(">=1.0.0").unwrap();
        let many = core::iter::repeat(req.comparators[0].clone())
            .take(MAX_COMPARATORS + 1)
            .collect::<Vec<_>>();
        let oversized = VersionReq { comparators: many };
        assert!(matches!(
            encode(&oversized).unwrap_err(),
            CodecError::TooManyComparators { count } if count == MAX_COMPARATORS + 1,
        ));
    }

    #[test]
    fn test_matches_semantics_unchanged() {
        let reqs = [
            "^1",
            "^1.2",
            "^1.2.0",
            "^0",
            "^0.0",
            ">=1.2.3-rc.1, <2",
            "~1.2",
            "1.*",
            "*",
        ];
        let versions = [
            "0.9.9",
            "1.0.0",
            "1.2.0",
            "1.2.3",
            "1.2.3-rc.1",
            "1.2.3-rc.2",
            "1.9.0",
            "2.0.0",
            "2.0.0-alpha",
        ];

        for req_text in reqs {
            let req = VersionReq::parse(req_text).unwrap();
            let decoded = round_trip(req_text);
            for version_text in versions {
                let version = crate::Version::parse(version_text).unwrap();
                assert_eq!(
                    req.matches(&version),
                    decoded.matches(&version),
                    "matches diverged for {} vs {}",
                    req_text,
                    version_text,
                );
            }
        }
    }

    #[test]
    fn test_star_round_trip_and_zero_count_trailing() {
        let star = VersionReq::STAR;
        let bytes = encode(&star).unwrap();
        assert_eq!(bytes, [b'S', b'V', PROTOCOL_VERSION, 0]);
        assert_eq!(decode(&bytes).unwrap(), star);

        let mut padded = bytes.clone();
        padded.push(0x07);
        assert!(matches!(
            decode(&padded).unwrap_err(),
            CodecError::TrailingBytes { remaining: 1 },
        ));
    }

    #[test]
    fn test_encode_rejects_illegal_combinations() {
        // Patch without minor cannot be encoded.
        let bad = Comparator {
            op: Op::Caret,
            major: 1,
            minor: None,
            patch: Some(0),
            pre: Prerelease::EMPTY,
        };
        assert!(matches!(
            encode(&VersionReq {
                comparators: alloc::vec![bad]
            })
            .unwrap_err(),
            CodecError::IllegalCombination(_),
        ));

        // Non-empty prerelease without patch cannot be encoded.
        let bad = Comparator {
            op: Op::Caret,
            major: 1,
            minor: Some(2),
            patch: None,
            pre: Prerelease::new("alpha").unwrap(),
        };
        assert!(matches!(
            encode(&VersionReq {
                comparators: alloc::vec![bad]
            })
            .unwrap_err(),
            CodecError::IllegalCombination(_),
        ));
    }

    #[test]
    fn test_wire_layout_of_caret_one() {
        let req = VersionReq::parse("^1").unwrap();
        let bytes = encode(&req).unwrap();
        assert_eq!(
            bytes,
            [
                b'S',
                b'V',
                PROTOCOL_VERSION,
                1, // header, one comparator
                6,
                0, // caret op, no flags
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1, // major = 1
            ],
        );
    }
}

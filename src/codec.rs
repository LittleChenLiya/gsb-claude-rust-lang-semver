//! Binary exchange codec for [`VersionReq`].
//!
//! This module provides a compact binary representation of version
//! requirements suitable for exchange over a wire or for persistence. The
//! format preserves the *structure* of each comparator: the operator, which of
//! major/minor/patch were explicitly present, and the raw pre-release bytes.
//! It does **not** pad omitted components with zero, because padding would
//! change the meaning of the requirement: `^1`, `^1.2`, and `^1.2.0` are three
//! different requirements and must round-trip as such.
//!
//! # Protocol
//!
//! An encoded message starts with a fixed-size header, followed by `count`
//! comparator records. All multi-byte integers are unsigned LEB128 varints,
//! encoded canonically (no redundant leading zero groups).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    version    |     count     |            records...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! ## Header
//!
//! | Field     | Size | Description                                   |
//! |-----------|------|-----------------------------------------------|
//! | `version` | u8   | Protocol version. Currently always `1`.       |
//! | `count`   | u8   | Number of comparators. `0` means `*` (any).   |
//!
//! ## Comparator record
//!
//! | Field   | Size    | Description                                         |
//! |---------|---------|-----------------------------------------------------|
//! | `flags` | u8      | Operator and presence bits (see below).            |
//! | `major` | varint  | Major version number.                               |
//! | `minor` | varint  | Minor version number; present only if its bit set. |
//! | `patch` | varint  | Patch version number; present only if its bit set. |
//! | `pre_len` | u8   | Length of the pre-release bytes that follow.       |
//! | `pre`   | pre_len | Raw pre-release bytes, validated as [`Prerelease`].|
//!
//! ## `flags` byte
//!
//! ```text
//!   7   6   5   4   3   2   1   0
//! +---+---+---+---+---+---+---+---+
//! |  reserved   | P | M |    op     |
//! +---+---+---+---+---+---+---+---+
//! ```
//!
//! | Bits  | Field      | Description                                              |
//! |-------|------------|----------------------------------------------------------|
//! | `0..3`| `op`       | Comparison operator. Values `0..=7` are defined;        |
//! |       |            | values `8..=15` are unknown and rejected.               |
//! | `4`   | `minor`    | `1` if the minor version is explicitly present.         |
//! | `5`   | `patch`    | `1` if the patch version is explicitly present.         |
//! | `6..7`| `reserved` | Must be `0`; otherwise the record is rejected.          |
//!
//! Operator values:
//!
//! | `op` | Operator       | `op` | Operator        |
//! |------|----------------|------|-----------------|
//! | `0`  | `=` Exact      | `4`  | `<=` LessEq     |
//! | `1`  | `>` Greater    | `5`  | `~` Tilde       |
//! | `2`  | `>=` GreaterEq | `6`  | `^` Caret       |
//! | `3`  | `<` Less       | `7`  | wildcard (`*`)  |
//!
//! # Limits
//!
//! The codec enforces explicit limits. Inputs that exceed them are rejected
//! with a [`DecodeError`] rather than being truncated or interpreted:
//!
//! | Limit              | Value | Rationale                                                |
//! |--------------------|-------|----------------------------------------------------------|
//! | protocol version   | `1`   | Only the current wire version is accepted.               |
//! | comparator count   | `32`  | Matches the limit enforced by the original parser.      |
//! | pre-release length | `255` | One-byte length prefix; generous for real-world use.  |
//!
//! # Validation
//!
//! Decoding is strict and all-or-nothing:
//!
//! - Unknown operators and illegal presence/reserved bits are rejected
//!   before any version number is read.
//! - Illegal field combinations (patch without minor, a non-empty
//!   pre-release without patch, and wildcard with a patch or pre-release)
//!   are rejected.
//! - Pre-release bytes are validated against the original parser's
//!   [`Prerelease`] syntax.
//! - After construction, the requirement is formatted with its `Display`
//!   implementation and re-parsed with the original [`VersionReq::parse`];
//!   the round-trip must reproduce the exact same structure, otherwise the
//!   message is rejected as not representable.
//! - Trailing bytes after the final comparator are an error; no partial
//!   [`VersionReq`] is returned on any failure.
//!
//! # Cargo commands
//!
//! Build the crate and run the codec-specific tests:
//!
//! ```text
//! cargo build
//! cargo test --test test_codec
//! ```
//!
//! Run the round-trip example that encodes and decodes a requirement:
//!
//! ```text
//! cargo run --example codec
//! ```
//!
//! # Example
//!
//! ```
//! use semver::VersionReq;
//! use semver::codec;
//!
//! let req = VersionReq::parse("^1.2").unwrap();
//! let bytes = codec::encode(&req).unwrap();
//! let decoded = codec::decode(&bytes).unwrap();
//! assert_eq!(req, decoded);
//! ```
//!
//! [`Prerelease`]: crate::Prerelease
//! [`VersionReq`]: crate::VersionReq
//! [`VersionReq::parse`]: crate::VersionReq::parse

use crate::{Comparator, Op, Prerelease, VersionReq};
use alloc::vec::Vec;
use core::fmt;

/// The wire format version produced and accepted by this codec.
pub const VERSION: u8 = 1;

/// Maximum number of comparators in one encoded requirement.
///
/// This matches the limit enforced by the original parser.
pub const MAX_COMPARATORS: usize = 32;

/// Maximum length in bytes of a single comparator's pre-release field.
pub const MAX_PRE_LEN: usize = u8::MAX as usize;

const OP_EXACT: u8 = 0;
const OP_GREATER: u8 = 1;
const OP_GREATER_EQ: u8 = 2;
const OP_LESS: u8 = 3;
const OP_LESS_EQ: u8 = 4;
const OP_TILDE: u8 = 5;
const OP_CARET: u8 = 6;
const OP_WILDCARD: u8 = 7;

const OP_MASK: u8 = 0b0000_1111;
const MINOR_PRESENT: u8 = 1 << 4;
const PATCH_PRESENT: u8 = 1 << 5;
const RESERVED_MASK: u8 = 0b1100_0000;
const KNOWN_OPS: u8 = 8;

/// Error returned when encoding a [`VersionReq`] fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// The requirement contains more than [`MAX_COMPARATORS`] comparators.
    TooManyComparators,
    /// A comparator's pre-release is longer than [`MAX_PRE_LEN`] bytes.
    PreTooLong,
    /// A comparator combines fields that cannot be represented on the wire.
    IllegalCombination,
}

/// Error returned when decoding a binary [`VersionReq`] fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The first byte is not a supported protocol version.
    UnsupportedVersion,
    /// The header declares more than [`MAX_COMPARATORS`] comparators.
    TooManyComparators,
    /// The input ended before a complete record could be read.
    Truncated,
    /// A varint encoded a value outside the range of `u64`.
    Overflow,
    /// A varint used a non-canonical (redundant) encoding.
    NonCanonical,
    /// The flags byte named an operator outside the known range.
    UnknownOp,
    /// The flags byte had reserved bits set.
    IllegalPresenceBits,
    /// The flags byte combined presence bits that are not legal together.
    IllegalCombination,
    /// The pre-release bytes are not valid UTF-8 or violate the original
    /// parser's syntax.
    InvalidPrerelease,
    /// The constructed requirement could not be reproduced by the original
    /// parser.
    NotRepresentable,
    /// Bytes remain after the final comparator record.
    TrailingBytes,
}

/// Encode a [`VersionReq`] into its binary wire representation.
///
/// # Errors
///
/// Returns [`EncodeError`] if the requirement exceeds a documented limit or
/// contains a comparator whose field combination is not representable.
pub fn encode(req: &VersionReq) -> Result<Vec<u8>, EncodeError> {
    if req.comparators.len() > MAX_COMPARATORS {
        return Err(EncodeError::TooManyComparators);
    }

    let mut out = Vec::new();
    out.push(VERSION);
    out.push(req.comparators.len() as u8);

    for comparator in &req.comparators {
        validate_for_encode(comparator)?;

        let mut flags = encode_op(comparator.op);
        if comparator.minor.is_some() {
            flags |= MINOR_PRESENT;
        }
        if comparator.patch.is_some() {
            flags |= PATCH_PRESENT;
        }
        out.push(flags);

        write_varint(&mut out, comparator.major);
        if let Some(minor) = comparator.minor {
            write_varint(&mut out, minor);
        }
        if let Some(patch) = comparator.patch {
            write_varint(&mut out, patch);
        }

        let pre_bytes = comparator.pre.as_str().as_bytes();
        if pre_bytes.len() > MAX_PRE_LEN {
            return Err(EncodeError::PreTooLong);
        }
        out.push(pre_bytes.len() as u8);
        out.extend_from_slice(pre_bytes);
    }

    Ok(out)
}

/// Decode a [`VersionReq`] from its binary wire representation.
///
/// Decoding is strict and all-or-nothing: on any failure an error is returned
/// and no partial [`VersionReq`] is produced.
///
/// # Errors
///
/// Returns [`DecodeError`] if the input is malformed, exceeds a documented
/// limit, contains an illegal field combination or unknown operator, fails
/// the original parser's syntax checks, cannot be reproduced by the original
/// parser, or has trailing bytes.
pub fn decode(input: &[u8]) -> Result<VersionReq, DecodeError> {
    let mut pos = 0;

    let version = read_u8(input, &mut pos)?;
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion);
    }

    let count = read_u8(input, &mut pos)? as usize;
    if count > MAX_COMPARATORS {
        return Err(DecodeError::TooManyComparators);
    }

    let mut comparators = Vec::with_capacity(count);
    for _ in 0..count {
        let flags = read_u8(input, &mut pos)?;
        let op_code = flags & OP_MASK;
        if op_code >= KNOWN_OPS {
            return Err(DecodeError::UnknownOp);
        }
        if flags & RESERVED_MASK != 0 {
            return Err(DecodeError::IllegalPresenceBits);
        }

        let minor_present = flags & MINOR_PRESENT != 0;
        let patch_present = flags & PATCH_PRESENT != 0;

        // Reject illegal presence combinations before reading any number.
        if patch_present && !minor_present {
            return Err(DecodeError::IllegalCombination);
        }
        if op_code == OP_WILDCARD && patch_present {
            return Err(DecodeError::IllegalCombination);
        }

        let major = read_varint(input, &mut pos)?;
        let minor = if minor_present {
            Some(read_varint(input, &mut pos)?)
        } else {
            None
        };
        let patch = if patch_present {
            Some(read_varint(input, &mut pos)?)
        } else {
            None
        };

        let pre_len = read_u8(input, &mut pos)? as usize;
        if pos.checked_add(pre_len).map_or(true, |end| end > input.len()) {
            return Err(DecodeError::Truncated);
        }
        let pre_bytes = &input[pos..pos + pre_len];
        pos += pre_len;

        let pre_str = core::str::from_utf8(pre_bytes)
            .map_err(|_| DecodeError::InvalidPrerelease)?;
        let pre = Prerelease::new(pre_str).map_err(|_| DecodeError::InvalidPrerelease)?;

        // A non-empty pre-release requires an explicitly present patch.
        if !pre.is_empty() && patch.is_none() {
            return Err(DecodeError::IllegalCombination);
        }
        if op_code == OP_WILDCARD && !pre.is_empty() {
            return Err(DecodeError::IllegalCombination);
        }

        comparators.push(Comparator {
            op: decode_op(op_code),
            major,
            minor,
            patch,
            pre,
        });
    }

    // Trailing bytes are never ignored.
    if pos != input.len() {
        return Err(DecodeError::TrailingBytes);
    }

    let req = VersionReq { comparators };

    // Verify representability with the original parser: format the
    // constructed requirement and parse it back. It must reproduce the exact
    // same structure, otherwise the message is rejected.
    let text = alloc::format!("{}", req);
    let reparsed = VersionReq::parse(&text).map_err(|_| DecodeError::NotRepresentable)?;
    if reparsed != req {
        return Err(DecodeError::NotRepresentable);
    }

    Ok(req)
}

fn validate_for_encode(comparator: &Comparator) -> Result<(), EncodeError> {
    if comparator.patch.is_some() && comparator.minor.is_none() {
        return Err(EncodeError::IllegalCombination);
    }
    if !comparator.pre.is_empty() && comparator.patch.is_none() {
        return Err(EncodeError::IllegalCombination);
    }
    if comparator.op == Op::Wildcard
        && (comparator.patch.is_some() || !comparator.pre.is_empty())
    {
        return Err(EncodeError::IllegalCombination);
    }
    Ok(())
}

fn encode_op(op: Op) -> u8 {
    match op {
        Op::Exact => OP_EXACT,
        Op::Greater => OP_GREATER,
        Op::GreaterEq => OP_GREATER_EQ,
        Op::Less => OP_LESS,
        Op::LessEq => OP_LESS_EQ,
        Op::Tilde => OP_TILDE,
        Op::Caret => OP_CARET,
        Op::Wildcard => OP_WILDCARD,
    }
}

fn decode_op(op: u8) -> Op {
    match op {
        OP_EXACT => Op::Exact,
        OP_GREATER => Op::Greater,
        OP_GREATER_EQ => Op::GreaterEq,
        OP_LESS => Op::Less,
        OP_LESS_EQ => Op::LessEq,
        OP_TILDE => Op::Tilde,
        OP_CARET => Op::Caret,
        OP_WILDCARD => Op::Wildcard,
        _ => unreachable!("op code was validated to be in 0..8"),
    }
}

fn read_u8(input: &[u8], pos: &mut usize) -> Result<u8, DecodeError> {
    if *pos >= input.len() {
        return Err(DecodeError::Truncated);
    }
    let byte = input[*pos];
    *pos += 1;
    Ok(byte)
}

fn read_varint(input: &[u8], pos: &mut usize) -> Result<u64, DecodeError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = read_u8(input, pos)?;
        if shift == 63 {
            // The tenth byte of a u64 varint carries at most one bit and must
            // terminate the sequence.
            if byte & 0x80 != 0 || byte > 1 {
                return Err(DecodeError::Overflow);
            }
            if byte == 0 {
                return Err(DecodeError::NonCanonical);
            }
            value |= (byte as u64) << 63;
            return Ok(value);
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            // Reject redundant leading zero groups (e.g. 0x80 0x00 for zero).
            if shift > 0 && byte == 0 {
                return Err(DecodeError::NonCanonical);
            }
            return Ok(value);
        }
        shift += 7;
    }
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            return;
        }
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            EncodeError::TooManyComparators => "too many comparators",
            EncodeError::PreTooLong => "pre-release is too long",
            EncodeError::IllegalCombination => "illegal comparator field combination",
        };
        f.write_str(msg)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            DecodeError::UnsupportedVersion => "unsupported protocol version",
            DecodeError::TooManyComparators => "too many comparators",
            DecodeError::Truncated => "truncated message",
            DecodeError::Overflow => "varint overflow",
            DecodeError::NonCanonical => "non-canonical varint",
            DecodeError::UnknownOp => "unknown operator",
            DecodeError::IllegalPresenceBits => "illegal presence bits",
            DecodeError::IllegalCombination => "illegal comparator field combination",
            DecodeError::InvalidPrerelease => "invalid pre-release",
            DecodeError::NotRepresentable => "requirement not representable by the original parser",
            DecodeError::TrailingBytes => "trailing bytes after final comparator",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}
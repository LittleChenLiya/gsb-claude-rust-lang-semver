#![allow(clippy::wildcard_imports)]

use semver::codec::{self, DecodeError, EncodeError};
use semver::{Comparator, Op, Prerelease, Version, VersionReq};

#[track_caller]
fn round_trip(text: &str) -> VersionReq {
    let req = VersionReq::parse(text).unwrap();
    let bytes = codec::encode(&req).unwrap();
    let decoded = codec::decode(&bytes).unwrap();
    assert_eq!(req, decoded, "round trip changed structure for {:?}", text);
    decoded
}

#[test]
fn test_round_trip_caret_structure() {
    // These three must remain distinct; omitted fields are not padded with 0.
    let req1 = round_trip("^1");
    let req12 = round_trip("^1.2");
    let req120 = round_trip("^1.2.0");

    assert_eq!(req1.comparators.len(), 1);
    assert_eq!(req1.comparators[0].op, Op::Caret);
    assert_eq!(req1.comparators[0].major, 1);
    assert_eq!(req1.comparators[0].minor, None);
    assert_eq!(req1.comparators[0].patch, None);

    assert_eq!(req12.comparators[0].minor, Some(2));
    assert_eq!(req12.comparators[0].patch, None);

    assert_eq!(req120.comparators[0].minor, Some(2));
    assert_eq!(req120.comparators[0].patch, Some(0));

    // They must not compare equal to one another.
    assert_ne!(req1, req12);
    assert_ne!(req12, req120);
    assert_ne!(req1, req120);
}

#[test]
fn test_round_trip_all_operators() {
    round_trip("=1.2.3");
    round_trip(">1.2.3");
    round_trip(">=1.2.3");
    round_trip("<1.2.3");
    round_trip("<=1.2.3");
    round_trip("~1.2.3");
    round_trip("^1.2.3");
    round_trip("1.*");
    round_trip("1.2.*");
}

#[test]
fn test_round_trip_omitted_fields_for_each_op() {
    round_trip("=1");
    round_trip("=1.2");
    round_trip(">1");
    round_trip(">1.2");
    round_trip(">=1");
    round_trip("<1");
    round_trip("<=1");
    round_trip("~1");
    round_trip("~1.2");
    round_trip("^1");
    round_trip("^1.2");
}

#[test]
fn test_round_trip_prerelease() {
    round_trip("^1.2.3-alpha.1");
    round_trip(">=1.0.0-rc.2, <2.0.0");
    round_trip("=1.2.3-beta");
}

#[test]
fn test_round_trip_multiple_comparators() {
    round_trip(">=1.2.3, <1.8.0");
    round_trip("^1.0.0, <2.0.0");
}

#[test]
fn test_round_trip_star() {
    let req = VersionReq::STAR;
    let bytes = codec::encode(&req).unwrap();
    assert_eq!(bytes, [codec::VERSION, 0]);
    let decoded = codec::decode(&bytes).unwrap();
    assert_eq!(decoded, VersionReq::STAR);
    assert!(decoded.comparators.is_empty());
}

#[test]
fn test_round_trip_large_numbers() {
    round_trip(">=18446744073709551615.0.0");
    round_trip("^0.18446744073709551615.18446744073709551615");
}

#[test]
fn test_matches_semantics_consistent() {
    let texts = [
        "^1",
        "^1.2",
        "^1.2.0",
        "=1.2.3",
        ">1.2.3",
        ">=1.2.3",
        "<1.2.3",
        "<=1.2.3",
        "~1.2.3",
        ">=1.2.3, <1.8.0",
        "^1.2.3-alpha.1",
        "1.*",
        "1.2.*",
    ];

    let versions = [
        "0.9.0",
        "1.0.0",
        "1.2.0",
        "1.2.3",
        "1.2.4",
        "1.3.0",
        "2.0.0",
        "1.2.3-alpha.1",
        "1.2.3-alpha.2",
        "1.2.4-alpha.1",
        "2.0.0-alpha.1",
    ];

    for text in texts {
        let original = VersionReq::parse(text).unwrap();
        let bytes = codec::encode(&original).unwrap();
        let decoded = codec::decode(&bytes).unwrap();
        for v in versions {
            let version = Version::parse(v).unwrap();
            assert_eq!(
                original.matches(&version),
                decoded.matches(&version),
                "matches mismatch for {:?} on {}",
                text,
                v
            );
        }
    }
}

#[test]
fn test_wildcard_structure_preserved() {
    let req = round_trip("1.*");
    assert_eq!(req.comparators[0].op, Op::Wildcard);
    assert_eq!(req.comparators[0].minor, None);
    assert_eq!(req.comparators[0].patch, None);

    let req = round_trip("1.2.*");
    assert_eq!(req.comparators[0].op, Op::Wildcard);
    assert_eq!(req.comparators[0].minor, Some(2));
    assert_eq!(req.comparators[0].patch, None);
}

// ---- rejection tests -----------------------------------------------------

#[test]
fn test_reject_unsupported_version() {
    let err = codec::decode(&[2, 0]).unwrap_err();
    assert_eq!(err, DecodeError::UnsupportedVersion);
}

#[test]
fn test_reject_too_many_comparators() {
    let err = codec::decode(&[codec::VERSION, 33]).unwrap_err();
    assert_eq!(err, DecodeError::TooManyComparators);
}

#[test]
fn test_reject_unknown_op() {
    // flags = 0x08 (op = 8, unknown), major = 0
    let err = codec::decode(&[codec::VERSION, 1, 0x08, 0x00, 0x00]).unwrap_err();
    assert_eq!(err, DecodeError::UnknownOp);
}

#[test]
fn test_reject_illegal_reserved_bits() {
    // flags = 0x40 (reserved bit 6 set), op = Caret
    let err = codec::decode(&[codec::VERSION, 1, 0x40 | 0x06, 0x00, 0x00]).unwrap_err();
    assert_eq!(err, DecodeError::IllegalPresenceBits);

    // flags = 0x80 (reserved bit 7 set)
    let err = codec::decode(&[codec::VERSION, 1, 0x80 | 0x06, 0x00, 0x00]).unwrap_err();
    assert_eq!(err, DecodeError::IllegalPresenceBits);
}

#[test]
fn test_reject_patch_without_minor() {
    // flags = Caret | PATCH_PRESENT (no minor), major = 0
    let err = codec::decode(&[codec::VERSION, 1, 0x06 | 0x20, 0x00, 0x00]).unwrap_err();
    assert_eq!(err, DecodeError::IllegalCombination);
}

#[test]
fn test_reject_wildcard_with_patch() {
    // flags = Wildcard | PATCH_PRESENT, major = 0
    let err = codec::decode(&[codec::VERSION, 1, 0x07 | 0x20, 0x00, 0x00]).unwrap_err();
    assert_eq!(err, DecodeError::IllegalCombination);
}

#[test]
fn test_reject_wildcard_with_prerelease() {
    // flags = Wildcard, major = 1, minor = 2, pre_len = 1, pre = "a"
    let err = codec::decode(&[codec::VERSION, 1, 0x07 | 0x10, 0x01, 0x02, 0x01, b'a']).unwrap_err();
    assert_eq!(err, DecodeError::IllegalCombination);
}

#[test]
fn test_reject_prerelease_without_patch() {
    // flags = Caret | MINOR_PRESENT, major = 1, minor = 2, pre_len = 1, pre = "a"
    let err = codec::decode(&[codec::VERSION, 1, 0x06 | 0x10, 0x01, 0x02, 0x01, b'a']).unwrap_err();
    assert_eq!(err, DecodeError::IllegalCombination);
}

#[test]
fn test_reject_invalid_prerelease_syntax() {
    // pre = "alpha_1" (underscore is illegal)
    let mut msg = vec![codec::VERSION, 1, 0x06 | 0x10 | 0x20, 0x01, 0x02, 0x03];
    msg.push(7);
    msg.extend_from_slice(b"alpha_1");
    let err = codec::decode(&msg).unwrap_err();
    assert_eq!(err, DecodeError::InvalidPrerelease);

    // pre = "01" (leading zero on a numeric identifier)
    let mut msg = vec![codec::VERSION, 1, 0x06 | 0x10 | 0x20, 0x01, 0x02, 0x03];
    msg.push(2);
    msg.extend_from_slice(b"01");
    let err = codec::decode(&msg).unwrap_err();
    assert_eq!(err, DecodeError::InvalidPrerelease);
}

#[test]
fn test_reject_non_utf8_prerelease() {
    let mut msg = vec![codec::VERSION, 1, 0x06 | 0x10 | 0x20, 0x01, 0x02, 0x03];
    msg.push(2);
    msg.extend_from_slice(&[0xff, 0xfe]);
    let err = codec::decode(&msg).unwrap_err();
    assert_eq!(err, DecodeError::InvalidPrerelease);
}

#[test]
fn test_reject_non_canonical_varint() {
    // major encoded as 0x80 0x00 (non-canonical zero)
    let err = codec::decode(&[codec::VERSION, 1, 0x06, 0x80, 0x00, 0x00]).unwrap_err();
    assert_eq!(err, DecodeError::NonCanonical);
}

#[test]
fn test_reject_varint_overflow() {
    // 10th byte > 1
    let mut msg = vec![codec::VERSION, 1, 0x06];
    msg.extend(std::iter::repeat(0x80).take(9));
    msg.push(0x02); // 10th byte = 2, overflow
    msg.push(0x00); // pre_len
    let err = codec::decode(&msg).unwrap_err();
    assert_eq!(err, DecodeError::Overflow);
}

#[test]
fn test_reject_truncated() {
    // Valid message: version=1, count=1, flags=Caret, major=0, pre_len=0
    let full = [codec::VERSION, 1, 0x06, 0x00, 0x00];
    for len in 0..full.len() {
        let err = codec::decode(&full[..len]).unwrap_err();
        assert_eq!(err, DecodeError::Truncated, "len {}", len);
    }
}

#[test]
fn test_reject_trailing_bytes() {
    let full = [codec::VERSION, 0];
    let mut with_trailing = full.to_vec();
    with_trailing.push(0x00);
    let err = codec::decode(&with_trailing).unwrap_err();
    assert_eq!(err, DecodeError::TrailingBytes);
}

#[test]
fn test_reject_trailing_bytes_after_comparator() {
    // ^1 with an extra trailing byte
    let mut msg = vec![codec::VERSION, 1, 0x06, 0x01, 0x00];
    msg.push(0x00);
    let err = codec::decode(&msg).unwrap_err();
    assert_eq!(err, DecodeError::TrailingBytes);
}

// ---- encode-side rejection ------------------------------------------------

#[test]
fn test_encode_reject_too_many_comparators() {
    let comparators = (0..=codec::MAX_COMPARATORS)
        .map(|_| Comparator {
            op: Op::Caret,
            major: 1,
            minor: None,
            patch: None,
            pre: Prerelease::EMPTY,
        })
        .collect();
    let req = VersionReq { comparators };
    let err = codec::encode(&req).unwrap_err();
    assert_eq!(err, EncodeError::TooManyComparators);
}

#[test]
fn test_encode_reject_illegal_combination() {
    // patch present but minor absent
    let req = VersionReq {
        comparators: vec![Comparator {
            op: Op::Caret,
            major: 1,
            minor: None,
            patch: Some(0),
            pre: Prerelease::EMPTY,
        }],
    };
    let err = codec::encode(&req).unwrap_err();
    assert_eq!(err, EncodeError::IllegalCombination);

    // non-empty pre-release but no patch
    let req = VersionReq {
        comparators: vec![Comparator {
            op: Op::Caret,
            major: 1,
            minor: Some(2),
            patch: None,
            pre: Prerelease::new("alpha").unwrap(),
        }],
    };
    let err = codec::encode(&req).unwrap_err();
    assert_eq!(err, EncodeError::IllegalCombination);

    // wildcard with patch
    let req = VersionReq {
        comparators: vec![Comparator {
            op: Op::Wildcard,
            major: 1,
            minor: None,
            patch: Some(3),
            pre: Prerelease::EMPTY,
        }],
    };
    let err = codec::encode(&req).unwrap_err();
    assert_eq!(err, EncodeError::IllegalCombination);
}

#[test]
fn test_encode_reject_pre_too_long() {
    let long = "a".repeat(codec::MAX_PRE_LEN + 1);
    let req = VersionReq {
        comparators: vec![Comparator {
            op: Op::Caret,
            major: 1,
            minor: Some(2),
            patch: Some(3),
            pre: Prerelease::new(&long).unwrap(),
        }],
    };
    let err = codec::encode(&req).unwrap_err();
    assert_eq!(err, EncodeError::PreTooLong);
}

#[test]
fn test_no_partial_result_on_failure() {
    // A malformed message must not produce a VersionReq; decode returns Err.
    let malformed = [codec::VERSION, 1, 0x08, 0x00, 0x00];
    assert!(codec::decode(&malformed).is_err());

    // And a valid message still decodes fine after a failed attempt.
    let valid = [codec::VERSION, 0];
    assert!(codec::decode(&valid).is_ok());
}

#[test]
fn test_constants() {
    assert_eq!(codec::VERSION, 1);
    assert_eq!(codec::MAX_COMPARATORS, 32);
    assert_eq!(codec::MAX_PRE_LEN, 255);
}

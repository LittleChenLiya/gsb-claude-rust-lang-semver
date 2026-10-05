//! Acceptance tests for the binary VersionReq codec. These exercise only the
//! public surface: `VersionReq::to_binary` / `VersionReq::from_binary` and the
//! `semver::codec` module.

use semver::codec::{decode, encode, CodecError, MAX_COMPARATORS};
use semver::{Version, VersionReq};

fn round_trip_structural(text: &str) -> VersionReq {
    let req = VersionReq::parse(text).unwrap();
    let bytes = req.to_binary().unwrap();
    let back = VersionReq::from_binary(&bytes).unwrap();
    assert_eq!(back, req, "structure must be preserved for {:?}", text);
    assert_eq!(back.to_string(), req.to_string());
    assert_eq!(encode(&back).unwrap(), bytes);
    back
}

#[test]
fn caret_one_one_two_one_two_zero_preserve_structure() {
    // ^1: minor and patch stay absent, never padded to 0.
    let req = round_trip_structural("^1");
    assert_eq!(req.comparators[0].minor, None);
    assert_eq!(req.comparators[0].patch, None);

    // ^1.2: minor present, patch still absent.
    let req = round_trip_structural("^1.2");
    assert_eq!(req.comparators[0].minor, Some(2));
    assert_eq!(req.comparators[0].patch, None);

    // ^1.2.0: explicit patch zero is retained.
    let req = round_trip_structural("^1.2.0");
    assert_eq!(req.comparators[0].minor, Some(2));
    assert_eq!(req.comparators[0].patch, Some(0));
}

#[test]
fn matches_semantics_agree_after_round_trip() {
    let requirement_texts = ["^1", "^1.2", "^1.2.0", "^0.0", ">=1.2.3-rc, <2"];
    let version_texts = [
        "1.0.0", "1.2.0", "1.2.3", "1.2.3-rc", "1.9.9", "2.0.0", "0.9.0",
    ];

    for req_text in requirement_texts {
        let original = VersionReq::parse(req_text).unwrap();
        let decoded = round_trip_structural(req_text);
        for v_text in version_texts {
            let v = Version::parse(v_text).unwrap();
            assert_eq!(
                original.matches(&v),
                decoded.matches(&v),
                "matches mismatch: {} vs {}",
                req_text,
                v_text,
            );
        }
    }
}

#[test]
fn unknown_op_is_rejected() {
    let req = VersionReq::parse("^1").unwrap();
    let mut bytes = encode(&req).unwrap();
    bytes[4] = 9;
    assert_eq!(decode(&bytes).unwrap_err(), CodecError::UnknownOp(9));
}

#[test]
fn illegal_presence_bits_are_rejected() {
    let req = VersionReq::parse("^1.2.0").unwrap();
    let bytes = encode(&req).unwrap();

    // Reserved bit.
    let mut reserved = bytes.clone();
    reserved[5] |= 0b1000;
    assert!(matches!(
        decode(&reserved).unwrap_err(),
        CodecError::IllegalFlags(_)
    ));

    // Patch present without minor.
    let mut patch_no_minor = bytes.clone();
    patch_no_minor[5] = 0b0010;
    assert!(matches!(
        decode(&patch_no_minor).unwrap_err(),
        CodecError::IllegalCombination(_)
    ));

    // Pre present without patch.
    let mut pre_no_patch = bytes.clone();
    pre_no_patch[5] = 0b0101;
    assert!(matches!(
        decode(&pre_no_patch).unwrap_err(),
        CodecError::IllegalCombination(_)
    ));
}

#[test]
fn prerelease_must_follow_original_grammar() {
    let req = VersionReq::parse("=1.2.3-alpha.1").unwrap();
    let bytes = encode(&req).unwrap();

    // Locate the one-byte length prefix preceding "alpha.1".
    let payload = b"alpha.1";
    let pre_len_at = bytes.len() - payload.len() - 1;
    assert_eq!(bytes[pre_len_at], payload.len() as u8);

    for bad in ["01", "alpha..1", ".alpha", "alpha.", "al pha", "alpha.01"] {
        let mut tampered = bytes.clone();
        tampered[pre_len_at] = bad.len() as u8;
        tampered.truncate(pre_len_at + 1);
        tampered.extend_from_slice(bad.as_bytes());
        assert!(matches!(
            decode(&tampered).unwrap_err(),
            CodecError::InvalidPrerelease
        ));
    }
}

#[test]
fn trailing_bytes_are_not_ignored() {
    let req = VersionReq::parse("^1").unwrap();
    let mut bytes = req.to_binary().unwrap();
    bytes.extend_from_slice(b"\x00\xff");
    assert_eq!(
        decode(&bytes).unwrap_err(),
        CodecError::TrailingBytes { remaining: 2 }
    );
}

#[test]
fn failures_do_not_return_partial_requirement() {
    // A frame claiming 2 comparators but containing 1 must fail outright.
    let mut one = encode(&VersionReq::parse(">=1.0.0").unwrap()).unwrap();
    one[3] = 2;
    assert_eq!(decode(&one).unwrap_err(), CodecError::UnexpectedEnd);

    // Smoke check the 32-comparator ceiling is honored both ways.
    let text = (0..MAX_COMPARATORS)
        .map(|_| ">=1.0.0")
        .collect::<Vec<_>>()
        .join(", ");
    round_trip_structural(&text);

    let mut over = one.clone();
    over[3] = (MAX_COMPARATORS + 1) as u8;
    assert!(matches!(
        decode(&over).unwrap_err(),
        CodecError::TooManyComparators { .. }
    ));
}

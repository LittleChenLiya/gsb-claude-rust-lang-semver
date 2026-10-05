//! Targeted acceptance tests for the certified `VersionReq` simplifier.
//!
//! Run only these tests with:
//!
//! ```text
//! cargo test --test test_simplify
//! ```

#![allow(clippy::missing_panics_doc)]

use semver::{RemovalJustification, SimplificationStep, SimplifyCertificate, Version, VersionReq};

#[track_caller]
fn req(text: &str) -> VersionReq {
    VersionReq::parse(text).unwrap()
}

#[track_caller]
fn version(text: &str) -> Version {
    Version::parse(text).unwrap()
}

/// Sanity check (not the proof): original and simplified agree on the given
/// versions. The certificate itself is proven and verified structurally,
/// without enumerating versions.
#[track_caller]
fn assert_same_matches(cert: &SimplifyCertificate, versions: &[&str]) {
    for string in versions {
        let v = version(string);
        assert_eq!(
            cert.original.matches(&v),
            cert.simplified.matches(&v),
            "mismatch on {}",
            string,
        );
    }
}

#[test]
fn test_redundant_lower_bound() {
    // Acceptance: `>=1.0, >=1.2, <2` drops the redundant lower bound.
    let original = req(">=1.0, >=1.2, <2");
    let cert = original.simplify();

    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), ">=1.2, <2");
    assert_eq!(cert.retained, [1, 2]);
    assert_eq!(cert.steps.len(), 1);
    let step = &cert.steps[0];
    assert_eq!(step.removed, 0);
    assert_eq!(step.justified_by, 1);
    assert_eq!(step.justification, RemovalJustification::LowerBoundSubsumed);

    assert_same_matches(
        &cert,
        &["0.9.9", "1.0.0", "1.1.5", "1.2.0", "1.2.3", "1.99.0", "2.0.0", "2.0.0-alpha"],
    );
    assert!(!cert.simplified.matches(&version("1.0.0")));
    assert!(cert.simplified.matches(&version("1.2.0")));
}

#[test]
fn test_three_range_examples() {
    // Three-range example 1: two lower bounds + one upper bound.
    let cert = req(">=1.0, >=1.2, <2").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), ">=1.2, <2");

    // Three-range example 2: exclusive lower bound is strictly stronger.
    let cert = req(">1.2.3, >=1.2.3, <2.0.0").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), ">1.2.3, <2.0.0");
    assert_eq!(cert.steps.len(), 1);
    assert_eq!(
        cert.steps[0].justification,
        RemovalJustification::LowerBoundSubsumed
    );

    // Three-range example 3: exclusive upper bound is strictly stronger.
    let cert = req(">=1.0, <2.0.0, <=2.0.0").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), ">=1.0, <2.0.0");
    assert_eq!(cert.steps.len(), 1);
    assert_eq!(
        cert.steps[0].justification,
        RemovalJustification::UpperBoundSubsumed
    );
}

#[test]
fn test_prerelease_unknown_is_retained() {
    // Numerically `>=1.2.4` implies `>=1.2.3-alpha`, but removing the alpha
    // comparator would change prerelease admission for the 1.2.3 triple.
    // Unknown => retained, not guessed.
    let cert = req(">=1.2.3-alpha, >=1.2.4").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), ">=1.2.3-alpha, >=1.2.4");
    assert!(cert.steps.is_empty());

    // Tilde and caret comparators are not normalized; combinations with
    // them are unknown and retained.
    let cert = req("~1.2.3, >=1.0.0").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), "~1.2.3, >=1.0.0");

    let cert = req("^1.2.3-alpha, >=1.0").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), "^1.2.3-alpha, >=1.0");

    // `<=1.2` is not a single half-open boundary under Cargo prerelease
    // semantics (it differs from `<1.3.0`); retained as unknown.
    let cert = req("<=1.2, >=1.0").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), "<=1.2, >=1.0");

    // A weaker prerelease upper bound is provably redundant against a
    // stronger one on the same triple.
    let cert = req("<1.2.3, <1.2.3-alpha").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), "<1.2.3-alpha");
}

#[test]
fn test_prerelease_provable_cases() {
    // Exact duplicate carrying a prerelease: admission is covered by the
    // retained twin, so the duplicate is removable.
    let cert = req(">=1.2.3-alpha, >=1.2.3-alpha").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), ">=1.2.3-alpha");
    assert_eq!(cert.steps.len(), 1);
    assert_eq!(cert.steps[0].justification, RemovalJustification::Duplicate);

    // `>=1.2.3-beta` implies `>=1.2.3-alpha` numerically, and the beta
    // comparator covers prerelease admission for the same 1.2.3 triple.
    let cert = req(">=1.2.3-alpha, >=1.2.3-beta").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), ">=1.2.3-beta");
    assert_same_matches(
        &cert,
        &[
            "1.2.3-alpha",
            "1.2.3-alpha.1",
            "1.2.3-beta",
            "1.2.3",
            "1.2.4-alpha",
            "1.2.4",
            "2.0.0",
        ],
    );
}

#[test]
fn test_empty_set_is_not_faked_as_universal() {
    // Unsatisfiable requirement: matches nothing, but must never be
    // "simplified" into the universal range `*`.
    let original = req(">=2.0.0, <1.0.0");
    let cert = original.simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified, original);
    assert!(!cert.simplified.comparators.is_empty());

    // A forged certificate that erases every comparator of a nonempty
    // requirement (claiming it became `*`) must fail verification.
    let forged = SimplifyCertificate {
        original: original.clone(),
        simplified: VersionReq::STAR,
        retained: Vec::new(),
        steps: vec![
            SimplificationStep {
                removed: 0,
                justified_by: 1,
                justification: RemovalJustification::LowerBoundSubsumed,
            },
            SimplificationStep {
                removed: 1,
                justified_by: 0,
                justification: RemovalJustification::UpperBoundSubsumed,
            },
        ],
    };
    assert!(!forged.verify());

    // Even a step-free forgery is rejected: the partition is incomplete and
    // a nonempty requirement may not collapse to zero retained comparators.
    let forged = SimplifyCertificate {
        original,
        simplified: VersionReq::STAR,
        retained: Vec::new(),
        steps: Vec::new(),
    };
    assert!(!forged.verify());
}

#[test]
fn test_certificate_verifies_from_original_comparators() {
    let original = req(">=1.0, >=1.2, <2");
    let cert = original.simplify();
    assert!(cert.verify());

    // Tampered: claim the upper bound was removed instead.
    let mut tampered = cert.clone();
    tampered.steps = vec![SimplificationStep {
        removed: 2,
        justified_by: 1,
        justification: RemovalJustification::LowerBoundSubsumed,
    }];
    tampered.retained = vec![0, 1];
    tampered.simplified = req(">=1.0, >=1.2");
    assert!(!tampered.verify());

    // Tampered: wrong justification kind.
    let mut tampered = cert.clone();
    tampered.steps[0].justification = RemovalJustification::UpperBoundSubsumed;
    assert!(!tampered.verify());

    // Tampered: justifier is not a retained comparator.
    let mut tampered = cert.clone();
    tampered.steps[0].justified_by = 0;
    assert!(!tampered.verify());

    // Tampered: simplified order does not follow the original order.
    let original = req("<2, >=1.0, >=1.2");
    let cert = original.simplify();
    assert!(cert.verify());
    assert_eq!(cert.retained, [0, 2]);
    let mut tampered = cert.clone();
    tampered.simplified = req(">=1.2, <2");
    assert!(!tampered.verify());
}

#[test]
fn test_order_and_original_indices_traceable() {
    // Comparators keep their original relative order; every kept comparator
    // is traceable to its original index.
    let original = req("<2, >=1.0, >=1.2");
    let cert = original.simplify();
    assert!(cert.verify());
    assert_eq!(cert.retained, [0, 2]);
    assert_eq!(cert.simplified.comparators[0], original.comparators[0]);
    assert_eq!(cert.simplified.comparators[1], original.comparators[2]);
    assert_eq!(cert.steps.len(), 1);
    assert_eq!(cert.steps[0].removed, 1);
    assert_eq!(cert.steps[0].justified_by, 2);
    assert_eq!(cert.simplified.to_string(), "<2, >=1.2");
}

#[test]
fn test_partial_and_duplicate_bounds() {
    // `>=1.0` and `>=1.0.0` normalize to the same boundary; one is dropped.
    let cert = req(">=1.0, >=1.0.0, <2").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.comparators.len(), 2);
    assert_same_matches(&cert, &["0.9.9", "1.0.0", "1.0.0-alpha", "1.5.0", "2.0.0"]);

    // Exact duplicates of any operator are deduplicated.
    let cert = req("~1.2.3, ~1.2.3, <2").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), "~1.2.3, <2");

    // `>1.2` is exactly `>=1.3.0` as a boundary; the weaker form is dropped.
    let cert = req(">1.2, >=1.3.0, <2").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.comparators.len(), 2);
    assert_same_matches(&cert, &["1.2.9", "1.3.0", "1.3.0-alpha", "2.0.0"]);
}

#[test]
fn test_numeric_edge_cases() {
    // Overflowing boundary: `>u64::MAX` cannot be normalized, so nothing
    // about it is proven and everything is retained.
    let original = req(">18446744073709551615, >=1.0");
    let cert = original.simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified, original);

    // Boundary just below overflow still normalizes fine.
    let cert = req(">18446744073709551614, >=1.0").simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified.to_string(), ">18446744073709551614");

    // The universal range stays the universal range.
    let cert = VersionReq::STAR.simplify();
    assert!(cert.verify());
    assert_eq!(cert.simplified, VersionReq::STAR);
    assert!(cert.retained.is_empty());
    assert!(cert.steps.is_empty());
}

#[test]
fn test_parse_is_unchanged() {
    // Simplification is an explicit, separate entry point: parsing does not
    // simplify behind the user's back.
    let parsed = req(">=1.0, >=1.2, <2");
    assert_eq!(parsed.comparators.len(), 3);
    assert_eq!(parsed.to_string(), ">=1.0, >=1.2, <2");
}

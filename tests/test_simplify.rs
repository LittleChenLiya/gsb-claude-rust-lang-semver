use semver::{Basis, CertError, Version, VersionReq};

fn req(s: &str) -> VersionReq {
    VersionReq::parse(s).unwrap()
}

#[test]
fn redundant_lower_bound_three_ranges() {
    // >=1.0 is implied by >=1.2, so it is removed. The upper bound <2 and the
    // stronger lower bound >=1.2 remain.
    let original = req(">=1.0,>=1.2,<2");
    let simplified = original.simplify();

    assert_eq!(simplified.req, req(">=1.2,<2"));
    assert_eq!(simplified.cert.removed_indices(), vec![0]);
    assert_eq!(simplified.cert.steps.len(), 1);
    assert_eq!(simplified.cert.steps[0].basis, Basis::ImpliedByBounds);

    // The certificate is independently verifiable against the original.
    simplified.cert.verify(&original).unwrap();

    // The simplified requirement matches exactly the same versions as the
    // original, including prerelease behavior.
    for v in [
        "0.9.0",
        "1.0.0",
        "1.1.0",
        "1.2.0",
        "1.9.9",
        "2.0.0",
        "2.0.1",
        "1.2.0-alpha",
        "1.5.0-alpha",
        "2.0.0-alpha",
    ] {
        let version = Version::parse(v).unwrap();
        assert_eq!(
            original.matches(&version),
            simplified.req.matches(&version),
            "mismatch on {v}",
        );
    }
}

#[test]
fn redundant_upper_bound() {
    // <=1.5 is implied by <1.2, so it is removed. Original comparator order
    // is preserved among the retained comparators.
    let original = req("<1.2,<=1.5,>=1.0");
    let simplified = original.simplify();

    assert_eq!(simplified.req, req("<1.2,>=1.0"));
    assert_eq!(simplified.cert.removed_indices(), vec![1]);
    simplified.cert.verify(&original).unwrap();

    for v in ["0.9.0", "1.0.0", "1.1.9", "1.2.0", "1.5.0", "2.0.0"] {
        let version = Version::parse(v).unwrap();
        assert_eq!(original.matches(&version), simplified.req.matches(&version));
    }
}

#[test]
fn prerelease_comparator_retained() {
    // >=1.2.0-alpha's release bound is implied by >=1.2.0, but no other
    // comparator carries a prerelease tag at the (1,2,0) tuple. Removing it
    // would drop prerelease admission, so it is retained.
    let original = req(">=1.2.0-alpha,>=1.2.0,<2");
    let simplified = original.simplify();

    assert_eq!(simplified.req, original);
    assert!(simplified.cert.steps.is_empty());
    simplified.cert.verify(&original).unwrap();

    // >=1.2.0 excludes prereleases at (1,2,0) (the empty prerelease is the
    // greatest slot), so this particular requirement matches no prerelease;
    // the retained comparator is conservative rather than impactful here.
    assert!(!original.matches(&Version::parse("1.2.0-alpha").unwrap()));
    assert!(original.matches(&Version::parse("1.2.0").unwrap()));
    assert!(original.matches(&Version::parse("1.9.0").unwrap()));
    assert!(!original.matches(&Version::parse("2.0.0").unwrap()));
}

#[test]
fn prerelease_admission_actually_admitted() {
    // >=1.2.0-alpha admits prereleases at (1,2,0). It is retained because no
    // other comparator admits them, and the requirement does match them.
    let original = req(">=1.2.0-alpha,<2");
    let simplified = original.simplify();

    assert_eq!(simplified.req, original);
    assert!(simplified.cert.steps.is_empty());
    simplified.cert.verify(&original).unwrap();

    assert!(original.matches(&Version::parse("1.2.0-alpha").unwrap()));
    assert!(original.matches(&Version::parse("1.2.0-beta.1").unwrap()));
    assert!(!original.matches(&Version::parse("1.3.0-alpha").unwrap()));
    assert!(!original.matches(&Version::parse("2.0.0-alpha").unwrap()));
}

#[test]
fn prerelease_admission_redundant_when_covered() {
    // >=1.2.0-alpha is implied by >=1.2.0-beta, which also admits
    // prereleases at the same tuple. Removal is safe.
    let original = req(">=1.2.0-alpha,>=1.2.0-beta,<2");
    let simplified = original.simplify();

    assert_eq!(simplified.req, req(">=1.2.0-beta,<2"));
    assert_eq!(simplified.cert.removed_indices(), vec![0]);
    simplified.cert.verify(&original).unwrap();

    for v in [
        "1.2.0-alpha",
        "1.2.0-alpha.1",
        "1.2.0-beta",
        "1.2.0-beta.1",
        "1.2.0",
        "1.9.0",
        "2.0.0",
    ] {
        let version = Version::parse(v).unwrap();
        assert_eq!(original.matches(&version), simplified.req.matches(&version));
    }
}

#[test]
fn empty_set_not_faked_as_universal() {
    // >2.0.0, <1.0.0 is unsatisfiable. Neither comparator is redundant, so
    // the requirement is left unchanged rather than being simplified to `*`.
    let original = req(">2.0.0,<1.0.0");
    let simplified = original.simplify();

    assert_eq!(simplified.req, original);
    assert!(simplified.cert.steps.is_empty());
    simplified.cert.verify(&original).unwrap();

    // It matches nothing, and must not be reported as matching everything.
    for v in ["0.5.0", "1.0.0", "1.5.0", "2.0.0", "2.5.0"] {
        assert!(!original.matches(&Version::parse(v).unwrap()));
    }
}

#[test]
fn star_stays_star() {
    let original = VersionReq::STAR;
    let simplified = original.simplify();
    assert_eq!(simplified.req, VersionReq::STAR);
    assert!(simplified.cert.steps.is_empty());
    simplified.cert.verify(&original).unwrap();
}

#[test]
fn certificate_detects_tampering() {
    let original = req(">=1.0,>=1.2,<2");
    let simplified = original.simplify();
    let mut tampered = simplified.clone();
    tampered.cert.steps[0].comparator = semver::Comparator::parse(">=9.0").unwrap();
    assert_eq!(
        tampered.cert.verify(&original).unwrap_err(),
        CertError::ComparatorMismatch { removed_index: 0 },
    );
}

#[test]
fn certificate_detects_out_of_range_index() {
    let original = req(">=1.0,>=1.2,<2");
    let simplified = original.simplify();
    let mut tampered = simplified.clone();
    tampered.cert.steps[0].removed_index = 99;
    assert_eq!(
        tampered.cert.verify(&original).unwrap_err(),
        CertError::IndexOutOfRange {
            removed_index: 99,
            len: 3,
        },
    );
}

#[test]
fn certificate_detects_unjustified_removal() {
    // Forge a certificate that claims to remove >=1.2 (index 1), which is
    // not implied by the remaining comparators.
    let original = req(">=1.0,>=1.2,<2");
    let mut forged = original.simplify();
    forged.cert.steps[0].removed_index = 1;
    forged.cert.steps[0].comparator = semver::Comparator::parse(">=1.2").unwrap();
    assert_eq!(
        forged.cert.verify(&original).unwrap_err(),
        CertError::NotRedundant { removed_index: 1 },
    );
}

#[test]
fn comparator_order_and_indices_tracked() {
    // The simplified requirement keeps the original order of retained
    // comparators, and the certificate tracks original indices.
    let original = req("<2,>=1.2,>=1.0");
    let simplified = original.simplify();

    assert_eq!(simplified.req, req("<2,>=1.2"));
    assert_eq!(simplified.cert.removed_indices(), vec![2]);
    simplified.cert.verify(&original).unwrap();
}

#[test]
fn no_redundant_comparators() {
    let original = req(">=1.2,<1.9");
    let simplified = original.simplify();
    assert_eq!(simplified.req, original);
    assert!(simplified.cert.steps.is_empty());
    simplified.cert.verify(&original).unwrap();
}

#[test]
fn wildcard_and_caret_simplification() {
    // ^1.2 is implied by ^1.5 (both allow the same major-1 range, and ^1.5
    // is the stronger lower bound).
    let original = req("^1.2,^1.5");
    let simplified = original.simplify();
    assert_eq!(simplified.req, req("^1.5"));
    simplified.cert.verify(&original).unwrap();

    for v in ["1.2.0", "1.5.0", "1.9.9", "2.0.0", "1.2.0-alpha"] {
        let version = Version::parse(v).unwrap();
        assert_eq!(original.matches(&version), simplified.req.matches(&version));
    }
}

#[test]
fn tilde_redundancy() {
    // ~1.2.3 is implied by ~1.2.5 (same minor, stronger lower bound).
    let original = req("~1.2.3,~1.2.5");
    let simplified = original.simplify();
    assert_eq!(simplified.req, req("~1.2.5"));
    simplified.cert.verify(&original).unwrap();

    for v in ["1.2.3", "1.2.4", "1.2.5", "1.2.9", "1.3.0", "1.2.5-alpha"] {
        let version = Version::parse(v).unwrap();
        assert_eq!(original.matches(&version), simplified.req.matches(&version));
    }
}

#[test]
fn prerelease_coverage_not_implied() {
    // >=1.2.0-beta is NOT implied by >=1.2.0-alpha: the latter admits
    // prereleases in [alpha, beta) that the former excludes. Removing
    // >=1.2.0-beta would change the set, so it is retained. (The weaker
    // >=1.2.0-alpha is itself implied by >=1.2.0-beta and removed.)
    let original = req(">=1.2.0-beta,>=1.2.0-alpha,<2");
    let simplified = original.simplify();

    assert_eq!(simplified.req, req(">=1.2.0-beta,<2"));
    assert_eq!(simplified.cert.removed_indices(), vec![1]);
    simplified.cert.verify(&original).unwrap();

    // The retained >=1.2.0-beta excludes 1.2.0-alpha.
    assert!(!simplified.req.matches(&Version::parse("1.2.0-alpha").unwrap()));
    assert!(simplified.req.matches(&Version::parse("1.2.0-beta").unwrap()));
}

#[test]
fn duplicate_comparators_deduped() {
    let original = req(">=1.0,>=1.0");
    let simplified = original.simplify();
    assert_eq!(simplified.req, req(">=1.0"));
    assert_eq!(simplified.cert.removed_indices(), vec![0]);
    simplified.cert.verify(&original).unwrap();

    for v in ["0.9.0", "1.0.0", "1.5.0", "2.0.0"] {
        let version = Version::parse(v).unwrap();
        assert_eq!(original.matches(&version), simplified.req.matches(&version));
    }
}

#[test]
fn exact_version_implies_broad_bound() {
    // =1.2.3 pins release 1.2.3, which implies >=1.2.0, so the broad bound is
    // removed and the exact pin is retained.
    let original = req("=1.2.3,>=1.2.0");
    let simplified = original.simplify();
    assert_eq!(simplified.req, req("=1.2.3"));
    assert_eq!(simplified.cert.removed_indices(), vec![1]);
    simplified.cert.verify(&original).unwrap();

    for v in ["1.2.0", "1.2.3", "1.2.4", "1.3.0"] {
        let version = Version::parse(v).unwrap();
        assert_eq!(original.matches(&version), simplified.req.matches(&version));
    }
}

#[test]
fn caret_zero_zero_patch_implies_broad_bound() {
    // ^0.0.3 pins the (0,0,3) tuple, which implies >=0.0.0, so the broad
    // bound is removed.
    let original = req("^0.0.3,>=0.0.0");
    let simplified = original.simplify();
    assert_eq!(simplified.req, req("^0.0.3"));
    assert_eq!(simplified.cert.removed_indices(), vec![1]);
    simplified.cert.verify(&original).unwrap();

    for v in ["0.0.3", "0.0.4", "0.1.0", "1.0.0", "0.0.3-alpha"] {
        let version = Version::parse(v).unwrap();
        assert_eq!(original.matches(&version), simplified.req.matches(&version));
    }
}

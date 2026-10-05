//! Demonstrates the explicit, conservative [`VersionReq`] simplifier.
//!
//! Run with:
//!
//! ```text
//! cargo run --example simplify
//! ```
//!
//! The simplifier removes a comparator only when the remaining comparators
//! can be proved to imply it, both at the level of numeric version bounds and
//! at the level of prerelease admission. Every removal is recorded in a
//! certificate that can be independently verified against the original
//! requirement without enumerating versions.

use semver::{Version, VersionReq};

fn main() {
    // The three-range example from the acceptance criteria: the redundant
    // lower bound `>=1.0` is implied by `>=1.2`.
    let original = VersionReq::parse(">=1.0,>=1.2,<2").unwrap();
    let simplified = original.simplify();

    println!("original:   {original}");
    println!("simplified: {}", simplified.req);
    println!(
        "removed original indices: {:?}",
        simplified.cert.removed_indices(),
    );
    for step in &simplified.cert.steps {
        println!(
            "  step: remove comparator #{} `{}` ({:?})",
            step.removed_index, step.comparator, step.basis,
        );
    }

    // The certificate is independently verifiable against the original.
    simplified.cert.verify(&original).unwrap();
    println!("certificate verified against original: OK");

    // The simplified requirement matches exactly the same versions.
    for v in ["0.9.0", "1.0.0", "1.2.0", "1.9.9", "2.0.0", "1.5.0-alpha"] {
        let version = Version::parse(v).unwrap();
        assert_eq!(original.matches(&version), simplified.req.matches(&version));
    }
    println!("matches set preserved across sampled versions: OK");

    // A prerelease tag that would be dropped is retained, because removing it
    // would lose prerelease admission.
    let pre = VersionReq::parse(">=1.2.0-alpha,>=1.2.0,<2").unwrap();
    let pre_simplified = pre.simplify();
    println!("\nprerelease case: {pre}");
    println!("simplified:      {}", pre_simplified.req);
    assert_eq!(pre_simplified.req, pre);
    pre_simplified.cert.verify(&pre).unwrap();
    println!("prerelease comparator retained and certificate verified: OK");

    // An unsatisfiable requirement is not faked as the universal `*` range.
    let empty = VersionReq::parse(">2.0.0,<1.0.0").unwrap();
    let empty_simplified = empty.simplify();
    println!("\nempty case: {empty}");
    println!("simplified: {}", empty_simplified.req);
    assert_eq!(empty_simplified.req, empty);
    empty_simplified.cert.verify(&empty).unwrap();
    println!("empty set left unchanged and certificate verified: OK");
}

//! Targeted, deterministic fixtures for `semver::release` release planning.

use semver::release::{plan_releases, Bump, Dependency, Package, PlanError};
use semver::{Version, VersionReq};

fn package(
    name: &str,
    version: &str,
    bump: Option<Bump>,
    dependencies: Vec<(&str, &str)>,
) -> Package {
    Package {
        name: name.to_owned(),
        version: Version::parse(version).unwrap(),
        bump,
        dependencies: dependencies
            .into_iter()
            .map(|(dependency, req)| Dependency {
                name: dependency.to_owned(),
                req: VersionReq::parse(req).unwrap(),
            })
            .collect(),
    }
}

fn updated(plan: &semver::release::ReleasePlan, name: &str, dependency: &str) -> VersionReq {
    let release = plan
        .get(name)
        .unwrap_or_else(|| panic!("{name} must release"));
    release
        .updated_dependencies
        .iter()
        .find(|updated| updated.name == dependency)
        .unwrap_or_else(|| panic!("{name} must rewrite its range on {dependency}"))
        .req
        .clone()
}

// Acceptance fixture: A 1.0.0 -> 2.0.0, B declares ^1.0 on A, C pins B to
// =1.0.0. Both dependents release at least at a patch with a caret range.
#[test]
fn test_acceptance_major_break_propagates_through_chain() {
    let packages = [
        package("A", "1.0.0", Some(Bump::Major), vec![]),
        package("B", "1.0.0", None, vec![("A", "^1.0")]),
        package("C", "1.0.0", None, vec![("B", "=1.0.0")]),
    ];

    let plan = plan_releases(&packages).unwrap();

    assert_eq!(plan.len(), 3);
    assert_eq!(plan.get("A").unwrap().version, Version::new(2, 0, 0));
    assert!(plan.get("A").unwrap().updated_dependencies.is_empty());

    assert_eq!(plan.get("B").unwrap().version, Version::new(1, 0, 1));
    assert_eq!(
        updated(&plan, "B", "A"),
        VersionReq::parse("^2.0.0").unwrap()
    );

    assert_eq!(plan.get("C").unwrap().version, Version::new(1, 0, 1));
    assert_eq!(
        updated(&plan, "C", "B"),
        VersionReq::parse("^1.0.1").unwrap()
    );
}

// A patch-level change that still lies inside a caret range does not release
// the dependent and does not rewrite its range.
#[test]
fn test_already_compatible_range_is_not_touched() {
    let packages = [
        package("A", "1.2.3", Some(Bump::Patch), vec![]),
        package("B", "1.0.0", None, vec![("A", "^1.2.0")]),
        package("C", "1.0.0", None, vec![("A", ">=1.0, <3.0")]),
    ];

    let plan = plan_releases(&packages).unwrap();

    assert_eq!(plan.len(), 1);
    assert_eq!(plan.get("A").unwrap().version, Version::new(1, 2, 4));
    assert!(plan.get("B").is_none());
    assert!(plan.get("C").is_none());
}

// An automatic patch bump must not downgrade an explicit minor or major.
#[test]
fn test_explicit_levels_are_merged_not_downgraded() {
    let packages = [
        package("A", "1.0.0", Some(Bump::Major), vec![]),
        package("B", "1.0.0", Some(Bump::Minor), vec![("A", "=1.0.0")]),
        package("C", "2.0.0", Some(Bump::Patch), vec![("A", "^1.0")]),
    ];

    let plan = plan_releases(&packages).unwrap();

    // B keeps its explicit minor: 1.1.0, and its range becomes A's caret.
    assert_eq!(plan.get("B").unwrap().version, Version::new(1, 1, 0));
    assert_eq!(
        updated(&plan, "B", "A"),
        VersionReq::parse("^2.0.0").unwrap()
    );

    // C keeps its explicit patch even though A's major break propagates.
    assert_eq!(plan.get("C").unwrap().version, Version::new(2, 0, 1));
    assert_eq!(
        updated(&plan, "C", "A"),
        VersionReq::parse("^2.0.0").unwrap()
    );
}

// Explicit patch and no breakage is just an ordinary patch release.
#[test]
fn test_explicit_patch_alone() {
    let packages = [package("A", "1.0.0", Some(Bump::Patch), vec![])];
    let plan = plan_releases(&packages).unwrap();
    assert_eq!(plan.get("A").unwrap().version, Version::new(1, 0, 1));
}

// Two-node cycle: an exact range is broken in both directions, but the cycle
// settles at a single patch bump each and never keeps escalating.
#[test]
fn test_two_node_cycle_settles_without_accumulating_bumps() {
    let packages = [
        package("A", "1.0.0", Some(Bump::Major), vec![("B", "=1.0.0")]),
        package("B", "1.0.0", None, vec![("A", "=1.0.0")]),
    ];

    let plan = plan_releases(&packages).unwrap();

    assert_eq!(plan.get("A").unwrap().version, Version::new(2, 0, 0));
    assert_eq!(
        updated(&plan, "A", "B"),
        VersionReq::parse("^1.0.1").unwrap()
    );

    assert_eq!(plan.get("B").unwrap().version, Version::new(1, 0, 1));
    assert_eq!(
        updated(&plan, "B", "A"),
        VersionReq::parse("^2.0.0").unwrap()
    );
}

// Three-node SCC fixture: A -> B -> C -> A, every edge pinned to =1.0.0.
// A goes major; every cycle member sees a broken edge, settles at one patch
// (never accumulating extra bumps) and rewrites to the other member's caret
// range. D consumes C with an exact range and is evaluated after the component
// has settled.
#[test]
fn test_three_node_cycle_is_one_component_and_propagates_once() {
    let packages = [
        package("A", "1.0.0", Some(Bump::Major), vec![("B", "=1.0.0")]),
        package("B", "1.0.0", None, vec![("C", "=1.0.0")]),
        package("C", "1.0.0", None, vec![("A", "=1.0.0")]),
        package("D", "1.0.0", None, vec![("C", "=1.0.0")]),
    ];

    let plan = plan_releases(&packages).unwrap();

    assert_eq!(plan.get("A").unwrap().version, Version::new(2, 0, 0));
    assert_eq!(plan.get("B").unwrap().version, Version::new(1, 0, 1));
    assert_eq!(plan.get("C").unwrap().version, Version::new(1, 0, 1));

    assert_eq!(
        updated(&plan, "B", "C"),
        VersionReq::parse("^1.0.1").unwrap()
    );
    assert_eq!(
        updated(&plan, "C", "A"),
        VersionReq::parse("^2.0.0").unwrap()
    );
    assert_eq!(
        updated(&plan, "A", "B"),
        VersionReq::parse("^1.0.1").unwrap()
    );

    // Downstream of the settled component: a single patch, not cascaded twice.
    assert_eq!(plan.get("D").unwrap().version, Version::new(1, 0, 1));
    assert_eq!(
        updated(&plan, "D", "C"),
        VersionReq::parse("^1.0.1").unwrap()
    );
}

// A caret-closed cycle needs no automatic release at all.
#[test]
fn test_compatible_cycle_stays_stable_under_patch_bump() {
    let packages = [
        package("A", "1.0.0", Some(Bump::Patch), vec![("B", "^1.0")]),
        package("B", "1.0.0", None, vec![("A", "^1.0")]),
    ];

    let plan = plan_releases(&packages).unwrap();

    assert_eq!(plan.len(), 1);
    assert_eq!(plan.get("A").unwrap().version, Version::new(1, 0, 1));
    assert!(plan.get("B").is_none());
}

// Documented pre-release rejection policy.
#[test]
fn test_pre_releases_are_rejected() {
    let packages = [package("A", "1.0.0-rc.1", Some(Bump::Major), vec![])];
    assert_eq!(
        plan_releases(&packages).unwrap_err(),
        PlanError::PreReleaseVersion {
            package: "A".to_owned(),
        }
    );

    let packages = [
        package("A", "1.0.0", Some(Bump::Patch), vec![]),
        package("B", "1.0.0", None, vec![("A", ">=1.0.0-alpha")]),
    ];
    assert_eq!(
        plan_releases(&packages).unwrap_err(),
        PlanError::PreReleaseRequirement {
            package: "B".to_owned(),
            dependency: "A".to_owned(),
        }
    );
}

// Structural validation.
#[test]
fn test_unknown_duplicate_and_incompatible_inputs_are_rejected() {
    let packages = [
        package("A", "1.0.0", Some(Bump::Patch), vec![]),
        package("B", "1.0.0", None, vec![("Z", "^1.0")]),
    ];
    assert_eq!(
        plan_releases(&packages).unwrap_err(),
        PlanError::UnknownDependency {
            package: "B".to_owned(),
            dependency: "Z".to_owned(),
        }
    );

    let packages = [
        package("A", "1.0.0", Some(Bump::Patch), vec![]),
        package("A", "2.0.0", None, vec![]),
    ];
    assert_eq!(
        plan_releases(&packages).unwrap_err(),
        PlanError::DuplicatePackage {
            package: "A".to_owned(),
        }
    );

    let packages = [
        package("A", "2.0.0", Some(Bump::Patch), vec![]),
        package("B", "1.0.0", None, vec![("A", "^1.0")]),
    ];
    assert_eq!(
        plan_releases(&packages).unwrap_err(),
        PlanError::IncompatibleDependency {
            package: "B".to_owned(),
            dependency: "A".to_owned(),
        }
    );
}

// The supplied input must not be mutated.
#[test]
fn test_input_is_not_modified() {
    let packages = [
        package("A", "1.0.0", Some(Bump::Major), vec![]),
        package("B", "1.0.0", None, vec![("A", "^1.0")]),
    ];
    let snapshot = packages.clone();

    let plan = plan_releases(&packages).unwrap();
    assert!(plan.get("A").is_some());
    assert_eq!(packages[0], snapshot[0]);
    assert_eq!(packages[1], snapshot[1]);
}

// No explicit releases and a consistent workspace means nothing to publish.
#[test]
fn test_no_changes_means_no_releases() {
    let packages = [
        package("A", "1.0.0", None, vec![]),
        package("B", "1.0.0", None, vec![("A", "^1.0")]),
    ];
    let plan = plan_releases(&packages).unwrap();
    assert!(plan.is_empty());
}

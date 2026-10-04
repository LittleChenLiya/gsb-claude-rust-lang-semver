//! Cargo-directed acceptance tests for the release planner.
//!
//! These tests exercise the public API of [`semver::release`] through the
//! crate's public interface, using small deterministic fixtures. They do not
//! read the package manager or access the network.
//!
//! # Propagation rules under test
//!
//! 1. A package with an explicit bump level is released at that level.
//! 2. When a dependency's new version no longer satisfies a dependent's
//!    declared range, the dependent is released at least as a patch and its
//!    range is rewritten to the caret of the dependency's new version.
//! 3. An already-compatible range triggers no release.
//! 4. An explicit major/minor is never downgraded by a forced patch.
//! 5. Cyclic dependencies are evaluated as a strongly connected group and
//!    never append more than one bump per planning run.

use semver::release::{plan, BumpLevel, Dependency, Package, PlanError};
use semver::{Version, VersionReq};

fn fixture() -> Vec<Package> {
    // Three-package fixture: A major 1.0.0 -> 2.0.0, B depends on ^1.0, C
    // depends on B's exact 1.0.0.
    vec![
        Package {
            name: "a".into(),
            version: Version::new(1, 0, 0),
            explicit: Some(BumpLevel::Major),
            dependencies: vec![],
        },
        Package {
            name: "b".into(),
            version: Version::new(1, 0, 0),
            explicit: None,
            dependencies: vec![Dependency {
                name: "a".into(),
                req: VersionReq::parse("^1.0").unwrap(),
            }],
        },
        Package {
            name: "c".into(),
            version: Version::new(1, 0, 0),
            explicit: None,
            dependencies: vec![Dependency {
                name: "b".into(),
                req: VersionReq::parse("=1.0.0").unwrap(),
            }],
        },
    ]
}

#[test]
fn acceptance_three_package_fixture() {
    let packages = fixture();
    let releases = plan(&packages).unwrap().releases;

    // All three packages are released.
    assert_eq!(releases.len(), 3);

    // A is explicitly major -> 2.0.0.
    assert_eq!(releases[0].name, "a");
    assert_eq!(releases[0].new_version, Version::new(2, 0, 0));
    assert!(releases[0].updated_dependencies.is_empty());

    // B is forced patch -> 1.0.1 and rewrites its range on A to ^2.0.0.
    assert_eq!(releases[1].name, "b");
    assert_eq!(releases[1].new_version, Version::new(1, 0, 1));
    assert_eq!(releases[1].updated_dependencies.len(), 1);
    assert_eq!(releases[1].updated_dependencies[0].name, "a");
    assert_eq!(
        releases[1].updated_dependencies[0].req,
        VersionReq::parse("^2.0.0").unwrap()
    );

    // C is forced patch -> 1.0.1 and rewrites its range on B to ^1.0.1.
    assert_eq!(releases[2].name, "c");
    assert_eq!(releases[2].new_version, Version::new(1, 0, 1));
    assert_eq!(releases[2].updated_dependencies.len(), 1);
    assert_eq!(releases[2].updated_dependencies[0].name, "b");
    assert_eq!(
        releases[2].updated_dependencies[0].req,
        VersionReq::parse("^1.0.1").unwrap()
    );
}

#[test]
fn acceptance_explicit_level_merge_major_wins() {
    // A is explicitly major; B is explicitly minor and depends on A with
    // ^1.0. B's explicit minor must not be downgraded to a patch by the
    // propagation from A.
    let packages = vec![
        Package {
            name: "a".into(),
            version: Version::new(1, 0, 0),
            explicit: Some(BumpLevel::Major),
            dependencies: vec![],
        },
        Package {
            name: "b".into(),
            version: Version::new(1, 0, 0),
            explicit: Some(BumpLevel::Minor),
            dependencies: vec![Dependency {
                name: "a".into(),
                req: VersionReq::parse("^1.0").unwrap(),
            }],
        },
    ];
    let releases = plan(&packages).unwrap().releases;
    assert_eq!(releases.len(), 2);
    assert_eq!(releases[0].new_version, Version::new(2, 0, 0));
    // B keeps its explicit minor level.
    assert_eq!(releases[1].new_version, Version::new(1, 1, 0));
    assert_eq!(
        releases[1].updated_dependencies[0].req,
        "^2.0.0".parse().unwrap()
    );
}

#[test]
fn acceptance_compatible_range_no_release() {
    // A is explicitly patch 1.0.0 -> 1.0.1; B depends on ^1.0, which is already
    // satisfied, so B is not released and its range is untouched.
    let packages = vec![
        Package {
            name: "a".into(),
            version: Version::new(1, 0, 0),
            explicit: Some(BumpLevel::Patch),
            dependencies: vec![],
        },
        Package {
            name: "b".into(),
            version: Version::new(1, 0, 0),
            explicit: None,
            dependencies: vec![Dependency {
                name: "a".into(),
                req: VersionReq::parse("^1.0").unwrap(),
            }],
        },
    ];
    let releases = plan(&packages).unwrap().releases;
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0].name, "a");
    assert_eq!(releases[0].new_version, Version::new(1, 0, 1));
}

#[test]
fn acceptance_cyclic_group_settles_without_appending() {
    // A and B depend on each other with exact ranges. A is explicitly major.
    // The group must settle at A=2.0.0, B=1.0.1 without bumping A a second
    // time (which would happen if propagation were applied incrementally).
    let packages = vec![
        Package {
            name: "a".into(),
            version: Version::new(1, 0, 0),
            explicit: Some(BumpLevel::Major),
            dependencies: vec![Dependency {
                name: "b".into(),
                req: VersionReq::parse("=1.0.0").unwrap(),
            }],
        },
        Package {
            name: "b".into(),
            version: Version::new(1, 0, 0),
            explicit: None,
            dependencies: vec![Dependency {
                name: "a".into(),
                req: VersionReq::parse("=1.0.0").unwrap(),
            }],
        },
    ];
    let releases = plan(&packages).unwrap().releases;
    assert_eq!(releases.len(), 2);
    assert_eq!(releases[0].name, "a");
    assert_eq!(releases[0].new_version, Version::new(2, 0, 0));
    assert_eq!(releases[1].name, "b");
    assert_eq!(releases[1].new_version, Version::new(1, 0, 1));
    // Each dependent rewrites its exact range to the caret of the new version.
    assert_eq!(
        releases[0].updated_dependencies[0].req,
        "^1.0.1".parse().unwrap()
    );
    assert_eq!(
        releases[1].updated_dependencies[0].req,
        "^2.0.0".parse().unwrap()
    );
}

#[test]
fn acceptance_prerelease_rejected() {
    let packages = vec![Package {
        name: "a".into(),
        version: Version::parse("1.0.0-alpha.1").unwrap(),
        explicit: Some(BumpLevel::Patch),
        dependencies: vec![],
    }];
    let err = plan(&packages).unwrap_err();
    assert!(matches!(
        err,
        PlanError::PrereleaseVersion { package, .. } if package == "a"
    ));
}

#[test]
fn acceptance_input_unchanged() {
    // The planner must not mutate its input.
    let packages = fixture();
    let before = packages.clone();
    let _ = plan(&packages).unwrap();
    assert_eq!(packages, before);
}

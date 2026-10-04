//! Release planning on top of Cargo's flavor of Semantic Versioning.
//!
//! This module implements a small, self-contained release planner for a set
//! of internally developed packages. It does **not** read the package manager,
//! the registry, or the network. The caller supplies each package's current
//! version, an optional explicit bump level, and its declared internal
//! dependency ranges; the planner returns the packages that must be released,
//! their new versions, and the updated internal ranges.
//!
//! # Propagation rules
//!
//! The planner evaluates the following rules until a fixed point is reached:
//!
//! 1. **Explicit level.** A package with an explicit [`BumpLevel`] is released
//!    at that level.
//! 2. **Propagation.** When a package `D` is released at a new version `V'`,
//!    every package `P` that declares an internal dependency on `D` with range
//!    `R` is inspected. If `V'` does not satisfy `R`, then `P` is released at
//!    least at [`BumpLevel::Patch`] and its range on `D` is rewritten to the
//!    caret range `^V'`.
//! 3. **Already compatible.** If `V'` already satisfies `R`, the range is left
//!    untouched and `P` is not forced to release on `D`'s account.
//! 4. **Level merging.** An explicit [`BumpLevel::Major`] or
//!    [`BumpLevel::Minor`] is never downgraded by propagation. The effective
//!    level of a package is the maximum of its explicit level and every level
//!    forced by propagation.
//! 5. **Strongly connected groups.** Cyclic dependencies are evaluated
//!    together as a strongly connected group. Levels are merged (rule 4) and
//!    each package's new version is computed exactly once from its current
//!    version, so a cyclic group cannot keep appending patches across
//!    iterations.
//!
//! # Pre-release versions
//!
//! Pre-release versions such as `1.0.0-alpha.1` are **rejected** by the
//! planner: [`plan`] returns [`PlanError::PrereleaseVersion`]. Bumping a
//! pre-release is ambiguous (it is not clear whether the result should be a
//! stable release, a new pre-release, or which identifier to advance), so the
//! planner refuses to guess. Callers that need to plan a pre-release should
//! resolve it to a stable version first.
//!
//! # Example: the three-package fixture
//!
//! Packages `A`, `B`, and `C` all start at `1.0.0`. `A` is explicitly bumped
//! major to `2.0.0`. `B` depends on `A` with `^1.0`, and `C` depends on `B`
//! with the exact range `=1.0.0`. Neither `^1.0` nor `=1.0.0` is satisfied by
//! the new versions, so propagation forces `B` and then `C` to release at
//! least a patch, and each dependent rewrites its internal range to the
//! caret of the dependency's new version:
//!
//! ```text
//! A 1.0.0 --major--> 2.0.0   (explicit)
//! B 1.0.0 --patch--> 1.0.1   (forced; range on A: ^1.0 -> ^2.0.0)
//! C 1.0.0 --patch--> 1.0.1   (forced; range on B: =1.0.0 -> ^1.0.1)
//! ```
//!
//! ```
//! use semver::release::{plan, BumpLevel, Dependency, Package};
//! use semver::{Version, VersionReq};
//!
//! let packages = vec![
//!     Package {
//!         name: "a".into(),
//!         version: Version::new(1, 0, 0),
//!         explicit: Some(BumpLevel::Major),
//!         dependencies: vec![],
//!     },
//!     Package {
//!         name: "b".into(),
//!         version: Version::new(1, 0, 0),
//!         explicit: None,
//!         dependencies: vec![Dependency {
//!             name: "a".into(),
//!             req: VersionReq::parse("^1.0").unwrap(),
//!         }],
//!     },
//!     Package {
//!         name: "c".into(),
//!         version: Version::new(1, 0, 0),
//!         explicit: None,
//!         dependencies: vec![Dependency {
//!             name: "b".into(),
//!             req: VersionReq::parse("=1.0.0").unwrap(),
//!         }],
//!     },
//! ];
//!
//! let releases = plan(&packages).unwrap().releases;
//! assert_eq!(releases.len(), 3);
//! assert_eq!(releases[0].name, "a");
//! assert_eq!(releases[0].new_version, Version::new(2, 0, 0));
//! assert_eq!(releases[1].name, "b");
//! assert_eq!(releases[1].new_version, Version::new(1, 0, 1));
//! assert_eq!(releases[2].name, "c");
//! assert_eq!(releases[2].new_version, Version::new(1, 0, 1));
//! ```

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::{Comparator, Op, Prerelease, Version, VersionReq};

/// The bump level explicitly requested for a package.
///
/// Higher levels take precedence when merged with levels forced by propagation
/// (see the [module-level documentation](self) for the merging rules).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum BumpLevel {
    /// `x.y.z` -> `x.y.(z+1)`
    Patch,
    /// `x.y.z` -> `x.(y+1).0`
    Minor,
    /// `x.y.z` -> `(x+1).0.0`
    Major,
}

impl BumpLevel {
    fn rank(self) -> u8 {
        match self {
            BumpLevel::Patch => 1,
            BumpLevel::Minor => 2,
            BumpLevel::Major => 3,
        }
    }
}

/// Merge two bump levels, taking the higher one. [`None`] means "no release".
fn merge_level(a: Option<BumpLevel>, b: Option<BumpLevel>) -> Option<BumpLevel> {
    match (a, b) {
        (None, _) => b,
        (_, None) => a,
        (Some(x), Some(y)) => Some(if x.rank() >= y.rank() { x } else { y }),
    }
}

/// A package's declared dependency on another package.
#[derive(Clone, Debug, PartialEq)]
pub struct Dependency {
    /// Name of the depended-upon package. Must match a [`Package::name`] in
    /// the input.
    pub name: String,
    /// The declared version range, for example `^1.0` or `=1.0.0`.
    pub req: VersionReq,
}

/// A package supplied to the planner.
#[derive(Clone, Debug, PartialEq)]
pub struct Package {
    /// Package name. Must be unique within the input.
    pub name: String,
    /// Current version. Pre-release versions are rejected.
    pub version: Version,
    /// Explicitly requested bump level, if any.
    pub explicit: Option<BumpLevel>,
    /// Internal dependencies. Each name must refer to another package in the
    /// input.
    pub dependencies: Vec<Dependency>,
}

/// A planned release for a single package.
#[derive(Clone, Debug, PartialEq)]
pub struct Release {
    /// Package name.
    pub name: String,
    /// The version the package will be released at.
    pub new_version: Version,
    /// Updated internal dependency ranges. Only dependencies whose range was
    /// rewritten are included; dependencies whose range already satisfied the
    /// dependency's new version are omitted.
    pub updated_dependencies: Vec<Dependency>,
}

/// The result of planning: the packages that must be released, in input order.
#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    /// The packages that must be released, in the order they were supplied to
    /// [`plan`].
    pub releases: Vec<Release>,
}

/// Errors returned by [`plan`].
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum PlanError {
    /// A package's current version carries a pre-release tag, which the
    /// planner rejects.
    PrereleaseVersion { package: String, version: Version },
    /// Two packages share the same name.
    DuplicatePackage(String),
    /// A dependency refers to a package that is not present in the input.
    UnknownDependency { package: String, dependency: String },
}

/// Plan the releases for a set of internally developed packages.
///
/// See the [module-level documentation](self) for the propagation rules and
/// the pre-release rejection policy.
pub fn plan(packages: &[Package]) -> Result<Plan, PlanError> {
    let n = packages.len();

    // Validate and build the name -> index map.
    let mut index_of: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, pkg) in packages.iter().enumerate() {
        if !pkg.version.pre.is_empty() {
            return Err(PlanError::PrereleaseVersion {
                package: pkg.name.clone(),
                version: pkg.version.clone(),
            });
        }
        if index_of.insert(pkg.name.as_str(), i).is_some() {
            return Err(PlanError::DuplicatePackage(pkg.name.clone()));
        }
    }

    // Resolve dependency names to package indices. `deps[i][k]` is the index
    // of the package that `packages[i].dependencies[k]` refers to.
    let mut deps: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, pkg) in packages.iter().enumerate() {
        for dep in &pkg.dependencies {
            let &j =
                index_of
                    .get(dep.name.as_str())
                    .ok_or_else(|| PlanError::UnknownDependency {
                        package: pkg.name.clone(),
                        dependency: dep.name.clone(),
                    })?;
            deps[i].push(j);
        }
    }

    // Compute strongly connected groups and a topological order in which
    // dependencies are finalized before their dependents.
    let (sccs, comp) = kosaraju(n, &deps);
    let order = topo_order(&sccs, &comp, &deps);

    // `level[i]` is the effective bump level of package i, or None if it is not
    // released. Levels only ever increase, so the fixed-point below terminates.
    let mut level: Vec<Option<BumpLevel>> = packages.iter().map(|p| p.explicit).collect();

    for scc in order {
        let members = &sccs[scc];
        // Fixed-point for this strongly connected group. Levels of packages in
        // the group can only increase; levels of external dependencies are
        // already finalized because of the topological order.
        loop {
            let mut changed = false;
            for &i in members {
                for (k, &j) in deps[i].iter().enumerate() {
                    // If the dependency is not released, its version is the
                    // current one and there is nothing to propagate.
                    let Some(dep_level) = level[j] else {
                        continue;
                    };
                    let new_dep_version = bump(&packages[j].version, dep_level);
                    let req = &packages[i].dependencies[k].req;
                    if !req.matches(&new_dep_version) {
                        let merged = merge_level(level[i], Some(BumpLevel::Patch));
                        if merged != level[i] {
                            level[i] = merged;
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }

    // Build the releases in input order.
    let mut releases = Vec::new();
    for (i, pkg) in packages.iter().enumerate() {
        let Some(effective) = level[i] else {
            continue;
        };
        let new_version = bump(&pkg.version, effective);
        let mut updated_dependencies = Vec::new();
        for (k, &j) in deps[i].iter().enumerate() {
            let Some(dep_level) = level[j] else {
                continue;
            };
            let new_dep_version = bump(&packages[j].version, dep_level);
            let req = &pkg.dependencies[k].req;
            if !req.matches(&new_dep_version) {
                updated_dependencies.push(Dependency {
                    name: packages[j].name.clone(),
                    req: caret_range(&new_dep_version),
                });
            }
        }
        releases.push(Release {
            name: pkg.name.clone(),
            new_version,
            updated_dependencies,
        });
    }

    Ok(Plan { releases })
}

/// Apply a bump level to a version, producing a clean release (no pre-release
/// or build metadata).
fn bump(version: &Version, level: BumpLevel) -> Version {
    match level {
        BumpLevel::Patch => Version::new(version.major, version.minor, version.patch + 1),
        BumpLevel::Minor => Version::new(version.major, version.minor + 1, 0),
        BumpLevel::Major => Version::new(version.major + 1, 0, 0),
    }
}

/// Build the caret range `^major.minor.patch` for a version.
fn caret_range(version: &Version) -> VersionReq {
    VersionReq {
        comparators: vec![Comparator {
            op: Op::Caret,
            major: version.major,
            minor: Some(version.minor),
            patch: Some(version.patch),
            pre: Prerelease::EMPTY,
        }],
    }
}

/// Compute the strongly connected components of the dependency graph using
/// Kosaraju's algorithm.
///
/// `deps[i]` lists the packages that `i` depends on (edge `i -> j`). Returns
/// the list of SCCs and a mapping from package index to SCC index.
fn kosaraju(n: usize, deps: &[Vec<usize>]) -> (Vec<Vec<usize>>, Vec<usize>) {
    // First pass: finish order on the original graph.
    let mut visited = vec![false; n];
    let mut finish_order = Vec::with_capacity(n);
    for v in 0..n {
        if !visited[v] {
            kosaraju_dfs1(v, deps, &mut visited, &mut finish_order);
        }
    }

    // Reverse graph.
    let mut radj = vec![Vec::new(); n];
    for (i, neighbors) in deps.iter().enumerate() {
        for &j in neighbors {
            radj[j].push(i);
        }
    }

    // Second pass: reverse graph in reverse finish order.
    let mut comp = vec![0usize; n];
    let mut sccs = Vec::new();
    let mut c = 0usize;
    for &v in finish_order.iter().rev() {
        if comp[v] == 0 {
            c += 1;
            let mut members = Vec::new();
            kosaraju_dfs2(v, c, &radj, &mut comp, &mut members);
            sccs.push(members);
        }
    }

    // `comp` uses 0 as "unvisited"; shift so SCC indices are 0-based.
    for x in &mut comp {
        *x -= 1;
    }

    (sccs, comp)
}

fn kosaraju_dfs1(
    v: usize,
    deps: &[Vec<usize>],
    visited: &mut [bool],
    finish_order: &mut Vec<usize>,
) {
    visited[v] = true;
    for &j in &deps[v] {
        if !visited[j] {
            kosaraju_dfs1(j, deps, visited, finish_order);
        }
    }
    finish_order.push(v);
}

fn kosaraju_dfs2(
    v: usize,
    c: usize,
    radj: &[Vec<usize>],
    comp: &mut [usize],
    members: &mut Vec<usize>,
) {
    comp[v] = c;
    members.push(v);
    for &j in &radj[v] {
        if comp[j] == 0 {
            kosaraju_dfs2(j, c, radj, comp, members);
        }
    }
}

/// Return the SCCs in topological order such that an SCC's dependencies are
/// finalized before the SCC itself.
fn topo_order(sccs: &[Vec<usize>], comp: &[usize], deps: &[Vec<usize>]) -> Vec<usize> {
    let s = sccs.len();
    let mut cond = vec![Vec::new(); s];
    for (i, neighbors) in deps.iter().enumerate() {
        for &j in neighbors {
            if comp[i] != comp[j] {
                cond[comp[i]].push(comp[j]);
            }
        }
    }

    let mut visited = vec![false; s];
    let mut order = Vec::with_capacity(s);
    for c in 0..s {
        if !visited[c] {
            topo_dfs(c, &cond, &mut visited, &mut order);
        }
    }
    order
}

fn topo_dfs(c: usize, cond: &[Vec<usize>], visited: &mut [bool], order: &mut Vec<usize>) {
    visited[c] = true;
    for &d in &cond[c] {
        if !visited[d] {
            topo_dfs(d, cond, visited, order);
        }
    }
    order.push(c);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(
        name: &str,
        version: &str,
        explicit: Option<BumpLevel>,
        deps: &[(&str, &str)],
    ) -> Package {
        Package {
            name: name.into(),
            version: Version::parse(version).unwrap(),
            explicit,
            dependencies: deps
                .iter()
                .map(|(n, r)| Dependency {
                    name: (*n).into(),
                    req: VersionReq::parse(r).unwrap(),
                })
                .collect(),
        }
    }

    fn release_map(plan: &Plan) -> BTreeMap<String, (Version, Vec<(String, String)>)> {
        let mut map = BTreeMap::new();
        for r in &plan.releases {
            let deps = r
                .updated_dependencies
                .iter()
                .map(|d| (d.name.clone(), d.req.to_string()))
                .collect();
            map.insert(r.name.clone(), (r.new_version.clone(), deps));
        }
        map
    }

    #[test]
    fn three_package_fixture() {
        let packages = vec![
            pkg("a", "1.0.0", Some(BumpLevel::Major), &[]),
            pkg("b", "1.0.0", None, &[("a", "^1.0")]),
            pkg("c", "1.0.0", None, &[("b", "=1.0.0")]),
        ];
        let plan = plan(&packages).unwrap();
        let map = release_map(&plan);

        assert_eq!(map["a"].0, Version::new(2, 0, 0));
        assert_eq!(map["b"].0, Version::new(1, 0, 1));
        assert_eq!(map["c"].0, Version::new(1, 0, 1));

        // b rewrites its range on a to ^2.0.0; c rewrites its range on b to ^1.0.1.
        assert_eq!(map["b"].1, vec![("a".to_string(), "^2.0.0".to_string())]);
        assert_eq!(map["c"].1, vec![("b".to_string(), "^1.0.1".to_string())]);
    }

    #[test]
    fn already_compatible_range_no_propagation() {
        // a is explicitly minor 1.0.0 -> 1.1.0; b depends on ^1.0, which is
        // already satisfied, so b is not released.
        let packages = vec![
            pkg("a", "1.0.0", Some(BumpLevel::Minor), &[]),
            pkg("b", "1.0.0", None, &[("a", "^1.0")]),
        ];
        let plan = plan(&packages).unwrap();
        let map = release_map(&plan);
        assert_eq!(map.len(), 1);
        assert_eq!(map["a"].0, Version::new(1, 1, 0));
    }

    #[test]
    fn explicit_minor_not_downgraded_by_patch() {
        // a major forces b; b is explicitly minor, so it stays minor.
        let packages = vec![
            pkg("a", "1.0.0", Some(BumpLevel::Major), &[]),
            pkg("b", "1.2.3", Some(BumpLevel::Minor), &[("a", "^1.0")]),
        ];
        let plan = plan(&packages).unwrap();
        let map = release_map(&plan);
        assert_eq!(map["a"].0, Version::new(2, 0, 0));
        assert_eq!(map["b"].0, Version::new(1, 3, 0));
    }

    #[test]
    fn cyclic_group_does_not_append_upgrades() {
        // a and b depend on each other with exact ranges. a is explicitly
        // major. The group must settle at a=2.0.0, b=1.0.1 without bumping a
        // second time.
        let packages = vec![
            pkg("a", "1.0.0", Some(BumpLevel::Major), &[("b", "=1.0.0")]),
            pkg("b", "1.0.0", None, &[("a", "=1.0.0")]),
        ];
        let plan = plan(&packages).unwrap();
        let map = release_map(&plan);
        assert_eq!(map.len(), 2);
        assert_eq!(map["a"].0, Version::new(2, 0, 0));
        assert_eq!(map["b"].0, Version::new(1, 0, 1));
        // Both ranges are rewritten to the caret of the new versions.
        assert_eq!(map["a"].1, vec![("b".to_string(), "^1.0.1".to_string())]);
        assert_eq!(map["b"].1, vec![("a".to_string(), "^2.0.0".to_string())]);
    }

    #[test]
    fn cyclic_group_with_explicit_minor() {
        // a and b in a cycle; a explicitly major, b explicitly minor. The
        // group merges levels: a stays major, b stays minor.
        let packages = vec![
            pkg("a", "1.0.0", Some(BumpLevel::Major), &[("b", "^1.0")]),
            pkg("b", "1.0.0", Some(BumpLevel::Minor), &[("a", "^1.0")]),
        ];
        let plan = plan(&packages).unwrap();
        let map = release_map(&plan);
        assert_eq!(map["a"].0, Version::new(2, 0, 0));
        assert_eq!(map["b"].0, Version::new(1, 1, 0));
        // b's range on a is rewritten to ^2.0.0; a's range on b: ^1.0 is not
        // satisfied by 1.1.0? It IS satisfied (^1.0 allows 1.1.0), so a's range
        // on b is left untouched.
        assert_eq!(map["a"].1, vec![]);
        assert_eq!(map["b"].1, vec![("a".to_string(), "^2.0.0".to_string())]);
    }

    #[test]
    fn prerelease_version_rejected() {
        let packages = vec![pkg("a", "1.0.0-alpha.1", Some(BumpLevel::Patch), &[])];
        let err = plan(&packages).unwrap_err();
        match err {
            PlanError::PrereleaseVersion { package, version } => {
                assert_eq!(package, "a");
                assert_eq!(version, Version::parse("1.0.0-alpha.1").unwrap());
            }
            other => panic!("expected PrereleaseVersion, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_package_rejected() {
        let packages = vec![
            pkg("a", "1.0.0", Some(BumpLevel::Patch), &[]),
            pkg("a", "2.0.0", None, &[]),
        ];
        let err = plan(&packages).unwrap_err();
        assert!(matches!(err, PlanError::DuplicatePackage(_)));
    }

    #[test]
    fn unknown_dependency_rejected() {
        let packages = vec![pkg(
            "a",
            "1.0.0",
            Some(BumpLevel::Patch),
            &[("missing", "^1.0")],
        )];
        let err = plan(&packages).unwrap_err();
        assert!(matches!(err, PlanError::UnknownDependency { .. }));
    }

    #[test]
    fn no_releases_when_nothing_bumped() {
        let packages = vec![
            pkg("a", "1.0.0", None, &[]),
            pkg("b", "1.0.0", None, &[("a", "^1.0")]),
        ];
        let plan = plan(&packages).unwrap();
        assert!(plan.releases.is_empty());
    }

    #[test]
    fn diamond_propagation() {
        // a major; b and c both depend on a; d depends on both b and c with
        // exact ranges. b and c are forced patch by a; d is then forced patch
        // by both b and c, exercising propagation through a diamond.
        let packages = vec![
            pkg("a", "1.0.0", Some(BumpLevel::Major), &[]),
            pkg("b", "1.0.0", None, &[("a", "^1.0")]),
            pkg("c", "1.0.0", None, &[("a", "^1.0")]),
            pkg("d", "1.0.0", None, &[("b", "=1.0.0"), ("c", "=1.0.0")]),
        ];
        let plan = plan(&packages).unwrap();
        let map = release_map(&plan);
        assert_eq!(map.len(), 4);
        assert_eq!(map["a"].0, Version::new(2, 0, 0));
        assert_eq!(map["b"].0, Version::new(1, 0, 1));
        assert_eq!(map["c"].0, Version::new(1, 0, 1));
        assert_eq!(map["d"].0, Version::new(1, 0, 1));
        assert_eq!(map["b"].1, vec![("a".to_string(), "^2.0.0".to_string())]);
        assert_eq!(map["c"].1, vec![("a".to_string(), "^2.0.0".to_string())]);
        // d rewrites both exact ranges to the caret of the new versions.
        assert_eq!(
            map["d"].1,
            vec![
                ("b".to_string(), "^1.0.1".to_string()),
                ("c".to_string(), "^1.0.1".to_string()),
            ]
        );
    }

    #[test]
    fn caret_range_covers_zero_versions() {
        // a 0.1.0 -> 0.2.0 minor; b depends on ^0.1, which is not satisfied.
        let packages = vec![
            pkg("a", "0.1.0", Some(BumpLevel::Minor), &[]),
            pkg("b", "0.1.0", None, &[("a", "^0.1")]),
        ];
        let plan = plan(&packages).unwrap();
        let map = release_map(&plan);
        assert_eq!(map["a"].0, Version::new(0, 2, 0));
        assert_eq!(map["b"].0, Version::new(0, 1, 1));
        assert_eq!(map["b"].1, vec![("a".to_string(), "^0.2.0".to_string())]);
    }
}

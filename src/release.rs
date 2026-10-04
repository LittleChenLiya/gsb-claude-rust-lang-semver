//! Small, offline **release planning** on top of Cargo-flavored SemVer.
//!
//! This module answers a narrow question: given the current versions of a set
//! of packages, the explicit release level requested for some of them, and the
//! version requirements declared on their *internal* dependencies, which
//! packages must be published in this release and at which versions?
//!
//! It never reads a package manager and never performs any network access. The
//! caller supplies all of the inputs as plain data; [`plan_releases`] does not
//! mutate them.
//!
//! # Inputs
//!
//! - [`Package`] describes one package: its current [`Version`], an optional
//!   explicit [`Bump`], and its internal [`Dependency`] requirements.
//! - [`Dependency`] pairs an internal package name with a [`VersionReq`] as it
//!   is declared by the dependent (for example `^1.0` or `=1.0.0`).
//!
//! Every name referenced by a dependency must be one of the packages in the
//! plan; this module only models internal dependencies. The declared
//! requirement must already match the dependency's current version: the
//! planner propagates *new* breakage caused by a release, it does not repair a
//! workspace that is inconsistent before planning.
//!
//! # Propagation rules
//!
//! 1. A package with an explicit [`Bump`] publishes at the version produced by
//!    applying that level to its current version: `Major` increments major and
//!    resets minor/patch, `Minor` increments minor and resets patch, `Patch`
//!    increments patch.
//!
//! 2. When a dependency publishes a new version that **no longer satisfies** a
//!    dependent's declared requirement, the dependent is published as well,
//!    with *at least* a patch bump, and the offending internal requirement is
//!    rewritten to the caret range of the dependency's new version, such as
//!    `^2.0.0`.
//!
//! 3. If the new version still satisfies the declared range, the dependent is
//!    left untouched: no release and no requirement rewrite. Already
//!    compatible ranges do not force propagation.
//!
//! 4. Bump levels merge by taking the stronger level. An automatic patch bump
//!    can therefore never *downgrade* an explicit `Minor` or `Major` request;
//!    the package publishes at the explicit level.
//!
//! 5. Packages participating in a dependency cycle form a strongly connected
//!    component and are evaluated together to a fixed point. Propagation only
//!    ever raises a level toward `Patch` and levels are monotonic (they can
//!    rise at most twice), so the fixed point is reached after a few passes;
//!    cycles never accumulate extra bumps. A dependency is always evaluated
//!    before the components that depend on it.
//!
//! # Pre-release rejection policy
//!
//! Only ordinary (stable) releases are planned. The planner rejects, rather
//! than guessing, both:
//!
//! - a package whose current [`Version`] carries a pre-release identifier, and
//! - an internal requirement whose any comparator carries a pre-release
//!   identifier.
//!
//! Planned versions are therefore always stable. Build metadata on an input
//! version is accepted for compatibility checks but omitted from planned
//! versions.
//!
//! # Example
//!
//! ```
//! use semver::release::{plan_releases, Bump, Dependency, Package};
//! use semver::{Version, VersionReq};
//!
//! // A goes 1.0.0 -> 2.0.0. B accepts ^1.0 of A; C pins B to =1.0.0.
//! let packages = [
//!     Package {
//!         name: "A".to_owned(),
//!         version: Version::new(1, 0, 0),
//!         bump: Some(Bump::Major),
//!         dependencies: Vec::new(),
//!     },
//!     Package {
//!         name: "B".to_owned(),
//!         version: Version::new(1, 0, 0),
//!         bump: None,
//!         dependencies: vec![Dependency {
//!             name: "A".to_owned(),
//!             req: VersionReq::parse("^1.0").unwrap(),
//!         }],
//!     },
//!     Package {
//!         name: "C".to_owned(),
//!         version: Version::new(1, 0, 0),
//!         bump: None,
//!         dependencies: vec![Dependency {
//!             name: "B".to_owned(),
//!             req: VersionReq::parse("=1.0.0").unwrap(),
//!         }],
//!     },
//! ];
//!
//! let plan = plan_releases(&packages).unwrap();
//!
//! let a = plan.releases().get("A").unwrap();
//! assert_eq!(a.version, Version::new(2, 0, 0));
//! assert!(a.updated_dependencies.is_empty());
//!
//! let b = plan.releases().get("B").unwrap();
//! assert_eq!(b.version, Version::new(1, 0, 1));
//! assert_eq!(b.updated_dependencies[0].name, "A");
//! assert_eq!(b.updated_dependencies[0].req, VersionReq::parse("^2.0.0").unwrap());
//!
//! let c = plan.releases().get("C").unwrap();
//! assert_eq!(c.version, Version::new(1, 0, 1));
//! assert_eq!(c.updated_dependencies[0].req, VersionReq::parse("^1.0.1").unwrap());
//! ```

use crate::{Version, VersionReq};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

/// Explicit or propagated release level, ordered from weakest to strongest.
///
/// `Patch < Minor < Major`; merging levels takes the maximum, so an automatic
/// patch never overrides an explicit minor or major.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bump {
    /// `1.2.3 -> 1.2.4`.
    Patch,
    /// `1.2.3 -> 1.3.0`.
    Minor,
    /// `1.2.3 -> 2.0.0`.
    Major,
}

/// One package participating in release planning.
///
/// Passed by shared reference to [`plan_releases`] and never modified; the
/// planner copies the data it needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    /// Unique package name, used to match internal dependencies.
    pub name: String,
    /// Current published version. Must be a stable (pre-release-free) version.
    pub version: Version,
    /// Explicit release level, if one was requested.
    pub bump: Option<Bump>,
    /// Internal dependency ranges declared by this package.
    pub dependencies: Vec<Dependency>,
}

/// An internal dependency as declared by a [`Package`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dependency {
    /// Name of the depended-on package; must appear in the planned set.
    pub name: String,
    /// Declared requirement, which must match the dependency's current version.
    pub req: VersionReq,
}

/// An internal requirement rewritten because the dependency left the range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatedDependency {
    /// Name of the depended-on package.
    pub name: String,
    /// New caret requirement, such as `^2.0.0`.
    pub req: VersionReq,
}

/// A package selected for release, with its new version and rewritten ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// Package name.
    pub name: String,
    /// Version to publish at.
    pub version: Version,
    /// Internal requirements that had to move to a caret range, sorted by name.
    pub updated_dependencies: Vec<UpdatedDependency>,
}

/// The resulting release set: only packages that must publish are present.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReleasePlan {
    releases: BTreeMap<String, Release>,
}

impl ReleasePlan {
    /// All planned releases keyed by package name, in name order.
    pub fn releases(&self) -> &BTreeMap<String, Release> {
        &self.releases
    }

    /// Look up the planned release for one package.
    pub fn get(&self, name: &str) -> Option<&Release> {
        self.releases.get(name)
    }

    /// Number of packages selected for release.
    pub fn len(&self) -> usize {
        self.releases.len()
    }

    /// Whether no package needs to release.
    pub fn is_empty(&self) -> bool {
        self.releases.is_empty()
    }
}

/// Reasons planning can be rejected.
///
/// In particular every pre-release-related variant documents the module's
/// rejection policy: pre-release versions and pre-release requirements are
/// never planned around.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlanError {
    /// Two packages share the same [`Package::name`].
    DuplicatePackage {
        /// The duplicated name.
        package: String,
    },
    /// A dependency references a name that is not a package in the plan.
    UnknownDependency {
        /// The dependent that declared the reference.
        package: String,
        /// The unknown dependency name.
        dependency: String,
    },
    /// A package is currently at a pre-release version (rejection policy).
    PreReleaseVersion {
        /// The package carrying the pre-release.
        package: String,
    },
    /// A declared requirement contains a pre-release comparator (rejection
    /// policy).
    PreReleaseRequirement {
        /// The dependent declaring the range.
        package: String,
        /// The dependency whose range contains a pre-release.
        dependency: String,
    },
    /// A declared range does not match the dependency's current version.
    ///
    /// The planner propagates breakage introduced by this release rather than
    /// repairing a pre-existing inconsistency.
    IncompatibleDependency {
        /// The dependent declaring the unsatisfiable range.
        package: String,
        /// The dependency whose current version is outside the range.
        dependency: String,
    },
    /// Applying a bump would overflow `u64` in one of the version components.
    VersionOverflow {
        /// The package whose bumped version would overflow.
        package: String,
    },
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PlanError::DuplicatePackage { package } => {
                write!(formatter, "duplicate package name `{package}`")
            }
            PlanError::UnknownDependency {
                package,
                dependency,
            } => write!(
                formatter,
                "package `{package}` depends on unknown internal package `{dependency}`"
            ),
            PlanError::PreReleaseVersion { package } => write!(
                formatter,
                "package `{package}` has a pre-release version; pre-releases are rejected"
            ),
            PlanError::PreReleaseRequirement {
                package,
                dependency,
            } => write!(
                formatter,
                "requirement of `{package}` on `{dependency}` contains a pre-release; \
                 pre-release requirements are rejected"
            ),
            PlanError::IncompatibleDependency {
                package,
                dependency,
            } => write!(
                formatter,
                "declared requirement of `{package}` on `{dependency}` does not match \
                 the dependency's current version"
            ),
            PlanError::VersionOverflow { package } => {
                write!(formatter, "bumping package `{package}` overflows u64")
            }
        }
    }
}

struct Edge {
    target: usize,
    req: VersionReq,
}

struct Node {
    name: String,
    base: Version,
    level: Option<Bump>,
    edges: Vec<Edge>,
}

/// Compute the releases implied by `packages` without modifying the input.
pub fn plan_releases(packages: &[Package]) -> Result<ReleasePlan, PlanError> {
    let mut indices: BTreeMap<&str, usize> = BTreeMap::new();
    let mut nodes: Vec<Node> = Vec::with_capacity(packages.len());

    for package in packages {
        if indices.insert(package.name.as_str(), nodes.len()).is_some() {
            return Err(PlanError::DuplicatePackage {
                package: package.name.clone(),
            });
        }
        if !package.version.pre.is_empty() {
            return Err(PlanError::PreReleaseVersion {
                package: package.name.clone(),
            });
        }
        nodes.push(Node {
            name: package.name.clone(),
            base: package.version.clone(),
            level: package.bump,
            edges: Vec::new(),
        });
    }

    for (index, package) in packages.iter().enumerate() {
        for dependency in &package.dependencies {
            let target = match indices.get(dependency.name.as_str()) {
                Some(&target) => target,
                None => {
                    return Err(PlanError::UnknownDependency {
                        package: package.name.clone(),
                        dependency: dependency.name.clone(),
                    });
                }
            };
            if dependency
                .req
                .comparators
                .iter()
                .any(|comparator| !comparator.pre.is_empty())
            {
                return Err(PlanError::PreReleaseRequirement {
                    package: package.name.clone(),
                    dependency: dependency.name.clone(),
                });
            }
            nodes[index].edges.push(Edge {
                target,
                req: dependency.req.clone(),
            });
        }
    }

    // The input workspace must be consistent before the release.
    for node in &nodes {
        for edge in &node.edges {
            if !edge.req.matches(&nodes[edge.target].base) {
                return Err(PlanError::IncompatibleDependency {
                    package: node.name.clone(),
                    dependency: nodes[edge.target].name.clone(),
                });
            }
        }
    }

    let components = strongly_connected_components(&nodes);
    let order = dependency_first_order(
        components.iter().copied().max().map_or(0, |n| n + 1),
        &components,
        &nodes,
    );

    // Versions reached so far; cross-component dependencies read final values
    // because their components are evaluated earlier in `order`.
    let mut versions: Vec<Version> = nodes.iter().map(|node| node.base.clone()).collect();
    // One caret override per declared edge, only set while the edge is broken.
    let mut overrides: Vec<Vec<Option<VersionReq>>> = nodes
        .iter()
        .map(|node| vec![None; node.edges.len()])
        .collect();

    for component in order {
        let members: Vec<usize> = (0..nodes.len())
            .filter(|&index| components[index] == component)
            .collect();

        // Fixed point for this strongly connected component. Bump levels only
        // rise (to at most Patch, merging with explicit levels) and caret
        // overrides track monotonically increasing dependency versions, so
        // this terminates; the bound is a defensive guard.
        for _ in 0..nodes.len() * 2 + 4 {
            // Snapshot the component's versions at pass start so evaluation
            // order within the component cannot change the result.
            let mut candidate = versions.clone();
            for &member in &members {
                candidate[member] = bumped_version(&nodes[member])?;
            }

            let mut progress = false;
            for &member in &members {
                let edges: Vec<(usize, VersionReq)> = nodes[member]
                    .edges
                    .iter()
                    .map(|edge| (edge.target, edge.req.clone()))
                    .collect();
                for (edge_index, (target, req)) in edges.into_iter().enumerate() {
                    let dependency_version = &candidate[target];
                    if req.matches(dependency_version) {
                        if overrides[member][edge_index].is_some() {
                            overrides[member][edge_index] = None;
                            progress = true;
                        }
                    } else {
                        let caret = caret_requirement(dependency_version);
                        if overrides[member][edge_index].as_ref() != Some(&caret) {
                            overrides[member][edge_index] = Some(caret);
                            progress = true;
                        }
                        let merged = merge_level(nodes[member].level, Some(Bump::Patch));
                        if merged != nodes[member].level {
                            nodes[member].level = merged;
                            progress = true;
                        }
                    }
                }
            }

            for &member in &members {
                versions[member] = bumped_version(&nodes[member])?;
            }

            if !progress {
                break;
            }
        }
    }

    let mut releases = BTreeMap::new();
    for (node_index, node) in nodes.iter().enumerate() {
        let Some(level) = node.level else {
            // A package without a bump never carries rewritten edges either.
            continue;
        };

        let mut updated_dependencies = Vec::new();
        for (edge_index, edge) in node.edges.iter().enumerate() {
            if let Some(req) = &overrides[node_index][edge_index] {
                updated_dependencies.push(UpdatedDependency {
                    name: nodes[edge.target].name.clone(),
                    req: req.clone(),
                });
            }
        }
        updated_dependencies.sort_by(|left, right| left.name.cmp(&right.name));

        let version =
            bump_version(&node.base, level).ok_or_else(|| PlanError::VersionOverflow {
                package: node.name.clone(),
            })?;
        releases.insert(
            node.name.clone(),
            Release {
                name: node.name.clone(),
                version,
                updated_dependencies,
            },
        );
    }

    Ok(ReleasePlan { releases })
}

fn merge_level(explicit: Option<Bump>, propagated: Option<Bump>) -> Option<Bump> {
    match (explicit, propagated) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

fn bumped_version(node: &Node) -> Result<Version, PlanError> {
    match node.level {
        Some(level) => bump_version(&node.base, level).ok_or_else(|| PlanError::VersionOverflow {
            package: node.name.clone(),
        }),
        None => Ok(stable_clone(&node.base)),
    }
}

fn bump_version(version: &Version, level: Bump) -> Option<Version> {
    let (major, minor, patch) = match level {
        Bump::Major => (version.major.checked_add(1)?, 0, 0),
        Bump::Minor => (version.major, version.minor.checked_add(1)?, 0),
        Bump::Patch => (version.major, version.minor, version.patch.checked_add(1)?),
    };
    Some(Version::new(major, minor, patch))
}

fn stable_clone(version: &Version) -> Version {
    Version::new(version.major, version.minor, version.patch)
}

fn caret_requirement(version: &Version) -> VersionReq {
    // Numeric stable components always form a valid caret requirement.
    VersionReq::parse(&format!(
        "^{}.{}.{}",
        version.major, version.minor, version.patch
    ))
    .expect("caret of a stable numeric version parses")
}

/// Tarjan's SCC algorithm over dependency edges (`package -> dependency`).
/// Returns a component id per node; ids are assigned in Tarjan emission order,
/// i.e. a component with no outgoing dependency edges (a leaf) is emitted
/// first.
fn strongly_connected_components(nodes: &[Node]) -> Vec<usize> {
    struct State {
        index: usize,
        indices: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        on_stack: Vec<bool>,
        stack: Vec<usize>,
        component: Vec<usize>,
        components: usize,
    }

    let mut state = State {
        index: 0,
        indices: vec![None; nodes.len()],
        lowlink: vec![0; nodes.len()],
        on_stack: vec![false; nodes.len()],
        stack: Vec::new(),
        component: vec![0; nodes.len()],
        components: 0,
    };

    fn connect(nodes: &[Node], state: &mut State, node: usize) {
        state.indices[node] = Some(state.index);
        state.lowlink[node] = state.index;
        state.index += 1;
        state.stack.push(node);
        state.on_stack[node] = true;

        for edge in &nodes[node].edges {
            match state.indices[edge.target] {
                None => {
                    connect(nodes, state, edge.target);
                    state.lowlink[node] = state.lowlink[node].min(state.lowlink[edge.target]);
                }
                Some(index) if state.on_stack[edge.target] => {
                    state.lowlink[node] = state.lowlink[node].min(index);
                }
                Some(_) => {}
            }
        }

        if state.lowlink[node] == state.indices[node].unwrap() {
            while let Some(popped) = state.stack.pop() {
                state.on_stack[popped] = false;
                state.component[popped] = state.components;
                if popped == node {
                    break;
                }
            }
            state.components += 1;
        }
    }

    for node in 0..nodes.len() {
        if state.indices[node].is_none() {
            connect(nodes, &mut state, node);
        }
    }

    state.component
}

/// Order components so every dependency is evaluated before its dependents.
///
/// Condensation edges point from the dependency's component to the dependent's
/// component; Kahn traversal therefore starts at components without incoming
/// edges, i.e. packages that have no cross-component dependencies.
fn dependency_first_order(
    component_count: usize,
    components: &[usize],
    nodes: &[Node],
) -> Vec<usize> {
    let mut incoming = vec![0usize; component_count];
    let mut outgoing: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); component_count];

    for (node_index, node) in nodes.iter().enumerate() {
        for edge in &node.edges {
            let from = components[edge.target];
            let to = components[node_index];
            if from != to && outgoing[from].insert(to) {
                incoming[to] += 1;
            }
        }
    }

    let mut ready: BTreeSet<usize> = (0..component_count)
        .filter(|&component| incoming[component] == 0)
        .collect();
    let mut order = Vec::with_capacity(component_count);
    while let Some(component) = ready.pop_first() {
        order.push(component);
        for next in &outgoing[component] {
            incoming[*next] -= 1;
            if incoming[*next] == 0 {
                ready.insert(*next);
            }
        }
    }
    order
}

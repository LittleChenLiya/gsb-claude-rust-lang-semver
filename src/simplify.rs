//! Explicit, conservative simplifier for [`VersionReq`].
//!
//! [`VersionReq::simplify`] returns a semantically equivalent [`VersionReq`]
//! with redundant comparators removed, together with a [`SimplifyCert`] that
//! records, for every removed comparator, the containment clause that proves
//! the removal leaves the matched set unchanged.
//!
//! The simplifier is deliberately conservative. A comparator is removed only
//! when the remaining comparators can be *proved* to imply it, both at the
//! level of numeric version bounds and at the level of prerelease admission.
//! Combinations that cannot be proved are retained rather than guessed. The
//! proof is symbolic (interval containment over the version order), never a
//! matter of enumerating versions.

use crate::{Comparator, Op, Prerelease, VersionReq};
use alloc::vec::Vec;
use core::cmp::Ordering;

/// A point in the total order of versions, including the prerelease slot.
///
/// The prerelease is ordered with the empty prerelease (a real release) as the
/// greatest element of any given `(major, minor, patch)` tuple, matching the
/// ordering used by [`crate::Version`].
#[derive(Clone)]
struct Endpoint {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Prerelease,
}

impl Endpoint {
    fn new(major: u64, minor: u64, patch: u64, pre: Prerelease) -> Self {
        Endpoint {
            major,
            minor,
            patch,
            pre,
        }
    }

    fn release(major: u64, minor: u64, patch: u64) -> Self {
        Endpoint::new(major, minor, patch, Prerelease::EMPTY)
    }
}

impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then(self.pre.cmp(&other.pre))
    }
}

impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Endpoint {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Endpoint {}

/// The smallest non-empty prerelease identifier, `"0"`.
///
/// A numeric identifier is always less than a non-numeric one, and `"0"` is
/// the smallest numeric identifier, so this is the least element of the
/// prerelease order. It is used as the infimum of a tuple when a comparator at
/// `minor` or `major` granularity ranges over prereleases.
fn prerelease_floor() -> Prerelease {
    Prerelease::new("0").unwrap()
}

/// A possibly-empty interval of the version order.
///
/// Bounds are `(endpoint, inclusive)`. A `None` lower bound means `-∞` and a
/// `None` upper bound means `+∞`.
#[derive(Clone)]
struct Interval {
    lo: Option<(Endpoint, bool)>,
    hi: Option<(Endpoint, bool)>,
}

impl Interval {
    fn all() -> Self {
        Interval { lo: None, hi: None }
    }

    fn empty() -> Self {
        // An interval whose lower bound sits above its upper bound is empty.
        Interval {
            lo: Some((Endpoint::release(0, 0, 0), true)),
            hi: Some((Endpoint::release(0, 0, 0), false)),
        }
    }

    fn point(endpoint: Endpoint) -> Self {
        Interval {
            lo: Some((endpoint.clone(), true)),
            hi: Some((endpoint, true)),
        }
    }

    fn is_empty(&self) -> bool {
        match (&self.lo, &self.hi) {
            (None, _) | (_, None) => false,
            (Some((l, l_inc)), Some((h, h_inc))) => {
                l > h || (l == h && (!*l_inc || !*h_inc))
            }
        }
    }
}

/// Intersection of two intervals.
fn intersect(a: &Interval, b: &Interval) -> Interval {
    Interval {
        lo: max_lo(&a.lo, &b.lo),
        hi: min_hi(&a.hi, &b.hi),
    }
}

fn max_lo(a: &Option<(Endpoint, bool)>, b: &Option<(Endpoint, bool)>) -> Option<(Endpoint, bool)> {
    match (a, b) {
        (None, x) | (x, None) => x.clone(),
        (Some((ae, ai)), Some((be, bi))) => match ae.cmp(be) {
            Ordering::Less => Some((be.clone(), *bi)),
            Ordering::Greater => Some((ae.clone(), *ai)),
            Ordering::Equal => Some((ae.clone(), *ai && *bi)),
        },
    }
}

fn min_hi(a: &Option<(Endpoint, bool)>, b: &Option<(Endpoint, bool)>) -> Option<(Endpoint, bool)> {
    match (a, b) {
        (None, x) | (x, None) => x.clone(),
        (Some((ae, ai)), Some((be, bi))) => match ae.cmp(be) {
            Ordering::Less => Some((ae.clone(), *ai)),
            Ordering::Greater => Some((be.clone(), *bi)),
            Ordering::Equal => Some((ae.clone(), *ai && *bi)),
        },
    }
}

/// True if every point of `inner` is a point of `outer`.
fn contains(outer: &Interval, inner: &Interval) -> bool {
    if inner.is_empty() {
        return true;
    }
    if outer.is_empty() {
        return false;
    }

    // Outer lower bound must sit at or below inner lower bound.
    if let Some((ol, o_inc)) = &outer.lo {
        match &inner.lo {
            None => return false,
            Some((il, i_inc)) => {
                if ol > il {
                    return false;
                }
                if ol == il && !o_inc && *i_inc {
                    return false;
                }
            }
        }
    }

    // Inner upper bound must sit at or below outer upper bound.
    if let Some((oh, o_inc)) = &outer.hi {
        match &inner.hi {
            None => return false,
            Some((ih, i_inc)) => {
                if ih > oh {
                    return false;
                }
                if ih == oh && !o_inc && *i_inc {
                    return false;
                }
            }
        }
    }

    true
}

/// The release-level interval of a comparator: the set of versions with an
/// empty prerelease slot that the comparator matches.
///
/// These follow the documented equivalences of each operator on real releases.
fn release_interval(c: &Comparator) -> Interval {
    let (m, n, p) = (c.major, c.minor, c.patch);
    let pre = &c.pre;

    match c.op {
        Op::Exact | Op::Wildcard => match (n, p) {
            (Some(nn), Some(pp)) => {
                if pre.is_empty() {
                    Interval::point(Endpoint::release(m, nn, pp))
                } else {
                    Interval::empty()
                }
            }
            (Some(nn), None) => Interval {
                lo: Some((Endpoint::release(m, nn, 0), true)),
                hi: Some((Endpoint::release(m, nn + 1, 0), false)),
            },
            (None, _) => Interval {
                lo: Some((Endpoint::release(m, 0, 0), true)),
                hi: Some((Endpoint::release(m + 1, 0, 0), false)),
            },
        },

        Op::Greater => match (n, p) {
            (Some(nn), Some(pp)) => Interval {
                lo: Some((Endpoint::new(m, nn, pp, pre.clone()), false)),
                hi: None,
            },
            (Some(nn), None) => Interval {
                lo: Some((Endpoint::release(m, nn + 1, 0), true)),
                hi: None,
            },
            (None, _) => Interval {
                lo: Some((Endpoint::release(m + 1, 0, 0), true)),
                hi: None,
            },
        },

        Op::GreaterEq => match (n, p) {
            (Some(nn), Some(pp)) => Interval {
                lo: Some((Endpoint::new(m, nn, pp, pre.clone()), true)),
                hi: None,
            },
            (Some(nn), None) => Interval {
                lo: Some((Endpoint::release(m, nn, 0), true)),
                hi: None,
            },
            (None, _) => Interval {
                lo: Some((Endpoint::release(m, 0, 0), true)),
                hi: None,
            },
        },

        Op::Less => match (n, p) {
            (Some(nn), Some(pp)) => Interval {
                lo: None,
                hi: Some((Endpoint::new(m, nn, pp, pre.clone()), false)),
            },
            (Some(nn), None) => Interval {
                lo: None,
                hi: Some((Endpoint::release(m, nn, 0), false)),
            },
            (None, _) => Interval {
                lo: None,
                hi: Some((Endpoint::release(m, 0, 0), false)),
            },
        },

        Op::LessEq => match (n, p) {
            (Some(nn), Some(pp)) => Interval {
                lo: None,
                hi: Some((Endpoint::new(m, nn, pp, pre.clone()), true)),
            },
            (Some(nn), None) => Interval {
                lo: None,
                hi: Some((Endpoint::release(m, nn + 1, 0), false)),
            },
            (None, _) => Interval {
                lo: None,
                hi: Some((Endpoint::release(m + 1, 0, 0), false)),
            },
        },

        Op::Tilde => match (n, p) {
            (Some(nn), Some(pp)) => Interval {
                lo: Some((Endpoint::new(m, nn, pp, pre.clone()), true)),
                hi: Some((Endpoint::release(m, nn + 1, 0), false)),
            },
            (Some(nn), None) => Interval {
                lo: Some((Endpoint::release(m, nn, 0), true)),
                hi: Some((Endpoint::release(m, nn + 1, 0), false)),
            },
            (None, _) => Interval {
                lo: Some((Endpoint::release(m, 0, 0), true)),
                hi: Some((Endpoint::release(m + 1, 0, 0), false)),
            },
        },

        Op::Caret => match (n, p) {
            (Some(nn), Some(pp)) => {
                if m > 0 {
                    Interval {
                        lo: Some((Endpoint::new(m, nn, pp, pre.clone()), true)),
                        hi: Some((Endpoint::release(m + 1, 0, 0), false)),
                    }
                } else if nn > 0 {
                    Interval {
                        lo: Some((Endpoint::new(0, nn, pp, pre.clone()), true)),
                        hi: Some((Endpoint::release(0, nn + 1, 0), false)),
                    }
                } else if pre.is_empty() {
                    Interval::point(Endpoint::release(0, 0, pp))
                } else {
                    Interval::empty()
                }
            }
            (Some(nn), None) => {
                if m > 0 {
                    Interval {
                        lo: Some((Endpoint::release(m, nn, 0), true)),
                        hi: Some((Endpoint::release(m + 1, 0, 0), false)),
                    }
                } else if nn > 0 {
                    Interval {
                        lo: Some((Endpoint::release(0, nn, 0), true)),
                        hi: Some((Endpoint::release(0, nn + 1, 0), false)),
                    }
                } else {
                    Interval {
                        lo: Some((Endpoint::release(0, 0, 0), true)),
                        hi: Some((Endpoint::release(0, 1, 0), false)),
                    }
                }
            }
            (None, _) => Interval {
                lo: Some((Endpoint::release(m, 0, 0), true)),
                hi: Some((Endpoint::release(m + 1, 0, 0), false)),
            },
        },
    }
}

/// The full impl interval of a comparator: the set of *all* versions (both
/// releases and prereleases) for which the comparator's raw operator holds,
/// ignoring the global prerelease-admission rule.
///
/// This is used only to reason about prerelease coverage, where the distinction
/// between a release and a prerelease at the same tuple matters.
fn impl_interval(c: &Comparator) -> Interval {
    let (m, n, p) = (c.major, c.minor, c.patch);
    let pre = &c.pre;
    let floor = prerelease_floor();

    match c.op {
        Op::Exact | Op::Wildcard => match (n, p) {
            (Some(nn), Some(pp)) => Interval::point(Endpoint::new(m, nn, pp, pre.clone())),
            (Some(nn), None) => Interval {
                lo: Some((Endpoint::release(m, nn, 0), true)),
                hi: Some((Endpoint::release(m, nn + 1, 0), false)),
            },
            (None, _) => Interval {
                lo: Some((Endpoint::release(m, 0, 0), true)),
                hi: Some((Endpoint::release(m + 1, 0, 0), false)),
            },
        },

        Op::Greater => match (n, p) {
            (Some(nn), Some(pp)) => Interval {
                lo: Some((Endpoint::new(m, nn, pp, pre.clone()), false)),
                hi: None,
            },
            (Some(nn), None) => Interval {
                lo: Some((Endpoint::new(m, nn + 1, 0, floor), true)),
                hi: None,
            },
            (None, _) => Interval {
                lo: Some((Endpoint::new(m + 1, 0, 0, floor), true)),
                hi: None,
            },
        },

        Op::GreaterEq => match (n, p) {
            (Some(nn), Some(pp)) => Interval {
                lo: Some((Endpoint::new(m, nn, pp, pre.clone()), true)),
                hi: None,
            },
            (Some(nn), None) => Interval {
                lo: Some((Endpoint::release(m, nn, 0), true)),
                hi: None,
            },
            (None, _) => Interval {
                lo: Some((Endpoint::release(m, 0, 0), true)),
                hi: None,
            },
        },

        Op::Less => match (n, p) {
            (Some(nn), Some(pp)) => Interval {
                lo: None,
                hi: Some((Endpoint::new(m, nn, pp, pre.clone()), false)),
            },
            (Some(nn), None) => Interval {
                lo: None,
                hi: Some((Endpoint::new(m, nn, 0, floor), false)),
            },
            (None, _) => Interval {
                lo: None,
                hi: Some((Endpoint::new(m, 0, 0, floor), false)),
            },
        },

        Op::LessEq => match (n, p) {
            (Some(nn), Some(pp)) => Interval {
                lo: None,
                hi: Some((Endpoint::new(m, nn, pp, pre.clone()), true)),
            },
            (Some(nn), None) => Interval {
                lo: None,
                hi: Some((Endpoint::new(m, nn + 1, 0, floor), false)),
            },
            (None, _) => Interval {
                lo: None,
                hi: Some((Endpoint::new(m + 1, 0, 0, floor), false)),
            },
        },

        Op::Tilde => match (n, p) {
            (Some(nn), Some(pp)) => Interval {
                lo: Some((Endpoint::new(m, nn, pp, pre.clone()), true)),
                hi: Some((Endpoint::release(m, nn + 1, 0), false)),
            },
            (Some(nn), None) => Interval {
                lo: Some((Endpoint::release(m, nn, 0), true)),
                hi: Some((Endpoint::release(m, nn + 1, 0), false)),
            },
            (None, _) => Interval {
                lo: Some((Endpoint::release(m, 0, 0), true)),
                hi: Some((Endpoint::release(m + 1, 0, 0), false)),
            },
        },

        Op::Caret => match (n, p) {
            (Some(nn), Some(pp)) => {
                if m > 0 {
                    Interval {
                        lo: Some((Endpoint::new(m, nn, pp, pre.clone()), true)),
                        hi: Some((Endpoint::release(m + 1, 0, 0), false)),
                    }
                } else if nn > 0 {
                    Interval {
                        lo: Some((Endpoint::new(0, nn, pp, pre.clone()), true)),
                        hi: Some((Endpoint::release(0, nn + 1, 0), false)),
                    }
                } else {
                    // ^0.0.p matches the prerelease interval [pre, release]
                    // within the single tuple (0, 0, p).
                    Interval {
                        lo: Some((Endpoint::new(0, 0, pp, pre.clone()), true)),
                        hi: Some((Endpoint::release(0, 0, pp), true)),
                    }
                }
            }
            (Some(nn), None) => {
                if m > 0 {
                    Interval {
                        lo: Some((Endpoint::new(m, nn, 0, floor.clone()), true)),
                        hi: Some((Endpoint::release(m + 1, 0, 0), false)),
                    }
                } else if nn > 0 {
                    Interval {
                        lo: Some((Endpoint::new(0, nn, 0, floor.clone()), true)),
                        hi: Some((Endpoint::release(0, nn + 1, 0), false)),
                    }
                } else {
                    // ^0.0 matches every prerelease in the (0, 0, *) tuple.
                    Interval {
                        lo: Some((Endpoint::new(0, 0, 0, floor.clone()), true)),
                        hi: Some((Endpoint::new(0, 1, 0, floor), false)),
                    }
                }
            }
            (None, _) => {
                // ^I matches every version with major == I.
                Interval {
                    lo: Some((Endpoint::new(m, 0, 0, floor.clone()), true)),
                    hi: Some((Endpoint::new(m + 1, 0, 0, floor), false)),
                }
            }
        },
    }
}

/// The tuple `(major, minor, patch)` that a comparator is anchored to, if it
/// carries a non-empty prerelease tag.
///
/// A comparator with a non-empty prerelease is the *only* kind of comparator
/// that can admit prerelease versions, and it only admits them at the exact
/// `(major, minor, patch)` tuple it is written against.
fn prerelease_tuple(c: &Comparator) -> Option<(u64, u64, u64)> {
    if c.pre.is_empty() {
        None
    } else {
        Some((c.major, c.minor?, c.patch?))
    }
}

/// Decide whether comparator `candidate` is redundant given `others`.
///
/// Redundancy is proved symbolically:
///
/// 1. The release-level intersection of `others` must be contained in the
///    release-level interval of `candidate`.
/// 2. If `candidate` carries a prerelease tag at some tuple, then `others`
///    must also carry a prerelease tag at that same tuple, so that prerelease
///    admission is preserved.
/// 3. For every tuple at which `others` admits a prerelease, the versions at
///    that tuple satisfying all of `others` must also satisfy `candidate`.
///
/// If any clause cannot be discharged, the candidate is retained.
fn is_redundant(candidate: &Comparator, others: &[&Comparator]) -> bool {
    // Clause 1: numeric release bounds.
    let release_others = others
        .iter()
        .fold(Interval::all(), |acc, c| intersect(&acc, &release_interval(c)));
    if !contains(&release_interval(candidate), &release_others) {
        return false;
    }

    // Clause 2: prerelease admission must be preserved.
    if let Some(tuple) = prerelease_tuple(candidate) {
        let admitted = others.iter().any(|c| prerelease_tuple(c) == Some(tuple));
        if !admitted {
            return false;
        }
    }

    // Clause 3: prerelease coverage at every admitted tuple.
    let impl_others = others
        .iter()
        .fold(Interval::all(), |acc, c| intersect(&acc, &impl_interval(c)));
    let impl_candidate = impl_interval(candidate);

    let mut checked_tuples = Vec::new();
    for c in others {
        if let Some(tuple) = prerelease_tuple(c) {
            if checked_tuples.contains(&tuple) {
                continue;
            }
            checked_tuples.push(tuple);
            let tuple_interval = Interval {
                lo: Some((
                    Endpoint::new(tuple.0, tuple.1, tuple.2, prerelease_floor()),
                    true,
                )),
                hi: Some((Endpoint::release(tuple.0, tuple.1, tuple.2), true)),
            };
            let admitted = intersect(&impl_others, &tuple_interval);
            if !contains(&impl_candidate, &admitted) {
                return false;
            }
        }
    }

    true
}

/// The result of simplifying a [`VersionReq`].
#[derive(Clone, Debug)]
pub struct SimplifiedReq {
    /// The simplified requirement, semantically equivalent to the original.
    pub req: VersionReq,
    /// The per-step certificate recording every removed comparator.
    pub cert: SimplifyCert,
}

/// A certificate recording the comparators removed during simplification.
///
/// The certificate is independent of the simplifier that produced it: call
/// [`SimplifyCert::verify`] with the original [`VersionReq`] to re-check every
/// removal symbolically, without trusting the simplifier and without
/// enumerating versions.
#[derive(Clone, Debug)]
pub struct SimplifyCert {
    /// The removal steps, in the order they were applied.
    pub steps: Vec<SimplifyStep>,
}

/// A single removal step within a [`SimplifyCert`].
#[derive(Clone, Debug)]
pub struct SimplifyStep {
    /// The index of the removed comparator in the original requirement.
    pub removed_index: usize,
    /// The comparator that was removed.
    pub comparator: Comparator,
    /// The clause that proves the removal preserves the matched set.
    pub basis: Basis,
}

/// The containment clause that justifies a single removal.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Basis {
    /// The comparator is implied by the remaining comparators: their release
    /// bounds contain it, and its prerelease admission and coverage are
    /// preserved by the remaining comparators.
    ImpliedByBounds,
}

/// An error returned by [`SimplifyCert::verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertError {
    /// A step references an index that is out of range for the original
    /// requirement.
    IndexOutOfRange {
        /// The removed index recorded in the certificate.
        removed_index: usize,
        /// The number of comparators in the original requirement.
        len: usize,
    },
    /// The comparator recorded in the certificate does not match the original
    /// comparator at that index.
    ComparatorMismatch {
        /// The removed index recorded in the certificate.
        removed_index: usize,
    },
    /// The removal is not justified: the remaining comparators do not imply
    /// the removed one, so removing it would change the matched set.
    NotRedundant {
        /// The removed index recorded in the certificate.
        removed_index: usize,
    },
}

impl core::fmt::Display for CertError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CertError::IndexOutOfRange { removed_index, len } => write!(
                f,
                "certificate step references removed index {removed_index}, but the original requirement has {len} comparators"
            ),
            CertError::ComparatorMismatch { removed_index } => write!(
                f,
                "certificate comparator at removed index {removed_index} does not match the original"
            ),
            CertError::NotRedundant { removed_index } => write!(
                f,
                "certificate step at removed index {removed_index} is not justified by the remaining comparators"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CertError {}

impl SimplifyCert {
    /// The original indices of every comparator removed by the simplifier.
    pub fn removed_indices(&self) -> Vec<usize> {
        self.steps.iter().map(|s| s.removed_index).collect()
    }

    /// Independently verify every removal step against the *original*
    /// requirement.
    ///
    /// For each step, the verifier recomputes redundancy using the comparators
    /// that remain after all earlier steps, checking the same symbolic
    /// containment clauses as the simplifier. It does not trust the
    /// certificate's recorded comparator; it reads the original comparator at
    /// the recorded index and confirms the two agree.
    pub fn verify(&self, original: &VersionReq) -> Result<(), CertError> {
        let mut removed = Vec::new();
        for step in &self.steps {
            let idx = step.removed_index;
            if idx >= original.comparators.len() {
                return Err(CertError::IndexOutOfRange {
                    removed_index: idx,
                    len: original.comparators.len(),
                });
            }
            if original.comparators[idx] != step.comparator {
                return Err(CertError::ComparatorMismatch {
                    removed_index: idx,
                });
            }
            let others: Vec<&Comparator> = original
                .comparators
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != idx && !removed.contains(i))
                .map(|(_, c)| c)
                .collect();
            if !is_redundant(&original.comparators[idx], &others) {
                return Err(CertError::NotRedundant {
                    removed_index: idx,
                });
            }
            removed.push(idx);
        }
        Ok(())
    }
}

impl VersionReq {
    /// Simplify the requirement by removing comparators that can be proved
    /// redundant.
    ///
    /// A comparator is removed only when the remaining comparators imply it,
    /// both at the level of numeric version bounds and at the level of
    /// prerelease admission. Combinations that cannot be proved are retained.
    /// The returned [`SimplifyCert`] records every removal and can be
    /// independently verified against the original requirement via
    /// [`SimplifyCert::verify`].
    pub fn simplify(&self) -> SimplifiedReq {
        let mut removed = Vec::new();
        let mut steps = Vec::new();

        for (idx, candidate) in self.comparators.iter().enumerate() {
            let others: Vec<&Comparator> = self
                .comparators
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != idx && !removed.contains(i))
                .map(|(_, c)| c)
                .collect();
            if is_redundant(candidate, &others) {
                removed.push(idx);
                steps.push(SimplifyStep {
                    removed_index: idx,
                    comparator: candidate.clone(),
                    basis: Basis::ImpliedByBounds,
                });
            }
        }

        let comparators = self
            .comparators
            .iter()
            .enumerate()
            .filter(|(i, _)| !removed.contains(i))
            .map(|(_, c)| c.clone())
            .collect();

        SimplifiedReq {
            req: VersionReq { comparators },
            cert: SimplifyCert { steps },
        }
    }
}


//! Provably equivalent simplification of [`VersionReq`].
//!
//! This module implements an explicit simplifier for version requirements.
//! A comparator is removed **only** when it can be proven, by a purely
//! structural argument over the comparator itself, that removing it does not
//! change the set of versions matched by [`VersionReq::matches`]. The proof
//! never relies on enumerating candidate versions.
//!
//! Two things are checked for every removal:
//!
//! - **Numeric bounds.** Some other comparator that survives the
//!   simplification must imply the removed comparator for every possible
//!   version. This is decided by normalizing `>`, `>=`, `<`, `<=`
//!   comparators (including partial ones like `>=1.2`) into canonical
//!   half-open boundaries and comparing those boundaries. Overflowing
//!   boundaries (for example `>18446744073709551615`) and comparator shapes
//!   that do not reduce to a single boundary (for example `<=1.2`, which
//!   under Cargo prerelease semantics is not the same as `<1.3.0`) are
//!   treated as *unknown* and are always retained.
//!
//! - **Prerelease admission.** `VersionReq::matches` only admits a
//!   prerelease version if some comparator names the same
//!   `major.minor.patch` triple and carries a nonempty prerelease of its
//!   own. A comparator with a nonempty `pre` is therefore only removed when
//!   a retained comparator covers the exact same triple with a nonempty
//!   `pre`. Anything that cannot be proven is retained; nothing is guessed.
//!
//! Every removal is recorded as a [`SimplificationStep`] that cites the
//! *retained* comparator justifying it, so the emitted
//! [`SimplifyCertificate`] can be checked independently of the simplifier
//! through [`SimplifyCertificate::verify`]. Comparator order is preserved
//! and every kept comparator is traceable to its original index via
//! [`SimplifyCertificate::retained`].
//!
//! An empty match set is never confused with a universal one: a certificate
//! that erases every comparator of a nonempty requirement fails
//! verification, so an unsatisfiable requirement such as `>=2.0.0, <1.0.0`
//! can never be "simplified" into `*`.
//!
//! # Three-range examples
//!
//! | input | simplified | removed clause |
//! |---|---|---|
//! | `>=1.0, >=1.2, <2` | `>=1.2, <2` | redundant lower bound `>=1.0` |
//! | `>1.2.3, >=1.2.3, <2.0.0` | `>1.2.3, <2.0.0` | weaker lower bound `>=1.2.3` |
//! | `>=1.0, <2.0.0, <=2.0.0` | `>=1.0, <2.0.0` | weaker upper bound `<=2.0.0` |
//!
//! # Targeted commands
//!
//! ```text
//! cargo test --test test_simplify        # targeted acceptance tests
//! cargo test --doc simplify              # doc examples of this module
//! cargo test simplify                    # everything touching the simplifier
//! ```

use crate::{Comparator, Op, Prerelease, VersionReq};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// Why a comparator was provably redundant.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum RemovalJustification {
    /// The removed comparator is structurally identical to a retained one.
    Duplicate,
    /// A retained `>`/`>=` comparator expresses a lower bound at least as
    /// strong as the removed one.
    LowerBoundSubsumed,
    /// A retained `<`/`<=` comparator expresses an upper bound at least as
    /// strong as the removed one.
    UpperBoundSubsumed,
}

/// One certified removal step: the comparator at original index
/// [`removed`](#structfield.removed) was dropped because the *retained*
/// comparator at original index [`justified_by`](#structfield.justified_by)
/// provably implies it, and its prerelease admission (if any) is covered by
/// a retained comparator on the same `major.minor.patch` triple.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SimplificationStep {
    /// Index into the original `VersionReq::comparators` of the removed
    /// comparator.
    pub removed: usize,
    /// Index into the original `VersionReq::comparators` of a comparator
    /// that is retained in the simplified requirement and justifies the
    /// removal.
    pub justified_by: usize,
    /// The structural reason the removal preserves the matched set.
    pub justification: RemovalJustification,
}

/// Certificate that [`VersionReq::simplify`] produced an equivalent
/// requirement.
///
/// The certificate is self-contained: it carries the original comparators,
/// the per-step removal justifications, the original indices of the
/// retained comparators (in order), and the simplified requirement.
/// [`verify`](#method.verify) re-checks everything from the original
/// comparators alone, without trusting the simplifier and without
/// enumerating any versions.
#[derive(Clone, Debug)]
pub struct SimplifyCertificate {
    /// The requirement before simplification.
    pub original: VersionReq,
    /// The simplified requirement: exactly the retained comparators, in
    /// their original relative order.
    pub simplified: VersionReq,
    /// Original indices of the retained comparators, ascending.
    pub retained: Vec<usize>,
    /// One entry per removed comparator, each citing the retained
    /// comparator that justifies the removal.
    pub steps: Vec<SimplificationStep>,
}

impl SimplifyCertificate {
    /// Independently verify this certificate against the original
    /// comparators it carries.
    ///
    /// Returns `true` only if:
    ///
    /// - `retained` and the `removed` indices of `steps` form an exact
    ///   partition of the original comparator indices;
    /// - `simplified` consists of exactly the retained comparators, in
    ///   their original relative order;
    /// - every removal step is re-proven from the original comparators
    ///   (numeric bound subsumption or exact duplicate) and its prerelease
    ///   admission is covered by a retained comparator on the same triple;
    /// - a nonempty requirement is never reduced to the empty comparator
    ///   list, i.e. an empty match set is never passed off as the universal
    ///   range `*`.
    pub fn verify(&self) -> bool {
        let comps = &self.original.comparators;
        let n = comps.len();

        // `retained` must be strictly increasing and in range.
        if self.retained.windows(2).any(|w| w[0] >= w[1]) {
            return false;
        }
        if let Some(&last) = self.retained.last() {
            if last >= n {
                return false;
            }
        }

        // Step indices must be in range.
        for step in &self.steps {
            if step.removed >= n || step.justified_by >= n {
                return false;
            }
        }

        // Retained and removed indices must partition 0..n exactly.
        let mut covered = vec![false; n];
        for &i in &self.retained {
            covered[i] = true;
        }
        for step in &self.steps {
            if covered[step.removed] {
                return false;
            }
            covered[step.removed] = true;
        }
        if covered.iter().any(|&c| !c) {
            return false;
        }

        // A nonempty requirement must not collapse to the universal range:
        // an empty match set is never faked as `*`.
        if n > 0 && self.retained.is_empty() {
            return false;
        }

        // The simplified requirement must be exactly the retained
        // comparators, in original relative order.
        if self.simplified.comparators.len() != self.retained.len() {
            return false;
        }
        for (cmp, &i) in self.simplified.comparators.iter().zip(&self.retained) {
            if *cmp != comps[i] {
                return false;
            }
        }

        // Every step must be re-provable from the original comparators and
        // justified by a comparator that is itself retained.
        for step in &self.steps {
            if !self.retained.contains(&step.justified_by) {
                return false;
            }
            let a = &comps[step.justified_by];
            let b = &comps[step.removed];
            if justification(a, b) != Some(step.justification) {
                return false;
            }
            if !prerelease_admission_safe(b, comps, &self.retained) {
                return false;
            }
        }

        true
    }
}

pub(crate) fn simplify(req: &VersionReq) -> SimplifyCertificate {
    let comps = &req.comparators;
    let n = comps.len();
    let mut retained = vec![true; n];

    // Fixpoint: remove one comparator at a time while some other currently
    // retained comparator provably implies it and its prerelease admission
    // stays covered. At least one comparator always survives, so a nonempty
    // requirement can never collapse into the universal range here.
    loop {
        let mut removable = None;
        for b in 0..n {
            if !retained[b] {
                continue;
            }
            let implied = (0..n)
                .any(|a| a != b && retained[a] && justification(&comps[a], &comps[b]).is_some());
            if !implied {
                continue;
            }
            let kept: Vec<usize> = (0..n).filter(|&i| retained[i] && i != b).collect();
            if prerelease_admission_safe(&comps[b], comps, &kept) {
                removable = Some(b);
                break;
            }
        }
        match removable {
            Some(b) => retained[b] = false,
            None => break,
        }
    }

    let retained_idx: Vec<usize> = (0..n).filter(|&i| retained[i]).collect();

    // Emit one certificate step per removal, each justified by a comparator
    // that survives to the final result. Such a justifier always exists:
    // implication of comparators is transitive, so the justifier chain of
    // any removed comparator ends at a retained one.
    let mut steps = Vec::new();
    for b in (0..n).filter(|&i| !retained[i]) {
        let justifier = retained_idx
            .iter()
            .copied()
            .find(|&a| justification(&comps[a], &comps[b]).is_some());
        if let Some(a) = justifier {
            if let Some(reason) = justification(&comps[a], &comps[b]) {
                steps.push(SimplificationStep {
                    removed: b,
                    justified_by: a,
                    justification: reason,
                });
            }
        }
    }

    let simplified = VersionReq {
        comparators: retained_idx.iter().map(|&i| comps[i].clone()).collect(),
    };
    let cert = SimplifyCertificate {
        original: req.clone(),
        simplified,
        retained: retained_idx,
        steps,
    };

    // Defensive: never hand out a certificate that does not verify. Fall
    // back to the identity simplification (no removals) instead.
    if cert.verify() {
        cert
    } else {
        SimplifyCertificate {
            original: req.clone(),
            simplified: req.clone(),
            retained: (0..n).collect(),
            steps: Vec::new(),
        }
    }
}

/// Prerelease tag used in a normalized boundary key.
///
/// `Bottom` sits below every prerelease and represents the implicit lower
/// edge of a partial bound: `<1.2` excludes `1.2.0-alpha`, so its boundary
/// is `(1, 2, 0, Bottom)`, not `(1, 2, 0, <empty>)`.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
enum BoundPre {
    Bottom,
    Pre(Prerelease),
}

/// A normalized half-open boundary. The matched set of the comparator it
/// came from is exactly `{ v : key(v) > key }` plus `key` itself when
/// `inclusive` (for a lower boundary), or the mirror image for an upper
/// boundary, where `key(v) = (major, minor, patch, pre)`.
struct Boundary {
    major: u64,
    minor: u64,
    patch: u64,
    pre: BoundPre,
    inclusive: bool,
}

fn cmp_key(a: &Boundary, b: &Boundary) -> Ordering {
    (a.major, a.minor, a.patch, &a.pre).cmp(&(b.major, b.minor, b.patch, &b.pre))
}

/// Mirrors the documented invariants of `Comparator`: patch requires
/// minor, and a nonempty prerelease requires patch. Comparators that break
/// these invariants (only constructible by hand, never by the parser) are
/// treated as unknown.
fn has_valid_shape(cmp: &Comparator) -> bool {
    if cmp.patch.is_some() && cmp.minor.is_none() {
        return false;
    }
    if cmp.patch.is_none() && !cmp.pre.is_empty() {
        return false;
    }
    true
}

/// Normalize a `>`/`>=` comparator to its exact lower boundary, matching
/// `matches_impl` semantics precisely (including partial versions and
/// prerelease tags). Returns `None` for anything we do not prove things
/// about: other operators, invalid shapes, and overflowing boundaries.
fn lower_boundary(cmp: &Comparator) -> Option<Boundary> {
    if !has_valid_shape(cmp) {
        return None;
    }
    match cmp.op {
        Op::GreaterEq => Some(Boundary {
            major: cmp.major,
            minor: cmp.minor.unwrap_or(0),
            patch: cmp.patch.unwrap_or(0),
            pre: BoundPre::Pre(cmp.pre.clone()),
            inclusive: true,
        }),
        Op::Greater => match (cmp.minor, cmp.patch) {
            (Some(minor), Some(patch)) => Some(Boundary {
                major: cmp.major,
                minor,
                patch,
                pre: BoundPre::Pre(cmp.pre.clone()),
                inclusive: false,
            }),
            // `>1.2` matches exactly the versions `>= (1, 3, 0, Bottom)`.
            (Some(minor), None) => Some(Boundary {
                major: cmp.major,
                minor: minor.checked_add(1)?,
                patch: 0,
                pre: BoundPre::Bottom,
                inclusive: true,
            }),
            // `>1` matches exactly the versions `>= (2, 0, 0, Bottom)`.
            (None, None) => Some(Boundary {
                major: cmp.major.checked_add(1)?,
                minor: 0,
                patch: 0,
                pre: BoundPre::Bottom,
                inclusive: true,
            }),
            (None, Some(_)) => None, // invalid shape, rejected above
        },
        _ => None,
    }
}

/// Normalize a `<`/`<=` comparator to its exact upper boundary. `<=I.J`
/// and `<=I` are deliberately *not* normalized: under Cargo prerelease
/// semantics `<=1.2` is not a single half-open boundary (it is not
/// equivalent to `<1.3.0` as a comparator), so it stays unproven and is
/// only removable as an exact duplicate.
fn upper_boundary(cmp: &Comparator) -> Option<Boundary> {
    if !has_valid_shape(cmp) {
        return None;
    }
    match cmp.op {
        Op::Less => Some(Boundary {
            major: cmp.major,
            minor: cmp.minor.unwrap_or(0),
            patch: cmp.patch.unwrap_or(0),
            pre: match cmp.patch {
                Some(_) => BoundPre::Pre(cmp.pre.clone()),
                // `<1.2` / `<1` exclude every prerelease of the boundary
                // triple itself.
                None => BoundPre::Bottom,
            },
            inclusive: false,
        }),
        Op::LessEq => match (cmp.minor, cmp.patch) {
            (Some(minor), Some(patch)) => Some(Boundary {
                major: cmp.major,
                minor,
                patch,
                pre: BoundPre::Pre(cmp.pre.clone()),
                inclusive: true,
            }),
            _ => None,
        },
        _ => None,
    }
}

/// Decide whether comparator `a` provably implies comparator `b` for every
/// version, i.e. `matches_impl(a, v)` implies `matches_impl(b, v)`.
/// Purely structural; returns `None` ("unknown") whenever no proof
/// applies, in which case `b` must be retained.
fn justification(a: &Comparator, b: &Comparator) -> Option<RemovalJustification> {
    if a == b {
        return Some(RemovalJustification::Duplicate);
    }
    if let (Some(la), Some(lb)) = (lower_boundary(a), lower_boundary(b)) {
        // `a` matches a subset of `b` iff its boundary is higher, or the
        // boundaries coincide and `a` is not more inclusive than `b`.
        let ord = cmp_key(&la, &lb);
        if ord == Ordering::Greater
            || (ord == Ordering::Equal && (!la.inclusive || lb.inclusive))
        {
            return Some(RemovalJustification::LowerBoundSubsumed);
        }
    }
    if let (Some(ua), Some(ub)) = (upper_boundary(a), upper_boundary(b)) {
        let ord = cmp_key(&ua, &ub);
        if ord == Ordering::Less
            || (ord == Ordering::Equal && (!ua.inclusive || ub.inclusive))
        {
            return Some(RemovalJustification::UpperBoundSubsumed);
        }
    }
    None
}

/// Would removing `b` leave the prerelease-admission set of the
/// requirement unchanged? Admission only depends on comparators that have
/// an explicit patch and a nonempty prerelease, so a comparator without
/// either contributes nothing. Otherwise a retained comparator must cover
/// the exact same `major.minor.patch` triple with a nonempty prerelease.
fn prerelease_admission_safe(b: &Comparator, comps: &[Comparator], kept: &[usize]) -> bool {
    if b.pre.is_empty() || b.patch.is_none() {
        return true;
    }
    kept.iter().any(|&i| {
        let c = &comps[i];
        c.major == b.major && c.minor == b.minor && c.patch == b.patch && !c.pre.is_empty()
    })
}

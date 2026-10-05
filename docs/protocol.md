# Version requirement binary wire format

The `semver::codec` module serializes a `VersionReq` into a compact, versioned
binary frame and deserializes it back. It is designed so that the structural
difference between `^1`, `^1.2`, and `^1.2.0` is preserved: omitted `minor` /
`patch` components are recorded by presence bits rather than being padded with
zeroes, because padding changes both wildcard shape and pre-release matching.

## Limits

| Quantity | Limit | Constant |
|---|---|---|
| Protocol version | `1` | `codec::PROTOCOL_VERSION` |
| Comparator count | `0..=32` | `codec::MAX_COMPARATORS` |
| Pre-release length | `1..=255` bytes | `codec::MAX_PRERELEASE_LEN` |
| Max frame size | 9028 bytes (derived) | checked internally |

A comparator count of `0` encodes the `*` requirement (`VersionReq::STAR`).

## Frame layout (protocol version 1)

All integers are unsigned and big-endian.

```
+----------------+------------------+---------------------+------------------+
| magic "SV" (2) | version u8 (1)   | comparator count u8 | comparators ...  |
+----------------+------------------+---------------------+------------------+
```

| offset | size | field | value |
|---|---|---|---|
| 0 | 2 | magic | `53 56` (`SV`); mismatch -> `InvalidMagic` |
| 2 | 1 | protocol version | `1`; anything else -> `UnsupportedVersion` |
| 3 | 1 | comparator count | `0..=32`; larger -> `TooManyComparators` |
| 4 | N | comparators | exactly `count` encoded comparators |

Any bytes remaining after `count` comparators produce `TrailingBytes`; running
out of bytes early produces `UnexpectedEnd`. Decoding only constructs and
returns the `VersionReq` after every check passes, so errors never leak a
partially populated value.

## Comparator layout

```
+-------+---------+------------+-----------------+-----------------+------------------+
| op u8 | flags u8| major u64  | minor u64?      | patch u64?      | pre: len u8 + str|
+-------+---------+------------+-----------------+-----------------+------------------+
```

### Op codes

| code | operator |
|---|---|
| 0 | `=` Exact |
| 1 | `>` Greater |
| 2 | `>=` GreaterEq |
| 3 | `<` Less |
| 4 | `<=` LessEq |
| 5 | `~` Tilde |
| 6 | `^` Caret |
| 7 | Wildcard |

Any other op byte is rejected with `UnknownOp` before fields are accepted.

### Flags byte

| bit | name | meaning |
|---|---|---|
| 0 | `HAS_MINOR` | the `minor` u64 follows |
| 1 | `HAS_PATCH` | the `patch` u64 follows (implies `HAS_MINOR`) |
| 2 | `HAS_PRE` | a pre-release length-prefixed string follows (implies `HAS_PATCH`) |
| 3-7 | reserved | must be zero; otherwise `IllegalFlags` |

Field-combination rules, enforced on both encode and decode:

- `HAS_PATCH` without `HAS_MINOR` -> `IllegalCombination`.
- `HAS_PRE` without `HAS_PATCH` -> `IllegalCombination`.
- `HAS_PRE` with a zero length -> `IllegalCombination`.
- Wildcard op with a patch component -> `IllegalCombination` (wildcards can
  only be `I.*` / `I.J.*` shapes produced by the parser).

### Pre-release

When `HAS_PRE` is set, one length byte (`1..=255`) precedes the raw ASCII
bytes. The bytes are decoded as UTF-8 and validated by constructing a
`Prerelease` through the original grammar (dot-separated identifiers of ASCII
alphanumerics/hyphens, no empty segments, no leading-zero numeric segments).
Failure yields `InvalidPrerelease`.

## Representability verification

After the structural decode of each comparator, it is rendered with its
canonical `Display` form and re-parsed with the original `Comparator` parser;
the whole `VersionReq` is then re-rendered and re-parsed as well. If either
round trip fails or yields a different value, decoding fails with
`NotRepresentable`. This guards against a frame that is bytewise legal but not
a requirement the text parser could have produced.

## Worked example

`^1` (caret, major only) encodes to exactly 14 bytes:

```
53 56 01 01 06 00 00 00 00 00 00 00 00 01
`S `V  v  n  ^  fl -------- major 1 ------
```

`^1.2` would set `HAS_MINOR` and append an 8-byte minor; `^1.2.0` additionally
sets `HAS_PATCH` and appends `patch = 0`, so the three forms remain distinct.

## Cargo commands

Run the codec-focused tests (small, deterministic, no network needed after the
first build):

```sh
cargo test --lib codec
cargo test --test test_codec
```

Type-check and lint without running the benchmark harness:

```sh
cargo check --lib
cargo clippy --lib --all-features
```

Check the `no_std` build (the codec only needs `alloc`):

```sh
cargo build --lib --no-default-features
```

//! Encode and decode a version requirement through the binary codec.
//!
//! Run with:
//!
//! ```text
//! cargo run --example codec
//! ```

use semver::codec;
use semver::VersionReq;

fn main() {
    let req = VersionReq::parse(">=1.2.3, <1.8.0").unwrap();
    println!("original: {}", req);

    let bytes = codec::encode(&req).unwrap();
    println!("encoded:  {:?}", bytes);

    let decoded = codec::decode(&bytes).unwrap();
    println!("decoded:  {}", decoded);

    assert_eq!(req, decoded);
    println!("round trip preserved the requirement");
}

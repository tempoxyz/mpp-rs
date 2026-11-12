//! README.md shows the server quick start verbatim from
//! examples/axum-extractor/src/readme.rs, which CI builds.
//!
//! The example is its own package, so the published crate does not ship it;
//! the test only runs from the repository.

#[test]
fn readme_server_quick_start_matches_the_built_example() {
    let root = env!("CARGO_MANIFEST_DIR");
    let Ok(example) =
        std::fs::read_to_string(format!("{root}/examples/axum-extractor/src/readme.rs"))
    else {
        // Running from the packaged crate, which has no examples.
        return;
    };
    let readme = std::fs::read_to_string(format!("{root}/README.md")).unwrap();
    // The example's module docs come first; the README shows the code after them.
    let code = example.split_once("\n\n").map(|(_, code)| code).unwrap();
    assert!(
        readme.contains(&format!("```rust\n{code}```")),
        "README.md's server quick start differs from examples/axum-extractor/src/readme.rs"
    );
}

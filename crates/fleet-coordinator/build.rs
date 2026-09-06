//! Rebuild when the embedded web asset tree changes.
//!
//! `include_dir!` expands to one `include_bytes!` per file, so cargo already
//! rebuilds when an *existing* asset's contents change — but not when a file is
//! **added or removed**, because the macro's file list is baked into the
//! previous expansion. Without this, a contributor who adds `web/pages/foo.mjs`
//! gets a stale binary that 404s it and concludes the embedding is broken.
//!
//! It runs no node, no npm and no code generation: there is nothing here that
//! could make `cargo build` fail on a machine without a JavaScript toolchain,
//! which is `docs/web-ui.md` D3's whole point.
fn main() {
    println!("cargo:rerun-if-changed=web");
}

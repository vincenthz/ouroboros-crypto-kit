//! BLS12-381 primitives used by Plutus (CIP-0381).
//!
//! The public API is backend-independent. By default it uses the pure-Rust
//! `eccoxide` implementation; enabling the `blst` feature selects upstream
//! `blst`'s C/assembly implementation without changing callers.

#[cfg(all(feature = "blst", not(feature = "capi")))]
mod blst_backend;
#[cfg(any(not(feature = "blst"), feature = "capi"))]
mod rust_backend;

// Compile both implementations into native-backend unit tests so parity is
// checked directly, not merely against separate copies of the vector corpus.
#[cfg(all(test, feature = "blst", not(feature = "capi")))]
#[path = "rust_backend.rs"]
mod parity_rust_backend;

#[cfg(all(feature = "blst", not(feature = "capi")))]
pub use blst_backend::*;
#[cfg(any(not(feature = "blst"), feature = "capi"))]
pub use rust_backend::*;

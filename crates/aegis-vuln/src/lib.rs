//! Vulnerability lookup adapters. Port of `internal/infra/osv`.
//!
//! The OSV.dev client is split so the pure JSON→[`Advisory`] mapping and
//! the CVSS scoring can be unit-tested without a network round-trip; the
//! transport goes through the [`aegis_net::HttpClient`] seam.

pub mod osv;

pub use osv::OsvClient;

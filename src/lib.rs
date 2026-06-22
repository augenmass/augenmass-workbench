//! Augenmass Workbench: a swiss-army toolkit for the EUDI Wallet ecosystem.
//!
//! This crate is the binary `augenmass` plus a small library surface so the
//! commands can be unit-tested in isolation. The cryptographic and over-ask
//! engine lives in the sibling [`augenmass_core`] crate; everything here is the
//! I/O shell around it (argument parsing, file and network I/O, rendering).

/// The relying party we register under for the demo. One relying party per
/// entity, many certificates; never mint extra relying parties.
pub const DEFAULT_RP_ID: &str = "2af138a8-59ea-4a84-aea3-666cafdb1369";
/// A placeholder support contact for generated bodies (any non-empty string).
pub const DEFAULT_SUPPORT_URI: &str = "support@example.com";
/// A placeholder privacy policy URL for generated bodies (must be a valid URL).
pub const DEFAULT_PRIVACY_POLICY: &str = "https://example.com/privacy";
/// A placeholder purpose for generated bodies.
pub const DEFAULT_PURPOSE: &str = "Age verification";

pub mod artifact;
pub mod checkbody;
pub mod cli;
pub mod clone_server;
pub mod commands;
pub mod config;
pub mod dcql;
pub mod generator;
pub mod http_target;
pub mod jose;
pub mod output;
pub mod render;
pub mod x509util;

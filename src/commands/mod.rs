//! Command handlers. Each module owns one command group's logic; `cli` wires
//! them to the clap definitions and exit codes.

pub mod audit;
pub mod baselines;
pub mod cache;
pub mod check;
pub mod clone;
pub mod decode;
pub mod doctor;
pub mod evidence;
pub mod generate;
pub mod inspect;
pub mod register;
pub mod validate;
pub mod verify;
pub mod x509hash;

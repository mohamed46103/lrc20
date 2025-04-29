#![doc = include_str!("../README.md")]
pub mod traits;

mod impls;

pub use impls::postgres::{PgDatabase, PgDatabaseConnectionManager};

pub mod converters;
pub mod entities;

pub use entities::prelude::*;

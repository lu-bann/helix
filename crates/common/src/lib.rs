#![allow(ambiguous_glob_reexports)]
pub mod api;
pub mod beacon_api;
pub mod bid_submission;
pub mod builder_info;
pub mod chain_info;
pub mod config;
pub mod constraints;
pub mod eth;
pub mod pending_block;
pub mod proposer;
pub mod signing;
pub mod simulator;
pub mod traces;
pub mod validator;
pub mod validator_preferences;

pub use api::*;
pub use builder_info::*;
use chain_info::ChainInfo;
pub use config::*;
pub use eth::*;
pub use proposer::*;
pub use traces::*;
pub use validator::*;
pub use validator_preferences::*;

pub fn get_genesis_time_with_delay(chain_info: &ChainInfo) -> u64 {
    match chain_info.context.genesis_time() {
        Ok(genesis_time) => genesis_time,
        Err(_) => chain_info.context.min_genesis_time + chain_info.context.genesis_delay,
    }
}

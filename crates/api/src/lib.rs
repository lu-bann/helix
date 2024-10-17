#![allow(clippy::too_many_arguments)]

use helix_common::chain_info::ChainInfo;

pub mod builder;
pub mod constraints;
pub mod gossiper;
pub mod integration_tests;
pub mod middleware;
pub mod proposer;
pub mod relay_data;
pub mod router;
pub mod service;

#[cfg(test)]
pub mod test_utils;

mod grpc {
    include!(concat!(env!("OUT_DIR"), "/gossip.rs"));
}

pub fn get_genesis_time(chain_info: &ChainInfo) -> u64 {
    match chain_info.context.genesis_time() {
        Ok(genesis_time) => genesis_time,
        Err(_) => chain_info.context.min_genesis_time + chain_info.context.genesis_delay,
    }
}

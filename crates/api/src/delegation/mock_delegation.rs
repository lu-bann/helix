use async_trait::async_trait;
use ethereum_consensus::primitives::BlsPublicKey;
use helix_common::api::constraints_api::SignedPreconferElection;

use super::{error::Error, traits::DelegationTrait};

#[derive(Clone, Default)]
pub struct MockDelegation {}

#[async_trait]
impl DelegationTrait for MockDelegation {
    async fn get_preconfer_election(&self, _validator_pubkey: &BlsPublicKey, _slot: u64) -> Result<Option<SignedPreconferElection>, Error> {
        Ok(None)
    }
}

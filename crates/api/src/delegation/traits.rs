use async_trait::async_trait;
use ethereum_consensus::primitives::BlsPublicKey;
use helix_common::api::constraints_api::SignedPreconferElection;

use super::error::Error;

#[async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait DelegationTrait: Send + Sync + Clone {
    async fn get_preconfer_election(&self, validator_pubkey: &BlsPublicKey, slot: u64) -> Result<Option<SignedPreconferElection>, Error>;
}

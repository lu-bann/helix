use std::sync::Arc;

use alloy_provider::{
    fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    network::Ethereum,
    Identity, RootProvider,
};
use alloy_sol_types::sol;
use alloy_transport::BoxTransport;
use ethereum_consensus::primitives::{BlsPublicKey, BlsSignature};
use helix_common::api::constraints_api::{PreconferElection, SignedPreconferElection};
use reth_primitives::{Address, Bytes};
use TaiyiCore::TaiyiCoreInstance;

use super::{error::Error, traits::DelegationTrait};

const DEFAULT_GAS_LIMIT: u64 = 100_000;

type RecommendProvider = FillProvider<
    JoinFill<Identity, JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>>,
    RootProvider<BoxTransport>,
    BoxTransport,
    Ethereum,
>;

// solidity codes from https://github.com/lu-bann/taiyi/blob/b3dc7487e3c6b7e75b5223bcd36155f93cf74ea3/contracts/src/interfaces/IDelegationContract.sol#L36-L41
sol! {
    #[derive(Debug)]
    struct PreconferElectionRes {
        bytes validatorPubkey;
        bytes preconferPubkey;
        uint256 chainId;
        address preconferAddress;
    }

    #[sol(rpc)]
    contract TaiyiCore {
        #[derive(Debug)]
        function getPreconferElection(bytes calldata validatorPubKey) external view returns (PreconferElectionRes memory);
    }
}

#[derive(Clone)]
pub struct ContractDelegation {
    delegation_contract_address: Address,
    provider: RecommendProvider,
}

impl ContractDelegation {
    pub fn new(delegation_contract_address: Address, provider: RecommendProvider) -> Self {
        Self { delegation_contract_address, provider }
    }
}

#[async_trait::async_trait]
impl DelegationTrait for ContractDelegation {
    async fn get_preconfer_election(&self, validator_pubkey: &BlsPublicKey, slot: u64) -> Result<Option<SignedPreconferElection>, Error> {
        let pubkey = Bytes::from(validator_pubkey.as_ref().to_vec());
        let taiyi_core_contract = Arc::new(TaiyiCoreInstance::new(self.delegation_contract_address, self.provider.clone()));
        let preconfer_election =
            taiyi_core_contract.getPreconferElection(pubkey).call().await.map_err(|e| Error::GetPreconferElection(e.to_string()))?;
        if preconfer_election._0.preconferAddress.is_zero() {
            return Ok(None);
        }
        let signed_preconfer_election = SignedPreconferElection {
            message: PreconferElection {
                slot_number: slot,
                preconfer_pubkey: BlsPublicKey::try_from(preconfer_election._0.preconferPubkey.as_ref())
                    .map_err(|e| Error::BlsPublicKey(e.to_string()))?,
                proposer_pubkey: BlsPublicKey::try_from(preconfer_election._0.validatorPubkey.as_ref())
                    .map_err(|e| Error::BlsPublicKey(e.to_string()))?,
                chain_id: preconfer_election._0.chainId.to(),
                // gas limit is not used
                gas_limit: DEFAULT_GAS_LIMIT,
            },
            signature: BlsSignature::default(),
        };
        Ok(Some(signed_preconfer_election))
    }
}

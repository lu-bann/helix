use std::fmt::Debug;

use ethereum_consensus::{
    crypto::SecretKey,
    deneb::compute_fork_data_root,
    domains::DomainType,
    phase0::mainnet::compute_domain,
    primitives::{BlsPublicKey, BlsSignature, Domain, Root, Slot, Version},
    signing::{compute_signing_root, sign_with_domain, verify_signed_data},
    ssz::prelude::*,
    state_transition::Context,
    Error, Fork,
};
use tracing::info;

pub const COMMIT_BOOST_DOMAIN: [u8; 4] = [109, 109, 111, 67];

pub fn verify_signed_consensus_message<T: HashTreeRoot + Debug>(
    message: &mut T,
    signature: &BlsSignature,
    public_key: &BlsPublicKey,
    context: &Context,
    slot_hint: Option<Slot>,
    root_hint: Option<Root>,
) -> Result<(), Error> {
    let fork_version = slot_hint.map(|slot| match context.fork_for(slot) {
        Fork::Bellatrix => context.bellatrix_fork_version,
        Fork::Capella => context.capella_fork_version,
        Fork::Deneb => context.deneb_fork_version,
        _ => unimplemented!("Fork {:?} is not supported", context.fork_for(slot)),
    });
    let domain = compute_domain(DomainType::BeaconProposer, fork_version, root_hint, context).unwrap();
    verify_signed_data(message, signature, public_key, domain)?;
    Ok(())
}

pub fn verify_signed_builder_message<T: HashTreeRoot + Debug>(
    message: &mut T,
    signature: &BlsSignature,
    public_key: &BlsPublicKey,
    context: &Context,
) -> Result<(), Error> {
    let domain = compute_builder_domain(context)?;
    verify_signed_data(message, signature, public_key, domain)?;
    Ok(())
}

pub fn verify_signed_commit_boost_message<T: HashTreeRoot + Debug>(
    message: &mut T,
    signature: &BlsSignature,
    public_key: &BlsPublicKey,
    slot_hint: Option<Slot>,
    root_hint: Option<Root>,
    context: &Context,
) -> Result<(), Error> {
    let fork_version = slot_hint.map(|slot| context.fork_version_for(context.fork_for(slot)));
    let domain = compute_commit_boost_domain(fork_version, root_hint, context)?;
    info!(
        "message: {:?}, signature: {:?}, public_key: {:?}, slot: {:?}, root: {:?}, fork_version: {:?}, domain: {:?}",
        message, signature, public_key, slot_hint, root_hint, fork_version, domain
    );
    verify_signed_data(message, signature, public_key, domain)?;
    Ok(())
}

pub fn compute_consensus_signing_root<T: HashTreeRoot>(
    data: &mut T,
    slot: Slot,
    genesis_validators_root: &Root,
    context: &Context,
) -> Result<Root, Error> {
    let fork = context.fork_for(slot);
    let fork_version = context.fork_version_for(fork);
    let domain = compute_domain(DomainType::BeaconProposer, Some(fork_version), Some(*genesis_validators_root), context)?;
    compute_signing_root(data, domain)
}

pub fn sign_builder_message<T: HashTreeRoot>(message: &mut T, signing_key: &SecretKey, context: &Context) -> Result<BlsSignature, Error> {
    let domain = compute_builder_domain(context)?;
    sign_with_domain(message, signing_key, domain)
}

pub fn compute_builder_signing_root<T: HashTreeRoot>(data: &mut T, context: &Context) -> Result<Root, Error> {
    let domain = compute_builder_domain(context)?;
    compute_signing_root(data, domain)
}

pub fn compute_builder_domain(context: &Context) -> Result<Domain, Error> {
    let domain_type = DomainType::ApplicationBuilder;
    compute_domain(domain_type, None, None, context)
}

pub fn compute_commit_boost_domain(fork_version: Option<Version>, root_hint: Option<Root>, context: &Context) -> Result<Domain, Error> {
    let domain_type = COMMIT_BOOST_DOMAIN;
    compute_custom_domain(&domain_type, fork_version, root_hint, context)
}

pub fn compute_custom_domain(
    domain_mask: &[u8; 4],
    fork_version: Option<Version>,
    genesis_validators_root: Option<Root>,
    context: &Context,
) -> Result<Domain, Error> {
    let fork_version = fork_version.unwrap_or(context.genesis_fork_version);
    let genesis_validators_root = genesis_validators_root.unwrap_or_default();
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root)?;

    let mut domain = Domain::default();
    domain[..4].copy_from_slice(domain_mask);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use helix_common::api::constraints_api::PreconferElection;

    use super::*;
    // message: PreconferElection { preconfer_pubkey:
    // 0xa7c828460fc5c8d24c60f9f30c8836659b60a610fe8b87b26a71e9b765a9d0cae16b1a963f65b3b7abe264cda187c113, slot_number: 835907, chain_id: 7014190335,
    // gas_limit: 0 }, signature:
    // 0x98629270f8b4530d049bcbbdb207256c13ad08ad35561687c59cc78f72eb0471681bde0b9b01e809b83b8a633b48ecd0105b331542462654afe15bc194ae0a23074d295277690556b9ea088b127ff4f53dc521fd88b7e4dc90cbe29402bdc959,
    // public_key: 0xa1154f0998b62bbafff2d3c8e1be4d6486bd738bfa145acd4a666df4681aea8f04ef0ab8f36bfd453c9b3625cb11101e, slot: Some(835901), root:
    // Some(0x0000000000000000000000000000000000000000000000000000000000000000), fork_version: Some([80, 19, 39, 54]), domain: [109, 109, 111, 67, 39,
    // 93, 246, 220, 110, 148, 41, 177, 176, 182, 29, 202, 170, 76, 39, 89, 8, 31, 152, 206, 212, 71, 229, 96, 186, 162, 28, 164]
    const PRECONFER_PUBKEY: &str = "0xa7c828460fc5c8d24c60f9f30c8836659b60a610fe8b87b26a71e9b765a9d0cae16b1a963f65b3b7abe264cda187c113";
    const SLOT_NUMBER: u64 = 835907;
    const CHAIN_ID: u64 = 7014190335;
    const GAS_LIMIT: u64 = 0;
    // const FORK_VERSION: [u8; 4] = [80, 19, 39, 54];
    const DOMAIN: [u8; 32] = [
        109, 109, 111, 67, 39, 93, 246, 220, 110, 148, 41, 177, 176, 182, 29, 202, 170, 76, 39, 89, 8, 31, 152, 206, 212, 71, 229, 96, 186, 162, 28,
        164,
    ];
    const SIGNATURE: &str = "0x98629270f8b4530d049bcbbdb207256c13ad08ad35561687c59cc78f72eb0471681bde0b9b01e809b83b8a633b48ecd0105b331542462654afe15bc194ae0a23074d295277690556b9ea088b127ff4f53dc521fd88b7e4dc90cbe29402bdc959";
    const VALIDATOR_PUBKEY: &str = "0xa1154f0998b62bbafff2d3c8e1be4d6486bd738bfa145acd4a666df4681aea8f04ef0ab8f36bfd453c9b3625cb11101e";
    #[test]
    fn test_verify_cb_signature() {
        // use the following inputs:
        let message = PreconferElection {
            preconfer_pubkey: BlsPublicKey::try_from(hex::decode(PRECONFER_PUBKEY.trim_start_matches("0x")).unwrap().as_slice()).unwrap(),
            slot_number: SLOT_NUMBER,
            chain_id: CHAIN_ID,
            gas_limit: GAS_LIMIT,
        };
        let signature = BlsSignature::try_from(hex::decode(SIGNATURE.trim_start_matches("0x")).unwrap().as_slice()).unwrap();
        let public_key = BlsPublicKey::try_from(hex::decode(VALIDATOR_PUBKEY.trim_start_matches("0x")).unwrap().as_slice()).unwrap();
        let domain: Domain = DOMAIN;
        let result = verify_signed_data(&message, &signature, &BlsPublicKey::from(public_key), domain);
        println!("result: {:?}", result);
        // assert the result
        assert!(result.is_ok());
    }
}

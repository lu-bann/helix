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

pub const COMMIT_BOOST_DOMAIN: [u8; 4] = [109, 109, 111, 67];

pub fn verify_signed_consensus_message<T: HashTreeRoot>(
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

pub fn verify_signed_builder_message<T: HashTreeRoot>(
    message: &mut T,
    signature: &BlsSignature,
    public_key: &BlsPublicKey,
    context: &Context,
) -> Result<(), Error> {
    let domain = compute_builder_domain(context)?;
    verify_signed_data(message, signature, public_key, domain)?;
    Ok(())
}

pub fn verify_signed_commit_boost_message<T: HashTreeRoot>(
    message: &mut T,
    signature: &BlsSignature,
    public_key: &BlsPublicKey,
    _slot_hint: Option<Slot>,
    root_hint: Option<Root>,
    context: &Context,
) -> Result<(), Error> {
    // let fork_version = slot_hint.map(|slot| context.fork_version_for(context.fork_for(slot)));
    let fork_version = context.genesis_fork_version;
    let domain = compute_commit_boost_domain(Some(fork_version), root_hint, context)?;
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
    // DENEB_FORK_VERSION: 0x50132736
    // GENESIS_FORK_VERSION: 0x10000000
    // domain mask: [109, 109, 111, 67]
    // signing domain: [109, 109, 111, 67, 148, 196, 26, 244, 132, 255, 247, 150, 73, 105, 224, 189, 217, 34, 248, 45, 255, 15, 75, 232, 122, 96, 208,
    // 102, 76, 201, 209, 255]
    const PRECONFER_PUBKEY: &str = "0xa7c828460fc5c8d24c60f9f30c8836659b60a610fe8b87b26a71e9b765a9d0cae16b1a963f65b3b7abe264cda187c113";
    const SLOT_NUMBER: u64 = 836343;
    const CHAIN_ID: u64 = 7014190335;
    const GAS_LIMIT: u64 = 0;
    const DOMAIN: [u8; 32] = [
        109, 109, 111, 67, 148, 196, 26, 244, 132, 255, 247, 150, 73, 105, 224, 189, 217, 34, 248, 45, 255, 15, 75, 232, 122, 96, 208, 102, 76, 201,
        209, 255,
    ];
    const SIGNATURE: &str = "0xa40574565c4c6e0fa79595f62e459b515c8dece2bf9f55e8bc26fd4a7052d1983a3f665112e1a7ccf70aba84d19bf1f21355f5c7bb784f51d3600469aebf9010ee8292e2dd9224410dd437102283dc90e681ba5799ab8eed07283bbb9ac1193e";
    const VALIDATOR_PUBKEY: &str = "0xb07a8c8c3b4d265a909ceaed1e9c25e0799c5c65c9639c3edd81f9421982aa25088f0fe9453ec36ddf1ba6d024bef004";
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
        // assert the result
        assert!(result.is_ok());
    }
}

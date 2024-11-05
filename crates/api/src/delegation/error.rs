#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("error getting preconfer election: {0}")]
    GetPreconferElection(String),
    #[error("error parsing bls public key: {0}")]
    BlsPublicKey(String),
}

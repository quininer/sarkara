mod newhope;


pub trait KeyExchange {
    type PrivateKey;
    type PublicKey;
    type Reconciliation;

    fn keygen() -> (Self::PrivateKey, Self::PublicKey);
    fn exchange(sharedkey: &mut [u8], pk: &Self::PublicKey) -> Self::Reconciliation;
    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, rec: &Self::Reconciliation);
}

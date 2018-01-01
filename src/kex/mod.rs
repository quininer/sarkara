use rand::Rng;
use Packing;

pub mod kyber;


pub trait KeyExchange {
    type PrivateKey: Packing;
    type PublicKey: Packing;
    type Message: Packing;

    const SHARED_LENGTH: usize;

    fn kerpair<R: Rng>(r: R) -> (Self::PrivateKey, Self::PublicKey);

    /// TODO shouldbe `sharedkey: &mut [u8; Self::SHARED_LENGTH]`
    fn exchange_to<R: Rng>(r: R, sharedkey: &mut [u8], pk: &Self::PublicKey) -> Self::Message;

    /// TODO shouldbe `sharedkey: &mut [u8; Self::SHARED_LENGTH]`
    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, m: &Self::Message);
}

pub trait CheckedExchange: KeyExchange {
    fn checked_exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, m: &Self::Message) -> bool;
}

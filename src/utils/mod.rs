//! Sarkara utils.

pub mod nonce;

pub use self::nonce::GenNonce;


macro_rules! new_type {
    (
        $(#[$note:meta])*
        pub struct $name:ident ( pub $typ:ty ) ;
        from: ( $input_from:ident ) $from:block,
        into: ( $input_into:ident ) -> $output:ty $into:block
    ) => {
        $(#[$note])*
        pub struct $name(pub $typ);

        impl<T> TryFrom<T> for $name where T: AsRef<[u8]> {
            type Error = io::Error;
            fn try_from($input_from: T) -> io::Result<Self> {
                let $input_from = $input_from.as_ref();
                $from
            }
        }

        impl Into<$output> for $name {
            fn into($input_into) -> $output $into
        }
    }
}

macro_rules! err {
    ( $err:ident, $msg:expr ) => {
        Err(::std::io::Error::new(
            ::std::io::ErrorKind::$err,
            $msg
        ))
    }
}

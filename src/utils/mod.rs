//! Sarkara utils.

mod nonce;

pub use self::nonce::{ Nonce, RngCounter };


macro_rules! new_type {
    (
        $(#[$note:meta])*
        pub struct $name:ident ( pub $typ:ty ) ;
        from: ( $input_from:ident ) $from:block,
        into: ( $input_into:ident ) -> $output:ty $into:block
    ) => {
        $(#[$note])*
        pub struct $name(pub $typ);

        impl<'a> TryFrom<&'a [u8]> for $name {
            type Err = io::Error;
            fn try_from($input_from: &[u8]) -> io::Result<Self> $from
        }

        impl From<$name> for $output {
            fn from($input_into: $name) -> $output $into
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

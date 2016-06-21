mod secbytes;
mod bytes;

pub use self::secbytes::SecBytes;
pub use self::bytes::Bytes;


#[macro_export]
macro_rules! rand {
    ( choose $range:expr, $num:expr ) => {{
        use ::rand::{ OsRng, sample };
        sample(&mut OsRng::new().unwrap(), $range, $num)
    }};
    ( choose $range:expr ) => {
        rand!(choose $range, 1).remove(0)
    };
    ( _ ) => {{
        use ::rand::{ Rng, OsRng };
        OsRng::new().unwrap().gen()
    }};
    ( dy $len:expr ) => {{
        use ::rand::{ Rng, OsRng };
        OsRng::new().unwrap()
            .gen_iter()
            .take($len)
            .collect::<Vec<_>>()
    }};
    ( $len:expr ) => {{
        use ::rand::{ Rng, OsRng };
        let mut output = [0; $len];
        OsRng::new().unwrap().fill_bytes(&mut output);
        output
    }};
}

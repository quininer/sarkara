/// rand macro.
///
/// # `rand!( choose $range, $n )`
///
/// Randomly choose $n values in $range.
///
/// ```
/// extern crate rand;
/// #[macro_use] extern crate sarkara;
///
/// # fn main() {
/// let mut output = rand!(choose 0..3, 3);
/// output.sort();
/// assert_eq!(output, [0, 1, 2]);
/// # }
/// ```
///
/// # `rand!( choose $range )`
///
/// Randomly choose a value in $range.
///
/// ```
/// extern crate rand;
/// #[macro_use] extern crate sarkara;
///
/// # fn main() {
/// let output = rand!(choose 0..3);
/// assert!([0, 1, 2].contains(&output));
/// # }
/// ```
///
/// # `rand!( _ )`
///
/// Generating a random value, like `rand::random()`.
///
/// ```
/// extern crate rand;
/// #[macro_use] extern crate sarkara;
///
/// # fn main() {
/// let output: u8 = rand!(_);
/// assert!(std::u8::MIN <= output && std::u8::MAX >= output);
/// # }
/// ```
///
/// # `rand!( fill $vec )`
///
/// fill a slice.
///
/// ```
/// extern crate rand;
/// #[macro_use] extern crate sarkara;
///
/// # fn main() {
/// let mut input = [0; 8];
/// rand!(fill input);
/// assert!(input.iter().any(|&b| b != 0));
/// # }
/// ```
///
/// # `rand!( bytes $len )`
///
/// Generate a random `[u8; $len]`.
///
/// ```
/// extern crate rand;
/// #[macro_use] extern crate sarkara;
///
/// # fn main() {
/// let output = rand!(bytes 8);
/// assert_eq!(output.len(), 8);
/// # }
/// ```
///
/// # `rand!( $len )`
///
/// Generate a random `Vec<_>`.
///
/// ```
/// extern crate rand;
/// #[macro_use] extern crate sarkara;
///
/// # fn main() {
/// let mut output = rand!(8);
/// output.push(99);
/// assert_eq!(output.len(), 9);
/// # }
/// ```
#[macro_export]
macro_rules! rand {
    ( choose $range:expr, $n:expr ) => {{
        use ::rand::{ OsRng, sample };
        sample(&mut OsRng::new().unwrap(), $range, $n)
    }};
    ( choose $range:expr ) => {
        rand!(choose $range, 1).remove(0)
    };
    ( _ ) => {{
        use ::rand::{ Rng, OsRng };
        OsRng::new().unwrap().gen()
    }};
    ( fill $vec:expr ) => {{
        use ::rand::{ Rng, OsRng };
        OsRng::new().unwrap().fill_bytes(&mut $vec);
    }};
    ( bytes $len:expr ) => {{
        let mut output = [0; $len];
        rand!(fill output);
        output
    }};
    ( $len:expr ) => {{
        use ::rand::{ Rng, OsRng };
        OsRng::new().unwrap()
            .gen_iter()
            .take($len)
            .collect::<Vec<_>>()
    }};
}

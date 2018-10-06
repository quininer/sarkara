macro_rules! eq {
    ( $t:ident ) => {
        impl PartialEq<$t> for $t {
            fn eq(&self, rhs: &$t) -> bool {
                &self.0[..] == &rhs.0[..]
            }
        }

        impl Eq for $t {}
    };
}

macro_rules! packing {
    ( $t:ident ; $len:expr ) => {
        impl Packing for $t {
            const BYTES_LENGTH: usize = $len;

            fn read_bytes<T, F>(&self, f: F)
                -> T
                where F: FnOnce(&[u8]) -> T
            {
                f(&self.0)
            }

            fn from_bytes(buf: &[u8]) -> Self {
                let buf = arrayref::array_ref!(buf, 0, $len);
                let mut pk = [0; $len];
                pk.clone_from(buf);
                $t(pk)
            }
        }
    };
}

#[cfg(feature = "serde")]
macro_rules! serde {
    ( $t:ident ) => {
        impl Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where S: Serializer
            {
                self.read_bytes(|bytes| serializer.serialize_bytes(bytes))
            }
        }

        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where D: Deserializer<'de>
            {
                struct BytesVisitor;

                impl<'de> Visitor<'de> for BytesVisitor {
                    type Value = $t;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("a valid point in Ristretto format")
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                        where E: de::Error
                    {
                        if v.len() == $t::BYTES_LENGTH {
                            Ok($t::from_bytes(v))
                        } else {
                            Err(de::Error::invalid_length(v.len(), &self))
                        }
                    }
                }

                deserializer.deserialize_bytes(BytesVisitor)
            }
        }
    }
}

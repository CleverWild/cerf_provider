macro_rules! const_length {
    ($name:ident $bytes_size:expr) => {
        pub struct $name;
        impl $name {
            pub const BYTES: usize = $bytes_size;
            pub const BITS: usize = Self::BYTES * 8;
        }
    };
}

const_length!(KeyPair 0x200);
const_length!(PubKey KeyPair::BYTES / 2);
const_length!(PrivKey KeyPair::BYTES / 2);
const_length!(Signature 0x80);
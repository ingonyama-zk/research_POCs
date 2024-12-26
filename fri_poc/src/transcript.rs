use std::fmt::Pointer;

use merlin::Transcript;
use icicle_core::{
    field::Field, hash::Hasher, traits::{Arithmetic, FieldConfig, FieldImpl, GenerateRandom}};

pub trait TranscriptProtocol<F:FieldImpl> {
    fn fri_domain_sep(&mut self, domain_seprator: &'static [u8],init_domain_size: u64, public: Vec<u8>);
    /// Append a `scalar` with the given `label`.
    fn append_root(&mut self, label: &'static [u8], scalar: &F);
    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> F;
}

impl<F: FieldImpl> TranscriptProtocol<F> for Transcript {

    fn fri_domain_sep(&mut self, domain_seperator:&'static [u8], init_domain_size: u64, public: Vec<u8>) {
        self.append_message(b"", domain_seperator);
        self.append_u64(b"Init_Domain_Size", init_domain_size);
        self.append_message(b"public", &public);
    }

    fn append_root(&mut self, label: &'static [u8], scalar: &F) {
        self.append_message(label, &scalar.to_bytes_le());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> F {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        F::from_bytes_le(&buf)
    }
}

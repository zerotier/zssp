// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

pub const SHA512_HASH_SIZE: usize = 64;

pub trait Sha512 {
    fn new() -> Self;

    fn reset(&mut self);

    fn update(&mut self, input: &[u8]);

    fn finish(&mut self, output: &mut [u8; SHA512_HASH_SIZE]);
}

pub trait HmacSha512 {
    fn new(key: &[u8]) -> Self;

    fn reset(&mut self, key: &[u8]);

    fn update(&mut self, input: &[u8]);

    fn finish(&mut self, output: &mut [u8; SHA512_HASH_SIZE]);
}

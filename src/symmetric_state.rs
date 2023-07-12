/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
use std::marker::PhantomData;

use crate::crypto::aes::AES_256_KEY_SIZE;
use crate::crypto::secret::Secret;
use crate::crypto::sha512::HmacSha512;

use crate::proto::NOISE_HASHLEN;

pub(crate) struct SymmetricState<Hmac: HmacSha512> {
    chaining_key: Secret<NOISE_HASHLEN>,
    token_counter: u8,
    p: PhantomData<Hmac>,
}
impl<Hmac: HmacSha512> Clone for SymmetricState<Hmac> {
    fn clone(&self) -> Self {
        Self {
            chaining_key: self.chaining_key.clone(),
            token_counter: self.token_counter.clone(),
            p: PhantomData,
        }
    }
}

impl<Hmac: HmacSha512> SymmetricState<Hmac> {
    pub(crate) fn new(h: [u8; NOISE_HASHLEN]) -> Self {
        Self { chaining_key: Secret(h), token_counter: b'P', p: PhantomData }
    }
    /// Corresponds to Noise `MixKey`.
    pub(crate) fn mix_key(&mut self, input_key_material: &[u8]) {
        let mut next_ck = Secret::new();

        self.kbkdf(input_key_material, self.label(), 2, next_ck.as_mut(), None, None);
        self.token_counter += 1;

        self.chaining_key.overwrite(&next_ck);
        // We don't need a key at this step of Noise, so generating that key and calling
        // `InitializeKey` would be completely pointless.
    }
    /// Corresponds to Noise `MixKey` followed by `InitializeKey`.
    #[inline(always)]
    pub(crate) fn mix_key_initialize_key(&mut self, input_key_material: &[u8]) -> Secret<AES_256_KEY_SIZE> {
        let mut next_ck = Secret::new();
        let mut temp_k = [0u8; NOISE_HASHLEN];

        self.kbkdf(input_key_material, self.label(), 2, next_ck.as_mut(), Some(&mut temp_k), None);
        self.token_counter += 1;

        self.chaining_key.overwrite(&next_ck);
        Secret::from_bytes_then_nuke(&mut temp_k[..AES_256_KEY_SIZE])
    }
    /// Corresponds to Noise `MixKeyAndHash`.
    pub(crate) fn mix_key_and_hash(&mut self, input_key_material: &[u8]) -> [u8; NOISE_HASHLEN] {
        let mut next_ck = Secret::new();
        let mut temp_h = [0u8; NOISE_HASHLEN];

        self.kbkdf(input_key_material, self.label(), 3, next_ck.as_mut(), Some(&mut temp_h), None);
        self.token_counter += 1;

        self.chaining_key.overwrite(&next_ck);
        temp_h
    }
    /// Corresponds to Noise `MixKeyAndHash` followed by `InitializeKey`.
    pub(crate) fn mix_key_and_hash_initialize_key(&mut self, input_key_material: &[u8]) -> ([u8; NOISE_HASHLEN], Secret<AES_256_KEY_SIZE>) {
        let mut next_ck = Secret::new();
        let mut temp_h = [0u8; NOISE_HASHLEN];
        let mut temp_k = [0u8; NOISE_HASHLEN];

        self.kbkdf(
            input_key_material,
            self.label(),
            3,
            next_ck.as_mut(),
            Some(&mut temp_h),
            Some(&mut temp_k),
        );
        self.token_counter += 1;

        self.chaining_key.overwrite(&next_ck);
        (temp_h, Secret::from_bytes_then_nuke(&mut temp_k[..AES_256_KEY_SIZE]))
    }
    /// Get an additional symmetric key (ASK) that is a collision resistant hash of the transcript,
    /// is forward secrect and is cryptographically independent from all other produced keys.
    /// Based on Noise's unstable ASK mechanism, using KBKDF instead of HKDF.
    /// https://github.com/noiseprotocol/noise_wiki/wiki/Additional-Symmetric-Keys.
    #[inline(always)]
    pub(crate) fn get_ask2(&self, label: u8, noise_h: &[u8; NOISE_HASHLEN]) -> (Secret<AES_256_KEY_SIZE>, Secret<AES_256_KEY_SIZE>) {
        let mut temp_k1 = [0u8; NOISE_HASHLEN];
        let mut temp_k2 = [0u8; NOISE_HASHLEN];
        self.kbkdf(noise_h, [b'A', b'S', b'K', label], 2, &mut temp_k1, Some(&mut temp_k2), None);
        (
            Secret::from_bytes_then_nuke(&mut temp_k1[..AES_256_KEY_SIZE]),
            Secret::from_bytes_then_nuke(&mut temp_k2[..AES_256_KEY_SIZE]),
        )
    }
    /// Corresponds to Noise `Split`.
    #[inline(always)]
    pub(crate) fn split(self) -> (Secret<AES_256_KEY_SIZE>, Secret<AES_256_KEY_SIZE>) {
        let mut temp_k1 = [0u8; NOISE_HASHLEN];
        let mut temp_k2 = [0u8; NOISE_HASHLEN];
        self.kbkdf(&[], self.label(), 2, &mut temp_k1, Some(&mut temp_k2), None);
        // Normally KBKDF would not truncate to derive the correct length of AES keys,
        // but Noise specifies that the AES keys be truncated from NOISE_HASHLEN to AES_256_KEY_SIZE.
        (
            Secret::from_bytes_then_nuke(&mut temp_k1[..AES_256_KEY_SIZE]),
            Secret::from_bytes_then_nuke(&mut temp_k2[..AES_256_KEY_SIZE]),
        )
    }
    #[inline(always)]
    fn label(&self) -> [u8; 4] {
        [b'Z', b'S', b'S', self.token_counter]
    }
    /// HMAC-SHA512 key derivation based on KBKDF Counter Mode:
    /// https://csrc.nist.gov/publications/detail/sp/800-108/rev-1/final.
    /// Cryptographically this isn't meaningfully different from
    /// `HKDF(self.chaining_key, input_key_material)` but this is how NIST rolls.
    /// These are the values we have assigned to the 4 variables involved in their KDF:
    /// * K_IN = `input_key_material`
    /// * Label = `label`
    /// * Context = `self.chaining_key`
    /// * L = `num_outputs*512u16`
    /// We have intentionally made every input small and fixed size to avoid unnecessary complexity
    /// and data representation ambiguity.
    #[inline(always)]
    fn kbkdf(
        &self,
        input_key_material: &[u8],
        label: [u8; 4],
        num_outputs: u16,
        output1: &mut [u8; NOISE_HASHLEN],
        output2: Option<&mut [u8; NOISE_HASHLEN]>,
        output3: Option<&mut [u8; NOISE_HASHLEN]>,
    ) {
        let l = &(num_outputs * 512u16).to_be_bytes();

        let mut hm = Hmac::new(input_key_material);
        hm.update(&[1, label[0], label[1], label[2], label[3], 0x00]);
        hm.update(self.chaining_key.as_ref());
        hm.update(l);
        hm.finish(output1);
        if let Some(output2) = output2 {
            hm.reset(input_key_material);
            hm.update(&[2, label[0], label[1], label[2], label[3], 0x00]);
            hm.update(self.chaining_key.as_ref());
            hm.update(l);
            hm.finish(output2);
        }
        if let Some(output3) = output3 {
            hm.reset(input_key_material);
            hm.update(&[3, label[0], label[1], label[2], label[3], 0x00]);
            hm.update(self.chaining_key.as_ref());
            hm.update(l);
            hm.finish(output3);
        }
    }
}

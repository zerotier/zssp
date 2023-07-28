use std::marker::PhantomData;

use crate::ApplicationLayer;
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
use crate::crypto::aes::AES_256_KEY_SIZE;
use crate::crypto::aes_gcm::{AesGcmAead, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE};
use crate::crypto::secret::Secret;

use crate::crypto::sha512::{HmacSha512, Sha512};
use crate::proto::HASHLEN;

#[derive(Clone)]
pub struct SymmetricState<App: ApplicationLayer> {
    k: Secret<AES_256_KEY_SIZE>,
    ck: Secret<HASHLEN>,
    h: [u8; HASHLEN],
    label: u32,
    _h: PhantomData<*const App>,
}

impl<App: ApplicationLayer> SymmetricState<App> {
    pub fn initialize(h: [u8; HASHLEN]) -> Self {
        Self {
            k: Secret::new(),
            ck: Secret(h),
            h,
            label: u32::from_be_bytes(*b"ZSSP"),
            _h: PhantomData,
        }
    }
    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let mut next_ck = Secret::new();
        let mut temp_k = Secret::new();

        self.kbkdf(
            input_key_material,
            self.label.to_be_bytes(),
            2,
            next_ck.as_mut(),
            Some(temp_k.as_mut()),
            None,
        );
        self.label += 1;

        self.ck.overwrite(&next_ck);
        self.k.overwrite_first_n(&temp_k);
    }
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hash = App::Hash::new();
        hash.update(&self.h);
        hash.update(data);
        hash.finish(&mut self.h);
    }
    pub fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
        let mut next_ck = Secret::new();
        let mut temp_h = [0u8; HASHLEN];
        let mut temp_k = Secret::new();

        self.kbkdf(
            input_key_material,
            self.label.to_be_bytes(),
            3,
            next_ck.as_mut(),
            Some(&mut temp_h),
            Some(temp_k.as_mut()),
        );
        self.label += 1;

        self.ck.overwrite(&next_ck);
        self.mix_hash(&temp_h);
        self.k.overwrite_first_n(&temp_k);
    }
    pub fn encrypt_and_hash(&mut self, iv: [u8; AES_GCM_IV_SIZE], plaintext_start: usize, buffer: &mut Vec<u8>) {
        let tag = App::Aead::encrypt_in_place(self.k.as_ref(), iv, Some(&self.h), &mut buffer[plaintext_start..]);
        buffer.extend(&tag);
        let mut hash = App::Hash::new();
        hash.update(&buffer[plaintext_start..]);
        hash.finish(&mut self.h);
    }
    #[must_use]
    pub fn decrypt_and_hash(&mut self, iv: [u8; AES_GCM_IV_SIZE], buffer: &mut [u8], tag: [u8; AES_GCM_TAG_SIZE]) -> bool {
        let mut hash = App::Hash::new();
        hash.update(buffer);
        hash.update(&tag);
        let ret = App::Aead::decrypt_in_place(self.k.as_ref(), iv, Some(&self.h), buffer, tag);
        hash.finish(&mut self.h);
        ret
    }
    /// Corresponds to Noise `Split`.
    pub fn split(self) -> (Secret<AES_256_KEY_SIZE>, Secret<AES_256_KEY_SIZE>) {
        let mut temp_k1 = [0u8; HASHLEN];
        let mut temp_k2 = [0u8; HASHLEN];
        self.kbkdf(&[], self.label.to_be_bytes(), 2, &mut temp_k1, Some(&mut temp_k2), None);
        // Normally KBKDF would not truncate to derive the correct length of AES keys,
        // but Noise specifies that the AES keys be truncated from HASHLEN to AES_256_KEY_SIZE.
        (
            Secret::from_bytes_then_delete(&mut temp_k1[..AES_256_KEY_SIZE]),
            Secret::from_bytes_then_delete(&mut temp_k2[..AES_256_KEY_SIZE]),
        )
    }
    /// Get an additional symmetric key (ASK) that is a collision resistant hash of the transcript,
    /// is forward secrect and is cryptographically independent from all other produced keys.
    /// Based on Noise's unstable ASK mechanism, using KBKDF instead of HKDF.
    /// https://github.com/noiseprotocol/noise_wiki/wiki/Additional-Symmetric-Keys.
    pub fn get_ask(&self, label: &[u8; 4]) -> (Secret<AES_256_KEY_SIZE>, Secret<AES_256_KEY_SIZE>) {
        let mut temp_k1 = [0u8; HASHLEN];
        let mut temp_k2 = [0u8; HASHLEN];
        self.kbkdf(&self.h, *label, 2, &mut temp_k1, Some(&mut temp_k2), None);
        (
            Secret::from_bytes_then_delete(&mut temp_k1[..AES_256_KEY_SIZE]),
            Secret::from_bytes_then_delete(&mut temp_k2[..AES_256_KEY_SIZE]),
        )
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
    fn kbkdf(
        &self,
        input_key_material: &[u8],
        label: [u8; 4],
        num_outputs: u16,
        output1: &mut [u8; HASHLEN],
        output2: Option<&mut [u8; HASHLEN]>,
        output3: Option<&mut [u8; HASHLEN]>,
    ) {
        let l = &(num_outputs * 512u16).to_be_bytes();

        let mut hm = App::HmacHash::new(input_key_material);
        hm.update(&[1, label[0], label[1], label[2], label[3], 0x00]);
        hm.update(self.ck.as_ref());
        hm.update(l);
        hm.finish(output1);
        if let Some(output2) = output2 {
            let mut hm = App::HmacHash::new(input_key_material);
            hm.update(&[2, label[0], label[1], label[2], label[3], 0x00]);
            hm.update(self.ck.as_ref());
            hm.update(l);
            hm.finish(output2);
        }
        if let Some(output3) = output3 {
            let mut hm = App::HmacHash::new(input_key_material);
            hm.update(&[3, label[0], label[1], label[2], label[3], 0x00]);
            hm.update(self.ck.as_ref());
            hm.update(l);
            hm.finish(output3);
        }
    }
}

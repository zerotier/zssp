use std::marker::PhantomData;

use crate::ApplicationLayer;
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
use crate::crypto::{AeadAesGcm, HashSha512, Secret, AES_256_KEY_SIZE, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE};
use crate::proto::HASHLEN;

pub struct SymmetricState<App: ApplicationLayer> {
    k: Secret<AES_256_KEY_SIZE>,
    ck: Secret<HASHLEN>,
    h: [u8; HASHLEN],
    label: u32,
    _app: PhantomData<*const App::Hash>,
}
impl<App: ApplicationLayer> Clone for SymmetricState<App> {
    fn clone(&self) -> Self {
        Self {
            k: self.k.clone(),
            ck: self.ck.clone(),
            h: self.h.clone(),
            label: self.label.clone(),
            _app: PhantomData,
        }
    }
}

const KBKDF_LABEL_START: usize = 1;
const KBKDF_LABEL_END: usize = KBKDF_LABEL_START + 4;
const KBKDF_CONTEXT_START: usize = KBKDF_LABEL_END + 1;
const KBKDF_LENGTH_START: usize = KBKDF_CONTEXT_START + HASHLEN;
const KBKDF_INPUT_SIZE: usize = KBKDF_LENGTH_START + 2;
const HASHLEN_BITS: usize = HASHLEN * 8;

impl<App: ApplicationLayer> SymmetricState<App> {
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
        let mut buffer = Secret::<KBKDF_INPUT_SIZE>::new();
        let buffer: &mut [u8] = buffer.as_mut();
        buffer[0] = 1;
        buffer[KBKDF_LABEL_START..KBKDF_LABEL_END].copy_from_slice(&label);
        buffer[KBKDF_LABEL_END] = 0x00;
        buffer[KBKDF_CONTEXT_START..KBKDF_LENGTH_START].copy_from_slice(self.ck.as_ref());
        buffer[KBKDF_LENGTH_START..].copy_from_slice(&(num_outputs * HASHLEN_BITS as u16).to_be_bytes());

        debug_assert!(num_outputs >= 1);
        *output1 = App::Hash::hmac(input_key_material, &buffer);

        if let Some(output2) = output2 {
            debug_assert!(num_outputs >= 2);
            buffer[0] = 2;
            *output2 = App::Hash::hmac(input_key_material, &buffer);
        }

        if let Some(output3) = output3 {
            debug_assert!(num_outputs >= 3);
            buffer[0] = 3;
            *output3 = App::Hash::hmac(input_key_material, &buffer);
        }
    }

    pub fn initialize(h: [u8; HASHLEN]) -> Self {
        Self {
            k: Secret::new(),
            ck: Secret(h),
            h,
            label: u32::from_be_bytes(*b"ZSSP"),
            _app: PhantomData,
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
        self.h = hash.finish();
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
    pub fn encrypt_and_hash_in_place(&mut self, iv: [u8; AES_GCM_IV_SIZE], plaintext_start: usize, buffer: &mut Vec<u8>) {
        let tag = App::Aead::encrypt_in_place(self.k.as_ref(), iv, Some(&self.h), &mut buffer[plaintext_start..]);
        buffer.extend(&tag);
        let mut hash = App::Hash::new();
        hash.update(&buffer[plaintext_start..]);
        self.h = hash.finish();
    }
    #[must_use]
    pub fn decrypt_and_hash_in_place(&mut self, iv: [u8; AES_GCM_IV_SIZE], buffer: &mut [u8], tag: [u8; AES_GCM_TAG_SIZE]) -> bool {
        let mut hash = App::Hash::new();
        hash.update(buffer);
        hash.update(&tag);
        let ret = App::Aead::decrypt_in_place(self.k.as_ref(), iv, Some(&self.h), buffer, tag);
        self.h = hash.finish();
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
    /// Used for internally debugging a key exchange.
    #[allow(unused)]
    pub(crate) fn finger(&self) -> (u8, u8, u8) {
        (self.k.as_bytes()[0], self.ck.as_bytes()[0], self.h[0])
    }
}

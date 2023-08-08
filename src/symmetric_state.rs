use std::marker::PhantomData;

use zeroize::Zeroizing;

use crate::application::ApplicationLayer;
use crate::crypto::*;
use crate::proto::*;

pub struct SymmetricState<App: ApplicationLayer> {
    k: Zeroizing<[u8; AES_256_KEY_SIZE]>,
    ck: Zeroizing<[u8; HASHLEN]>,
    h: [u8; HASHLEN],
    /// If anyone knows a better way to get rid of the "parameter `App` is never used" error please
    /// let me know.
    _app: PhantomData<fn() -> App::SessionData>,
}
impl<App: ApplicationLayer> Clone for SymmetricState<App> {
    fn clone(&self) -> Self {
        Self {
            k: self.k.clone(),
            ck: self.ck.clone(),
            h: self.h.clone(),
            _app: PhantomData,
        }
    }
}

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
    /// Corresponds to Noise `HKDF`.
    fn kbkdf(
        &self,
        hmac: &mut App::HmacHash,
        input_key_material: &[u8],
        label: &[u8; 4],
        num_outputs: u16,
        output1: &mut [u8; HASHLEN],
        output2: Option<&mut [u8; HASHLEN]>,
        output3: Option<&mut [u8; HASHLEN]>,
    ) {
        const LABEL_START: usize = 1;
        const LABEL_END: usize = 5;
        const CONTEXT_START: usize = 6;
        const LEN_START: usize = 70;
        const LEN_END: usize = 72;
        let mut buffer = Zeroizing::new([0u8; LEN_END]);
        buffer[0] = 1;
        buffer[LABEL_START..LABEL_END].copy_from_slice(label);
        buffer[LABEL_END] = 0x00;
        buffer[CONTEXT_START..LEN_START].copy_from_slice(self.ck.as_ref());
        buffer[LEN_START..LEN_END].copy_from_slice(&(num_outputs * 8 * HASHLEN as u16).to_be_bytes());

        debug_assert!(num_outputs >= 1);
        hmac.hash(input_key_material, buffer.as_ref(), output1);

        if let Some(output2) = output2 {
            debug_assert!(num_outputs >= 2);
            buffer[0] = 2;
            hmac.hash(input_key_material, buffer.as_ref(), output2);
        }

        if let Some(output3) = output3 {
            debug_assert!(num_outputs >= 3);
            buffer[0] = 3;
            hmac.hash(input_key_material, buffer.as_ref(), output3);
        }
    }

    /// Corresponds to Noise `Initialize` on a SymmetricState.
    pub fn initialize(h: &[u8; HASHLEN]) -> Self {
        Self {
            k: Zeroizing::default(),
            ck: Zeroizing::new(*h),
            h: *h,
            _app: PhantomData,
        }
    }
    /// Corresponds to Noise `MixKey`.
    pub fn mix_key(&mut self, hmac: &mut App::HmacHash, input_key_material: &[u8]) {
        let mut next_ck = Zeroizing::new([0u8; HASHLEN]);
        let mut temp_k = Zeroizing::new([0u8; HASHLEN]);

        self.kbkdf(
            hmac,
            input_key_material,
            LABEL_KBKDF_CHAIN,
            2,
            &mut next_ck,
            Some(&mut temp_k),
            None,
        );

        *self.ck = *next_ck;
        self.k.clone_from_slice(&temp_k[..AES_256_KEY_SIZE]);
    }
    /// Corresponds to Noise `MixKey`.
    pub fn mix_key_no_init(&mut self, hmac: &mut App::HmacHash, input_key_material: &[u8]) {
        let mut next_ck = Zeroizing::new([0u8; HASHLEN]);

        self.kbkdf(hmac, input_key_material, LABEL_KBKDF_CHAIN, 2, &mut next_ck, None, None);

        *self.ck = *next_ck;
    }
    /// Corresponds to Noise `MixHash`.
    pub fn mix_hash(&mut self, hash: &mut App::Hash, data: &[u8]) {
        hash.update(&self.h);
        hash.update(data);
        hash.finish_and_reset(&mut self.h);
    }
    /// Corresponds to Noise `MixKeyAndHash`.
    pub fn mix_key_and_hash(&mut self, hash: &mut App::Hash, hmac: &mut App::HmacHash, input_key_material: &[u8]) {
        let mut next_ck = Zeroizing::new([0u8; HASHLEN]);
        let mut temp_h = [0u8; HASHLEN];
        let mut temp_k = Zeroizing::new([0u8; HASHLEN]);

        self.kbkdf(
            hmac,
            input_key_material,
            LABEL_KBKDF_CHAIN,
            3,
            &mut next_ck,
            Some(&mut temp_h),
            Some(&mut temp_k),
        );

        *self.ck = *next_ck;
        self.mix_hash(hash, &temp_h);
        self.k.clone_from_slice(&temp_k[..AES_256_KEY_SIZE]);
    }
    /// Corresponds to Noise `MixKeyAndHash`.
    pub fn mix_key_and_hash_no_init(
        &mut self,
        hash: &mut App::Hash,
        hmac: &mut App::HmacHash,
        input_key_material: &[u8],
    ) {
        let mut next_ck = Zeroizing::new([0u8; HASHLEN]);
        let mut temp_h = [0u8; HASHLEN];

        self.kbkdf(
            hmac,
            input_key_material,
            LABEL_KBKDF_CHAIN,
            3,
            &mut next_ck,
            Some(&mut temp_h),
            None,
        );

        *self.ck = *next_ck;
        self.mix_hash(hash, &temp_h);
    }
    /// Corresponds to Noise `EncryptAndHash`.
    #[must_use]
    pub fn encrypt_and_hash_in_place(
        &mut self,
        hash: &mut App::Hash,
        iv: [u8; AES_GCM_IV_SIZE],
        data: &mut [u8],
    ) -> [u8; AES_GCM_TAG_SIZE] {
        let tag = App::Aead::encrypt_in_place(&self.k, &iv, &self.h, data);
        hash.update(&self.h);
        hash.update(data);
        hash.update(&tag);
        hash.finish_and_reset(&mut self.h);
        tag
    }
    /// Corresponds to Noise `DecryptAndHash`.
    #[must_use]
    pub fn decrypt_and_hash_in_place(
        &mut self,
        hash: &mut App::Hash,
        iv: [u8; AES_GCM_IV_SIZE],
        data: &mut [u8],
        tag: [u8; AES_GCM_TAG_SIZE],
    ) -> bool {
        hash.update(&self.h);
        hash.update(data);
        hash.update(&tag);
        let is_auth = App::Aead::decrypt_in_place(&self.k, &iv, &self.h, data, tag.as_ref().try_into().unwrap());
        hash.finish_and_reset(&mut self.h);
        is_auth
    }
    /// Corresponds to Noise `Split`.
    pub fn split(self, hmac: &mut App::HmacHash, key1: &mut [u8; HASHLEN], key2: &mut [u8; HASHLEN]) {
        self.kbkdf(hmac, &[], LABEL_KBKDF_CHAIN, 2, key1, Some(key2), None);
    }
    /// Get an additional symmetric key (ASK) that is a collision resistant hash of the transcript,
    /// is forward secrect and is cryptographically independent from all other produced keys.
    /// Based on Noise's unstable ASK mechanism, using KBKDF instead of HKDF.
    /// https://github.com/noiseprotocol/noise_wiki/wiki/Additional-Symmetric-Keys.
    pub fn get_ask(
        &self,
        hmac: &mut App::HmacHash,
        label: &[u8; 4],
        key1: &mut [u8; HASHLEN],
        key2: &mut [u8; HASHLEN],
    ) {
        self.kbkdf(hmac, &self.h, label, 2, key1, Some(key2), None);
    }
    /// Used for internally debugging a key exchange.
    #[allow(unused)]
    pub(crate) fn finger(&self) -> (u8, u8, u8) {
        (self.k[0], self.ck[0], self.h[0])
    }
}

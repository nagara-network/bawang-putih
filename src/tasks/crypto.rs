pub(crate) struct CryptographicOperator {
    flash_wrapper: super::flash::FlashWrapper,
    our_signer: ed25519_compact::SigningState,
    cipher_buffer: arrayvec::ArrayVec<u8, { Self::MAX_ENCRYPTION_SIZE }>,
}

impl CryptographicOperator {
    const HEADER_ABORTED: u8 = 0xAA;
    const HEADER_BB_ACCEPTED: u8 = 0xBA;
    const HEADER_BB_REMOVED: u8 = 0xBF;
    const HEADER_INFO: u8 = 0x11;
    const HEADER_S2W: u8 = 0xE3;
    const HEADER_SIG: u8 = 0x51;
    const HEADER_W2S: u8 = 0x3E;
    const KDF_CONTEXT: &'static str = "nagara-storage-ppv";
    const MAX_ENCRYPTION_SIZE: usize = 4096;
    const RANGE_BB_0_BB_ID: core::ops::Range<usize> = 0..32;
    const RANGE_BB_1_BB_SIG: core::ops::Range<usize> = 32..96;
    const RANGE_BB_2_CTX_BB: core::ops::Range<usize> = 96..128;
    const RANGE_TE_S2W_0_BB_ID: core::ops::Range<usize> = 0..32;
    const RANGE_TE_S2W_1_BB_SIG: core::ops::Range<usize> = 32..96;
    const RANGE_TE_S2W_2_FILE_ID: core::ops::Range<usize> = 96..128;
    const RANGE_TE_S2W_3_RECV_ID: core::ops::Range<usize> = 128..160;
    const RANGE_TE_S2W_4_ORI_HASH: core::ops::Range<usize> = 160..192;
    const RANGE_TE_S2W_5_ENC_HASH: core::ops::Range<usize> = 192..224;
    const RANGE_TE_S2W_6_TAG: core::ops::Range<usize> = 224..240;
    const RANGE_TE_S2W_7_NONCE: core::ops::Range<usize> = 240..256;
    const RANGE_TE_S2W_8_CONTENT: core::ops::RangeFrom<usize> = 256..;
    const RANGE_TE_W2S_0_SNDR_ID: core::ops::Range<usize> = 0..32;
    const RANGE_TE_W2S_1_FILE_ID: core::ops::Range<usize> = 32..64;
    const RANGE_TE_W2S_2_ORI_HASH: core::ops::Range<usize> = 64..96;
    const RANGE_TE_W2S_3_ENC_HASH: core::ops::Range<usize> = 96..128;
    const RANGE_TE_W2S_4_TAG: core::ops::Range<usize> = 128..144;
    const RANGE_TE_W2S_5_NONCE: core::ops::Range<usize> = 144..160;
    const RANGE_TE_W2S_6_CONTENT: core::ops::RangeFrom<usize> = 160..;

    pub(crate) async fn create() -> Self {
        let flash_wrapper = super::flash::FlashWrapper::create().await;
        let our_signer = flash_wrapper.get_our_signer();
        let cipher_buffer = arrayvec::ArrayVec::new();

        Self {
            flash_wrapper,
            our_signer,
            cipher_buffer,
        }
    }

    pub(crate) fn fill_device_info(&mut self, outgoing_raw_buffer: &mut super::RawBufferOutgoing) {
        outgoing_raw_buffer.clear();

        let system_clock = embassy_rp::clocks::clk_sys_freq().to_le_bytes();
        let our_pk_slice = self.flash_wrapper.get_our_pk_slice();

        outgoing_raw_buffer.push(Self::HEADER_INFO);
        outgoing_raw_buffer
            .try_extend_from_slice(&system_clock)
            .unwrap();
        outgoing_raw_buffer
            .try_extend_from_slice(our_pk_slice)
            .unwrap();
        self.flash_wrapper.get_our_sn_into(outgoing_raw_buffer);
        self.flash_wrapper.bb_get_all_into(outgoing_raw_buffer);
    }

    pub(crate) async fn add_big_brother(
        &mut self,
        incoming_raw_buffer: &super::RawBufferIncoming,
        outgoing_raw_buffer: &mut super::RawBufferOutgoing,
    ) {
        // clear all except incoming buffer
        outgoing_raw_buffer.clear();

        // slices
        let bb_id_ref = &incoming_raw_buffer[Self::RANGE_BB_0_BB_ID];
        let bb_sig_ref = &incoming_raw_buffer[Self::RANGE_BB_1_BB_SIG];
        let bb_ctx_ref = &incoming_raw_buffer[Self::RANGE_BB_2_CTX_BB];

        // ensure correct initiator
        let bb_verifier =
            if let super::Option::Some(bb_id) = self.flash_wrapper.bb_try_get(bb_id_ref) {
                bb_id
            } else {
                outgoing_raw_buffer.push(Self::HEADER_ABORTED);
                outgoing_raw_buffer.push(super::BawangPutihError::BigBrotherDoesntExist as u8);
                return;
            };
        let bb_signature = if let core::result::Result::Ok(bb_sig) =
            ed25519_compact::Signature::from_slice(bb_sig_ref)
        {
            bb_sig
        } else {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::BadSignature as u8);
            return;
        };
        let mut bb_ops_message = [0; 33];
        bb_ops_message[0] = Self::HEADER_BB_ACCEPTED;
        bb_ops_message[1..33].copy_from_slice(bb_ctx_ref);
        if bb_verifier.verify(bb_ops_message, &bb_signature).is_err() {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::BadSignature as u8);
            return;
        }

        // add context bb
        if let super::Result::Err(err) = self.flash_wrapper.bb_insert(bb_ctx_ref).await {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(err as u8);
            return;
        }

        // update outgoing buffer
        outgoing_raw_buffer.push(Self::HEADER_BB_ACCEPTED);
    }

    pub(crate) async fn remove_big_brother(
        &mut self,
        incoming_raw_buffer: &super::RawBufferIncoming,
        outgoing_raw_buffer: &mut super::RawBufferOutgoing,
    ) {
        // clear all except incoming buffer
        outgoing_raw_buffer.clear();

        // slices
        let bb_id_ref = &incoming_raw_buffer[Self::RANGE_BB_0_BB_ID];
        let bb_sig_ref = &incoming_raw_buffer[Self::RANGE_BB_1_BB_SIG];
        let bb_ctx_ref = &incoming_raw_buffer[Self::RANGE_BB_2_CTX_BB];

        // ensure correct initiator
        let bb_verifier =
            if let super::Option::Some(bb_id) = self.flash_wrapper.bb_try_get(bb_id_ref) {
                bb_id
            } else {
                outgoing_raw_buffer.push(Self::HEADER_ABORTED);
                outgoing_raw_buffer.push(super::BawangPutihError::BigBrotherDoesntExist as u8);
                return;
            };
        let bb_signature = if let core::result::Result::Ok(bb_sig) =
            ed25519_compact::Signature::from_slice(bb_sig_ref)
        {
            bb_sig
        } else {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::BadSignature as u8);
            return;
        };
        let mut bb_ops_message = [0; 33];
        bb_ops_message[0] = Self::HEADER_BB_REMOVED;
        bb_ops_message[1..33].copy_from_slice(bb_ctx_ref);
        if bb_verifier.verify(bb_ops_message, &bb_signature).is_err() {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::BadSignature as u8);
            return;
        }

        // add context bb
        if let super::Result::Err(err) = self.flash_wrapper.bb_remove(bb_ctx_ref).await {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(err as u8);
            return;
        }

        // update outgoing buffer
        outgoing_raw_buffer.push(Self::HEADER_BB_REMOVED);
    }

    pub(crate) fn reset_signer(&mut self) {
        self.our_signer = self.flash_wrapper.get_our_signer();
    }

    pub(crate) fn feed_signer(&mut self, message_chunk: &[u8]) {
        self.our_signer.absorb(message_chunk);
    }

    pub(crate) fn sign_and_reset(&mut self, outgoing_raw_buffer: &mut super::RawBufferOutgoing) {
        outgoing_raw_buffer.clear();
        let our_signature = self.our_signer.sign();
        self.reset_signer();

        outgoing_raw_buffer.push(Self::HEADER_SIG);
        outgoing_raw_buffer
            .try_extend_from_slice(self.flash_wrapper.get_our_pk_slice())
            .unwrap();
        outgoing_raw_buffer
            .try_extend_from_slice(our_signature.as_slice())
            .unwrap();
    }

    pub(crate) fn transform_encryption_from_storage_to_wire(
        &mut self,
        incoming_raw_buffer: &super::RawBufferIncoming,
        outgoing_raw_buffer: &mut super::RawBufferOutgoing,
    ) {
        // clear all except incoming buffer
        outgoing_raw_buffer.clear();
        self.cipher_buffer.clear();

        // slices
        let bb_id_ref = &incoming_raw_buffer[Self::RANGE_TE_S2W_0_BB_ID];
        let bb_sig_ref = &incoming_raw_buffer[Self::RANGE_TE_S2W_1_BB_SIG];
        let file_id_ref = &incoming_raw_buffer[Self::RANGE_TE_S2W_2_FILE_ID];
        let recv_id_ref = &incoming_raw_buffer[Self::RANGE_TE_S2W_3_RECV_ID];
        let ori_hash_ref = &incoming_raw_buffer[Self::RANGE_TE_S2W_4_ORI_HASH];
        let enc_hash_ref = &incoming_raw_buffer[Self::RANGE_TE_S2W_5_ENC_HASH];
        let tag_ref = &incoming_raw_buffer[Self::RANGE_TE_S2W_6_TAG];
        let nonce_ref = &incoming_raw_buffer[Self::RANGE_TE_S2W_7_NONCE];
        let content_ref = &incoming_raw_buffer[Self::RANGE_TE_S2W_8_CONTENT];

        // ensure correct encrypted hash
        let content_hash = blake3::hash(content_ref);
        if content_hash.as_bytes() != enc_hash_ref {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::ContentHashCompromised as u8);
            return;
        }

        // ensure correct initiator
        let bb_verifier =
            if let super::Option::Some(bb_id) = self.flash_wrapper.bb_try_get(bb_id_ref) {
                bb_id
            } else {
                outgoing_raw_buffer.push(Self::HEADER_ABORTED);
                outgoing_raw_buffer.push(super::BawangPutihError::BigBrotherDoesntExist as u8);
                return;
            };
        let bb_signature = if let core::result::Result::Ok(bb_sig) =
            ed25519_compact::Signature::from_slice(bb_sig_ref)
        {
            bb_sig
        } else {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::BadSignature as u8);
            return;
        };
        if bb_verifier.verify(ori_hash_ref, &bb_signature).is_err() {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::BadSignature as u8);
            return;
        }

        // decrypt
        let file_ed25519_pubkey = if let core::result::Result::Ok(pubkey) =
            ed25519_compact::PublicKey::from_slice(file_id_ref)
        {
            pubkey
        } else {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::MalformedPublicKey as u8);
            return;
        };
        let decrypt_key = match self.try_get_shared_morus_key(&file_ed25519_pubkey) {
            super::Result::Ok(shared_key) => shared_key,
            super::Result::Err(err) => {
                outgoing_raw_buffer.push(Self::HEADER_ABORTED);
                outgoing_raw_buffer.push(err as u8);
                return;
            }
        };
        let mut decrypt_tag = morus::Tag::default();
        decrypt_tag.copy_from_slice(tag_ref);
        let mut decrypt_nonce = morus::Nonce::default();
        decrypt_nonce.copy_from_slice(nonce_ref);
        self.cipher_buffer
            .try_extend_from_slice(content_ref)
            .unwrap();
        let decryptor = morus::Morus::new(&decrypt_nonce, &decrypt_key);
        if decryptor
            .decrypt_in_place(&mut self.cipher_buffer, &decrypt_tag, ori_hash_ref)
            .is_err()
        {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::InvalidCipherDetails as u8);
            return;
        }

        // ensure correct original hash
        let original_hash = blake3::hash(&self.cipher_buffer);
        if original_hash.as_bytes() != ori_hash_ref {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::ContentHashCompromised as u8);
            return;
        }

        // encrypt
        let receiver_ed25519_pubkey = if let core::result::Result::Ok(pubkey) =
            ed25519_compact::PublicKey::from_slice(recv_id_ref)
        {
            pubkey
        } else {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::MalformedPublicKey as u8);
            return;
        };
        let encrypt_key = match self.try_get_shared_morus_key(&receiver_ed25519_pubkey) {
            super::Result::Ok(shared_key) => shared_key,
            super::Result::Err(err) => {
                outgoing_raw_buffer.push(Self::HEADER_ABORTED);
                outgoing_raw_buffer.push(err as u8);
                return;
            }
        };
        let mut encrypt_nonce = morus::Nonce::default();
        crate::get_random_implementation(&mut encrypt_nonce).unwrap();
        let encryptor = morus::Morus::new(&encrypt_nonce, &encrypt_key);
        let encrypt_tag = encryptor.encrypt_in_place(&mut self.cipher_buffer, ori_hash_ref);
        let encrypted_hash = blake3::hash(&self.cipher_buffer);

        // update outgoing buffer
        outgoing_raw_buffer.push(Self::HEADER_S2W);
        outgoing_raw_buffer
            .try_extend_from_slice(&encrypt_tag)
            .unwrap();
        outgoing_raw_buffer
            .try_extend_from_slice(&encrypt_nonce)
            .unwrap();
        outgoing_raw_buffer
            .try_extend_from_slice(encrypted_hash.as_bytes())
            .unwrap();
        outgoing_raw_buffer
            .try_extend_from_slice(&self.cipher_buffer)
            .unwrap();
    }

    pub(crate) fn transform_encryption_from_wire_to_storage(
        &mut self,
        incoming_raw_buffer: &super::RawBufferIncoming,
        outgoing_raw_buffer: &mut super::RawBufferOutgoing,
    ) {
        // clear all except incoming buffer
        outgoing_raw_buffer.clear();
        self.cipher_buffer.clear();

        // slices
        let sndr_id_ref = &incoming_raw_buffer[Self::RANGE_TE_W2S_0_SNDR_ID];
        let file_id_ref = &incoming_raw_buffer[Self::RANGE_TE_W2S_1_FILE_ID];
        let ori_hash_ref = &incoming_raw_buffer[Self::RANGE_TE_W2S_2_ORI_HASH];
        let enc_hash_ref = &incoming_raw_buffer[Self::RANGE_TE_W2S_3_ENC_HASH];
        let tag_ref = &incoming_raw_buffer[Self::RANGE_TE_W2S_4_TAG];
        let nonce_ref = &incoming_raw_buffer[Self::RANGE_TE_W2S_5_NONCE];
        let content_ref = &incoming_raw_buffer[Self::RANGE_TE_W2S_6_CONTENT];

        // ensure correct encrypted hash
        let encrypted_hash = blake3::hash(content_ref);
        if encrypted_hash.as_bytes() != enc_hash_ref {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::ContentHashCompromised as u8);
            return;
        }

        // decrypt
        let sender_ed25519_pubkey = if let core::result::Result::Ok(pubkey) =
            ed25519_compact::PublicKey::from_slice(sndr_id_ref)
        {
            pubkey
        } else {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::MalformedPublicKey as u8);
            return;
        };
        let decrypt_key = match self.try_get_shared_morus_key(&sender_ed25519_pubkey) {
            super::Result::Ok(shared_key) => shared_key,
            super::Result::Err(err) => {
                outgoing_raw_buffer.push(Self::HEADER_ABORTED);
                outgoing_raw_buffer.push(err as u8);
                return;
            }
        };
        let mut decrypt_tag = morus::Tag::default();
        decrypt_tag.copy_from_slice(tag_ref);
        let mut decrypt_nonce = morus::Nonce::default();
        decrypt_nonce.copy_from_slice(nonce_ref);
        self.cipher_buffer
            .try_extend_from_slice(content_ref)
            .unwrap();
        let decryptor = morus::Morus::new(&decrypt_nonce, &decrypt_key);
        if decryptor
            .decrypt_in_place(&mut self.cipher_buffer, &decrypt_tag, ori_hash_ref)
            .is_err()
        {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::InvalidCipherDetails as u8);
            return;
        }

        // ensure correct original hash
        let original_hash = blake3::hash(&self.cipher_buffer);
        if original_hash.as_bytes() != ori_hash_ref {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::ContentHashCompromised as u8);
            return;
        }

        // encrypt
        let file_ed25519_pubkey = if let core::result::Result::Ok(pubkey) =
            ed25519_compact::PublicKey::from_slice(file_id_ref)
        {
            pubkey
        } else {
            outgoing_raw_buffer.push(Self::HEADER_ABORTED);
            outgoing_raw_buffer.push(super::BawangPutihError::MalformedPublicKey as u8);
            return;
        };
        let encrypt_key = match self.try_get_shared_morus_key(&file_ed25519_pubkey) {
            super::Result::Ok(shared_key) => shared_key,
            super::Result::Err(err) => {
                outgoing_raw_buffer.push(Self::HEADER_ABORTED);
                outgoing_raw_buffer.push(err as u8);
                return;
            }
        };
        let mut encrypt_nonce = morus::Nonce::default();
        crate::get_random_implementation(&mut encrypt_nonce).unwrap();
        let encryptor = morus::Morus::new(&encrypt_nonce, &encrypt_key);
        let encrypt_tag = encryptor.encrypt_in_place(&mut self.cipher_buffer, ori_hash_ref);
        let encrypted_hash = blake3::hash(&self.cipher_buffer);

        // update outgoing buffer
        outgoing_raw_buffer.push(Self::HEADER_W2S);
        outgoing_raw_buffer
            .try_extend_from_slice(&encrypt_tag)
            .unwrap();
        outgoing_raw_buffer
            .try_extend_from_slice(&encrypt_nonce)
            .unwrap();
        outgoing_raw_buffer
            .try_extend_from_slice(encrypted_hash.as_bytes())
            .unwrap();
        outgoing_raw_buffer
            .try_extend_from_slice(&self.cipher_buffer)
            .unwrap();
    }

    fn try_get_shared_morus_key(
        &self,
        their_public_key: &ed25519_compact::PublicKey,
    ) -> super::Result<morus::Key> {
        let our_dh_sk =
            ed25519_compact::x25519::SecretKey::from_ed25519(self.flash_wrapper.get_our_sk())
                .map_err(|_| super::BawangPutihError::DHOperationFailure)?;
        let their_dh_pk = ed25519_compact::x25519::PublicKey::from_ed25519(their_public_key)
            .map_err(|_| super::BawangPutihError::DHOperationFailure)?;
        let our_dh = their_dh_pk
            .dh(&our_dh_sk)
            .map_err(|_| super::BawangPutihError::DHOperationFailure)?;
        let derived_key = blake3::derive_key(Self::KDF_CONTEXT, our_dh.as_slice());
        let mut morus_key = morus::Key::default();
        morus_key.copy_from_slice(&derived_key[0..16]);

        super::Result::Ok(morus_key)
    }
}

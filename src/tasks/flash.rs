type BigBrotherList = arrayvec::ArrayVec<ed25519_compact::PublicKey, 16>;

pub(crate) struct FlashWrapper {
    big_brothers: BigBrotherList,
    our_kp: ed25519_compact::KeyPair,
    our_sn: arrayvec::ArrayString<8>,
}

impl FlashWrapper {
    pub(crate) async fn create() -> Self {
        let initial_bb =
            ed25519_compact::PublicKey::from_slice(&hex_lit::hex!(env!("ANCESTOR_ID"))).unwrap();
        let mut big_brothers = BigBrotherList::new();
        big_brothers.push(initial_bb);
        let our_kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(
            hex_lit::hex!(env!("INITIAL_SK")),
        ));
        let our_sn =
            <arrayvec::ArrayString<8> as core::str::FromStr>::from_str(env!("USB_SN")).unwrap();

        Self {
            big_brothers,
            our_kp,
            our_sn,
        }
    }

    pub(crate) fn get_our_signer(&self) -> ed25519_compact::SigningState {
        self.our_kp
            .sk
            .sign_incremental(ed25519_compact::Noise::generate())
    }

    pub(crate) fn get_our_pk_slice(&self) -> &[u8] {
        self.our_kp.pk.as_slice()
    }

    pub(crate) fn get_our_sk(&self) -> &ed25519_compact::SecretKey {
        &self.our_kp.sk
    }

    pub(crate) fn bb_try_get(&self, bb_id: &[u8]) -> super::Option<&ed25519_compact::PublicKey> {
        (&self.big_brothers)
            .into_iter()
            .find(|&bb_pk| bb_pk.as_slice() == bb_id)
    }

    pub(crate) async fn bb_index_of(&self, pk: &[u8]) -> super::Option<usize> {
        for (index, item) in self.big_brothers.iter().enumerate() {
            if item.as_slice() == pk {
                return Option::Some(index);
            }
        }

        super::Option::None
    }

    pub(crate) async fn bb_remove(&mut self, pk: &[u8]) -> super::Result<()> {
        if let super::Option::Some(index) = self.bb_index_of(pk).await {
            self.big_brothers.remove(index);

            return super::Result::Ok(());
        }

        super::Result::Err(super::BawangPutihError::BigBrotherDoesntExist)
    }

    pub(crate) async fn bb_insert(&mut self, pk: &[u8]) -> super::Result<()> {
        if self.bb_try_get(pk).is_some() {
            return super::Result::Err(super::BawangPutihError::BigBrotherAlreadyRegistered);
        }

        let bb_pk = ed25519_compact::PublicKey::from_slice(pk)
            .map_err(|_| super::BawangPutihError::MalformedPublicKey)?;

        self.big_brothers
            .try_push(bb_pk)
            .map_err(|_| super::BawangPutihError::BigBrotherRegistryIsFull)?;

        super::Result::Ok(())
    }

    pub(crate) fn bb_get_all_into(&self, destination: &mut super::RawBufferOutgoing) {
        for bb_pk in &self.big_brothers {
            destination.try_extend_from_slice(bb_pk.as_slice()).unwrap();
        }
    }

    pub(crate) fn get_our_sn_into(&self, destination: &mut super::RawBufferOutgoing) {
        destination
            .try_extend_from_slice(self.our_sn.as_bytes())
            .unwrap();
    }
}

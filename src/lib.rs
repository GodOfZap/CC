use generic_ec::{Curve, Generator, Point, Scalar, SecretScalar};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptError {
    CiphertextTooShort,
    InvalidEphemeralPoint,
}

fn xor_with_repeated_key(input: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return input.to_vec();
    }

    input
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

fn compressed_point_len<E: Curve>() -> usize {
    let g = Generator::<E>::default();
    let p: Point<E> = g.into();
    p.to_bytes(true).len()
}

pub fn encrypt<E: Curve>(pk: &Point<E>, message: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let eph = SecretScalar::<E>::random(&mut rng);
    let r: Point<E> = Generator::<E>::default() * &eph;

    let shared: Point<E> = pk * &eph;
    let digest = Sha256::digest(shared.to_bytes(true));
    let ciphertext = xor_with_repeated_key(message, digest.as_ref());

    let mut out = r.to_bytes(true).to_vec();
    out.extend_from_slice(&ciphertext);
    out
}

pub fn decrypt<E: Curve>(sk: &Scalar<E>, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let r_len = compressed_point_len::<E>();
    if ciphertext.len() < r_len {
        return Err(DecryptError::CiphertextTooShort);
    }

    let (r_encoded, c) = ciphertext.split_at(r_len);
    let r = Point::<E>::from_bytes(r_encoded).map_err(|_| DecryptError::InvalidEphemeralPoint)?;

    let shared: Point<E> = r * sk;
    let digest = Sha256::digest(shared.to_bytes(true));
    Ok(xor_with_repeated_key(c, digest.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt, DecryptError};
    use generic_ec::curves::{Ed25519, Secp256k1, Secp384r1};
    use generic_ec::{Curve, Generator, Point, Scalar, SecretScalar};
    use hex::decode;

    fn roundtrip<E: Curve>(message: &[u8]) {
        let mut rng = rand::thread_rng();
        let sk = SecretScalar::<E>::random(&mut rng);
        let pk: Point<E> = Generator::<E>::default() * &sk;

        let ct = encrypt(&pk, message);
        let pt = decrypt(sk.as_ref(), &ct);
        assert!(pt.is_ok());
        assert_eq!(pt.unwrap_or_default(), message);
    }

    fn vector_decrypt<E: Curve>(ciphertext_hex: &str, plaintext_hex: &str) {
        let ct = decode(ciphertext_hex);
        assert!(ct.is_ok());
        let pt_expected = decode(plaintext_hex);
        assert!(pt_expected.is_ok());

        let sk = Scalar::<E>::from(65_537u64);
        let pt = decrypt(&sk, ct.as_deref().unwrap_or_default());
        assert!(pt.is_ok());
        assert_eq!(pt.unwrap_or_default(), pt_expected.unwrap_or_default());
    }

    fn vector_decrypt_all_ff<E: Curve>(ciphertext_hex: &str) {
        let ct = decode(ciphertext_hex);
        assert!(ct.is_ok());

        let ct = ct.unwrap_or_default();
        let sk = Scalar::<E>::from(65_537u64);
        let pt = decrypt(&sk, &ct);
        assert!(pt.is_ok());

        let msg_len = ct.len().saturating_sub(super::compressed_point_len::<E>());
        assert_eq!(pt.unwrap_or_default(), vec![0xff; msg_len]);
    }

    #[test]
    fn roundtrip_ed25519() {
        roundtrip::<Ed25519>(b"Hello, LFDT!");
    }

    #[test]
    fn roundtrip_secp256k1() {
        roundtrip::<Secp256k1>(b"Hello, LFDT!");
    }

    #[test]
    fn roundtrip_secp384r1() {
        roundtrip::<Secp384r1>(b"Hello, LFDT!");
    }

    #[test]
    fn decrypt_rejects_short_ciphertext() {
        let sk = Scalar::<Ed25519>::from(65_537u64);
        let out = decrypt(&sk, &[0u8; 5]);
        assert_eq!(out, Err(DecryptError::CiphertextTooShort));
    }

    #[test]
    fn vector_1_ed25519() {
        vector_decrypt::<Ed25519>(
            "83789da3b47511d971be426996e29773dbf1fd0b5d4117dc3f6197ac3b390b16021c4d4dcacd69fa6ddfbd70272254a8c1d6caa1553718b4b592f518ca856030",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn vector_2_ed25519() {
        vector_decrypt_all_ff::<Ed25519>(
            "63dddd19ca1aae622af6419925c1ccb6aa009255f08fc8f36ebc96aeffb0e575cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64",
        );
    }

    #[test]
    fn vector_3_ed25519() {
        vector_decrypt::<Ed25519>(
            "b453eb48c662ee52064508cf2c0cae99a36e1eaca32141c9a9fa15d3f0851b7c6c7bd0aeb14d7e7ee098eac3e03360d3b35b13432fced2ef3b83f313208bcfde433e94b4b704377ee69cead8ea343fd3b413185e3ececee16e9ceb15a7908a98067495fdb24b782dac9da5c0eb246c9fb15c00593e",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c206a6520766f757320646f6e6e65206c6120766965",
        );
    }

    #[test]
    fn vector_4_secp256k1() {
        vector_decrypt::<Secp256k1>(
            "028ff73c6a81376adeb0a5b9d3e0a89de67ef1215174c1b53a953bc51a5849ad4940c21b932a166cb2b913778a30f500b4f1c09d48c2549560c9f5513a6cf395f1",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn vector_5_secp256k1() {
        vector_decrypt_all_ff::<Secp256k1>(
            "022361daf6095c336b21f3ae6a9cb3a4389071e65f3dddc910783fd2805f80d0660ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123bf6",
        );
    }

    #[test]
    fn vector_6_secp256k1() {
        vector_decrypt::<Secp256k1>(
            "0209f092f4d63ca4efa0e639fb6225039a406cff3123e37b8b3bb5271cd758795f5a44b3beca08af02c430eec8b4f83785314f463c9ad9eeb96eb978ce14e661a27501f7a4cc41e602c234eed3beff688536074d218bd9f2b73ba660c893fd24e4304bf6edc90ea9518835a1cbbfef3bc9334855268b",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c206a6520766f757320646f6e6e65206c6120766965",
        );
    }

    #[test]
    fn vector_7_secp384r1() {
        vector_decrypt::<Secp384r1>(
            "03e448a1a9041bda41d16e521223572ed634169df6cd56ce5ae7f42b3914497afb8156b91c3f5baa12b4d81b5f44f2eb402399e501ed395e834c44d5c85008ef0a8b281240c5d409e4d1b85a586e493332",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn vector_8_secp384r1() {
        vector_decrypt_all_ff::<Secp384r1>(
            "0289b66ed7a9f3a649057afee3700e5ea217e059b88f05e76054991f133ec2fa5abb536caf174cc3258bf387f3e72e496c018163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932cd63e456eea56a0548bba4fe135f73faa9e",
        );
    }

    #[test]
    fn vector_9_secp384r1() {
        vector_decrypt::<Secp384r1>(
            "035371df7afefe2df5d492d62754bf6aa28aa269b1ea58936235f6c4a22e7a0a3e79b4895fe83593a0cbe39b4010d96c63d39a10133ef7f68aabfc63253f4537337539a69d1792df589046a3fcc51d6780fcdf540938bebf8aadf8633e354268337271ad800692c356c559bbfa420622c6b99555403df1f0d9e7f92c2634523b7f773eb58706",
            "4a652073756973206c61206d65722c20632765737420706f757271756f69206a6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c206a6520766f757320646f6e6e65206c6120766965",
        );
    }
}

use crypto_core::{
    security_level, SecurityLevel, VERSION,
    AeadWrapper, AeadError, NonceGenerator, NonceTracker, Nonce,
    AssociatedData, AadError, AeadKey, KeyError,
};

#[test]
fn test_metadata_and_security_level() {
    assert!(!VERSION.is_empty());
    assert_eq!(security_level(), SecurityLevel::Bits256);
}

#[test]
fn test_aead_wrapper_errors() {
    let bad_key = [0u8; 31];
    assert!(matches!(AeadWrapper::new(&bad_key), Err(AeadError::InvalidKey)));

    let key = [0x11u8; 32];
    let wrapper = AeadWrapper::new(&key).unwrap();
    let nonce = *NonceGenerator::new().next().unwrap().as_bytes();

    let err = wrapper.decrypt(&nonce, &[], b"aad").err().unwrap();
    assert_eq!(err, AeadError::CiphertextTooShort);
}

#[test]
fn test_nonce_tracking() {
    let gen = NonceGenerator::new();
    let nonce = gen.next().unwrap();

    let mut tracker = NonceTracker::new();
    assert!(tracker.check_and_mark(&nonce).is_ok());
    assert!(tracker.was_seen(&nonce));
    assert!(matches!(tracker.check_and_mark(&nonce), Err(crypto_core::NonceError::AlreadyUsed)));
}

#[test]
fn test_nonce_from_bytes_error() {
    assert!(matches!(Nonce::from_bytes(&[0u8; 11]), Err(crypto_core::NonceError::InvalidLength { .. })));
}

#[test]
fn test_aead_key_and_aad_validation() {
    let _key = AeadKey::from_bytes(&[0x22u8; 32]).unwrap();

    assert!(matches!(
        AeadKey::from_bytes(&[0u8; 16]),
        Err(KeyError::InvalidLength { .. })
    ));

    let aad = AssociatedData::new(vec![1, 2, 3]).unwrap();
    assert_eq!(aad.as_bytes(), &[1, 2, 3]);

    let too_long = vec![0u8; AssociatedData::MAX_LEN + 1];
    assert!(matches!(AssociatedData::new(too_long), Err(AadError::TooLong { .. })));
}

#![cfg(target_os = "macos")]

use core_foundation::base::{TCFType, ToVoid};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::Location;
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
};
use std::ffi::c_void;
use uuid::Uuid;

#[test]
#[ignore = "requires keychain entitlements and interactive login session"]
fn secure_enclave_key_has_acl_attributes() {
    let mut options = GenerateKeyOptions::default();
    let label = format!("com.agentpay.vault.it.{}", Uuid::new_v4());
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
        kSecAccessControlPrivateKeyUsage,
    )
    .expect("access control");

    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_label(label)
        .set_token(Token::SecureEnclave)
        .set_location(Location::DataProtectionKeychain)
        .set_access_control(access);

    let key = SecKey::new(&options).expect("secure enclave key generation must succeed");
    let attrs = key.attributes();

    let token = attrs
        .find(unsafe { kSecAttrTokenID }.to_void())
        .expect("token id must exist");
    let token_str = format!("{}", unsafe {
        core_foundation::string::CFString::wrap_under_get_rule(token.cast())
    });
    let expected = format!("{}", unsafe {
        core_foundation::string::CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave)
    });
    assert_eq!(token_str, expected);

    let access_control = attrs
        .find(unsafe { kSecAttrAccessControl }.to_void())
        .expect("access control entry must exist");
    let access_control_ref: *const c_void = access_control.cast();
    assert!(!access_control_ref.is_null());

    key.delete().expect("key cleanup");
}

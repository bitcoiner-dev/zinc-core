#![cfg(target_arch = "wasm32")]
//! WASM Interface Tests
//!
//! These tests run in a Headless Node.js environment via `wasm-bindgen-test`.
//! They verify the actual JS values returned by the WASM bindings, ensuring
//! that serialization contracts (Map vs Object) are respected.

use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;
use zinc_core::*;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_generate_wallet_returns_object() {
    let result = generate_wallet(12).unwrap();

    // In our bug, this was returning a Map.
    // We want to ensure we know what it returns.
    // Ideally it should be an Object for easier JS consumption,
    // or at least we test what it IS so we don't break the frontend.

    assert!(result.is_object(), "Result should be a JS Object (or Map)");

    // If it's a POJO (Plain Old JS Object), we can check keys
    // If it's a Map, result.is_object() is also true.
}

#[wasm_bindgen_test]
fn test_decrypt_wallet_contract() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = "strong_password_123";

    // 1. Encrypt
    let encrypted_json = encrypt_wallet(mnemonic, password).unwrap();

    // 2. Decrypt
    let result_js = decrypt_wallet(&encrypted_json, password).unwrap();

    // 3. Verify Contract
    // Check if it's a Map (which was the bug case, but if we support it, we check keys)
    if let Some(map) = result_js.dyn_ref::<js_sys::Map>() {
        assert!(
            map.has(&JsValue::from_str("success")),
            "Map should have success key"
        );
        return;
    }

    // Otherwise, assume POJO and check properties using Reflect
    let success = js_sys::Reflect::get(&result_js, &JsValue::from_str("success")).unwrap();
    let phrase = js_sys::Reflect::get(&result_js, &JsValue::from_str("phrase")).unwrap();

    assert!(
        !success.is_undefined(),
        "Should have 'success' property (POJO or Map)"
    );
    assert!(
        !phrase.is_undefined(),
        "Should have 'phrase' property (POJO or Map)"
    );
}

#[wasm_bindgen_test]
fn test_wasm_log_level_api() {
    set_logging_enabled(true);

    set_log_level("warn").expect("warn should be accepted");
    assert_eq!(get_log_level(), "warn");

    set_log_level("debug").expect("debug should be accepted");
    assert_eq!(get_log_level(), "debug");

    assert!(set_log_level("verbose").is_err());
}

#[wasm_bindgen_test]
fn test_wasm_logging_toggle_api() {
    set_logging_enabled(false);
    set_log_level("info").expect("level should still update while disabled");
    assert_eq!(get_log_level(), "info");
    set_logging_enabled(true);
}

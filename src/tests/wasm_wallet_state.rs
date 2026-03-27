#[cfg(test)]
mod tests {
    use crate::ZincWasmWallet;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen::JsValue;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    const TEST_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn create_wallet() -> ZincWasmWallet {
        ZincWasmWallet::new(
            "regtest",
            TEST_PHRASE,
            Some("unified".to_string()),
            None,
            Some(0),
        )
        .expect("wallet should initialize")
    }

    #[cfg(target_arch = "wasm32")]
    fn err_text(err: JsValue) -> String {
        err.as_string()
            .unwrap_or_else(|| format!("non-string JsValue error: {err:?}"))
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_wasm_wallet_busy_paths_return_wallet_busy_errors() {
        let wallet = create_wallet();
        let _guard = wallet
            .inner
            .try_borrow_mut()
            .expect("test should hold a mutable borrow");

        let err = wallet
            .set_network("signet")
            .expect_err("set_network should return busy while borrowed");
        assert!(err_text(err).contains("Wallet busy (set_network):"));

        let err = wallet
            .set_active_account(1)
            .expect_err("set_active_account should return busy while borrowed");
        assert!(err_text(err).contains("Wallet busy (set_active_account):"));

        let err = wallet
            .set_scheme("dual")
            .expect_err("set_scheme should return busy while borrowed");
        assert!(err_text(err).contains("Wallet busy (set_scheme):"));

        let err = wallet
            .sign_psbt("not-a-valid-psbt", JsValue::NULL)
            .expect_err("sign_psbt should return busy while borrowed");
        assert!(err_text(err).contains("Wallet busy (sign_psbt):"));
    }

    #[test]
    fn test_wasm_wallet_generation_bumps_and_noops_are_stable() {
        let wallet = create_wallet();

        let initial_generation = wallet
            .inner
            .try_borrow()
            .expect("wallet borrow should work")
            .account_generation();

        wallet.set_scheme("dual").expect("set_scheme should work");
        let after_scheme = wallet
            .inner
            .try_borrow()
            .expect("wallet borrow should work")
            .account_generation();
        assert_eq!(after_scheme, initial_generation.wrapping_add(1));

        wallet
            .set_scheme("dual")
            .expect("set_scheme noop should still succeed");
        let after_scheme_noop = wallet
            .inner
            .try_borrow()
            .expect("wallet borrow should work")
            .account_generation();
        assert_eq!(after_scheme_noop, after_scheme);

        wallet
            .set_active_account(1)
            .expect("set_active_account should work");
        let after_account = wallet
            .inner
            .try_borrow()
            .expect("wallet borrow should work")
            .account_generation();
        assert_eq!(after_account, after_scheme.wrapping_add(1));

        wallet
            .set_active_account(1)
            .expect("set_active_account noop should still succeed");
        let after_account_noop = wallet
            .inner
            .try_borrow()
            .expect("wallet borrow should work")
            .account_generation();
        assert_eq!(after_account_noop, after_account);

        wallet
            .set_network("signet")
            .expect("set_network should work");
        let after_network = wallet
            .inner
            .try_borrow()
            .expect("wallet borrow should work")
            .account_generation();
        assert_eq!(after_network, after_account.wrapping_add(1));

        wallet
            .set_network("signet")
            .expect("set_network noop should still succeed");
        let after_network_noop = wallet
            .inner
            .try_borrow()
            .expect("wallet borrow should work")
            .account_generation();
        assert_eq!(after_network_noop, after_network);
    }

    #[test]
    fn test_wasm_wallet_mutators_work_with_shared_receiver() {
        let wallet = create_wallet();

        wallet.set_scheme("dual").expect("set_scheme should work");
        wallet
            .set_active_account(1)
            .expect("set_active_account should work");
        wallet
            .set_network("signet")
            .expect("set_network should work");
        let state = wallet.state.get();
        assert_eq!(state.account_index, 1);
        assert_eq!(state.network, crate::Network::Signet);
        assert_eq!(state.scheme, crate::AddressScheme::Dual);
    }
}

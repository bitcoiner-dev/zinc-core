#[cfg(test)]
mod tests {
    fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(future)
    }

    #[test]
    fn receive_scan_detects_non_zero_address_activity() {
        let is_active = run_async(crate::account_is_active_from_receive_scan(
            200,
            |index| async move { index == 37 },
        ));

        assert!(
            is_active,
            "scan should detect activity on later derived address"
        );
    }

    #[test]
    fn receive_scan_returns_false_when_all_addresses_are_empty() {
        let is_active = run_async(crate::account_is_active_from_receive_scan(
            200,
            |_index| async move { false },
        ));

        assert!(
            !is_active,
            "scan should remain inactive when no address has history"
        );
    }

    #[test]
    fn receive_scan_enforces_minimum_depth_of_one() {
        let is_active = run_async(crate::account_is_active_from_receive_scan(
            0,
            |index| async move { index == 0 },
        ));

        assert!(is_active, "zero depth should still check address index 0");
    }

    #[test]
    fn receive_scan_with_depth_one_checks_only_main_address() {
        let is_active = run_async(crate::account_is_active_from_receive_scan(
            1,
            |index| async move { index == 1 },
        ));

        assert!(
            !is_active,
            "depth=1 must not scan derived addresses beyond index 0"
        );
    }
}

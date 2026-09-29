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

    #[test]
    fn strict_receive_scan_does_not_treat_errors_as_inactive() {
        let result = run_async(crate::account_is_active_from_receive_scan_strict(
            2,
            |index| async move {
                if index == 0 {
                    Err(crate::AccountDiscoveryProbeError::Backend)
                } else {
                    Ok(false)
                }
            },
        ));

        assert_eq!(result, Err(crate::AccountDiscoveryProbeError::Backend));
    }

    #[test]
    fn strict_receive_scan_accepts_conclusive_activity_despite_peer_error() {
        let result = run_async(crate::account_is_active_from_receive_scan_strict(
            2,
            |index| async move {
                if index == 0 {
                    Err(crate::AccountDiscoveryProbeError::Backend)
                } else {
                    Ok(true)
                }
            },
        ));

        assert_eq!(result, Ok(true));
    }

    #[test]
    fn strict_receive_scan_preserves_deadline_errors() {
        let result = run_async(crate::account_is_active_from_receive_scan_strict(
            1,
            |_index| async move { Err(crate::AccountDiscoveryProbeError::Deadline) },
        ));

        assert_eq!(result, Err(crate::AccountDiscoveryProbeError::Deadline));
    }

    #[test]
    fn strict_receive_scan_reports_the_first_active_address_index() {
        let result = run_async(crate::first_active_receive_index_from_scan_strict(
            40,
            |index| async move { Ok(index == 27) },
        ));

        assert_eq!(result, Ok(Some(27)));
    }

    #[test]
    fn strict_receive_index_scan_never_collapses_backend_failure_to_empty() {
        let result = run_async(crate::first_active_receive_index_from_scan_strict(
            20,
            |index| async move {
                if index == 7 {
                    Err(crate::AccountDiscoveryProbeError::Backend)
                } else {
                    Ok(false)
                }
            },
        ));

        assert_eq!(result, Err(crate::AccountDiscoveryProbeError::Backend));
    }

    #[test]
    fn discovery_tracker_reports_empty_probe_progress_without_expanding_active_frontier() {
        let mut tracker = crate::AccountDiscoveryTracker::default();

        assert_eq!(tracker.record_probe(0, true), 1);
        assert_eq!(tracker.record_probe(1, false), 1);
        assert_eq!(tracker.record_probe(2, true), 3);
        assert_eq!(tracker.discovered_count(), 3);
        assert_eq!(tracker.scanned_accounts, 3);
        assert!(!tracker.gap_reached(2));
        for index in 3..23 {
            assert_eq!(tracker.record_probe(index, false), 3);
        }
        assert!(tracker.gap_reached(20));
        assert_eq!(tracker.scanned_accounts, 23);
    }

    #[test]
    fn discovery_tracker_stops_only_after_the_full_trailing_gap() {
        let mut tracker = crate::AccountDiscoveryTracker::default();
        tracker.record_probe(0, true);
        tracker.record_probe(1, false);
        assert!(!tracker.gap_reached(2));
        tracker.record_probe(2, false);
        assert!(tracker.gap_reached(2));
        assert_eq!(tracker.discovered_count(), 1);
    }
}

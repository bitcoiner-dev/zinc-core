//! Restore-only activity evidence. Never used by current-state synchronization,
//! balances, asset protection or signing. Each owner disposes its scope when the
//! restore job ends; expiry and binding checks are additional fail-closed fences.
use std::collections::BTreeMap;
use std::time::Duration;
use web_time::Instant;

const MAX_PROBES: usize = 4096;
const MAX_AGE: Duration = Duration::from_secs(15 * 60);

pub(crate) fn context(wallet: &crate::ZincWallet) -> String {
    format!(
        "{}:{:?}:{:?}:{}",
        wallet.vault_wallet.network(),
        wallet.scheme,
        wallet.derivation_mode,
        wallet
            .vault_wallet
            .public_descriptor(bdk_wallet::KeychainKind::External)
    )
}

pub(crate) struct DiscoveryActivityMemo {
    context: String,
    backend: String,
    created: Instant,
    retired: bool,
    probes: BTreeMap<String, bool>,
}
impl DiscoveryActivityMemo {
    pub(crate) fn new(context: String, backend: String) -> Self {
        Self {
            context,
            backend,
            created: Instant::now(),
            retired: false,
            probes: BTreeMap::new(),
        }
    }
    pub(crate) fn validate(&self, context: &str, backend: &str, now: Instant) -> Result<(), ()> {
        if self.retired
            || self.context != context
            || self.backend != backend
            || now < self.created
            || now.duration_since(self.created) >= MAX_AGE
        {
            Err(())
        } else {
            Ok(())
        }
    }
    pub(crate) fn lookup(
        &self,
        context: &str,
        backend: &str,
        address: &str,
        now: Instant,
    ) -> Result<Option<bool>, ()> {
        self.validate(context, backend, now)?;
        Ok(self.probes.get(address).copied())
    }
    pub(crate) fn record(
        &mut self,
        context: &str,
        backend: &str,
        address: String,
        activity: bool,
        now: Instant,
    ) -> Result<(), ()> {
        self.validate(context, backend, now)?;
        if address.len() <= 100 && self.probes.len() < MAX_PROBES {
            self.probes.insert(address, activity);
        }
        // Reaching the memory bound never establishes missing coverage. A miss
        // continues through the normal HTTP probe rather than becoming false.
        Ok(())
    }
    pub(crate) fn retire(&mut self) {
        self.retired = true;
        self.probes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        builder::{DerivationMode, PaymentAddressType},
        Network, Seed64, WalletBuilder,
    };
    #[test]
    fn formats_share_context_but_wallet_account_network_and_mode_do_not() {
        let build = |seed, network, mode, account, payment| {
            WalletBuilder::from_seed(network, Seed64::from_array([seed; 64]))
                .with_scheme(crate::AddressScheme::Dual)
                .with_derivation_mode(mode)
                .with_account_index(account)
                .with_payment_address_type(payment)
                .build()
                .unwrap()
        };
        let first = build(
            7,
            Network::Regtest,
            DerivationMode::Account,
            0,
            PaymentAddressType::NativeSegwit,
        );
        let nested = build(
            7,
            Network::Regtest,
            DerivationMode::Account,
            0,
            PaymentAddressType::NestedSegwit,
        );
        assert_eq!(context(&first), context(&nested));
        for (account, network, mode, index) in [
            (8, Network::Regtest, DerivationMode::Account, 0),
            (7, Network::Testnet, DerivationMode::Account, 0),
            (7, Network::Regtest, DerivationMode::Index, 0),
            (7, Network::Regtest, DerivationMode::Account, 1),
        ] {
            let other = build(
                account,
                network,
                mode,
                index,
                PaymentAddressType::NativeSegwit,
            );
            assert_ne!(context(&first), context(&other));
        }
    }
    #[test]
    fn only_explicit_success_enters_scope_and_distinct_payment_probes_remain_unknown() {
        let mut memo = DiscoveryActivityMemo::new("wallet".into(), "backend".into());
        let now = memo.created;
        assert_eq!(memo.lookup("wallet", "backend", "vault", now), Ok(None));
        memo.record("wallet", "backend", "vault".into(), false, now)
            .unwrap();
        memo.record("wallet", "backend", "used".into(), true, now)
            .unwrap();
        assert_eq!(
            memo.lookup("wallet", "backend", "vault", now),
            Ok(Some(false))
        );
        assert_eq!(
            memo.lookup("wallet", "backend", "used", now),
            Ok(Some(true))
        );
        assert_eq!(
            memo.lookup("wallet", "backend", "nested-payment", now),
            Ok(None)
        );
    }
    #[test]
    fn context_backend_expiry_and_retirement_reject_reuse_and_late_writes() {
        let mut memo = DiscoveryActivityMemo::new("wallet".into(), "backend".into());
        let now = memo.created;
        memo.record("wallet", "backend", "vault".into(), false, now)
            .unwrap();
        for (ctx, backend, time) in [
            ("other", "backend", now),
            ("wallet", "other", now),
            ("wallet", "backend", now + MAX_AGE),
        ] {
            assert!(memo.lookup(ctx, backend, "vault", time).is_err());
        }
        memo.retire();
        assert!(memo.probes.is_empty());
        assert!(memo.lookup("wallet", "backend", "vault", now).is_err());
        assert!(memo
            .record("wallet", "backend", "late".into(), false, now)
            .is_err());
    }
    #[test]
    fn full_scope_does_not_turn_an_unrecorded_probe_into_negative_evidence() {
        let mut memo = DiscoveryActivityMemo::new("wallet".into(), "backend".into());
        let now = memo.created;
        for i in 0..=MAX_PROBES {
            memo.record("wallet", "backend", i.to_string(), false, now)
                .unwrap();
        }
        assert_eq!(memo.probes.len(), MAX_PROBES);
        assert_eq!(
            memo.lookup("wallet", "backend", &MAX_PROBES.to_string(), now),
            Ok(None)
        );
    }
}

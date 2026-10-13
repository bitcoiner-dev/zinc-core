//! Join two independent wallet roles without publishing a partial pair.
//! Caller owns concurrency caps, the origin budget and cancellation of the pair.
use std::{
    future::Future,
    sync::atomic::{AtomicU8, Ordering},
};

pub async fn fetch<T, E>(
    vault: impl Future<Output = Result<T, E>>,
    payment: Option<impl Future<Output = Result<T, E>>>,
) -> Result<(T, Option<T>), (E, u8)> {
    let Some(payment) = payment else {
        return vault
            .await
            .map(|value| (value, None))
            .map_err(|error| (error, 0));
    };
    let completed = AtomicU8::new(0);
    let observe = |result: Result<T, E>| {
        if result.is_ok() {
            completed.fetch_add(1, Ordering::Relaxed);
        }
        result
    };
    // An error drops the sibling future, cancelling its queued admissions and
    // owned read. Do not wait through cooldown to finish an unusable partial pair.
    futures_util::future::try_join(async { observe(vault.await) }, async {
        observe(payment.await)
    })
    .await
    .map(|(vault, payment)| (vault, Some(payment)))
    .map_err(|error| (error, completed.load(Ordering::Relaxed)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        future::{poll_fn, ready},
        task::{Context, Poll},
    };
    #[test]
    fn both_roles_start_before_either_finishes() {
        let (vault_started, payment_started) = (Cell::new(false), Cell::new(false));
        let vault = async {
            vault_started.set(true);
            poll_fn(|_| {
                if payment_started.get() {
                    Poll::Ready(Ok::<_, ()>(1))
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        let payment = async {
            payment_started.set(true);
            poll_fn(|_| {
                if vault_started.get() {
                    Poll::Ready(Ok::<_, ()>(2))
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        let pair = fetch(vault, Some(payment));
        futures_util::pin_mut!(pair);
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(pair.as_mut().poll(&mut cx).is_pending());
        assert!(vault_started.get() && payment_started.get());
        assert_eq!(pair.as_mut().poll(&mut cx), Poll::Ready(Ok((1, Some(2)))));
    }
    #[test]
    fn no_partial_pair_survives_either_role_failure() {
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        for (a, b, completed) in [
            (Ok(1), Err("payment"), 1),
            (Err("vault"), Ok(2), 0),
            (Err("vault"), Err("payment"), 0),
        ] {
            let error = a.err().or_else(|| b.err()).unwrap();
            let pair = fetch(ready(a), Some(ready(b)));
            futures_util::pin_mut!(pair);
            assert_eq!(
                pair.as_mut().poll(&mut cx),
                Poll::Ready(Err((error, completed)))
            );
        }
    }
    #[test]
    fn unified_wallet_has_only_one_fetch() {
        let pair = fetch(
            ready(Ok::<_, ()>(1)),
            None::<std::future::Ready<Result<i32, ()>>>,
        );
        futures_util::pin_mut!(pair);
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert_eq!(pair.as_mut().poll(&mut cx), Poll::Ready(Ok((1, None))));
    }
    #[test]
    fn an_error_drops_the_other_role_without_polling_or_waiting_for_it() {
        struct Pending<'a>(&'a Cell<bool>);
        impl Future for Pending<'_> {
            type Output = Result<u8, &'static str>;
            fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
                panic!("a failed pair must not continue dispatching its sibling");
            }
        }
        impl Drop for Pending<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let dropped = Cell::new(false);
        let pair = fetch(ready(Err("vault")), Some(Pending(&dropped)));
        futures_util::pin_mut!(pair);
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert_eq!(pair.as_mut().poll(&mut cx), Poll::Ready(Err(("vault", 0))));
        assert!(dropped.get());
    }
}

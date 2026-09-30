//! Cancels the owned read future, not merely publication of its result.
//! Dropping an aborted future releases queued admission and reqwest's WASM
//! AbortGuard. Already dispatched requests cannot be recalled from a server.
use futures_util::future::{AbortHandle, Abortable, Aborted};
use std::{cell::RefCell, future::Future, rc::Rc};

#[derive(Clone, Default)]
pub(crate) struct SyncReadCancellation(Rc<RefCell<Option<Rc<AbortHandle>>>>);

struct CurrentRead {
    owner: SyncReadCancellation,
    handle: Rc<AbortHandle>,
}

impl Drop for CurrentRead {
    fn drop(&mut self) {
        let mut current = self.owner.0.borrow_mut();
        if current
            .as_ref()
            .is_some_and(|handle| Rc::ptr_eq(handle, &self.handle))
        {
            current.take();
        }
    }
}

impl SyncReadCancellation {
    pub(crate) fn cancel(&self) {
        if let Some(handle) = self.0.borrow_mut().take() {
            handle.abort();
        }
    }

    pub(crate) async fn run<F: Future>(&self, future: F) -> Result<F::Output, Aborted> {
        self.cancel();
        let (handle, registration) = AbortHandle::new_pair();
        let handle = Rc::new(handle);
        *self.0.borrow_mut() = Some(handle.clone());
        let _current = CurrentRead {
            owner: self.clone(),
            handle,
        };
        Abortable::new(future, registration).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, task::Poll};

    #[test]
    fn cancellation_drops_pending_work_and_clears_the_slot() {
        struct Pending(Rc<Cell<bool>>);
        impl Future for Pending {
            type Output = ();
            fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        impl Drop for Pending {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let gate = SyncReadCancellation::default();
        let dropped = Rc::new(Cell::new(false));
        let future = gate.run(Pending(dropped.clone()));
        futures_util::pin_mut!(future);
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        gate.cancel();
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
        assert!(dropped.get());
        assert!(gate.0.borrow().is_none());
    }

    #[test]
    fn retired_completion_cannot_clear_replacement_read() {
        let gate = SyncReadCancellation::default();
        let old = gate.run(std::future::pending::<()>());
        let next = gate.run(std::future::pending::<()>());
        futures_util::pin_mut!(old, next);
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(old.as_mut().poll(&mut cx).is_pending());
        assert!(next.as_mut().poll(&mut cx).is_pending());
        assert!(matches!(old.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
        assert!(gate.0.borrow().is_some());
        gate.cancel();
        assert!(matches!(next.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
    }

    #[test]
    fn completed_error_does_not_suppress_a_later_read() {
        let gate = SyncReadCancellation::default();
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        let first = gate.run(std::future::ready(Err::<(), _>("failure")));
        futures_util::pin_mut!(first);
        assert_eq!(
            first.as_mut().poll(&mut cx),
            Poll::Ready(Ok(Err("failure")))
        );
        assert!(gate.0.borrow().is_none());
        let next = gate.run(std::future::ready(42));
        futures_util::pin_mut!(next);
        assert_eq!(next.as_mut().poll(&mut cx), Poll::Ready(Ok(42)));
    }
}

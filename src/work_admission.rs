//! Cancellable, work-conserving priority admission. No rate budget lives here.
//! FIFO within each lane; a waiting background job receives at least every
//! fourth grant. Dropping a queued ticket or held permit wakes the next job.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    Foreground,
    Background,
}
struct Waiter {
    id: u64,
    priority: Priority,
    waker: Option<Waker>,
}
struct State {
    available: usize,
    next_id: u64,
    foreground_run: u8,
    waiting: VecDeque<Waiter>,
}
pub struct WorkAdmission {
    state: Mutex<State>,
}
pub struct Ticket {
    gate: Arc<WorkAdmission>,
    id: u64,
    queued: bool,
}
pub struct Permit {
    gate: Arc<WorkAdmission>,
}

impl WorkAdmission {
    pub fn new(capacity: usize) -> Arc<Self> {
        assert!(capacity > 0);
        Arc::new(Self {
            state: Mutex::new(State {
                available: capacity,
                next_id: 0,
                foreground_run: 0,
                waiting: VecDeque::new(),
            }),
        })
    }
    pub fn register(self: &Arc<Self>, priority: Priority) -> Ticket {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.next_id = state
            .next_id
            .checked_add(1)
            .expect("work admission identity exhausted");
        let id = state.next_id;
        state.waiting.push_back(Waiter {
            id,
            priority,
            waker: None,
        });
        drop(state);
        self.wake();
        Ticket {
            gate: self.clone(),
            id,
            queued: true,
        }
    }
    pub async fn acquire(self: &Arc<Self>, priority: Priority) -> Permit {
        let mut ticket = self.register(priority);
        futures_util::future::poll_fn(|cx| match ticket.poll(Some(cx.waker())) {
            Some(permit) => Poll::Ready(permit),
            None => Poll::Pending,
        })
        .await
    }
    fn wake(&self) {
        let wake: Vec<_> = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .waiting
            .iter()
            .filter_map(|entry| entry.waker.clone())
            .collect();
        for waker in wake {
            waker.wake();
        }
    }
}
impl Ticket {
    /// Polling adapters retain the ticket between polls and must drop it on
    /// cancellation. The HTTP adapter additionally expires abandoned tickets.
    pub fn poll(&mut self, waker: Option<&Waker>) -> Option<Permit> {
        if !self.queued {
            return None;
        }
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = state.waiting.iter_mut().find(|entry| entry.id == self.id) {
            entry.waker = waker.cloned();
        }
        let foreground = state
            .waiting
            .iter()
            .position(|entry| entry.priority == Priority::Foreground);
        let background = state
            .waiting
            .iter()
            .position(|entry| entry.priority == Priority::Background);
        let chosen = if state.foreground_run >= 3 {
            background.or(foreground)
        } else {
            foreground.or(background)
        }?;
        if state.available == 0 || state.waiting[chosen].id != self.id {
            return None;
        }
        let granted = state
            .waiting
            .remove(chosen)
            .expect("selected waiter exists");
        state.foreground_run = if granted.priority == Priority::Foreground {
            state.foreground_run.saturating_add(1).min(3)
        } else {
            0
        };
        state.available -= 1;
        self.queued = false;
        drop(state);
        self.gate.wake();
        Some(Permit {
            gate: self.gate.clone(),
        })
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if self.queued {
            self.gate
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .waiting
                .retain(|entry| entry.id != self.id);
            self.gate.wake();
        }
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .available += 1;
        self.gate.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreground_priority_background_bound_and_fifo() {
        let gate = WorkAdmission::new(1);
        let mut background = gate.register(Priority::Background);
        let mut second_background = gate.register(Priority::Background);
        let mut foreground: Vec<_> = (0..8)
            .map(|_| gate.register(Priority::Foreground))
            .collect();
        for ticket in foreground.iter_mut().take(3) {
            assert!(background.poll(None).is_none());
            drop(ticket.poll(None).expect("foreground turn"));
        }
        assert!(foreground[3].poll(None).is_none());
        assert!(second_background.poll(None).is_none());
        drop(background.poll(None).expect("guaranteed background turn"));
        for ticket in foreground.iter_mut().skip(3).take(3) {
            drop(ticket.poll(None).unwrap());
        }
        drop(second_background.poll(None).expect("next background FIFO"));
        assert!(foreground[7].poll(None).is_none());
        drop(foreground[6].poll(None).unwrap());
    }
    #[test]
    fn cancelled_waiter_never_holds_capacity_or_changes_other_lane_order() {
        let gate = WorkAdmission::new(1);
        let mut holder = gate.register(Priority::Foreground);
        let held = holder.poll(None).unwrap();
        let cancelled = gate.register(Priority::Foreground);
        let mut background = gate.register(Priority::Background);
        assert!(background.poll(None).is_none());
        drop(cancelled);
        drop(held);
        drop(background.poll(None).unwrap());
        assert_eq!(gate.state.lock().unwrap().available, 1);
    }
    #[test]
    fn selection_replaces_foreground_work_without_restarting_background_fifo() {
        let gate = WorkAdmission::new(1);
        let mut background = gate.register(Priority::Background);
        let retired = gate.register(Priority::Foreground);
        drop(retired);
        for _ in 0..3 {
            let mut selected = gate.register(Priority::Foreground);
            drop(selected.poll(None).unwrap());
        }
        let mut newest_selection = gate.register(Priority::Foreground);
        assert!(newest_selection.poll(None).is_none());
        drop(
            background
                .poll(None)
                .expect("selection churn cannot starve recovery"),
        );
        drop(newest_selection.poll(None).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn cancelled_async_waiter_is_removed_and_release_wakes_next() {
        let gate = WorkAdmission::new(1);
        let held = gate.acquire(Priority::Foreground).await;
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(1),
            gate.acquire(Priority::Foreground)
        )
        .await
        .is_err());
        drop(held);
        let _next = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            gate.acquire(Priority::Background),
        )
        .await
        .unwrap();
    }
}

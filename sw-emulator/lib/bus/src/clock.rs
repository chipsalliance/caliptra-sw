/*++

Licensed under the Apache-2.0 license.

File Name:

    clock.rs

Abstract:

    File contains Clock and Timer types, used to implement timer-based deferred
    execution for peripherals.

--*/
use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    ptr,
    rc::Rc,
};

use crate::Bus;

/// Peripherals that want to use timer-based deferred execution will typically
/// store a clone of Timer inside themselves, and use it to schedule future
/// notification via [`Bus::poll`]).
///
/// # Example
///
/// ```
/// use caliptra_emu_bus::{Bus, BusError, Timer, TimerAction};
/// use caliptra_emu_types::{RvAddr, RvData, RvSize};
/// struct MyPeriph {
///     timer: Timer,
///     action0: Option<TimerAction>,
/// }
/// impl Bus for MyPeriph {
///     fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
///         Ok(0)
///     }
///     fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
///         // If a timer action was previously scheduled, cancel it
///         if let Some(action0) = self.action0.take() {
///             self.timer.cancel(action0);
///         }
///         // Request that Bus::poll be called in 1000 clock cycles, storing
///         // a reference to the timer action in self.action0.
///         self.action0 = Some(self.timer.schedule_poll_in(1000));
///         Ok(())
///     }
///     fn poll(&mut self) {
///         if self.timer.fired(&mut self.action0) {
///             println!("It is 1000 clock cyles after the last write to MyPeriph.")
///         }
///     }
/// }
/// ```
#[derive(Clone)]
pub struct Timer {
    clock: Rc<ClockImpl>,
}
impl Timer {
    /// Constructs a new timer bound to the specified clock.
    pub fn new(clock: &Clock) -> Self {
        Self {
            clock: Rc::clone(&clock.clock),
        }
    }

    /// Returns the current time: the number of clock cycles that have elapsed
    /// since simulation start.
    #[inline]
    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// If the scheduled time for `action` has come, `action` will be set to
    /// None and the function will return true. Otherwise (or if action is None),
    /// the function will return false.
    pub fn fired(&self, action: &mut Option<TimerAction>) -> bool {
        let has_fired = if let Some(ref action) = action {
            debug_assert_eq!(
                action.0.id.timer_ptr,
                Rc::as_ptr(&self.clock),
                "Supplied action was not created by this timer."
            );
            self.clock.has_fired(action.0.time)
        } else {
            false
        };
        if has_fired {
            *action = None;
        }
        has_fired
    }

    /// Schedules a future call to [`Bus::poll()`] at `time`, and returns a
    /// `TimerAction` that can be used with [`Timer::cancel`] or
    /// [`Timer::fired`].
    pub fn schedule_poll_at(&self, time: u64) -> TimerAction {
        self.clock.schedule_poll_at(time)
    }

    /// Schedules a future call to [`Bus::poll()`] at `self.now() + time`, and
    /// returns a `TimerAction` that can be used with [`Timer::cancel`] or
    /// [`Timer::fired`].
    pub fn schedule_poll_in(&self, ticks_from_now: u64) -> TimerAction {
        self.schedule_poll_at(self.now().wrapping_add(ticks_from_now))
    }

    /// Cancels a previously scheduled poll action.
    ///
    /// * Panics
    ///
    /// Panics if the supplied `TimerAction` was not created by this Timer.
    pub fn cancel(&self, handle: TimerAction) {
        self.clock.cancel(handle)
    }
}

pub struct Clock {
    clock: Rc<ClockImpl>,
}
impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}
impl Clock {
    /// Constructs a new Clock with the cycle counter set to 0.
    pub fn new() -> Clock {
        Self {
            clock: ClockImpl::new(),
        }
    }

    /// Constructs a `Timer` associated with this clock.
    pub fn timer(&self) -> Timer {
        Timer::new(self)
    }

    /// Returns the number of simulated clock cycles that have elapsed since
    /// simulation start.
    #[inline]
    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Increments the clock by `delta`, and returns true if any scheduled timer
    /// actions fired.
    #[inline]
    pub fn increment(&self, delta: u64) -> bool {
        self.clock.increment(delta)
    }

    /// Increments the clock by `delta`, and polls the bus if any scheduled
    /// timer actions fired.
    #[inline]
    pub fn increment_and_poll(&self, delta: u64, bus: &mut impl Bus) {
        if self.increment(delta) {
            bus.poll();
        }
    }
}

/// Represents an action scheduled with a `Timer`. Returned by
/// [`Timer::schedule_poll_at`] and passed to [`Timer::has_fired()`] or
/// [`Timer::cancel`].
pub struct TimerAction(TimerActionImpl);
impl From<TimerActionImpl> for TimerAction {
    fn from(val: TimerActionImpl) -> Self {
        TimerAction(val)
    }
}

/// The internal representation of `TimerAction`. We keep these types separate
/// to avoid exposing these implementation-specific traits.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
struct TimerActionImpl {
    /// The time the action is supposed to fire.
    time: u64,

    id: TimerActionId,
}
impl From<TimerAction> for TimerActionImpl {
    fn from(val: TimerAction) -> Self {
        val.0
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
struct TimerActionId {
    /// Pointer to the TimerImpl that this action is scheduled on. This pointer
    /// is used for identification purposes only; it prevents ActionIds from one
    /// Timer from being mixed up with another Timer.
    timer_ptr: *const ClockImpl,

    /// An ID assigned by the TimerImpl
    id: u64,
}
impl Default for TimerActionId {
    fn default() -> Self {
        Self {
            timer_ptr: ptr::null(),
            id: 0,
        }
    }
}

struct ClockImpl {
    now: Cell<u64>,
    next_action_time: Cell<Option<u64>>,
    next_action_id: Cell<u64>,
    future_poll_actions: RefCell<BTreeSet<TimerActionImpl>>,
}
impl ClockImpl {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            now: Cell::new(0),
            next_action_time: Cell::new(None),
            next_action_id: Cell::new(0),
            future_poll_actions: RefCell::new(BTreeSet::new()),
        })
    }

    #[inline]
    fn now(&self) -> u64 {
        self.now.get()
    }

    #[inline]
    fn increment(&self, delta: u64) -> bool {
        assert!(
            delta < (u64::MAX >> 1),
            "Cannot increment the current time by more than {} clock cycles.",
            (u64::MAX >> 1)
        );
        self.now.set(self.now.get().wrapping_add(delta));
        if let Some(next_action_time) = self.next_action_time.get() {
            if self.has_fired(next_action_time) {
                self.remove_fired_actions();
                return true;
            }
        }
        false
    }

    fn schedule_poll_at(self: &Rc<Self>, time: u64) -> TimerAction {
        assert!(
            time.wrapping_sub(self.now()) < (u64::MAX >> 1),
            "Cannot schedule a timer action more than {} clock cycles from now.",
            (u64::MAX >> 1)
        );
        let new_action = TimerActionImpl {
            time,
            id: self.next_action_id(),
        };
        let mut actions = self.future_poll_actions.borrow_mut();
        actions.insert(new_action);
        self.recompute_next_action_time(&actions);
        new_action.into()
    }
    fn cancel(self: &Rc<Self>, action: TimerAction) {
        let action = TimerActionImpl::from(action);
        assert_eq!(
            Rc::as_ptr(self),
            action.id.timer_ptr,
            "Supplied action was not created by this timer."
        );
        let mut future_actions = self.future_poll_actions.borrow_mut();
        future_actions.remove(&action);
        self.recompute_next_action_time(&future_actions)
    }
    fn next_action_id(self: &Rc<Self>) -> TimerActionId {
        let result = TimerActionId {
            timer_ptr: Rc::as_ptr(self),
            id: self.next_action_id.get(),
        };
        self.next_action_id
            .set(self.next_action_id.get().wrapping_add(1));
        result
    }
    fn has_fired(&self, action_time: u64) -> bool {
        self.now().wrapping_sub(action_time) < (u64::MAX >> 1)
    }
    fn recompute_next_action_time(&self, future_actions: &BTreeSet<TimerActionImpl>) {
        self.next_action_time
            .set(self.find_next_action(future_actions).map(|a| a.time));
    }
    fn find_next_action<'a>(
        &self,
        future_actions: &'a BTreeSet<TimerActionImpl>,
    ) -> Option<&'a TimerActionImpl> {
        let search_start = self.now().wrapping_sub(u64::MAX >> 1);
        let search_action = TimerActionImpl {
            time: search_start,
            id: TimerActionId::default(),
        };
        if let Some(action) = future_actions.range(&search_action..).next() {
            return Some(action);
        }
        future_actions.iter().next()
    }

    #[cold]
    fn remove_fired_actions(&self) {
        let mut future_actions = self.future_poll_actions.borrow_mut();
        while let Some(action) = self.find_next_action(&future_actions) {
            if !self.has_fired(action.time) {
                break;
            }
            let action = *action;
            future_actions.remove(&action);
        }
        self.recompute_next_action_time(&future_actions);
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::FakeBus;

    use super::*;

    #[test]
    fn test_clock() {
        let clock = Clock::new();
        assert_eq!(clock.now(), 0);
        assert_eq!(clock.now(), 0);
        assert!(!clock.increment(25));
        assert_eq!(clock.now(), 25);
        assert!(!clock.increment(100));
        assert_eq!(clock.now(), 125);
    }

    fn test_timer_schedule_with_clock(clock: Clock) {
        let t0 = clock.now();
        let timer = clock.timer();
        let mut action0 = Some(timer.schedule_poll_in(25));
        let mut action1 = Some(timer.schedule_poll_in(40));
        let mut action2 = Some(timer.schedule_poll_in(100));
        let mut action3 = Some(timer.schedule_poll_in(100));
        let mut action4 = Some(timer.schedule_poll_in(101));
        let mut action5 = Some(timer.schedule_poll_in(102));
        let mut action6 = Option::<TimerAction>::None;

        assert!(!clock.increment(24));
        assert_eq!(clock.now().wrapping_sub(t0), 24);
        assert!(!timer.fired(&mut action0) && action0.is_some());
        assert!(!timer.fired(&mut action2) && action2.is_some());
        assert!(!timer.fired(&mut action3) && action3.is_some());
        assert!(!timer.fired(&mut action4) && action4.is_some());
        assert!(!timer.fired(&mut action5) && action5.is_some());
        assert!(!timer.fired(&mut action6) && action6.is_none());

        assert!(clock.increment(1));
        assert_eq!(clock.now().wrapping_sub(t0), 25);
        assert!(timer.fired(&mut action0) && action0.is_none());
        assert!(!timer.fired(&mut action2) && action2.is_some());
        assert!(!timer.fired(&mut action3) && action3.is_some());
        assert!(!timer.fired(&mut action4) && action4.is_some());
        assert!(!timer.fired(&mut action5) && action5.is_some());
        assert!(!timer.fired(&mut action6) && action6.is_none());

        assert!(!clock.increment(1));
        assert_eq!(clock.now().wrapping_sub(t0), 26);
        assert!(!timer.fired(&mut action0) && action0.is_none());
        assert!(!timer.fired(&mut action2) && action2.is_some());
        assert!(!timer.fired(&mut action3) && action3.is_some());
        assert!(!timer.fired(&mut action4) && action4.is_some());
        assert!(!timer.fired(&mut action5) && action5.is_some());
        assert!(!timer.fired(&mut action6) && action6.is_none());

        action6 = Some(timer.schedule_poll_in(1));

        assert!(clock.increment(1));
        assert_eq!(clock.now().wrapping_sub(t0), 27);
        assert!(!timer.fired(&mut action0) && action0.is_none());
        assert!(!timer.fired(&mut action2) && action2.is_some());
        assert!(!timer.fired(&mut action3) && action3.is_some());
        assert!(!timer.fired(&mut action4) && action4.is_some());
        assert!(!timer.fired(&mut action5) && action5.is_some());
        assert!(timer.fired(&mut action6) && action6.is_none());

        timer.cancel(action1.take().unwrap());
        assert!(!clock.increment(24));
        assert_eq!(clock.now().wrapping_sub(t0), 51);

        assert!(clock.increment(50));
        assert_eq!(clock.now().wrapping_sub(t0), 101);
        assert!(!timer.fired(&mut action0) && action0.is_none());
        assert!(timer.fired(&mut action2) && action2.is_none());
        assert!(timer.fired(&mut action3) && action3.is_none());
        assert!(timer.fired(&mut action4) && action4.is_none());
        assert!(!timer.fired(&mut action5) && action5.is_some());
        assert!(!timer.fired(&mut action6) && action6.is_none());

        assert!(clock.increment(1000000000000000000));
        assert!(!timer.fired(&mut action0) && action0.is_none());
        assert!(!timer.fired(&mut action2) && action2.is_none());
        assert!(!timer.fired(&mut action3) && action3.is_none());
        assert!(!timer.fired(&mut action4) && action4.is_none());
        assert!(timer.fired(&mut action5) && action5.is_none());
        assert!(!timer.fired(&mut action6) && action6.is_none());

        assert!(!clock.increment(1000000000000000000));
    }

    #[test]
    fn test_timer_schedule_with_clock_at_0() {
        let clock = Clock::new();
        test_timer_schedule_with_clock(clock);
    }

    #[test]
    fn test_timer_schedule_with_clock_at_12327834() {
        let clock = Clock::new();
        assert!(!clock.increment(234293489238));
        test_timer_schedule_with_clock(clock);
    }

    #[test]
    fn test_timer_schedule_clock_wraparound() {
        for i in (u64::MAX - 120)..=u64::MAX {
            let clock = Clock::new();
            clock.clock.now.set(i);
            test_timer_schedule_with_clock(clock);
        }
    }
    #[test]
    fn test_timer_schedule_clock_searchback_wraparound() {
        for i in ((u64::MAX >> 1) - 130)..=((u64::MAX >> 1) + 130) {
            let clock = Clock::new();
            clock.clock.now.set(i);
            test_timer_schedule_with_clock(clock);
        }
    }

    #[test]
    fn test_increment_and_poll() {
        let clock = Clock::new();
        let timer = clock.timer();
        let mut bus = FakeBus::new();

        let mut action0 = Some(timer.schedule_poll_in(25));
        clock.increment_and_poll(20, &mut bus);
        assert_eq!(bus.log.take(), "");

        clock.increment_and_poll(20, &mut bus);
        assert_eq!(bus.log.take(), "poll()\n");

        assert!(timer.fired(&mut action0));
    }

    #[test]
    #[should_panic(
        expected = "Cannot schedule a timer action more than 9223372036854775807 clock cycles from now."
    )]
    fn test_schedule_too_far_in_future() {
        let clock = Clock::new();
        clock.increment(123729);
        let timer = Timer::new(&clock);
        timer.schedule_poll_in(0x7fff_ffff_ffff_ffff);
    }

    #[test]
    #[should_panic(
        expected = "Cannot increment the current time by more than 9223372036854775807 clock cycles."
    )]
    fn test_increment_too_far() {
        let clock = Clock::new();
        clock.increment(0x7fff_ffff_ffff_ffff);
    }

    #[test]
    #[should_panic(expected = "Supplied action was not created by this timer.")]
    fn test_mixup_timer_actions_on_cancel() {
        let clock0 = Clock::new();
        let clock0_action0 = clock0.timer().schedule_poll_at(50);

        let clock1 = Clock::new();
        let _clock1_action0 = clock1.timer().schedule_poll_at(50);

        clock1.timer().cancel(clock0_action0);
    }
}

/*++

Licensed under the Apache-2.0 license.

File Name:

    uart.rs

Abstract:

    File contains VeeR Internal Timers implementation.

--*/

use caliptra_emu_bus::{ActionHandle, Clock, Timer, TimerAction};
use std::rc::Rc;

struct InternalTimer {
    /// Which timer are we.
    id: u8,
    /// Clock.now() when this timer was last written to.
    last_set_ticks: u64,
    /// Value this timer was last set to
    last_set_val: u32,
    /// Bound to trigger interrupt at.
    bound: u32,
    /// The handle for the timer action for the last fired trap.
    timer_action: Option<ActionHandle>,
    /// Whether this timer is cascaded (timer 1 only).
    cascade: bool,
    /// True if this timer is incremented in pause mode.
    pause_en: bool,
    /// True if this timer is incremented in sleep mode.
    halt_en: bool,
    /// Whether this timer is enabled.
    enabled: bool,
}

impl InternalTimer {
    fn new(id: u8) -> InternalTimer {
        InternalTimer {
            id,
            last_set_ticks: 0,
            last_set_val: 0,
            bound: 0xffff_ffff,
            timer_action: None,
            cascade: false,
            pause_en: false,
            halt_en: false,
            enabled: true,
        }
    }

    fn read_control(&self) -> u32 {
        let mut ctl = 0;
        if self.cascade {
            ctl |= 1 << 3;
        }
        if self.pause_en {
            ctl |= 1 << 2;
        }
        if self.halt_en {
            ctl |= 1 << 1;
        }
        if self.enabled {
            ctl |= 1;
        }
        ctl
    }

    fn write_control(&mut self, val: u32, timer: &Timer, now: u64) {
        self.enabled = val & 1 == 1;
        self.halt_en = val & 2 == 2;
        self.pause_en = val & 4 == 4;
        self.cascade = val & 8 == 8;
        self.arm(timer, now);
    }

    fn read_time(&self, now: u64) -> u32 {
        let elapsed = ((now - self.last_set_ticks) & 0xffff_ffff) as u32;
        self.last_set_val.wrapping_add(elapsed)
    }

    fn write_time(&mut self, val: u32, timer: &Timer, now: u64) {
        self.last_set_ticks = now;
        self.last_set_val = val;
        self.arm(timer, now);
    }

    fn write_bound(&mut self, val: u32, timer: &Timer, now: u64) {
        self.bound = val;
        self.arm(timer, now);
    }

    fn interrupt_pending(&self, now: u64) -> bool {
        self.read_time(now) >= self.bound
    }

    pub(crate) fn ticks_to_interrupt(&self, now: u64) -> u32 {
        self.bound.saturating_sub(self.read_time(now)).max(1)
    }

    fn arm(&mut self, timer: &Timer, now: u64) {
        if let Some(action) = self.timer_action.take() {
            timer.cancel(action);
        }
        if !self.enabled {
            return;
        }
        // TODO: support cascaded timer
        let next_interrupt = self.ticks_to_interrupt(now);
        self.timer_action = Some(timer.schedule_action_in(
            next_interrupt as u64,
            TimerAction::InternalTimerLocalInterrupt { timer_id: self.id },
        ));
    }
}

pub struct InternalTimers {
    clock: Rc<Clock>,
    clock_timer: Timer,
    timer0: InternalTimer,
    timer1: InternalTimer,
}

impl InternalTimers {
    pub fn new(clock: Rc<Clock>) -> Self {
        let clock_timer = clock.timer();
        Self {
            clock: clock.clone(),
            clock_timer,
            timer0: InternalTimer::new(0),
            timer1: InternalTimer::new(1),
        }
    }

    pub fn read_mitcnt0(&self) -> u32 {
        self.timer0.read_time(self.clock.now())
    }

    pub fn read_mitcnt1(&self) -> u32 {
        self.timer1.read_time(self.clock.now())
    }

    pub fn write_mitcnt0(&mut self, val: u32) {
        self.timer0
            .write_time(val, &self.clock_timer, self.clock.now());
    }

    pub fn write_mitcnt1(&mut self, val: u32) {
        self.timer1
            .write_time(val, &self.clock_timer, self.clock.now());
    }

    pub fn read_mitb0(&self) -> u32 {
        self.timer0.bound
    }

    pub fn read_mitb1(&self) -> u32 {
        self.timer0.bound
    }

    pub fn write_mitb0(&mut self, val: u32) {
        self.timer0
            .write_bound(val, &self.clock_timer, self.clock.now());
    }

    pub fn write_mitb1(&mut self, val: u32) {
        self.timer1
            .write_bound(val, &self.clock_timer, self.clock.now());
    }

    pub fn read_mitctl0(&self) -> u32 {
        self.timer0.read_control()
    }

    pub fn read_mitctl1(&self) -> u32 {
        self.timer1.read_control()
    }

    pub fn write_mitctl0(&mut self, val: u32) {
        self.timer0
            .write_control(val, &self.clock_timer, self.clock.now())
    }

    pub fn write_mitctl1(&mut self, val: u32) {
        self.timer1
            .write_control(val, &self.clock_timer, self.clock.now())
    }

    pub fn interrupts_pending(&self) -> (bool, bool) {
        (
            self.timer0.interrupt_pending(self.clock.now()),
            self.timer1.interrupt_pending(self.clock.now()),
        )
    }
}

#[cfg(test)]
mod test {
    use std::rc::Rc;

    use super::InternalTimer;
    use caliptra_emu_bus::Clock;

    #[test]
    fn test_ticks_to_interrupt() {
        let clock = Rc::new(Clock::new());
        let t = clock.timer();
        let mut itimer = InternalTimer::new(0);
        itimer.write_bound(300, &t, 100);
        assert_eq!(200, itimer.ticks_to_interrupt(100));
    }

    #[test]
    fn test_ticks_to_interrupt_underflow() {
        let clock = Rc::new(Clock::new());
        let t = clock.timer();
        let mut itimer = InternalTimer::new(0);
        itimer.write_bound(300, &t, 100);
        assert_eq!(1, itimer.ticks_to_interrupt(400));
    }
}

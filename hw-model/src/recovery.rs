// Licensed under the Apache-2.0 license

use caliptra_emu_bus::{Device, Event, EventData, ReadWriteRegister, RecoveryCommandCode};
use caliptra_emu_periph::dma::recovery::RecoveryStatus;
use smlang::statemachine;
use std::sync::mpsc;
use tock_registers::interfaces::Readable;
use tock_registers::register_bitfields;

statemachine! {
    derive_states: [Clone, Copy, Debug],
    transitions: {
        // syntax: CurrentState Event [guard] / action = NextState

        // start by reading ProtCap to see if the device supports recovery
        *ReadProtCap + ProtCap(ProtCapBlock) [check_device_status_support] = ReadDeviceStatus,
        ReadProtCap + ProtCap(ProtCapBlock) [check_no_device_status_support] = Done,

        // read the device status to see if it needs recovery
        ReadDeviceStatus + DeviceStatus(DeviceStatusBlock) [check_device_status_healthy] = Done,

        // if the device needs recovery, send the recovery control message
        ReadDeviceStatus + DeviceStatus(DeviceStatusBlock) [check_device_status_recovery]
            / send_recovery_control = WaitForRecoveryStatus,

        // send the requested recovery image
        WaitForRecoveryStatus + RecoveryStatus(RecoveryStatusBlock) [check_recovery_status_awaiting]
            / start_recovery = WaitForRecoveryPending,

        // activate the recovery image after it has been processed
        WaitForRecoveryPending + DeviceStatus(DeviceStatusBlock) [check_device_status_recovery_pending]
            / activate = Activate,

        // check if we need to send another recovery image (if awaiting image is set and running recovery)
        Activate + DeviceStatus(DeviceStatusBlock) [check_device_status_recovery]
            = WaitForRecoveryStatus,
        // Activate + DeviceStatus(DeviceStatusBlock) [check_device_status_recovery_running_recovery]
        //     = ActivateCheckRecoveryStatus,
        // ActivateCheckRecoveryStatus + RecoveryStatus(RecoveryStatusBlock) [check_recovery_status_awaiting]
        //     / start_recovery = WaitForRecoveryPending,
    }
}

// map states to the corresponding recovery read block we want to read
pub(crate) fn state_to_read_request(state: States) -> Option<Event> {
    let command_code = match state {
        States::ReadProtCap => Some(RecoveryCommandCode::ProtCap),
        States::ReadDeviceStatus => Some(RecoveryCommandCode::DeviceStatus),
        States::WaitForRecoveryStatus => Some(RecoveryCommandCode::RecoveryStatus),
        States::WaitForRecoveryPending => Some(RecoveryCommandCode::DeviceStatus),
        States::Activate => Some(RecoveryCommandCode::DeviceStatus),
        //States::ActivateCheckRecoveryStatus => Some(RecoveryCommandCode::RecoveryStatus),
        _ => None,
    };

    command_code.map(|command_code| {
        Event::new(
            Device::BMC,
            Device::CaliptraCore,
            EventData::RecoveryBlockReadRequest {
                source_addr: 0,
                target_addr: 0,
                command_code,
            },
        )
    })
}

register_bitfields! [
    u32,
    pub ProtCap2 [
        AgentCapabilities OFFSET(16) NUMBITS(16) [
            Identification = 1<<0,
            ForcedRecovery = 1<<1,
            MgmtReset = 1<<2,
            DeviceReset = 1<<3,
            DeviceStatus = 1<<4,
            RecoveryImageAccess = 1<<5,
            LocalCImageSupport = 1<<6,
            PushCImageSupport = 1<<7,
            InterfaceIsolation = 1<<8,
            HardwareStatus = 1<<9,
            VendorCommand = 1<<10,
            FlashlessBoot = 1<<11,
            FifoCmsSupport = 1<<12,
            // Other bits are reserved
        ],
    ],
    pub DeviceStatus [
        Status OFFSET(0) NUMBITS(8) [
            Pending = 0,
            Healthy = 1,
            Error = 2,
            RecoveryMode = 3,
            RecoveryPending = 4,
            RunnningRecoveryImage = 5,
            BootFailure = 0xe,
            FatalError = 0xf,
            // Other values reserved
        ],
        ProtocolError OFFSET(8) NUMBITS(8) [
            NoError = 0,
            UnsupportedWriteCommand = 1,
            UnsupportedParameter = 2,
            LengthWriteError = 3,
            CrcError = 4,
            GeneralProtocolError = 0xff,
            // Other values reserved
        ],
        RecoveryReasonCode OFFSET(16) NUMBITS(16) [],
    ],
];

type ProtCapBlock = ReadWriteRegister<u32, ProtCap2::Register>;
type DeviceStatusBlock = ReadWriteRegister<u32, DeviceStatus::Register>;
type RecoveryStatusBlock = ReadWriteRegister<u32, RecoveryStatus::Register>;

/// State machine extended variables.
pub(crate) struct Context {
    events_to_caliptra: mpsc::Sender<Event>,
    pub(crate) recovery_images: Vec<Vec<u8>>,
}

impl Context {
    pub(crate) fn new(events_to_caliptra: mpsc::Sender<Event>) -> Context {
        Context {
            events_to_caliptra,
            recovery_images: vec![],
        }
    }
}

impl StateMachineContext for Context {
    /// Check that the the protcap supports device status
    fn check_device_status_support(&self, prot_cap: &ProtCapBlock) -> Result<bool, ()> {
        let agent_cap = prot_cap.reg.get();
        Ok(ProtCap2::AgentCapabilities::DeviceStatus.any_matching_bits_set(agent_cap))
    }

    /// Check that the the protcap does not support device status
    fn check_no_device_status_support(&self, prot_cap: &ProtCapBlock) -> Result<bool, ()> {
        let agent_cap = prot_cap.reg.get();
        Ok(!ProtCap2::AgentCapabilities::DeviceStatus.any_matching_bits_set(agent_cap))
    }

    /// Chjeck that the device status is healthy
    fn check_device_status_healthy(&self, status: &DeviceStatusBlock) -> Result<bool, ()> {
        let status = status.reg.read(DeviceStatus::Status);
        if status == DeviceStatus::Status::Healthy.value {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check that the device status is recovery mode
    fn check_device_status_recovery(&self, status: &DeviceStatusBlock) -> Result<bool, ()> {
        let status = status.reg.read(DeviceStatus::Status);
        if status == DeviceStatus::Status::RecoveryMode.value {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check that the recovery status is awaiting a recovery image
    fn check_recovery_status_awaiting(&self, status: &RecoveryStatusBlock) -> Result<bool, ()> {
        let recovery = status.reg.read(RecoveryStatus::DEVICE_RECOVERY);
        if recovery == RecoveryStatus::DEVICE_RECOVERY::AwaitingRecoveryImage.value {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check that the device status is recovery pending
    fn check_device_status_recovery_pending(&self, status: &DeviceStatusBlock) -> Result<bool, ()> {
        let status = status.reg.read(DeviceStatus::Status);
        if status == DeviceStatus::Status::RecoveryPending.value {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn send_recovery_control(&mut self, _status: DeviceStatusBlock) -> Result<(), ()> {
        self.events_to_caliptra
            .send(Event::new(
                Device::BMC,
                Device::CaliptraCore,
                EventData::RecoveryBlockWrite {
                    source_addr: 0,
                    target_addr: 0,
                    command_code: RecoveryCommandCode::RecoveryCtrl,
                    payload: vec![0, 0, 0],
                },
            ))
            .unwrap();
        Ok(())
    }

    fn activate(&mut self, _: DeviceStatusBlock) -> Result<(), ()> {
        self.events_to_caliptra
            .send(Event::new(
                Device::BMC,
                Device::CaliptraCore,
                EventData::RecoveryBlockWrite {
                    source_addr: 0,
                    target_addr: 0,
                    command_code: RecoveryCommandCode::RecoveryCtrl,
                    payload: vec![0, 0, 0xf], // activate
                },
            ))
            .unwrap();
        Ok(())
    }

    fn start_recovery(&mut self, status: RecoveryStatusBlock) -> Result<(), ()> {
        let idx = status.reg.read(RecoveryStatus::RECOVERY_IMAGE_INDEX);

        if idx as usize >= self.recovery_images.len() {
            println!(
                "[emulator bmc recovery] Invalid recovery image index {}",
                idx
            );
            Err(())
        } else {
            let image = &self.recovery_images[idx as usize];
            println!("[emulator bmc recovery] Sending recovery image {}", idx);
            self.events_to_caliptra
                .send(Event::new(
                    Device::BMC,
                    Device::CaliptraCore,
                    EventData::RecoveryImageAvailable {
                        image_id: idx as u8,
                        image: image.clone(),
                    },
                ))
                .unwrap();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_no_prot_cap() {
        let (tx, _) = mpsc::channel();
        let context = Context::new(tx);
        let mut sm = StateMachine::new(context);
        assert_eq!(*sm.state(), States::ReadProtCap);
        // we will go straight to Done if the ProtCap isn't valid
        assert!(sm.process_event(Events::ProtCap(0u32.into())).is_ok());
        assert_eq!(*sm.state(), States::Done);
    }
}

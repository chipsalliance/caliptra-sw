/*++

Licensed under the Apache-2.0 license.

File Name:

    gdb_state.rs

Abstract:

    File contains gdb_state module for Caliptra Emulator.

--*/

use super::gdb_target::GdbTarget;
use gdbstub::common::Signal;
use gdbstub::conn::{Connection, ConnectionExt};
use gdbstub::stub::SingleThreadStopReason;
use gdbstub::stub::{run_blocking, DisconnectReason, GdbStub, GdbStubError};
use gdbstub::target::Target;
use std::net::TcpListener;

enum GdbEventLoop {}

// The `run_blocking::BlockingEventLoop` groups together various callbacks
// the `GdbStub::run_blocking` event loop requires you to implement.
impl run_blocking::BlockingEventLoop for GdbEventLoop {
    type Target = GdbTarget;
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;

    // or MultiThreadStopReason on multi threaded targets
    type StopReason = SingleThreadStopReason<u32>;

    // Invoked immediately after the target's `resume` method has been
    // called. The implementation should block until either the target
    // reports a stop reason, or if new data was sent over the connection.
    fn wait_for_stop_reason(
        target: &mut GdbTarget,
        _conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<SingleThreadStopReason<u32>>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as Connection>::Error,
        >,
    > {
        // Execute Target until a stop reason (e.g. SW Breakpoint)
        let stop_reason = target.run();

        // Report Stop Reason
        Ok(run_blocking::Event::TargetStopped(stop_reason))
    }

    // Invoked when the GDB client sends a Ctrl-C interrupt.
    fn on_interrupt(
        _target: &mut GdbTarget,
    ) -> Result<Option<SingleThreadStopReason<u32>>, <GdbTarget as Target>::Error> {
        // a pretty typical stop reason in response to a Ctrl-C interrupt is to
        // report a "Signal::SIGINT".
        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}

// Routine which creates TCP Socket for GDB and execute State Machine
pub fn wait_for_gdb_run(cpu: &mut GdbTarget, port: u16) {
    // Create Socket
    let sockaddr = format!("localhost:{}", port);
    eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);
    let sock = TcpListener::bind(sockaddr).unwrap();
    let (stream, addr) = sock.accept().unwrap();
    eprintln!("Debugger connected from {}", addr);

    // Create Connection
    let connection: Box<dyn ConnectionExt<Error = std::io::Error>> = Box::new(stream);

    // Instantiate GdbStub
    let gdb = GdbStub::new(connection);

    // Execute GDB until a disconnect event
    match gdb.run_blocking::<GdbEventLoop>(cpu) {
        Ok(disconnect_reason) => match disconnect_reason {
            DisconnectReason::Disconnect => {
                println!("Client disconnected")
            }
            DisconnectReason::TargetExited(code) => {
                println!("Target exited with code {}", code)
            }
            DisconnectReason::TargetTerminated(sig) => {
                println!("Target terminated with signal {}", sig)
            }
            DisconnectReason::Kill => println!("GDB sent a kill command"),
        },
        Err(GdbStubError::TargetError(e)) => {
            println!("target encountered a fatal error: {}", e)
        }
        Err(e) => {
            println!("gdbstub encountered a fatal error: {}", e)
        }
    }
}

// Licensed under the Apache-2.0 license

mod find_usb_block_device;
mod fpga_jtag;
mod ftdi;
mod ftdi_uart;
mod sd_mux;
mod tty;
mod usb_port_path;

use anyhow::{anyhow, Context};

use clap::{arg, value_parser};
use libftdi1_sys::ftdi_interface;
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{stdout, BufRead, BufReader, Error, ErrorKind, Lines, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

pub(crate) use fpga_jtag::{FpgaJtag, FpgaReset};
pub(crate) use ftdi::FtdiCtx;
use sd_mux::{SDWire, SdMux, SdMuxTarget, UsbsdMux};
pub(crate) use usb_port_path::UsbPortPath;

fn cli() -> clap::Command<'static> {
    clap::Command::new("fpga-boss")
        .about("FPGA boss tool")
        .arg(
            arg!(--"sdwire" [PORT_PATH] "USB port path to the hub chip on the SDWire (ex: 3-1.2)")
                .value_parser(value_parser!(OsString)))
        .arg(
            arg!(--"usbsdmux" [USBID] "USB unique ID for the usbsdmux device (ex: 00048.00643)")
                .value_parser(value_parser!(OsString))
        )
        .arg(
            arg!(--"zcu104" [PORT_PATH] "USB port path to the FTDI chip on the ZCU104 dev board (ex: 3-1.2)")
                .value_parser(value_parser!(UsbPortPath))
        )
        .arg(
            arg!(--"boss_ftdi" [PORT_PATH] "USB port path to a FTDI C232HM-DDHSL cable plugged into an rPi (ex: 3-1.2")
                .value_parser(value_parser!(UsbPortPath))
        )
        .subcommand_required(true)
        .subcommand(clap::Command::new("mode")
            .about("Set the state of the reset / sdwire pins")
            .arg(arg!(<MODE>).value_parser(value_parser!(SdMuxTarget))))
            .arg_required_else_help(true)
        .subcommand(clap::Command::new("flash")
            .about("Flash an image file to the sdwire and boot the DUT")
            .arg(arg!(-r --read_first).takes_value(false).help("To reduce write cycles, read contents first, and don't flash if they are already as expected."))
            .arg(arg!(<IMAGE_FILENAME>).value_parser(value_parser!(PathBuf))))
        .subcommand(clap::Command::new("console")
            .about("Tail the UART output from zcu104"))
        .subcommand(clap::Command::new("reset_ftdi")
            .about("Reset FTDI chip on zcu104"))
        .subcommand(clap::Command::new("serve")
            .arg(arg!(<IMAGE_FILENAME>).value_parser(value_parser!(PathBuf)))
            .arg(arg!(<CMD> ...).value_parser(value_parser!(OsString)).help("The command (and arguments) to read jitconfig entries from")))
}

fn main() {
    match main_impl() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("Fatal error: {e:#}");
            std::process::exit(1);
        }
    }
}

fn open_block_dev(path: &Path) -> std::io::Result<File> {
    let mut tries = 0_u32;
    loop {
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(result) => return Ok(result),
            Err(err) => {
                if err.raw_os_error() == Some(libc::ENOMEDIUM) {
                    if tries == 0 {
                        println!("Waiting for attached sd card to be noticed by OS")
                    }
                    // SD card hasn't been found by the OS yet
                    tries += 1;
                    if tries < 1000 {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                }
                return Err(err);
            }
        }
    }
}

/// Returns true if the device already contains the image.
fn verify_image(dev: &mut File, image: &mut File) -> std::io::Result<bool> {
    dev.seek(SeekFrom::Start(0))?;
    let file_len = image.metadata()?.len();
    let mut want = vec![0_u8; 1024 * 1024];
    let mut have = vec![0_u8; 1024 * 1024];
    let mut total_read: u64 = 0;
    let start_time = Instant::now();
    loop {
        let bytes_read = image.read(&mut want)?;
        if bytes_read == 0 {
            return Ok(true);
        }
        dev.read_exact(&mut have[..bytes_read])?;
        if want[..bytes_read] != have[..bytes_read] {
            return Ok(false);
        }
        total_read += u64::try_from(bytes_read).unwrap();
        let duration = Instant::now() - start_time;
        print!(
            "Read {} MB of {} MB: {:.1} MB/sec \r",
            total_read / (1024 * 1024),
            file_len / (1024 * 1024),
            total_read as f64 / duration.as_secs_f64() / (1024.0 * 1024.0)
        );
        std::io::stdout().flush()?;
    }
}

fn copy_file(dest: &mut File, src: &mut File) -> std::io::Result<()> {
    src.seek(SeekFrom::Start(0))?;
    dest.seek(SeekFrom::Start(0))?;
    let file_len = src.metadata()?.len();
    let mut buf = vec![0_u8; 1024 * 1024];
    let mut total_written: u64 = 0;
    let start_time = Instant::now();
    loop {
        let bytes_read = src.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        total_written += u64::try_from(bytes_read).unwrap();
        dest.write_all(&buf[..bytes_read])?;
        dest.sync_data()?;
        let duration = Instant::now() - start_time;
        print!(
            "Wrote {} MB of {} MB: {:.1} MB/sec \r",
            total_written / (1024 * 1024),
            file_len / (1024 * 1024),
            total_written as f64 / duration.as_secs_f64() / (1024.0 * 1024.0)
        );
        std::io::stdout().flush()?;
    }
    dest.flush()?;
    dest.sync_all()?;
    Ok(())
}

/// As we observe conditions that get the FGPA stuck, add them to the error parser.
fn active_runner_error_checks(input: &str) -> std::io::Result<()> {
    check_for_github_runner_exception(input)?;
    check_for_kernel_panic(input)?;
    Ok(())
}

/// If the GitHub runner has an unhandled exception it will crash and get stuck. Add this check
/// to recover the FPGA.
fn check_for_github_runner_exception(input: &str) -> std::io::Result<()> {
    if input.contains("Unhandled exception") {
        Err(Error::new(
            ErrorKind::BrokenPipe,
            "Github runner had an unhandled exception",
        ))?;
    }
    Ok(())
}

/// A kernel panic will cause the FPGA to never complete the job, so we want to reset the FPGA.
fn check_for_kernel_panic(input: &str) -> std::io::Result<()> {
    if input.contains("Kernel panic") {
        Err(Error::new(ErrorKind::BrokenPipe, "FPGA had a kernel panic"))?;
    }
    Ok(())
}

fn log_uart_until<R: BufRead>(
    lines: &mut Lines<R>,
    needle: &str,
    error_parser: impl Fn(&str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    log_uart_until_helper(lines, needle, None, Some(error_parser))
}

fn log_uart_until_with_timeout<R: BufRead>(
    lines: &mut Lines<R>,
    needle: &str,
    timeout: Duration,
) -> std::io::Result<()> {
    log_uart_until_helper(
        lines,
        needle,
        Some(timeout),
        None::<fn(&str) -> std::io::Result<()>>,
    )
}

fn log_uart_until_helper<R: BufRead>(
    lines: &mut Lines<R>,
    needle: &str,
    timeout: Option<Duration>,
    error_parser: Option<impl Fn(&str) -> std::io::Result<()>>,
) -> std::io::Result<()> {
    let start = Instant::now();
    for line in lines.by_ref() {
        match line {
            Ok(line) => {
                println!("UART: {}", line);
                if line.contains(needle) {
                    return Ok(());
                }
                if let Some(ref error_parser) = error_parser {
                    error_parser(&line)?;
                }
            }
            // If no time out was configured, swallow this error.
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                if let Some(timeout) = timeout {
                    if start.elapsed() > timeout {
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                println!("UART error: {}", e);
            }
        }
    }
    Err(Error::new(ErrorKind::UnexpectedEof, "unexpected EOF"))
}

fn main_impl() -> anyhow::Result<()> {
    let matches = cli().get_matches();
    let sdwire = matches.get_one::<OsString>("sdwire");
    let usbsdmux = matches.get_one::<OsString>("usbsdmux");

    let zcu104_path = matches.get_one::<UsbPortPath>("zcu104");
    let boss_ftdi_path = matches.get_one::<UsbPortPath>("boss_ftdi");

    let get_nonblocking_uart = || match (zcu104_path, boss_ftdi_path) {
        (Some(zcu104_path), None) => {
            ftdi_uart::open(zcu104_path.clone(), ftdi_interface::INTERFACE_B)
        }
        (None, Some(boss_ftdi_path)) => {
            ftdi_uart::open(boss_ftdi_path.clone(), ftdi_interface::INTERFACE_A)
        }
        _ => Err(anyhow!("One of --zcu104_path or --boss_ftdi_path required")),
    };

    let get_zcu104_path = || {
        zcu104_path
            .ok_or(anyhow!("--zcu104 flag required"))
            .cloned()
    };

    let mut sd_mux: Box<dyn SdMux> = match (sdwire, usbsdmux) {
        (Some(sdwire), None) => {
            Box::new(SDWire::open(String::from(sdwire.to_str().unwrap()))?) as Box<dyn SdMux>
        }
        (None, Some(usbsdmux)) => {
            Box::new(UsbsdMux::open(String::from(usbsdmux.to_str().unwrap()))?) as Box<dyn SdMux>
        }
        _ => return Err(anyhow!("One of --sdwire or --usbsdmux required")),
    };

    let get_fpga_ftdi = || FpgaJtag::open(get_zcu104_path()?);
    match matches.subcommand() {
        Some(("mode", sub_matches)) => {
            let mut fpga = get_fpga_ftdi();
            match sub_matches.get_one::<SdMuxTarget>("MODE").unwrap() {
                SdMuxTarget::Dut => {
                    if let Ok(fpga) = &mut fpga {
                        fpga.set_reset(FpgaReset::Reset)?;
                    }
                    sd_mux.set_target(SdMuxTarget::Dut)?;
                    std::thread::sleep(Duration::from_millis(1));
                    if let Ok(fpga) = &mut fpga {
                        fpga.set_reset(FpgaReset::Run)?;
                    }
                }
                SdMuxTarget::Host => {
                    if let Ok(fpga) = &mut fpga {
                        fpga.set_reset(FpgaReset::Reset)?;
                    }
                    sd_mux.set_target(SdMuxTarget::Host)?;
                }
            }
        }
        Some(("reset_ftdi", _)) => {
            let mut fpga = get_fpga_ftdi()?;
            fpga.ftdi.reset()?;
        }
        Some(("console", _)) => {
            let (mut uart_rx, mut uart_tx) = get_nonblocking_uart()?;

            let mut stdout_buf = [0_u8; 4096];
            let mut stdin_buf = [0_u8; 4096];

            println!("To exit terminal type Ctrl-T then Q");
            // Will reset terminal back to regular settings upon drop
            let raw_terminal = tty::RawTerminal::from_stdin()?;

            let mut escaper = tty::EscapeSeqStateMachine::new();
            let mut alive = true;

            while alive {
                let mut stdin_len = tty::read_stdin_nonblock(&mut stdin_buf)?;
                escaper.process(&mut stdin_buf, &mut stdin_len, |ch| match ch {
                    b'q' | b'Q' => alive = false,
                    b'b' | b'B' => {
                        uart_tx.send_break().unwrap();
                    }
                    ch => println!(
                        "Unknown escape sequence: Ctrl-T + {:?}",
                        char::from_u32(ch.into()).unwrap_or('?')
                    ),
                });
                if stdin_len > 0 {
                    uart_tx.write_all(&stdin_buf[..stdin_len])?;
                }
                let stdout_len = uart_rx.read(&mut stdout_buf)?;
                if stdout_len > 0 {
                    stdout().write_all(&stdout_buf[..stdout_len])?;
                    stdout().flush()?;
                }
            }
            drop(raw_terminal);
            println!();
        }
        Some(("flash", sub_matches)) => {
            let mut fpga = get_fpga_ftdi();
            let sd_dev_path = sd_mux.get_sd_dev_path()?;
            if let Ok(fpga) = &mut fpga {
                fpga.set_reset(FpgaReset::Reset)?;
            }
            sd_mux.set_target(SdMuxTarget::Host)?;
            let image_filename = sub_matches.get_one::<PathBuf>("IMAGE_FILENAME").unwrap();
            println!(
                "Flashing {} to {}",
                image_filename.display(),
                sd_dev_path.display()
            );
            let mut file =
                File::open(image_filename).with_context(|| image_filename.display().to_string())?;
            let mut sd_dev =
                open_block_dev(&sd_dev_path).with_context(|| sd_dev_path.display().to_string())?;
            if !sub_matches.is_present("read_first") || !verify_image(&mut sd_dev, &mut file)? {
                copy_file(&mut sd_dev, &mut file)?;
            } else {
                println!("Device already contains the desired image");
            }
            sd_mux.set_target(SdMuxTarget::Dut)?;
            std::thread::sleep(Duration::from_millis(100));
            if let Ok(fpga) = &mut fpga {
                fpga.set_reset(FpgaReset::Run)?
            }
        }

        Some(("serve", sub_matches)) => {
            // Reuse the previous token if we never connect to GitHub.
            // This avoids creating a bunch of offline runners if the FPGA fails to establish a
            // connection.
            let mut cached_token: Option<Vec<u8>> = None;
            let mut fpga = get_fpga_ftdi()?;
            let sd_dev_path = sd_mux.get_sd_dev_path()?;
            'outer: loop {
                println!("Putting FPGA into reset");
                fpga.set_reset(FpgaReset::Reset)?;
                sd_mux.set_target(SdMuxTarget::Host)?;

                {
                    println!("Ensuring SD card contents are as expected");
                    let image_filename = sub_matches.get_one::<PathBuf>("IMAGE_FILENAME").unwrap();
                    let mut file = File::open(image_filename)
                        .with_context(|| image_filename.display().to_string())?;
                    let mut sd_dev = open_block_dev(&sd_dev_path)
                        .with_context(|| sd_dev_path.display().to_string())?;

                    if !verify_image(&mut sd_dev, &mut file)? {
                        copy_file(&mut sd_dev, &mut file)?;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }

                let boot_timeout = Duration::from_secs(60);
                let (uart_rx, mut uart_tx) = ftdi_uart::open_blocking(
                    get_zcu104_path()?,
                    ftdi_interface::INTERFACE_B,
                    Some(boot_timeout),
                )?;

                println!("Taking FPGA out of reset");
                sd_mux.set_target(SdMuxTarget::Dut)?;
                std::thread::sleep(Duration::from_millis(100));
                fpga.set_reset(FpgaReset::Run)?;

                let mut uart_lines = BufReader::new(uart_rx).lines();
                // FPGA has `fpga_timeout: Duration` to boot until we reset and try again.
                match log_uart_until_with_timeout(
                    &mut uart_lines,
                    "36668aa492b1c83cdd3ade8466a0153d --- Command input",
                    boot_timeout,
                ) {
                    Err(e) if e.kind() == ErrorKind::TimedOut => {
                        eprintln!("Timed out waiting for FPGA to boot!");
                        continue 'outer;
                    }
                    Err(e) => Err(e)?,
                    _ => (),
                }

                if cached_token.is_none() {
                    let command_args: Vec<_> =
                        sub_matches.get_many::<OsString>("CMD").unwrap().collect();

                    println!("Executing command {:?} to retrieve jitconfig", command_args);
                    let output = std::process::Command::new(command_args[0])
                        .args(&command_args[1..])
                        .stderr(Stdio::inherit())
                        .output()?;
                    if !output.status.success() {
                        println!("Error retrieving jitconfig: stdout:");
                        stdout().write_all(&output.stdout)?;
                        continue;
                    }
                    cached_token = Some(output.stdout);
                }

                uart_tx.write_all(b"runner-jitconfig ")?;
                uart_tx.write_all(
                    &cached_token
                        .clone()
                        .expect("A token should always be cached before sending it over the UART"),
                )?;
                uart_tx.write_all(b"\n")?;

                // FGPA has `boot_timeout: Duration` to connect to GitHub until we reset and try again.
                match log_uart_until_with_timeout(
                    &mut uart_lines,
                    "Listening for Jobs",
                    boot_timeout,
                ) {
                    Err(e) if e.kind() == ErrorKind::TimedOut => {
                        eprintln!("Timed out waiting for FPGA to connect to Github!");
                        continue 'outer;
                    }
                    Err(e) => Err(e)?,
                    _ => (),
                }

                cached_token = None;

                // The period of time we wait to receive a job is undefined so a timeout is not
                // appropriate.
                log_uart_until(&mut uart_lines, "Running job", active_runner_error_checks)?;

                // Now the job is started, so we want to enforce a timeout with enough time for the
                // job to complete.
                let job_timeout = Duration::from_secs(7_200);
                match log_uart_until_with_timeout(
                    &mut uart_lines,
                    "3297327285280f1ffb8b57222e0a5033 --- ACTION IS COMPLETE",
                    job_timeout,
                ) {
                    Err(e) if e.kind() == ErrorKind::TimedOut => {
                        eprintln!("Timed out waiting for FPGA to complete job!");
                        continue 'outer;
                    }
                    Err(e) => Err(e)?,
                    _ => (),
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

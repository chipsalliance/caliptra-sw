// Licensed under the Apache-2.0 license

mod find_usb_block_device;
mod fpga_jtag;
mod ftdi;
mod ftdi_uart;
mod sd_mux;
mod tty;
mod usb_port_path;

use anyhow::{anyhow, Context};
use find_usb_block_device::find_usb_block_device;

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
pub(crate) use sd_mux::{SdMux, SdMuxTarget};
pub(crate) use usb_port_path::UsbPortPath;

fn cli() -> clap::Command<'static> {
    clap::Command::new("fpga-boss")
        .about("FPGA boss tool")
        .arg(
            arg!(--"sdwire" [PORT_PATH] "USB port path to the hub chip on the SDWire (ex: 3-1.2)")
                .value_parser(value_parser!(UsbPortPath))
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

/// Returns true if the device alread contains the image.
fn verify_image(dev: &mut File, image: &mut File) -> std::io::Result<bool> {
    dev.seek(SeekFrom::Start(0))?;
    let file_len = image.metadata()?.len();
    let mut buf1 = vec![0_u8; 1024 * 1024];
    let mut buf2 = vec![0_u8; 1024 * 1024];
    let mut total_read: u64 = 0;
    let start_time = Instant::now();
    loop {
        let bytes_read = image.read(&mut buf1)?;
        if bytes_read == 0 {
            return Ok(true);
        }
        dev.read_exact(&mut buf2[..bytes_read])?;
        if buf1[..bytes_read] != buf2[..bytes_read] {
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

fn log_uart_until<R: BufRead>(lines: &mut Lines<R>, needle: &str) -> std::io::Result<()> {
    for line in lines.by_ref() {
        match line {
            Ok(line) => {
                println!("UART: {}", line);
                if line.contains(needle) {
                    return Ok(());
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
    let sdwire_hub_path = matches.get_one::<UsbPortPath>("sdwire");
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
    let get_sd_mux = || {
        SdMux::open(
            sdwire_hub_path
                .ok_or(anyhow!("--sdwire flag required"))?
                .child(2),
        )
    };
    let get_fpga_ftdi = || FpgaJtag::open(get_zcu104_path()?);
    let get_sd_dev_path = || {
        let sdwire_hub_path = sdwire_hub_path.ok_or(anyhow!("--sdwire flag required"))?;
        find_usb_block_device(&sdwire_hub_path.child(1)).with_context(|| {
            format!(
                "Could not find block device associated with {}",
                sdwire_hub_path.child(1)
            )
        })
    };

    match matches.subcommand() {
        Some(("mode", sub_matches)) => {
            let mut fpga = get_fpga_ftdi();
            let mut sd_mux = get_sd_mux()?;
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
            let mut sd_mux = get_sd_mux()?;
            let sd_dev_path = get_sd_dev_path()?;
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
            let mut fpga = get_fpga_ftdi()?;
            let mut sd_mux = get_sd_mux()?;
            let sd_dev_path = get_sd_dev_path()?;
            loop {
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

                let (uart_rx, mut uart_tx) =
                    ftdi_uart::open_blocking(get_zcu104_path()?, ftdi_interface::INTERFACE_B)?;

                println!("Taking FPGA out of reset");
                sd_mux.set_target(SdMuxTarget::Dut)?;
                std::thread::sleep(Duration::from_millis(100));
                fpga.set_reset(FpgaReset::Run)?;

                let mut uart_lines = BufReader::new(uart_rx).lines();
                log_uart_until(
                    &mut uart_lines,
                    "36668aa492b1c83cdd3ade8466a0153d --- Command input",
                )?;

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

                uart_tx.write_all(b"runner-jitconfig ")?;
                uart_tx.write_all(&output.stdout)?;
                uart_tx.write_all(b"\n")?;

                log_uart_until(
                    &mut uart_lines,
                    "3297327285280f1ffb8b57222e0a5033 --- ACTION IS COMPLETE",
                )?;
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

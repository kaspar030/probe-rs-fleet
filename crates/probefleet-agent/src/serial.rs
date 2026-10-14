//! Board USB-serial passthrough, node side (architecture §4.2, "Serial
//! passthrough").
//!
//! Three parts:
//!
//! * **Discovery** — [`SysfsSerialLister`] walks `/sys/class/tty` and resolves
//!   each tty to the USB device it hangs off; [`resolve_ports`] then picks the
//!   ttys that share a board's probe (same USB serial number, and vid/pid when
//!   known) and merges them with the board's explicit `[[board.uart]]`
//!   entries. Pure functions over an injectable lister, so tests use a sysfs
//!   fixture in a tempdir.
//! * **Opening** — the [`SerialOpener`] seam. Production opens the tty with the
//!   `serialport` crate (exclusive, i.e. `TIOCEXCL` + `flock`); tests hand out
//!   one end of a pty pair.
//! * **The channel pump** — [`run_channel`] speaks the framed
//!   [`SerialRequest`]/[`SerialEvent`] protocol on a relay channel: wait for
//!   `Open`, open the port, then pump bytes both ways and apply line-setting /
//!   modem-control requests until the client, the device, or a stop signal
//!   (lease release, kill, power cycle) ends it.
//!
//! The client never names a device path: it names a port, and the node maps
//! that name to a path it discovered or was configured with.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use probefleet_proto::serial::{
    self as wire, DataBits, FlowControl, LineSettings, Parity, SerialEvent, SerialRequest,
    StopBits, DEFAULT_BAUD,
};
use probefleet_proto::{ChannelId, DataFrame, NodeReport, SerialPortInfo};
use probefleet_wire::NodeToCoord;
use tokio::sync::{mpsc, watch};

use crate::config::BoardSpec;

/// How long the reader thread blocks in one `read` before re-checking its
/// stop flag. Bounds how long a closed channel keeps the fd open.
const READ_POLL: Duration = Duration::from_millis(50);

/// A tty that hangs off a USB device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbTty {
    /// The kernel tty name (`ttyACM0`, `ttyUSB1`).
    pub tty: String,
    /// The path to open: a `/dev/serial/by-id` link when one points at the
    /// tty (stable across re-enumeration), else `/dev/<tty>`.
    pub path: PathBuf,
    /// USB vendor id of the parent device.
    pub vid: u16,
    /// USB product id of the parent device.
    pub pid: u16,
    /// The USB device's serial-number string, if it has one.
    pub usb_serial: Option<String>,
    /// The sysfs path of the parent USB device (same for every interface).
    pub usb_device_path: PathBuf,
    /// The USB interface number the tty belongs to.
    pub interface: Option<u8>,
}

/// Enumerates USB-attached ttys. Synchronous: it reads a handful of sysfs
/// files.
pub trait SerialLister: Send + Sync {
    /// List every tty that hangs off a USB device.
    fn list(&self) -> Vec<UsbTty>;
}

/// The real lister: walks `<sys_root>/class/tty` and `<dev_root>/serial/by-id`.
#[derive(Debug, Clone)]
pub struct SysfsSerialLister {
    sys_root: PathBuf,
    dev_root: PathBuf,
}

impl Default for SysfsSerialLister {
    fn default() -> Self {
        Self::new("/sys", "/dev")
    }
}

impl SysfsSerialLister {
    /// A lister rooted at `sys_root` / `dev_root` (tests point these at a
    /// fixture).
    pub fn new(sys_root: impl Into<PathBuf>, dev_root: impl Into<PathBuf>) -> Self {
        Self {
            sys_root: sys_root.into(),
            dev_root: dev_root.into(),
        }
    }

    /// `/dev/serial/by-id` links, as `(link path, target tty name)`.
    fn by_id_links(&self) -> Vec<(PathBuf, String)> {
        let Ok(dir) = std::fs::read_dir(self.dev_root.join("serial/by-id")) else {
            return Vec::new();
        };
        let mut links: Vec<(PathBuf, String)> = dir
            .flatten()
            .filter_map(|e| {
                let target = std::fs::read_link(e.path()).ok()?;
                let tty = target.file_name()?.to_str()?.to_owned();
                Some((e.path(), tty))
            })
            .collect();
        links.sort();
        links
    }

    fn resolve_one(&self, tty: &str, by_id: &[(PathBuf, String)]) -> Option<UsbTty> {
        let device =
            std::fs::canonicalize(self.sys_root.join("class/tty").join(tty).join("device")).ok()?;
        let sys_root =
            std::fs::canonicalize(&self.sys_root).unwrap_or_else(|_| self.sys_root.clone());
        let mut interface = None;
        let mut dir: &Path = &device;
        loop {
            if !dir.starts_with(&sys_root) {
                return None;
            }
            if interface.is_none() {
                if let Some(n) = read_attr(dir, "bInterfaceNumber") {
                    interface = u8::from_str_radix(&n, 16).ok();
                }
            }
            if let (Some(vid), Some(pid)) =
                (read_attr(dir, "idVendor"), read_attr(dir, "idProduct"))
            {
                let path = by_id
                    .iter()
                    .find(|(_, t)| t == tty)
                    .map_or_else(|| self.dev_root.join(tty), |(p, _)| p.clone());
                return Some(UsbTty {
                    tty: tty.to_owned(),
                    path,
                    vid: u16::from_str_radix(&vid, 16).ok()?,
                    pid: u16::from_str_radix(&pid, 16).ok()?,
                    usb_serial: read_attr(dir, "serial"),
                    usb_device_path: dir.to_path_buf(),
                    interface,
                });
            }
            dir = dir.parent()?;
        }
    }
}

fn read_attr(dir: &Path, name: &str) -> Option<String> {
    let s = std::fs::read_to_string(dir.join(name)).ok()?;
    let s = s.trim_end_matches(['\n', '\r', '\0']).to_owned();
    (!s.is_empty()).then_some(s)
}

impl SerialLister for SysfsSerialLister {
    fn list(&self) -> Vec<UsbTty> {
        let Ok(dir) = std::fs::read_dir(self.sys_root.join("class/tty")) else {
            return Vec::new();
        };
        let by_id = self.by_id_links();
        let mut names: Vec<String> = dir
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(ToOwned::to_owned))
            .collect();
        names.sort();
        names
            .iter()
            .filter_map(|t| self.resolve_one(t, &by_id))
            .collect()
    }
}

/// A lister that finds nothing (non-Linux hosts, and tests that do not care).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSerialLister;

impl SerialLister for NoSerialLister {
    fn list(&self) -> Vec<UsbTty> {
        Vec::new()
    }
}

/// A fixed tty set (tests).
#[derive(Debug, Default)]
pub struct StaticSerialLister(pub StdMutex<Vec<UsbTty>>);

impl SerialLister for StaticSerialLister {
    fn list(&self) -> Vec<UsbTty> {
        self.0.lock().expect("lister lock").clone()
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Whether `tty` belongs to the probe with `probe_serial` (and, when known,
/// `vid`/`pid`).
///
/// The serial matches case-insensitively, or as the hex of the sysfs serial
/// string's bytes: probe-rs hex-encodes the raw serial descriptor of some
/// probes (ST-Link V2-1), so the two sides can disagree on representation.
#[must_use]
pub fn tty_matches_probe(probe_serial: &str, vid_pid: Option<(u16, u16)>, tty: &UsbTty) -> bool {
    if probe_serial.trim().is_empty() {
        return false;
    }
    if let Some((vid, pid)) = vid_pid {
        if (vid, pid) != (tty.vid, tty.pid) {
            return false;
        }
    }
    let Some(usb_serial) = tty.usb_serial.as_deref() else {
        return false;
    };
    usb_serial.eq_ignore_ascii_case(probe_serial)
        || hex_lower(usb_serial.as_bytes()).eq_ignore_ascii_case(probe_serial)
}

/// A port as the node will open it: the reported info plus the device path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPort {
    /// What is reported upward.
    pub info: SerialPortInfo,
    /// What is opened.
    pub path: PathBuf,
}

/// The ports of `spec`: its `[[board.uart]]` entries first (in order), then,
/// unless `uart_discover = false`, every discovered tty sharing its probe,
/// sorted by interface number.
///
/// `vid_pid` is the probe's USB ids when discovery knows them (`None`
/// matches on serial alone).
#[must_use]
pub fn resolve_ports(
    spec: &BoardSpec,
    vid_pid: Option<(u16, u16)>,
    ttys: &[UsbTty],
) -> Vec<ResolvedPort> {
    let mut ports: Vec<ResolvedPort> = spec
        .uart
        .iter()
        .enumerate()
        .map(|(i, u)| ResolvedPort {
            info: SerialPortInfo {
                name: u.name.clone().unwrap_or_else(|| format!("uart{i}")),
                device: u.path.file_name().map_or_else(
                    || u.path.display().to_string(),
                    |n| n.to_string_lossy().into_owned(),
                ),
                interface: None,
                default_baud: u.baud.unwrap_or(DEFAULT_BAUD),
            },
            path: u.path.clone(),
        })
        .collect();
    if !spec.uart_discover {
        return ports;
    }
    let mut found: Vec<&UsbTty> = ttys
        .iter()
        .filter(|t| tty_matches_probe(&spec.serial, vid_pid, t))
        .collect();
    found.sort_by(|a, b| (a.interface, &a.tty).cmp(&(b.interface, &b.tty)));
    for t in found {
        if ports
            .iter()
            .any(|p| p.path == t.path || p.path == Path::new("/dev").join(&t.tty))
        {
            continue;
        }
        let mut name = t
            .interface
            .map_or_else(|| t.tty.clone(), |n| format!("if{n}"));
        if ports.iter().any(|p| p.info.name == name) {
            name.clone_from(&t.tty);
        }
        ports.push(ResolvedPort {
            info: SerialPortInfo {
                name,
                device: t
                    .path
                    .file_name()
                    .map_or_else(|| t.tty.clone(), |n| n.to_string_lossy().into_owned()),
                interface: t.interface,
                default_baud: DEFAULT_BAUD,
            },
            path: t.path.clone(),
        });
    }
    ports
}

/// Opens a serial device. The seam tests replace with a pty pair.
pub trait SerialOpener: Send + Sync {
    /// Open `path` exclusively with `settings`.
    ///
    /// # Errors
    ///
    /// A human-readable reason.
    fn open(
        &self,
        path: &Path,
        settings: &LineSettings,
    ) -> Result<Box<dyn serialport::SerialPort>, String>;
}

/// The production opener (`serialport`, exclusive access).
#[derive(Debug, Default, Clone, Copy)]
pub struct SerialportOpener;

impl SerialOpener for SerialportOpener {
    fn open(
        &self,
        path: &Path,
        settings: &LineSettings,
    ) -> Result<Box<dyn serialport::SerialPort>, String> {
        let mut port = serialport::new(path.to_string_lossy(), settings.baud)
            .timeout(Duration::from_secs(1))
            .open()
            .map_err(|e| format!("opening {}: {e}", path.display()))?;
        apply_settings(port.as_mut(), settings)?;
        Ok(port)
    }
}

/// Apply every line setting to an open port.
///
/// # Errors
///
/// The first setting the device refused.
pub fn apply_settings(
    port: &mut dyn serialport::SerialPort,
    s: &LineSettings,
) -> Result<(), String> {
    port.set_baud_rate(s.baud)
        .map_err(|e| format!("baud {}: {e}", s.baud))?;
    port.set_data_bits(match s.data_bits {
        DataBits::Five => serialport::DataBits::Five,
        DataBits::Six => serialport::DataBits::Six,
        DataBits::Seven => serialport::DataBits::Seven,
        DataBits::Eight => serialport::DataBits::Eight,
    })
    .map_err(|e| format!("data bits: {e}"))?;
    port.set_parity(match s.parity {
        Parity::None => serialport::Parity::None,
        Parity::Odd => serialport::Parity::Odd,
        Parity::Even => serialport::Parity::Even,
    })
    .map_err(|e| format!("parity: {e}"))?;
    port.set_stop_bits(match s.stop_bits {
        StopBits::One => serialport::StopBits::One,
        StopBits::Two => serialport::StopBits::Two,
    })
    .map_err(|e| format!("stop bits: {e}"))?;
    port.set_flow_control(match s.flow {
        FlowControl::None => serialport::FlowControl::None,
        FlowControl::Software => serialport::FlowControl::Software,
        FlowControl::Hardware => serialport::FlowControl::Hardware,
    })
    .map_err(|e| format!("flow control: {e}"))?;
    Ok(())
}

/// The set of device paths currently open on some channel (one channel per
/// port).
pub type BusyPorts = Arc<StdMutex<HashSet<PathBuf>>>;

/// Removes a path from [`BusyPorts`] when the channel lets go of it.
struct BusyGuard {
    busy: BusyPorts,
    path: PathBuf,
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        if let Ok(mut b) = self.busy.lock() {
            b.remove(&self.path);
        }
    }
}

/// Everything [`run_channel`] needs besides the relay plumbing.
pub struct SerialChannelCtx {
    /// The board's ports, resolved when the channel was spliced.
    pub ports: Vec<ResolvedPort>,
    /// Opens the device.
    pub opener: Arc<dyn SerialOpener>,
    /// Ports open on other channels.
    pub busy: BusyPorts,
    /// Fires (or is dropped) when the agent tears the channel down.
    pub stop: watch::Receiver<bool>,
}

/// Why a serial channel ended, and whether the agent already reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelEnd {
    /// The agent stopped it (kill / release / power cycle); it already
    /// emitted `SessionClosed`.
    Stopped,
    /// It ended on its own (client gone, device error, refused open).
    Ended(String),
}

async fn send_event(
    out_tx: &mpsc::Sender<NodeToCoord>,
    channel: ChannelId,
    ev: &SerialEvent,
) -> bool {
    out_tx
        .send(NodeToCoord::Data(DataFrame {
            channel,
            bytes: wire::encode(ev),
        }))
        .await
        .is_ok()
}

/// Wait for the stop signal: a `true` value or the sender being dropped.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            return;
        }
        if stop.changed().await.is_err() {
            return;
        }
    }
}

/// Run a blocking port operation off the async runtime.
async fn with_port<T: Send + 'static>(
    port: &Arc<StdMutex<Box<dyn serialport::SerialPort>>>,
    f: impl FnOnce(&mut dyn serialport::SerialPort) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let port = Arc::clone(port);
    tokio::task::spawn_blocking(move || {
        let mut guard = port.lock().map_err(|_| "port lock poisoned".to_owned())?;
        f(guard.as_mut())
    })
    .await
    .map_err(|e| format!("port task failed: {e}"))?
}

/// Serve one serial channel until it ends. See the module docs.
///
/// Sends `SerialEvent::Closed` (best-effort) on every exit path after the
/// client's `Open`. The caller emits `SessionClosed` when the result is
/// [`ChannelEnd::Ended`].
///
/// # Panics
///
/// If the shared busy-port lock was poisoned.
#[allow(clippy::too_many_lines)]
pub async fn run_channel(
    channel: ChannelId,
    ctx: SerialChannelCtx,
    out_tx: mpsc::Sender<NodeToCoord>,
    mut from_relay: mpsc::Receiver<DataFrame>,
) -> ChannelEnd {
    let SerialChannelCtx {
        ports,
        opener,
        busy,
        mut stop,
    } = ctx;

    // Phase 1: wait for `Open`.
    let (port_name, settings) = loop {
        let frame = tokio::select! {
            () = stopped(&mut stop) => return ChannelEnd::Stopped,
            f = from_relay.recv() => f,
        };
        let Some(frame) = frame else {
            return ChannelEnd::Ended("client closed the channel".to_owned());
        };
        match wire::decode::<SerialRequest>(&frame.bytes) {
            Ok(SerialRequest::Open { port, settings }) => break (port, settings),
            Ok(_) => {
                send_event(
                    &out_tx,
                    channel,
                    &SerialEvent::Error("port not open yet".to_owned()),
                )
                .await;
            }
            Err(e) => {
                send_event(
                    &out_tx,
                    channel,
                    &SerialEvent::Error(format!("malformed request: {e}")),
                )
                .await;
            }
        }
    };

    let close = |reason: String| async {
        send_event(&out_tx, channel, &SerialEvent::Closed(reason.clone())).await;
        ChannelEnd::Ended(reason)
    };

    let resolved = match &port_name {
        None => ports.first(),
        Some(n) => ports.iter().find(|p| &p.info.name == n),
    };
    let Some(resolved) = resolved.cloned() else {
        let names: Vec<&str> = ports.iter().map(|p| p.info.name.as_str()).collect();
        let reason = match &port_name {
            None => "this board has no serial ports".to_owned(),
            Some(n) => format!(
                "no serial port {n:?} on this board (have: {})",
                names.join(", ")
            ),
        };
        return close(reason).await;
    };

    let claimed = busy
        .lock()
        .expect("busy lock")
        .insert(resolved.path.clone());
    if !claimed {
        return close(format!(
            "serial port {} is already open on another channel",
            resolved.info.name
        ))
        .await;
    }
    let _busy = BusyGuard {
        busy: Arc::clone(&busy),
        path: resolved.path.clone(),
    };

    let open = {
        let opener = Arc::clone(&opener);
        let path = resolved.path.clone();
        tokio::task::spawn_blocking(move || opener.open(&path, &settings)).await
    };
    let port = match open {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => return close(e).await,
        Err(e) => return close(format!("open task failed: {e}")).await,
    };
    let mut reader = match port.try_clone() {
        Ok(r) => r,
        Err(e) => return close(format!("cloning the port handle: {e}")).await,
    };
    if let Err(e) = reader.set_timeout(READ_POLL) {
        return close(format!("setting the read timeout: {e}")).await;
    }
    let port = Arc::new(StdMutex::new(port));

    // Reader thread: blocking reads with a short timeout so the stop flag is
    // honoured promptly.
    let stop_flag = Arc::new(AtomicBool::new(false));
    let (read_tx, mut read_rx) = mpsc::channel::<Result<Vec<u8>, String>>(64);
    let reader_thread = {
        let stop_flag = Arc::clone(&stop_flag);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            while !stop_flag.load(Ordering::Relaxed) {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        let _ = read_tx.blocking_send(Err("device closed".to_owned()));
                        break;
                    }
                    Ok(n) => {
                        if read_tx.blocking_send(Ok(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => {
                        let _ = read_tx.blocking_send(Err(format!("read failed: {e}")));
                        break;
                    }
                }
            }
            // `reader` (a dup of the fd) is dropped here.
        })
    };

    send_event(
        &out_tx,
        channel,
        &SerialEvent::Opened {
            port: resolved.info.name.clone(),
            settings,
        },
    )
    .await;
    tracing::info!(channel = channel.0, port = %resolved.info.name, path = %resolved.path.display(), %settings, "serial port opened");

    let end = loop {
        tokio::select! {
            () = stopped(&mut stop) => break ChannelEnd::Stopped,
            r = read_rx.recv() => match r {
                Some(Ok(bytes)) => {
                    if !send_event(&out_tx, channel, &SerialEvent::Data(bytes)).await {
                        break ChannelEnd::Ended("relay closed".to_owned());
                    }
                }
                Some(Err(e)) => break ChannelEnd::Ended(e),
                None => break ChannelEnd::Ended("reader stopped".to_owned()),
            },
            f = from_relay.recv() => {
                let Some(frame) = f else {
                    break ChannelEnd::Ended("client closed the channel".to_owned());
                };
                let req = match wire::decode::<SerialRequest>(&frame.bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        send_event(&out_tx, channel, &SerialEvent::Error(format!("malformed request: {e}"))).await;
                        continue;
                    }
                };
                let result = match req {
                    SerialRequest::Open { .. } => Err("port is already open".to_owned()),
                    SerialRequest::Data(bytes) => {
                        match with_port(&port, move |p| {
                            p.write_all(&bytes).and_then(|()| p.flush()).map_err(|e| format!("write failed: {e}"))
                        }).await {
                            Ok(()) => Ok(()),
                            // A failed write means the device is gone.
                            Err(e) => break ChannelEnd::Ended(e),
                        }
                    }
                    SerialRequest::Configure(s) => with_port(&port, move |p| apply_settings(p, &s)).await,
                    SerialRequest::SetDtr(level) => with_port(&port, move |p| {
                        p.write_data_terminal_ready(level).map_err(|e| format!("DTR: {e}"))
                    }).await,
                    SerialRequest::SetRts(level) => with_port(&port, move |p| {
                        p.write_request_to_send(level).map_err(|e| format!("RTS: {e}"))
                    }).await,
                    SerialRequest::Break { millis } => with_port(&port, move |p| {
                        p.set_break().map_err(|e| format!("break: {e}"))?;
                        std::thread::sleep(Duration::from_millis(u64::from(millis.min(5_000))));
                        p.clear_break().map_err(|e| format!("break: {e}"))
                    }).await,
                };
                if let Err(e) = result {
                    send_event(&out_tx, channel, &SerialEvent::Error(e)).await;
                }
            }
        }
    };

    // Teardown: stop the reader, wait for it to drop its fd, then drop ours.
    // Unread input dies with the fds.
    stop_flag.store(true, Ordering::Relaxed);
    drop(read_rx);
    let _ = tokio::task::spawn_blocking(move || reader_thread.join()).await;
    drop(port);
    tracing::info!(channel = channel.0, port = %resolved.info.name, ?end, "serial port closed");

    let reason = match &end {
        ChannelEnd::Stopped => "lease released or session killed".to_owned(),
        ChannelEnd::Ended(r) => r.clone(),
    };
    send_event(&out_tx, channel, &SerialEvent::Closed(reason)).await;
    end
}

/// The `SessionClosed` report for a channel that ended on its own.
#[must_use]
pub fn session_closed(channel: ChannelId) -> NodeToCoord {
    NodeToCoord::Report(NodeReport::SessionClosed {
        channel,
        exit_code: None,
    })
}

/// An opener that hands out pre-opened ports by path (tests, including the
/// coordinator's end-to-end tests, which stand a pty pair in for the tty).
#[derive(Default)]
pub struct MapOpener(
    pub StdMutex<std::collections::HashMap<PathBuf, Box<dyn serialport::SerialPort>>>,
);

impl MapOpener {
    /// Register `port` to be handed out (once) for `path`.
    ///
    /// # Panics
    ///
    /// If the internal lock was poisoned.
    pub fn insert(&self, path: impl Into<PathBuf>, port: Box<dyn serialport::SerialPort>) {
        self.0
            .lock()
            .expect("opener lock")
            .insert(path.into(), port);
    }
}

impl SerialOpener for MapOpener {
    fn open(
        &self,
        path: &Path,
        settings: &LineSettings,
    ) -> Result<Box<dyn serialport::SerialPort>, String> {
        let mut port = self
            .0
            .lock()
            .map_err(|_| "opener lock poisoned".to_owned())?
            .remove(path)
            .ok_or_else(|| format!("no such device {}", path.display()))?;
        apply_settings(port.as_mut(), settings)?;
        Ok(port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PowerSpec, UartSpec};
    use serialport::SerialPort as _;
    use std::io::Write as _;
    use std::os::unix::fs::symlink;

    fn spec(serial: &str) -> BoardSpec {
        BoardSpec {
            id: "b1".to_owned(),
            serial: serial.to_owned(),
            vid: 0,
            pid: 0,
            chip: String::new(),
            model: None,
            tags: Vec::new(),
            exclusive: true,
            power: PowerSpec::None,
            uart: Vec::new(),
            uart_discover: true,
        }
    }

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("sys/class/tty")).unwrap();
            std::fs::create_dir_all(dir.path().join("dev/serial/by-id")).unwrap();
            Self { dir }
        }
        fn sys(&self) -> PathBuf {
            self.dir.path().join("sys")
        }
        fn usb_device(&self, name: &str, vid: &str, pid: &str, serial: Option<&str>) -> PathBuf {
            let d = self.sys().join("devices/pci0000:00/usb1").join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("idVendor"), format!("{vid}\n")).unwrap();
            std::fs::write(d.join("idProduct"), format!("{pid}\n")).unwrap();
            if let Some(s) = serial {
                std::fs::write(d.join("serial"), format!("{s}\n")).unwrap();
            }
            d
        }
        fn interface(dev: &Path, name: &str, num: u8) -> PathBuf {
            let i = dev.join(name);
            std::fs::create_dir_all(&i).unwrap();
            std::fs::write(i.join("bInterfaceNumber"), format!("{num:02x}\n")).unwrap();
            i
        }
        /// A tty whose `device` link points at `device_dir`.
        fn tty(&self, tty: &str, device_dir: &Path) {
            let node = device_dir.join("tty").join(tty);
            std::fs::create_dir_all(&node).unwrap();
            symlink(device_dir, node.join("device")).unwrap();
            symlink(&node, self.sys().join("class/tty").join(tty)).unwrap();
        }
        fn lister(&self) -> SysfsSerialLister {
            SysfsSerialLister::new(self.sys(), self.dir.path().join("dev"))
        }
    }

    #[test]
    fn cdc_acm_and_ftdi_ttys_resolve_to_their_usb_device() {
        let f = Fixture::new();
        // CDC-ACM: tty → interface dir → device.
        let dk = f.usb_device("1-1", "1366", "1015", Some("001050257890"));
        let if2 = Fixture::interface(&dk, "1-1:1.2", 2);
        f.tty("ttyACM0", &if2);
        // FTDI: tty → usb-serial port dir → interface → device.
        let ftdi = f.usb_device("1-2", "0403", "6010", Some("FT1234"));
        let if0 = Fixture::interface(&ftdi, "1-2:1.0", 0);
        let port = if0.join("ttyUSB0");
        std::fs::create_dir_all(&port).unwrap();
        f.tty("ttyUSB0", &port);
        // A non-USB tty.
        let platform = f.sys().join("devices/platform/serial8250");
        std::fs::create_dir_all(&platform).unwrap();
        f.tty("ttyS0", &platform);
        // A by-id link for the FTDI port.
        symlink(
            "../../ttyUSB0",
            f.dir
                .path()
                .join("dev/serial/by-id/usb-FTDI_FT1234-if00-port0"),
        )
        .unwrap();

        let ttys = f.lister().list();
        assert_eq!(ttys.len(), 2, "{ttys:?}");
        let acm = ttys.iter().find(|t| t.tty == "ttyACM0").unwrap();
        assert_eq!((acm.vid, acm.pid, acm.interface), (0x1366, 0x1015, Some(2)));
        assert_eq!(acm.usb_serial.as_deref(), Some("001050257890"));
        assert_eq!(acm.path, f.dir.path().join("dev/ttyACM0"));
        let usb = ttys.iter().find(|t| t.tty == "ttyUSB0").unwrap();
        assert_eq!((usb.vid, usb.pid, usb.interface), (0x0403, 0x6010, Some(0)));
        assert_eq!(
            usb.path,
            f.dir
                .path()
                .join("dev/serial/by-id/usb-FTDI_FT1234-if00-port0")
        );

        let ports = resolve_ports(&spec("001050257890"), Some((0x1366, 0x1015)), &ttys);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].info.name, "if2");
        assert_eq!(ports[0].info.device, "ttyACM0");
        let ports = resolve_ports(&spec("FT1234"), None, &ttys);
        assert_eq!(ports[0].info.name, "if0");
        assert_eq!(ports[0].info.device, "usb-FTDI_FT1234-if00-port0");
    }

    fn tty(name: &str, vid: u16, pid: u16, serial: Option<&str>, interface: Option<u8>) -> UsbTty {
        UsbTty {
            tty: name.to_owned(),
            path: PathBuf::from("/dev").join(name),
            vid,
            pid,
            usb_serial: serial.map(ToOwned::to_owned),
            usb_device_path: PathBuf::from("/sys/devices/x"),
            interface,
        }
    }

    #[test]
    fn matching_requires_serial_and_known_vid_pid() {
        let t = tty("ttyACM0", 0x0483, 0x374b, Some("066DFF"), Some(2));
        assert!(tty_matches_probe("066dff", Some((0x0483, 0x374b)), &t));
        assert!(tty_matches_probe("066DFF", None, &t));
        assert!(!tty_matches_probe("066DFF", Some((0x1366, 0x1015)), &t));
        assert!(!tty_matches_probe("other", None, &t));
        assert!(!tty_matches_probe(
            "",
            None,
            &tty("x", 0, 0, Some(""), None)
        ));
        assert!(!tty_matches_probe("abc", None, &tty("x", 0, 0, None, None)));
    }

    #[test]
    fn st_link_hex_serial_quirk_matches() {
        // probe-rs reports the hex of the raw descriptor bytes.
        let t = tty("ttyACM0", 0x0483, 0x3748, Some("U\u{ff}"), Some(2));
        let hex = hex_lower("U\u{ff}".as_bytes());
        assert!(tty_matches_probe(&hex.to_uppercase(), None, &t));
    }

    #[test]
    fn ports_sort_by_interface_and_config_comes_first() {
        let ttys = vec![
            tty("ttyACM1", 1, 2, Some("S"), Some(3)),
            tty("ttyACM0", 1, 2, Some("S"), Some(1)),
            tty("ttyACM2", 9, 9, Some("T"), Some(0)),
        ];
        let mut s = spec("S");
        s.uart.push(UartSpec {
            name: Some("console".to_owned()),
            path: PathBuf::from("/dev/serial/by-id/usb-FTDI-x"),
            baud: Some(9600),
        });
        s.uart.push(UartSpec {
            name: None,
            path: PathBuf::from("/dev/ttyACM1"),
            baud: None,
        });
        let ports = resolve_ports(&s, None, &ttys);
        let names: Vec<&str> = ports.iter().map(|p| p.info.name.as_str()).collect();
        // ttyACM1 is configured as uart1, so it is not listed twice.
        assert_eq!(names, ["console", "uart1", "if1"]);
        assert_eq!(ports[0].info.default_baud, 9600);
        assert_eq!(ports[1].info.default_baud, DEFAULT_BAUD);

        s.uart_discover = false;
        let names: Vec<String> = resolve_ports(&s, None, &ttys)
            .into_iter()
            .map(|p| p.info.name)
            .collect();
        assert_eq!(names, ["console", "uart1"]);
    }

    // ---- the channel pump, against a pty pair --------------------------

    fn pty_ctx(
        ports: Vec<ResolvedPort>,
    ) -> (SerialChannelCtx, serialport::TTYPort, watch::Sender<bool>) {
        let (master, slave) = serialport::TTYPort::pair().unwrap();
        let opener = MapOpener::default();
        opener.insert("/dev/ttyTEST", Box::new(slave));
        let (stop_tx, stop) = watch::channel(false);
        (
            SerialChannelCtx {
                ports,
                opener: Arc::new(opener),
                busy: BusyPorts::default(),
                stop,
            },
            master,
            stop_tx,
        )
    }

    fn test_port() -> ResolvedPort {
        ResolvedPort {
            info: SerialPortInfo {
                name: "if1".to_owned(),
                device: "ttyTEST".to_owned(),
                interface: Some(1),
                default_baud: DEFAULT_BAUD,
            },
            path: PathBuf::from("/dev/ttyTEST"),
        }
    }

    fn req(r: &SerialRequest) -> DataFrame {
        DataFrame {
            channel: ChannelId(1),
            bytes: wire::encode(r),
        }
    }

    async fn next_event(rx: &mut mpsc::Receiver<NodeToCoord>) -> SerialEvent {
        let msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("event in time")
            .expect("channel open");
        let NodeToCoord::Data(frame) = msg else {
            panic!("expected data, got {msg:?}");
        };
        wire::decode(&frame.bytes).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pump_relays_bytes_and_settings_and_stops_on_signal() {
        let (ctx, mut master, stop_tx) = pty_ctx(vec![test_port()]);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (in_tx, in_rx) = mpsc::channel(64);
        let task = tokio::spawn(run_channel(ChannelId(1), ctx, out_tx, in_rx));

        in_tx
            .send(req(&SerialRequest::Open {
                port: None,
                settings: LineSettings::default(),
            }))
            .await
            .unwrap();
        assert!(
            matches!(next_event(&mut out_rx).await, SerialEvent::Opened { ref port, .. } if port == "if1")
        );

        // device → client
        master.write_all(b"hello").unwrap();
        let mut got = Vec::new();
        while got.len() < 5 {
            let SerialEvent::Data(b) = next_event(&mut out_rx).await else {
                panic!("expected data");
            };
            got.extend(b);
        }
        assert_eq!(got, b"hello");

        // client → device
        in_tx
            .send(req(&SerialRequest::Data(b"world".to_vec())))
            .await
            .unwrap();
        let mut buf = [0u8; 5];
        // Hand the master back: dropping it would hang up the slave.
        let master = tokio::task::spawn_blocking(move || {
            master.set_timeout(Duration::from_secs(5)).unwrap();
            master.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"world");
            master
        })
        .await
        .unwrap();

        // Configure on a pty slave works; DTR does not (non-fatal error).
        in_tx
            .send(req(&SerialRequest::Configure(LineSettings {
                baud: 9600,
                ..LineSettings::default()
            })))
            .await
            .unwrap();
        in_tx.send(req(&SerialRequest::SetDtr(true))).await.unwrap();
        let ev = next_event(&mut out_rx).await;
        assert!(
            matches!(ev, SerialEvent::Error(ref e) if e.contains("DTR")),
            "{ev:?}"
        );
        // Configure was applied before the DTR request was handled; on Linux
        // a pty master's termios reads the slave's.
        #[cfg(target_os = "linux")]
        assert_eq!(master.baud_rate().unwrap(), 9600);

        stop_tx.send(true).unwrap();
        let end = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(end, ChannelEnd::Stopped);
        assert!(matches!(
            next_event(&mut out_rx).await,
            SerialEvent::Closed(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_port_and_busy_port_are_refused() {
        let (ctx, _master, _stop) = pty_ctx(vec![test_port()]);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (in_tx, in_rx) = mpsc::channel(64);
        let task = tokio::spawn(run_channel(ChannelId(1), ctx, out_tx, in_rx));
        in_tx
            .send(req(&SerialRequest::Open {
                port: Some("nope".to_owned()),
                settings: LineSettings::default(),
            }))
            .await
            .unwrap();
        assert!(
            matches!(next_event(&mut out_rx).await, SerialEvent::Closed(ref r) if r.contains("nope"))
        );
        assert!(matches!(task.await.unwrap(), ChannelEnd::Ended(_)));

        let (ctx, _master, _stop) = pty_ctx(vec![test_port()]);
        ctx.busy
            .lock()
            .unwrap()
            .insert(PathBuf::from("/dev/ttyTEST"));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (in_tx, in_rx) = mpsc::channel(64);
        let task = tokio::spawn(run_channel(ChannelId(1), ctx, out_tx, in_rx));
        in_tx
            .send(req(&SerialRequest::Open {
                port: Some("if1".to_owned()),
                settings: LineSettings::default(),
            }))
            .await
            .unwrap();
        assert!(
            matches!(next_event(&mut out_rx).await, SerialEvent::Closed(ref r) if r.contains("already open"))
        );
        assert!(matches!(task.await.unwrap(), ChannelEnd::Ended(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn requests_before_open_are_errors_and_client_close_ends_it() {
        let (ctx, _master, _stop) = pty_ctx(vec![test_port()]);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (in_tx, in_rx) = mpsc::channel(64);
        let task = tokio::spawn(run_channel(ChannelId(1), ctx, out_tx, in_rx));
        in_tx.send(req(&SerialRequest::SetRts(true))).await.unwrap();
        assert!(matches!(
            next_event(&mut out_rx).await,
            SerialEvent::Error(_)
        ));
        drop(in_tx);
        assert!(matches!(task.await.unwrap(), ChannelEnd::Ended(_)));
    }
}

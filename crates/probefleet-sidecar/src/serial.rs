//! Board USB-serial passthrough, client side (architecture §4.2, "Serial
//! passthrough").
//!
//! `probefleet ctl serial <board>` opens a [`ChannelKind::Serial`] channel
//! on a lease the caller already holds and speaks the framed
//! [`SerialRequest`]/[`SerialEvent`] protocol on it. Two local faces:
//!
//! * **stdio** — the current terminal (raw mode when stdin is a tty) or a
//!   pipe. `Ctrl-]` starts an escape command ([`EscapeParser`]). When stdin
//!   is not a tty (CI), its EOF only stops input: the command runs until a
//!   signal or the channel closes, so `ctl serial b > uart.log < /dev/null`
//!   captures a UART.
//! * **pty** — a pseudo-terminal whose slave is exposed through a symlink,
//!   so picocom/tio/minicom/pyserial open it like a local port. Line
//!   settings a tool applies to the slave are detected by polling the
//!   slave's termios and forwarded as `Configure`. Linux's pty driver forces
//!   CS8 and clears PARENB on the slave, so through a pty only baud, stop
//!   bits and flow control are forwarded; data bits / parity come from the
//!   command line (`--data-bits`, `--parity`). DTR/RTS cannot pass
//!   through a pty (Linux ptys have no modem lines), so those stay on the
//!   escape commands of the controlling terminal.
//!
//! Unix only; the module is compiled out elsewhere.

use std::io::IsTerminal as _;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use probefleet_proto::serial::{
    self as wire, DataBits, FlowControl, LineSettings, Parity, SerialEvent, SerialRequest,
    StopBits,
};
use probefleet_proto::{ChannelId, ChannelKind, DataFrame, LeaseId};
use probefleet_wire::CoordToSidecar;
use rustix::termios::{self, ControlModes, InputModes, OptionalActions, Termios};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::io::unix::AsyncFd;

use crate::transport::{CoordSession, TransportError};

/// The escape byte (`Ctrl-]`, as in telnet and picocom's default).
pub const ESCAPE: u8 = 0x1d;

/// How often the pty's termios is polled for line-setting changes.
const TERMIOS_POLL: Duration = Duration::from_millis(200);

/// Where the local end of the port lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalMode {
    /// The current stdin/stdout.
    Stdio,
    /// A pseudo-terminal, exposed at `link`.
    Pty {
        /// The symlink to create (an existing *symlink* there is replaced).
        link: PathBuf,
    },
}

/// What to open and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialOptions {
    /// Node-side port name; `None` = the board's first port.
    pub port: Option<String>,
    /// Initial line settings.
    pub settings: LineSettings,
    /// Initial DTR level, if any.
    pub dtr: Option<bool>,
    /// Initial RTS level, if any.
    pub rts: Option<bool>,
    /// Local face.
    pub mode: LocalMode,
}

/// A command decoded from the escape sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Bytes to send to the port.
    Send(Vec<u8>),
    /// Leave.
    Quit,
    /// Pulse the board into reset (ESP/Arduino style auto-reset).
    Reset,
    /// Toggle DTR.
    ToggleDtr,
    /// Toggle RTS.
    ToggleRts,
    /// Send a 250 ms break.
    Break,
    /// Print the escape help.
    Help,
}

/// `Ctrl-]` escape parser: a pure state machine over the input stream.
#[derive(Debug, Default, Clone)]
pub struct EscapeParser {
    pending: bool,
}

impl EscapeParser {
    /// Feed input bytes; returns the actions they produce, in order.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Action> {
        let mut out = Vec::new();
        let mut data = Vec::new();
        for &b in bytes {
            if self.pending {
                self.pending = false;
                let action = match b {
                    b'q' | b'Q' | b'.' => Some(Action::Quit),
                    b'r' | b'R' => Some(Action::Reset),
                    b'd' | b'D' => Some(Action::ToggleDtr),
                    b't' | b'T' => Some(Action::ToggleRts),
                    b'b' | b'B' => Some(Action::Break),
                    ESCAPE => {
                        data.push(ESCAPE);
                        None
                    }
                    _ => Some(Action::Help),
                };
                if let Some(a) = action {
                    if !data.is_empty() {
                        out.push(Action::Send(std::mem::take(&mut data)));
                    }
                    out.push(a);
                }
            } else if b == ESCAPE {
                self.pending = true;
            } else {
                data.push(b);
            }
        }
        if !data.is_empty() {
            out.push(Action::Send(data));
        }
        out
    }
}

/// The escape help text.
pub const HELP: &str = "escape is Ctrl-]: q quit, r reset pulse, d toggle DTR, t toggle RTS, \
                        b break, Ctrl-] send a literal Ctrl-]";

/// Read line settings out of a termios.
#[must_use]
pub fn settings_from_termios(t: &Termios) -> LineSettings {
    let c = t.control_modes;
    let size = c & ControlModes::CSIZE;
    let data_bits = if size == ControlModes::CS5 {
        DataBits::Five
    } else if size == ControlModes::CS6 {
        DataBits::Six
    } else if size == ControlModes::CS7 {
        DataBits::Seven
    } else {
        DataBits::Eight
    };
    let parity = if !c.contains(ControlModes::PARENB) {
        Parity::None
    } else if c.contains(ControlModes::PARODD) {
        Parity::Odd
    } else {
        Parity::Even
    };
    let stop_bits = if c.contains(ControlModes::CSTOPB) {
        StopBits::Two
    } else {
        StopBits::One
    };
    let flow = if c.contains(ControlModes::CRTSCTS) {
        FlowControl::Hardware
    } else if t.input_modes.contains(InputModes::IXON) {
        FlowControl::Software
    } else {
        FlowControl::None
    };
    LineSettings {
        baud: t.output_speed(),
        data_bits,
        parity,
        stop_bits,
        flow,
    }
}

/// Write line settings into a termios (the inverse of
/// [`settings_from_termios`]).
///
/// # Errors
///
/// If the platform cannot represent the baud rate.
pub fn apply_to_termios(t: &mut Termios, s: &LineSettings) -> std::io::Result<()> {
    t.set_speed(s.baud)?;
    let mut c = t.control_modes - ControlModes::CSIZE;
    c |= match s.data_bits {
        DataBits::Five => ControlModes::CS5,
        DataBits::Six => ControlModes::CS6,
        DataBits::Seven => ControlModes::CS7,
        DataBits::Eight => ControlModes::CS8,
    };
    c.set(ControlModes::PARENB, s.parity != Parity::None);
    c.set(ControlModes::PARODD, s.parity == Parity::Odd);
    c.set(ControlModes::CSTOPB, s.stop_bits == StopBits::Two);
    c.set(ControlModes::CRTSCTS, s.flow == FlowControl::Hardware);
    t.control_modes = c;
    t.input_modes
        .set(InputModes::IXON | InputModes::IXOFF, s.flow == FlowControl::Software);
    Ok(())
}

/// Restores a terminal's termios on drop.
struct RawGuard {
    fd: std::os::fd::BorrowedFd<'static>,
    saved: Termios,
}

impl RawGuard {
    fn stdin() -> std::io::Result<Self> {
        let fd = rustix::stdio::stdin();
        let saved = termios::tcgetattr(fd)?;
        let mut raw = saved.clone();
        raw.make_raw();
        termios::tcsetattr(fd, OptionalActions::Now, &raw)?;
        Ok(Self { fd, saved })
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(self.fd, OptionalActions::Now, &self.saved);
    }
}

/// A pseudo-terminal: the master we relay, and our own slave fd (kept open
/// so the master never sees a hangup when the tool closes the port).
pub struct Pty {
    master: AsyncFd<OwnedFd>,
    slave: OwnedFd,
    /// The slave device path (`/dev/pts/N`).
    pub slave_path: PathBuf,
}

impl Pty {
    /// Allocate a pty with its slave in raw mode at `settings`.
    ///
    /// # Errors
    ///
    /// Any failing pty / termios call.
    pub fn open(settings: &LineSettings) -> std::io::Result<Self> {
        use rustix::pty::OpenptFlags;
        let master = rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        rustix::pty::grantpt(&master)?;
        rustix::pty::unlockpt(&master)?;
        let name = rustix::pty::ptsname(&master, Vec::new())?;
        let slave_path = PathBuf::from(name.to_string_lossy().into_owned());
        let slave = rustix::fs::open(
            &slave_path,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY,
            rustix::fs::Mode::empty(),
        )?;
        let mut t = termios::tcgetattr(&slave)?;
        t.make_raw();
        apply_to_termios(&mut t, settings)?;
        termios::tcsetattr(&slave, OptionalActions::Now, &t)?;
        let flags = rustix::fs::fcntl_getfl(&master)?;
        rustix::fs::fcntl_setfl(&master, flags | rustix::fs::OFlags::NONBLOCK)?;
        Ok(Self {
            master: AsyncFd::new(master)?,
            slave,
            slave_path,
        })
    }

    /// The line settings currently on the slave (what the tool set).
    ///
    /// # Errors
    ///
    /// If `tcgetattr` fails.
    pub fn settings(&self) -> std::io::Result<LineSettings> {
        Ok(settings_from_termios(&termios::tcgetattr(&self.slave)?))
    }

    /// Read what the tool wrote to the slave.
    ///
    /// # Errors
    ///
    /// A read failure on the master.
    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.master.readable().await?;
            match guard.try_io(|fd| rustix::io::read(fd.get_ref(), &mut *buf).map_err(Into::into)) {
                Ok(r) => return r,
                Err(_would_block) => {}
            }
        }
    }

    /// Hand bytes to the tool. When nobody drains the slave for a while,
    /// the stale input is flushed rather than stalling the relay: a UART
    /// nobody is reading loses bytes, exactly like real hardware.
    ///
    /// # Errors
    ///
    /// A write failure on the master.
    pub async fn write(&self, mut bytes: &[u8]) -> std::io::Result<()> {
        while !bytes.is_empty() {
            let ready = tokio::time::timeout(Duration::from_millis(200), self.master.writable()).await;
            let Ok(guard) = ready else {
                termios::tcflush(&self.slave, termios::QueueSelector::IFlush)?;
                return Ok(());
            };
            let mut guard = guard?;
            match guard.try_io(|fd| rustix::io::write(fd.get_ref(), bytes).map_err(Into::into)) {
                Ok(Ok(n)) => bytes = &bytes[n..],
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {
                    termios::tcflush(&self.slave, termios::QueueSelector::IFlush)?;
                }
            }
        }
        Ok(())
    }
}

/// Removes the pty symlink on drop.
struct LinkGuard(PathBuf);

impl Drop for LinkGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Point `link` at `target`, replacing a stale *symlink* (never a file).
///
/// # Errors
///
/// If `link` exists and is not a symlink, or the link cannot be created.
pub fn make_link(link: &Path, target: &Path) -> std::io::Result<()> {
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(link) {
        Ok(m) if m.file_type().is_symlink() => std::fs::remove_file(link)?,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a symlink", link.display()),
            ))
        }
        Err(_) => {}
    }
    std::os::unix::fs::symlink(target, link)
}

/// The default pty link for `board` (and `port`):
/// `$XDG_RUNTIME_DIR/probefleet/serial/<board>[-<port>]`.
#[must_use]
pub fn default_link(board: &str, port: Option<&str>) -> PathBuf {
    let sanitize = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
            .collect()
    };
    let base = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
        || std::env::temp_dir().join(format!("probefleet-{}", rustix::process::getuid().as_raw())),
        |d| PathBuf::from(d).join("probefleet"),
    );
    let mut name = sanitize(board);
    if let Some(p) = port {
        name.push('-');
        name.push_str(&sanitize(p));
    }
    base.join("serial").join(name)
}

async fn send(session: &CoordSession, channel: ChannelId, req: &SerialRequest) -> Result<(), TransportError> {
    session
        .send_frame(DataFrame {
            channel,
            bytes: wire::encode(req),
        })
        .await
}

/// Modem-line state we track for the toggle commands.
struct Lines {
    dtr: bool,
    rts: bool,
}

async fn apply_action(
    session: &CoordSession,
    channel: ChannelId,
    lines: &mut Lines,
    action: Action,
) -> Result<bool, TransportError> {
    match action {
        Action::Send(bytes) => send(session, channel, &SerialRequest::Data(bytes)).await?,
        Action::Quit => return Ok(false),
        Action::Reset => {
            // Classic auto-reset: DTR deasserted, pulse RTS (EN low on an
            // ESP32 devkit; the cap-coupled reset on Arduino-style boards
            // fires on the DTR edge, so DTR is pulsed too).
            send(session, channel, &SerialRequest::SetDtr(false)).await?;
            send(session, channel, &SerialRequest::SetRts(true)).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            send(session, channel, &SerialRequest::SetRts(false)).await?;
            lines.dtr = false;
            lines.rts = false;
            eprint!("\r\n[probefleet: reset pulse]\r\n");
        }
        Action::ToggleDtr => {
            lines.dtr = !lines.dtr;
            send(session, channel, &SerialRequest::SetDtr(lines.dtr)).await?;
            eprint!("\r\n[probefleet: DTR {}]\r\n", if lines.dtr { "on" } else { "off" });
        }
        Action::ToggleRts => {
            lines.rts = !lines.rts;
            send(session, channel, &SerialRequest::SetRts(lines.rts)).await?;
            eprint!("\r\n[probefleet: RTS {}]\r\n", if lines.rts { "on" } else { "off" });
        }
        Action::Break => send(session, channel, &SerialRequest::Break { millis: 250 }).await?,
        Action::Help => eprint!("\r\n[probefleet: {HELP}]\r\n"),
    }
    Ok(true)
}

/// Open a serial channel on `lease` and run it until the user quits, a
/// signal arrives, or the channel closes. Returns the process exit code.
///
/// # Errors
///
/// A refused channel, a refused `Open`, or local I/O setup failures.
#[allow(clippy::too_many_lines)]
pub async fn run(
    session: &CoordSession,
    lease: LeaseId,
    board_label: &str,
    opts: SerialOptions,
) -> Result<i32, TransportError> {
    let io = |e: std::io::Error| TransportError::Io(e.to_string());
    let opened = session.open_channel(lease, ChannelKind::Serial).await?;
    let channel = opened.channel;
    let mut data_rx = session.attach_data(channel).await;

    send(
        session,
        channel,
        &SerialRequest::Open {
            port: opts.port.clone(),
            settings: opts.settings,
        },
    )
    .await?;
    let (port, settings) = loop {
        let Some(frame) = data_rx.recv().await else {
            return Err(TransportError::Connect("connection closed".to_owned()));
        };
        match wire::decode::<SerialEvent>(&frame.bytes) {
            Ok(SerialEvent::Opened { port, settings }) => break (port, settings),
            Ok(SerialEvent::Closed(reason) | SerialEvent::Error(reason)) => {
                session.close_channel_acked(channel).await;
                return Err(TransportError::Declined(reason));
            }
            Ok(SerialEvent::Data(_)) => {}
            Err(e) => return Err(TransportError::Wire(e.to_string())),
        }
    };
    let mut lines = Lines {
        dtr: opts.dtr.unwrap_or(true),
        rts: opts.rts.unwrap_or(true),
    };
    if let Some(d) = opts.dtr {
        send(session, channel, &SerialRequest::SetDtr(d)).await?;
    }
    if let Some(r) = opts.rts {
        send(session, channel, &SerialRequest::SetRts(r)).await?;
    }

    let stdin_tty = std::io::stdin().is_terminal();
    let (pty, _link) = match &opts.mode {
        LocalMode::Stdio => (None, None),
        LocalMode::Pty { link } => {
            let pty = Pty::open(&settings).map_err(io)?;
            make_link(link, &pty.slave_path).map_err(io)?;
            println!("{} -> {} ({board_label} port {port}, {settings})", link.display(), pty.slave_path.display());
            (Some(pty), Some(LinkGuard(link.clone())))
        }
    };
    eprintln!("[probefleet: {board_label} port {port} open at {settings}]");
    if stdin_tty {
        eprintln!("[probefleet: {HELP}]");
    }
    // Raw mode only after the banners, and only for a real terminal.
    let _raw = if stdin_tty { Some(RawGuard::stdin().map_err(io)?) } else { None };

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stdin_open = pty.is_none() || stdin_tty;
    let mut parser = EscapeParser::default();
    let mut in_buf = vec![0u8; 4096];
    let mut pty_buf = vec![0u8; 4096];
    let mut last = settings;
    let mut poll = tokio::time::interval(TERMIOS_POLL);
    let signal = crate::signal::shutdown_signal();
    tokio::pin!(signal);

    let (code, channel_open) = loop {
        tokio::select! {
            sig = &mut signal => break (128 + sig, true),
            frame = data_rx.recv() => {
                let Some(frame) = frame else { break (1, false) };
                match wire::decode::<SerialEvent>(&frame.bytes) {
                    Ok(SerialEvent::Data(bytes)) => {
                        if let Some(p) = &pty {
                            p.write(&bytes).await.map_err(io)?;
                        } else {
                            stdout.write_all(&bytes).await.map_err(io)?;
                            stdout.flush().await.map_err(io)?;
                        }
                    }
                    Ok(SerialEvent::Error(e)) => eprint!("\r\n[probefleet: {e}]\r\n"),
                    Ok(SerialEvent::Closed(reason)) => {
                        eprint!("\r\n[probefleet: port closed: {reason}]\r\n");
                        break (1, true);
                    }
                    Ok(SerialEvent::Opened { .. }) => {}
                    Err(e) => eprint!("\r\n[probefleet: malformed frame: {e}]\r\n"),
                }
            }
            ctrl = session.next_control() => match ctrl {
                Ok(CoordToSidecar::ChannelClosed { channel: c }) if c == channel => {
                    eprint!("\r\n[probefleet: channel closed (lease released?)]\r\n");
                    break (1, false);
                }
                Ok(other) => tracing::debug!(?other, "control message during serial session"),
                Err(_) => break (1, false),
            },
            n = stdin.read(&mut in_buf), if stdin_open => {
                let n = n.map_err(io)?;
                if n == 0 {
                    // A pipe ran dry: keep relaying output.
                    stdin_open = false;
                    continue;
                }
                let mut quit = false;
                for action in parser.feed(&in_buf[..n]) {
                    // In pty mode the tool owns the data path; the terminal
                    // only issues commands.
                    if pty.is_some() && matches!(action, Action::Send(_)) {
                        continue;
                    }
                    if !apply_action(session, channel, &mut lines, action).await? {
                        quit = true;
                    }
                }
                if quit {
                    break (0, true);
                }
            }
            n = async { pty.as_ref().expect("guarded").read(&mut pty_buf).await }, if pty.is_some() => {
                let n = n.map_err(io)?;
                if n > 0 {
                    send(session, channel, &SerialRequest::Data(pty_buf[..n].to_vec())).await?;
                }
            }
            _ = poll.tick(), if pty.is_some() => {
                if let Ok(mut now) = pty.as_ref().expect("guarded").settings() {
                    // Not observable through a Linux pty (forced CS8, no
                    // PARENB): keep what the command line asked for.
                    now.data_bits = last.data_bits;
                    now.parity = last.parity;
                    if now != last && now.baud != 0 {
                        tracing::info!(%now, "tool changed the line settings");
                        send(session, channel, &SerialRequest::Configure(now)).await?;
                        last = now;
                    }
                }
            }
        }
    };
    drop(_raw);
    if channel_open {
        session.close_channel_acked(channel).await;
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_parser_splits_data_and_commands() {
        let mut p = EscapeParser::default();
        assert_eq!(p.feed(b"ab"), vec![Action::Send(b"ab".to_vec())]);
        assert_eq!(
            p.feed(&[b'x', ESCAPE, b'r', b'y']),
            vec![Action::Send(b"x".to_vec()), Action::Reset, Action::Send(b"y".to_vec())]
        );
        // An escape split across reads.
        assert_eq!(p.feed(&[ESCAPE]), vec![]);
        assert_eq!(p.feed(b"q"), vec![Action::Quit]);
        // A doubled escape sends a literal one.
        assert_eq!(p.feed(&[ESCAPE, ESCAPE]), vec![Action::Send(vec![ESCAPE])]);
        assert_eq!(p.feed(&[ESCAPE, b'd', ESCAPE, b't', ESCAPE, b'b']), vec![Action::ToggleDtr, Action::ToggleRts, Action::Break]);
        assert_eq!(p.feed(&[ESCAPE, b'?']), vec![Action::Help]);
    }

    #[tokio::test]
    async fn termios_round_trips_line_settings() {
        let pty = Pty::open(&LineSettings::default()).unwrap();
        let mut t = termios::tcgetattr(&pty.slave).unwrap();
        for s in [
            LineSettings::default(),
            LineSettings {
                baud: 9600,
                data_bits: DataBits::Seven,
                parity: Parity::Even,
                stop_bits: StopBits::Two,
                flow: FlowControl::Hardware,
            },
            LineSettings {
                baud: 57_600,
                data_bits: DataBits::Eight,
                parity: Parity::Odd,
                stop_bits: StopBits::One,
                flow: FlowControl::Software,
            },
        ] {
            apply_to_termios(&mut t, &s).unwrap();
            assert_eq!(settings_from_termios(&t), s);
        }
    }

    #[tokio::test]
    async fn a_tool_on_the_pty_link_is_relayed_and_its_baud_change_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        let pty = Pty::open(&LineSettings::default()).unwrap();
        let link = dir.path().join("sub/tty");
        make_link(&link, &pty.slave_path).unwrap();
        let _guard = LinkGuard(link.clone());
        assert_eq!(pty.settings().unwrap(), LineSettings::default());

        // The "tool": opens the link, sets 9600 8N2 rts/cts, writes. (Linux
        // ptys force CS8 and clear PARENB, so data bits / parity a tool sets
        // are not observable through a pty; baud, stop bits and flow are.)
        let tool = rustix::fs::open(
            &link,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let mut t = termios::tcgetattr(&tool).unwrap();
        let want = LineSettings {
            baud: 9600,
            stop_bits: StopBits::Two,
            flow: FlowControl::Hardware,
            ..LineSettings::default()
        };
        apply_to_termios(&mut t, &want).unwrap();
        termios::tcsetattr(&tool, OptionalActions::Now, &t).unwrap();
        assert_eq!(pty.settings().unwrap(), want, "the poller sees the tool's settings");

        rustix::io::write(&tool, b"ping").unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), pty.read(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"ping");

        pty.write(b"pong").await.unwrap();
        let mut got = [0u8; 4];
        let n = rustix::io::read(&tool, &mut got).unwrap();
        assert_eq!(&got[..n], b"pong");

        // A stale symlink is replaced; a regular file is not.
        make_link(&link, &pty.slave_path).unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(make_link(&file, &pty.slave_path).is_err());
    }

    #[test]
    fn default_link_is_sanitized() {
        let l = default_link("org/node/dk 1", Some("if1"));
        assert!(l.ends_with("serial/org_node_dk_1-if1"), "{}", l.display());
    }
}

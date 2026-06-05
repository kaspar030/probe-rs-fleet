//! USB power control: the [`PowerControl`] trait and its `uhubctl` / `gpio` /
//! `none` implementations (architecture §4.2).
//!
//! Power control is used for post-lease cleanup and fault recovery, and is also
//! callable on explicit coordinator command. Shell-outs (`uhubctl`) go through
//! an injectable [`CommandRunner`] so unit tests can assert the exact argv
//! without spawning processes.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_proto::PowerKind;

/// Errors from power-control operations.
#[derive(Debug, thiserror::Error)]
pub enum PowerError {
    /// The underlying command/device invocation failed.
    #[error("power command failed: {0}")]
    Command(String),

    /// The requested power backend is not available in this build (e.g. the
    /// `gpio` feature is disabled, or running on a non-Linux host).
    #[error("power backend unsupported: {0}")]
    Unsupported(String),

    /// An I/O error talking to the device.
    #[error("power i/o error: {0}")]
    Io(String),
}

/// Controls USB power to a single board.
///
/// Implementations are object-safe (`Box<dyn PowerControl>`) via
/// [`async_trait`]. A power-cycle is off-then-on; the default `cycle`
/// implementation composes `off` and `on` with a short settle delay.
#[async_trait]
pub trait PowerControl: Send + Sync {
    /// Cut power to the board.
    async fn off(&self) -> Result<(), PowerError>;

    /// Restore power to the board.
    async fn on(&self) -> Result<(), PowerError>;

    /// Power-cycle the board (off, settle, on).
    async fn cycle(&self) -> Result<(), PowerError> {
        self.off().await?;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        self.on().await
    }

    /// A short human label for logging (e.g. `"uhubctl 1-1:2"`).
    fn label(&self) -> String;
}

/// Abstraction over running an external command, so `uhubctl` shell-outs are
/// mockable in tests.
#[async_trait]
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args`. Returns `Ok(())` if the process exited with
    /// status 0, otherwise an error describing the failure.
    async fn run(&self, program: &str, args: &[String]) -> Result<(), PowerError>;
}

/// A [`CommandRunner`] that actually spawns processes via tokio.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioCommandRunner;

#[async_trait]
impl CommandRunner for TokioCommandRunner {
    async fn run(&self, program: &str, args: &[String]) -> Result<(), PowerError> {
        let output = tokio::process::Command::new(program)
            .args(args)
            .output()
            .await
            .map_err(|e| PowerError::Io(format!("spawning {program}: {e}")))?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(PowerError::Command(format!(
                "{program} exited with {}: {}",
                output.status,
                stderr.trim()
            )))
        }
    }
}

/// `uhubctl`-based power control for a single hub port.
pub struct Uhubctl {
    hub: String,
    port: u8,
    runner: Arc<dyn CommandRunner>,
}

impl Uhubctl {
    /// Build a `uhubctl` controller using the real process runner.
    #[must_use]
    pub fn new(hub: String, port: u8) -> Self {
        Self::with_runner(hub, port, Arc::new(TokioCommandRunner))
    }

    /// Build a `uhubctl` controller with an injected [`CommandRunner`] (tests).
    #[must_use]
    pub fn with_runner(hub: String, port: u8, runner: Arc<dyn CommandRunner>) -> Self {
        Self { hub, port, runner }
    }

    fn args(&self, action: &str) -> Vec<String> {
        vec![
            "-a".to_owned(),
            action.to_owned(),
            "-l".to_owned(),
            self.hub.clone(),
            "-p".to_owned(),
            self.port.to_string(),
        ]
    }
}

#[async_trait]
impl PowerControl for Uhubctl {
    async fn off(&self) -> Result<(), PowerError> {
        self.runner.run("uhubctl", &self.args("off")).await
    }

    async fn on(&self) -> Result<(), PowerError> {
        self.runner.run("uhubctl", &self.args("on")).await
    }

    fn label(&self) -> String {
        format!("uhubctl {}:{}", self.hub, self.port)
    }
}

/// No-op power control for boards with no external power switching.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoPower;

#[async_trait]
impl PowerControl for NoPower {
    async fn off(&self) -> Result<(), PowerError> {
        Ok(())
    }

    async fn on(&self) -> Result<(), PowerError> {
        Ok(())
    }

    async fn cycle(&self) -> Result<(), PowerError> {
        // No external switch: best-effort reset happens via the probe elsewhere.
        Ok(())
    }

    fn label(&self) -> String {
        "none".to_owned()
    }
}

/// GPIO-relay power control (Linux gpiod char device).
///
/// Driving convention: line **high** = powered on, **low** = powered off. The
/// line is requested as an output for each operation and released afterwards so
/// concurrent boards on the same chip don't contend for a held handle.
pub struct Gpio {
    chip: String,
    line: u32,
}

impl Gpio {
    /// Build a GPIO controller for `chip` line `line`.
    #[must_use]
    pub fn new(chip: String, line: u32) -> Self {
        Self { chip, line }
    }

    #[cfg(all(feature = "gpio", target_os = "linux"))]
    async fn set(&self, value: bool) -> Result<(), PowerError> {
        use tokio_gpiod::{Chip, Options};

        let chip = Chip::new(&self.chip)
            .await
            .map_err(|e| PowerError::Io(format!("opening {}: {e}", self.chip)))?;
        let opts = Options::output([self.line])
            .values([value])
            .consumer("fleet-agent");
        let _lines = chip
            .request_lines(opts)
            .await
            .map_err(|e| PowerError::Io(format!("requesting line {}: {e}", self.line)))?;
        Ok(())
    }

    #[cfg(not(all(feature = "gpio", target_os = "linux")))]
    #[allow(clippy::unused_async)]
    async fn set(&self, _value: bool) -> Result<(), PowerError> {
        Err(PowerError::Unsupported(
            "gpio power control requires the `gpio` feature on Linux".to_owned(),
        ))
    }
}

#[async_trait]
impl PowerControl for Gpio {
    async fn off(&self) -> Result<(), PowerError> {
        self.set(false).await
    }

    async fn on(&self) -> Result<(), PowerError> {
        self.set(true).await
    }

    fn label(&self) -> String {
        format!("gpio {}:{}", self.chip, self.line)
    }
}

/// Build a [`PowerControl`] from a board's declared [`PowerKind`].
#[must_use]
pub fn from_power_kind(kind: &PowerKind) -> Box<dyn PowerControl> {
    match kind {
        PowerKind::Uhubctl { hub, port } => Box::new(Uhubctl::new(hub.clone(), *port)),
        PowerKind::Gpio { chip, line } => Box::new(Gpio::new(chip.clone(), *line)),
        PowerKind::None => Box::new(NoPower),
    }
}

/// Recorded `(program, args)` invocations captured by [`RecordingRunner`].
type RecordedCalls = Arc<Mutex<Vec<(String, Vec<String>)>>>;

/// A recording [`CommandRunner`] for tests: captures every invocation and can
/// be configured to fail.
#[derive(Debug, Default, Clone)]
pub struct RecordingRunner {
    calls: RecordedCalls,
    fail: bool,
}

impl RecordingRunner {
    /// A runner that records calls and reports success.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A runner that records calls and reports failure.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            fail: true,
        }
    }

    /// Snapshot of recorded `(program, args)` invocations.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock was poisoned by a panicking writer.
    #[must_use]
    pub fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls.lock().expect("lock poisoned").clone()
    }
}

#[async_trait]
impl CommandRunner for RecordingRunner {
    async fn run(&self, program: &str, args: &[String]) -> Result<(), PowerError> {
        self.calls
            .lock()
            .expect("lock poisoned")
            .push((program.to_owned(), args.to_vec()));
        if self.fail {
            Err(PowerError::Command("simulated failure".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn uhubctl_emits_correct_off_argv() {
        let runner = RecordingRunner::new();
        let ctl = Uhubctl::with_runner("1-1".into(), 2, Arc::new(runner.clone()));
        ctl.off().await.unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "uhubctl");
        assert_eq!(
            calls[0].1,
            vec!["-a", "off", "-l", "1-1", "-p", "2"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn uhubctl_emits_correct_on_argv() {
        let runner = RecordingRunner::new();
        let ctl = Uhubctl::with_runner("3-2".into(), 4, Arc::new(runner.clone()));
        ctl.on().await.unwrap();
        let calls = runner.calls();
        assert_eq!(calls[0].1, vec!["-a", "on", "-l", "3-2", "-p", "4"]);
    }

    #[tokio::test(start_paused = true)]
    async fn uhubctl_cycle_runs_off_then_on() {
        let runner = RecordingRunner::new();
        let ctl = Uhubctl::with_runner("1-1".into(), 1, Arc::new(runner.clone()));
        ctl.cycle().await.unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1[1], "off");
        assert_eq!(calls[1].1[1], "on");
    }

    #[tokio::test]
    async fn uhubctl_propagates_failure() {
        let runner = RecordingRunner::failing();
        let ctl = Uhubctl::with_runner("1-1".into(), 1, Arc::new(runner));
        assert!(matches!(ctl.off().await, Err(PowerError::Command(_))));
    }

    #[tokio::test]
    async fn nopower_is_noop() {
        let ctl = NoPower;
        ctl.off().await.unwrap();
        ctl.on().await.unwrap();
        ctl.cycle().await.unwrap();
        assert_eq!(ctl.label(), "none");
    }

    #[test]
    fn factory_dispatches_each_kind() {
        let u = from_power_kind(&PowerKind::Uhubctl {
            hub: "1-1".into(),
            port: 2,
        });
        assert_eq!(u.label(), "uhubctl 1-1:2");

        let g = from_power_kind(&PowerKind::Gpio {
            chip: "gpiochip0".into(),
            line: 17,
        });
        assert_eq!(g.label(), "gpio gpiochip0:17");

        let n = from_power_kind(&PowerKind::None);
        assert_eq!(n.label(), "none");
    }

    #[cfg(not(all(feature = "gpio", target_os = "linux")))]
    #[tokio::test]
    async fn gpio_unsupported_without_feature() {
        let g = Gpio::new("gpiochip0".into(), 1);
        assert!(matches!(g.off().await, Err(PowerError::Unsupported(_))));
    }
}

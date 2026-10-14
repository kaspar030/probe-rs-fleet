//! Board USB-serial passthrough (architecture §4.2, "Serial passthrough").
//!
//! A [`crate::ChannelKind::Serial`] channel rides the ordinary relay: the
//! coordinator forwards its [`crate::DataFrame`]s byte-opaquely, exactly as it
//! does the probe-rs data plane. What differs is the *content*: every
//! `DataFrame` on a serial channel carries **exactly one** postcard-encoded
//! message — [`SerialRequest`] client → node, [`SerialEvent`] node → client.
//! `WebSocket` messages are delimited and the relay forwards frames 1:1, so
//! message boundaries survive end to end and control (baud, DTR/RTS, break)
//! travels in-band without the coordinator learning anything new.
//!
//! The client never names a device path. Ports are named by the node
//! ([`SerialPortInfo::name`]) and resolved to a `/dev` node *on the node* at
//! open time, so a leaseholder cannot make the node open an arbitrary file.

use serde::{Deserialize, Serialize};

/// The default baud rate for a port nobody configured one for.
pub const DEFAULT_BAUD: u32 = 115_200;

/// A serial port the node associates with a board, as reported in the
/// inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialPortInfo {
    /// The node-chosen name a client opens the port by (`if1`, `console`, …).
    pub name: String,
    /// Informational device name (`ttyACM0`, or a `/dev/serial/by-id`
    /// basename). Never used to open anything on the client's say-so.
    pub device: String,
    /// The USB interface number, for auto-discovered ports.
    pub interface: Option<u8>,
    /// The baud rate the port opens at unless the client asks otherwise.
    pub default_baud: u32,
}

/// Number of data bits per character.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataBits {
    /// 5 bits.
    Five,
    /// 6 bits.
    Six,
    /// 7 bits.
    Seven,
    /// 8 bits.
    Eight,
}

/// Parity checking mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Parity {
    /// No parity bit.
    None,
    /// Odd parity.
    Odd,
    /// Even parity.
    Even,
}

/// Number of stop bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopBits {
    /// One stop bit.
    One,
    /// Two stop bits.
    Two,
}

/// Flow-control mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowControl {
    /// No flow control.
    None,
    /// XON/XOFF software flow control.
    Software,
    /// RTS/CTS hardware flow control.
    Hardware,
}

/// A complete set of line settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineSettings {
    /// Baud rate.
    pub baud: u32,
    /// Data bits.
    pub data_bits: DataBits,
    /// Parity.
    pub parity: Parity,
    /// Stop bits.
    pub stop_bits: StopBits,
    /// Flow control.
    pub flow: FlowControl,
}

impl Default for LineSettings {
    /// 115200 8N1, no flow control.
    fn default() -> Self {
        Self {
            baud: DEFAULT_BAUD,
            data_bits: DataBits::Eight,
            parity: Parity::None,
            stop_bits: StopBits::One,
            flow: FlowControl::None,
        }
    }
}

impl std::fmt::Display for LineSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bits = match self.data_bits {
            DataBits::Five => 5,
            DataBits::Six => 6,
            DataBits::Seven => 7,
            DataBits::Eight => 8,
        };
        let parity = match self.parity {
            Parity::None => 'N',
            Parity::Odd => 'O',
            Parity::Even => 'E',
        };
        let stop = match self.stop_bits {
            StopBits::One => 1,
            StopBits::Two => 2,
        };
        let flow = match self.flow {
            FlowControl::None => "",
            FlowControl::Software => " xon/xoff",
            FlowControl::Hardware => " rts/cts",
        };
        write!(f, "{} {bits}{parity}{stop}{flow}", self.baud)
    }
}

/// Client → node messages on a serial channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerialRequest {
    /// Open a port. Must be the first message on the channel.
    Open {
        /// The node-side port name; `None` picks the board's first port.
        port: Option<String>,
        /// Initial line settings.
        settings: LineSettings,
    },
    /// Bytes to write to the port.
    Data(Vec<u8>),
    /// Change the line settings.
    Configure(LineSettings),
    /// Set (`true`) or clear the DTR line.
    SetDtr(bool),
    /// Set (`true`) or clear the RTS line.
    SetRts(bool),
    /// Send a break condition for `millis` milliseconds.
    Break {
        /// Duration of the break.
        millis: u32,
    },
}

/// Node → client messages on a serial channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerialEvent {
    /// The port is open with these settings.
    Opened {
        /// The port name that was opened.
        port: String,
        /// The settings in effect.
        settings: LineSettings,
    },
    /// Bytes read from the port.
    Data(Vec<u8>),
    /// A non-fatal error (e.g. modem control unsupported by the device).
    Error(String),
    /// The port closed; no further events follow.
    Closed(String),
}

/// Encode a serial message for a `DataFrame` body.
///
/// # Panics
///
/// Never in practice: postcard serialisation into a `Vec` of these types
/// cannot fail.
#[must_use]
pub fn encode<T: Serialize>(msg: &T) -> Vec<u8> {
    postcard::to_allocvec(msg).expect("postcard encoding of a serial message cannot fail")
}

/// Decode a serial message from a `DataFrame` body.
///
/// # Errors
///
/// Returns the postcard error for a malformed frame.
pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, postcard::Error> {
    postcard::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_events_roundtrip() {
        let reqs = [
            SerialRequest::Open {
                port: Some("if1".to_owned()),
                settings: LineSettings::default(),
            },
            SerialRequest::Data(vec![1, 2, 3]),
            SerialRequest::Configure(LineSettings {
                baud: 9600,
                data_bits: DataBits::Seven,
                parity: Parity::Even,
                stop_bits: StopBits::Two,
                flow: FlowControl::Hardware,
            }),
            SerialRequest::SetDtr(true),
            SerialRequest::SetRts(false),
            SerialRequest::Break { millis: 250 },
        ];
        for r in reqs {
            assert_eq!(decode::<SerialRequest>(&encode(&r)).unwrap(), r);
        }
        let evs = [
            SerialEvent::Opened {
                port: "if1".to_owned(),
                settings: LineSettings::default(),
            },
            SerialEvent::Data(b"hello".to_vec()),
            SerialEvent::Error("nope".to_owned()),
            SerialEvent::Closed("gone".to_owned()),
        ];
        for e in evs {
            assert_eq!(decode::<SerialEvent>(&encode(&e)).unwrap(), e);
        }
    }

    #[test]
    fn settings_render_like_a_terminal_program() {
        assert_eq!(LineSettings::default().to_string(), "115200 8N1");
    }
}

//! A library for running a USB/IP server

use log::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use rusb::*;
use std::{
    any::Any,
    collections::{HashMap, VecDeque},
    io::Result,
    sync::{Arc, Mutex},
};

pub mod cdc;
mod consts;
mod device;
mod endpoint;
pub mod hid;
mod host;
mod interface;
pub mod server;
mod setup;
pub mod usbip_protocol;
mod util;

pub use consts::*;
pub use device::*;
pub use endpoint::*;
pub use host::*;
pub use interface::*;
pub use setup::*;
pub use util::*;

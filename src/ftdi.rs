use crate::{EndpointAttributes, SetupPacket, UsbDeviceHandler, UsbEndpoint};
use std::any::Any;

const FTDI_DEVICE_REQ_TYPE: u8 = 0xC0;
const FTDI_SIO_RESET: u8 = 0; /* Reset the port */
const FTDI_SIO_MODEM_CTRL: u8 = 1; /* Set the modem control register */
const FTDI_SIO_SET_FLOW_CTRL: u8 = 2; /* Set flow control register */
const FTDI_SIO_SET_BAUD_RATE: u8 = 3; /* Set baud rate */
const FTDI_SIO_SET_DATA: u8 = 4; /* Set the data characteristics ofthe port */
const FTDI_SIO_GET_MODEM_STATUS: u8 = 5; /* Retrieve current value of modem status register */
const FTDI_SIO_SET_EVENT_CHAR: u8 = 6; /* Set the event character */
const FTDI_SIO_SET_ERROR_CHAR: u8 = 7; /* Set the error character */
const FTDI_SIO_SET_LATENCY_TIMER: u8 = 9; /* Set the latency timer */
const FTDI_SIO_GET_LATENCY_TIMER: u8 = 0x0a; /* Get the latency timer */
const FTDI_SIO_SET_BITMODE: u8 = 0x0b; /* Set bitbang mode */
const FTDI_SIO_READ_PINS: u8 = 0x0c; /* Read immediate value of pins */
const FTDI_SIO_READ_EEPROM: u8 = 0x90; /* Read EEPROM */

const EP_MAX_PACKET_SIZE: u16 = 512;

#[derive(Debug)]
enum FTDISIORequestTypes {
    Reset,
    ModemCtrl,
    SetFlowCtrl,
    SetBaudRate,
    SetData,
    GetModemStatus,
    SetEventChar,
    SetErrorChar,
    SetLatencyTimer,
    GetLatencyTimer,
    SetBitmode,
    ReadPins,
    ReadEEPROM,
    Unknown,
}

impl From<u8> for FTDISIORequestTypes {
    fn from(orig: u8) -> Self {
        match orig {
            FTDI_SIO_RESET => FTDISIORequestTypes::Reset,
            FTDI_SIO_MODEM_CTRL => FTDISIORequestTypes::ModemCtrl,
            FTDI_SIO_SET_FLOW_CTRL => FTDISIORequestTypes::SetFlowCtrl,
            FTDI_SIO_SET_BAUD_RATE => FTDISIORequestTypes::SetBaudRate,
            FTDI_SIO_SET_DATA => FTDISIORequestTypes::SetData,
            FTDI_SIO_GET_MODEM_STATUS => FTDISIORequestTypes::GetModemStatus,
            FTDI_SIO_SET_EVENT_CHAR => FTDISIORequestTypes::SetEventChar,
            FTDI_SIO_SET_ERROR_CHAR => FTDISIORequestTypes::SetErrorChar,
            FTDI_SIO_SET_LATENCY_TIMER => FTDISIORequestTypes::SetLatencyTimer,
            FTDI_SIO_GET_LATENCY_TIMER => FTDISIORequestTypes::GetLatencyTimer,
            FTDI_SIO_SET_BITMODE => FTDISIORequestTypes::SetBitmode,
            FTDI_SIO_READ_PINS => FTDISIORequestTypes::ReadPins,
            FTDI_SIO_READ_EEPROM => FTDISIORequestTypes::ReadEEPROM,
            _ => FTDISIORequestTypes::Unknown,
        }
    }
}

#[derive(Clone)]
pub struct FtdiDeviceHandler {}

impl FtdiDeviceHandler {
    pub fn new() -> Self {
        Self {}
    }

    pub fn endpoints(interface_count: u8) -> Vec<UsbEndpoint> {
        let mut ret_eps = vec![];

        for i in 0..interface_count {
            ret_eps.push(UsbEndpoint {
                /// bEndpointAddress
                address: 0x81 + (0x2 * i),
                /// bmAttributes
                attributes: EndpointAttributes::Bulk as u8,
                /// wMaxPacketSize
                max_packet_size: EP_MAX_PACKET_SIZE as u16,
                /// bInterval
                interval: 0,
            });

            ret_eps.push(UsbEndpoint {
                /// bEndpointAddress
                address: 0x2 + (0x2 * i),
                /// bmAttributes
                attributes: EndpointAttributes::Bulk as u8,
                /// wMaxPacketSize
                max_packet_size: EP_MAX_PACKET_SIZE as u16,
                /// bInterval
                interval: 0,
            })
        }
        ret_eps
    }
}

impl UsbDeviceHandler for FtdiDeviceHandler {
    fn handle_urb(&mut self, setup: SetupPacket, _: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        match setup.request_type {
            FTDI_DEVICE_REQ_TYPE => match setup.request.into() {
                FTDISIORequestTypes::GetModemStatus => Ok(vec![0x00]),
                // 1 ms
                FTDISIORequestTypes::GetLatencyTimer => Ok(vec![0x01]),
                request => {
                    println!("Unhandled: {:?}", request);
                    Ok(vec![])
                }
            },
            _ => Ok(vec![]),
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

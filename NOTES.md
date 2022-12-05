# usbip

## linux modules

- vhci-hcd: client side, virtual usb host controller
- usbip-host: server side, bound to usb device to make it exportable
- usbip-vudc: server side, export a usb gadget

### usbip-host

Files:

- drivers/usb/usbip/stub.h
- drivers/usb/usbip/stub_main.c
- drivers/usb/usbip/stub_dev.c
- drivers/usb/usbip/stub_rx.c
- drivers/usb/usbip/stub_tx.c
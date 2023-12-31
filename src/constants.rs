// region: product information

pub(crate) const GUID: &str = env!("USB_GUID");
pub(crate) const PRODUCT_ID: u16 = 0xd33d;
pub(crate) const PRODUCT_NAME: &str = "PPV Signer";
pub(crate) const SERIAL_NUMBER: &str = env!("USB_SN");
pub(crate) const VENDOR_ID: u16 = 0x600d;
pub(crate) const VENDOR_NAME: &str = "Nusameta";

// endregion

// region: usb constants

pub(crate) const USB_DESCRIPTOR_SIZE: usize = 256;
pub(crate) const USB_DEVICE_CLASS: u8 = 0xef;
pub(crate) const USB_DEVICE_PROTOCOL: u8 = 0x01;
pub(crate) const USB_DEVICE_SUB_CLASS: u8 = 0x02;
pub(crate) const USB_GUIDS: &str = GUID;
pub(crate) const USB_MAX_PACKET_SIZE: u8 = 64;
pub(crate) const USB_MAX_POWER: u16 = 500;
pub(crate) const USB_PRODUCT_ID: u16 = PRODUCT_ID;
pub(crate) const USB_PRODUCT_NAME: &str = PRODUCT_NAME;
pub(crate) const USB_SERIAL_NUMBER: &str = SERIAL_NUMBER;
pub(crate) const USB_VENDOR_ID: u16 = VENDOR_ID;
pub(crate) const USB_VENDOR_NAME: &str = VENDOR_NAME;

// endregion

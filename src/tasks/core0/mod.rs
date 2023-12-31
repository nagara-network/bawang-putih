static mut USB_BUFFERS: USBBuffers = USBBuffers::create();
static mut USB_CONTROLLER: USBControlDataHandler = USBControlDataHandler::create();

#[embassy_executor::task]
async fn indicator_loop(mut indicator_led: super::IndicatorLed) {
    let mut led_is_on = false;
    let mut current_status = super::ModeIndicatorEvent::Standby;
    let mut colors;
    let mut sleep_time;

    loop {
        if let super::Option::Some(new_status) = super::MODE_INDICATOR_SIGNAL.try_take() {
            current_status = new_status;
        }

        led_is_on = !led_is_on;
        (colors, sleep_time) = current_status.get_color_and_sleep_time(led_is_on);
        indicator_led.set(&colors).await;
        sleep_time.await;
    }
}

#[embassy_executor::task]
async fn to_host_writer(mut usb_writer: super::BulkEndpointWriter<'static>) {
    embassy_usb::driver::Endpoint::wait_enabled(&mut usb_writer).await;
    let mut pending_chunk;

    loop {
        pending_chunk = super::WRITE_QUEUE.receive().await;
        let _ = super::IUSBWriter::write(&mut usb_writer, &pending_chunk).await;
    }
}

#[embassy_executor::task]
async fn from_host_reader(mut usb_reader: super::BulkEndpointReader<'static>) {
    embassy_usb::driver::Endpoint::wait_enabled(&mut usb_reader).await;
    let mut read_buffer = [0; super::MEM_MAX_CHUNK_SIZE];

    loop {
        match super::IUSBReader::read(&mut usb_reader, &mut read_buffer).await {
            core::result::Result::Err(_) => embassy_time::Timer::after_millis(100).await,
            core::result::Result::Ok(buffer_read_size) => {
                if buffer_read_size == 0 {
                    embassy_time::Timer::after_millis(100).await;
                    continue;
                }

                let mut pending_chunk = super::ChunkedBuffer::new();
                let _ = pending_chunk.try_extend_from_slice(&read_buffer[0..buffer_read_size]);
                super::READ_QUEUE.send(pending_chunk).await;
            }
        }
    }
}

#[embassy_executor::task]
pub(super) async fn run(
    spawner: embassy_executor::Spawner,
    usb_peripheral: embassy_rp::peripherals::USB,
    indicator_led: super::IndicatorLed,
) {
    spawner.spawn(indicator_loop(indicator_led)).unwrap();
    let config = USBHelper::get_config();
    let driver = USBHelper::get_driver(usb_peripheral);
    let mut builder = unsafe {
        embassy_usb::Builder::new(
            driver,
            config,
            &mut USB_BUFFERS.descriptor_device,
            &mut USB_BUFFERS.descriptor_config,
            &mut USB_BUFFERS.descriptor_bos,
            &mut USB_BUFFERS.descriptor_msos,
            &mut USB_BUFFERS.control_buffer,
        )
    };

    // WINUSB Compatibility
    builder.msos_descriptor(embassy_usb::msos::windows_version::WIN8_1, 0);
    builder.msos_feature(embassy_usb::msos::CompatibleIdFeatureDescriptor::new(
        "WINUSB", "",
    ));
    builder.msos_feature(embassy_usb::msos::RegistryPropertyFeatureDescriptor::new(
        "DeviceInterfaceGUIDs",
        embassy_usb::msos::PropertyData::RegMultiSz(&[crate::constants::USB_GUIDS]),
    ));

    // Vendor specific function impl (usb class 0xff)
    let mut function_builder = builder.function(0xff, 0x00, 0x00);
    let mut interface_builder = function_builder.interface();
    let mut interface_alternate_builder =
        interface_builder.alt_setting(0xff, 0x00, 0x00, super::Option::None);
    let writer = interface_alternate_builder.endpoint_bulk_in(crate::USB_MAX_PACKET_SIZE as u16);
    let reader = interface_alternate_builder.endpoint_bulk_out(crate::USB_MAX_PACKET_SIZE as u16);
    unsafe {
        USB_CONTROLLER.set_interface_number(interface_builder.interface_number());
    }
    drop(function_builder);
    unsafe {
        builder.handler(&mut USB_CONTROLLER);
    }

    // threads
    let mut device = builder.build();
    spawner.spawn(to_host_writer(writer)).unwrap();
    spawner.spawn(from_host_reader(reader)).unwrap();

    device.run().await;
}

struct USBControlDataHandler {
    interface_number: embassy_usb::types::InterfaceNumber,
}

impl USBControlDataHandler {
    fn set_interface_number(&mut self, new_interface_number: embassy_usb::types::InterfaceNumber) {
        self.interface_number = new_interface_number;
    }

    const fn create() -> Self {
        Self {
            interface_number: embassy_usb::types::InterfaceNumber(0),
        }
    }
}

impl embassy_usb::Handler for USBControlDataHandler {
    fn control_out(
        &mut self,
        usb_request: embassy_usb::control::Request,
        usb_buffer: &[u8],
    ) -> super::Option<embassy_usb::control::OutResponse> {
        if usb_request.request_type != embassy_usb::control::RequestType::Vendor
            || usb_request.recipient != embassy_usb::control::Recipient::Interface
        {
            return super::Option::None;
        }

        if usb_request.index != self.interface_number.0 as u16 {
            return super::Option::None;
        }

        if let super::Result::Ok(new_mode) =
            super::ModeChangeEvent::try_construct_from_control_out(&usb_request, usb_buffer)
        {
            super::MODE_CHANGE_SIGNAL.signal(new_mode);

            super::Option::Some(embassy_usb::control::OutResponse::Accepted)
        } else {
            super::Option::Some(embassy_usb::control::OutResponse::Rejected)
        }
    }
}

pub(crate) struct USBBuffers {
    pub(crate) control_buffer: [u8; Self::MAX_PACKET_SIZE],
    pub(crate) descriptor_bos: [u8; Self::DESCRIPTOR_SIZE],
    pub(crate) descriptor_config: [u8; Self::DESCRIPTOR_SIZE],
    pub(crate) descriptor_device: [u8; Self::DESCRIPTOR_SIZE],
    pub(crate) descriptor_msos: [u8; Self::DESCRIPTOR_SIZE],
}

impl USBBuffers {
    const DESCRIPTOR_SIZE: usize = crate::USB_DESCRIPTOR_SIZE;
    const MAX_PACKET_SIZE: usize = crate::USB_MAX_PACKET_SIZE as usize;

    pub(crate) const fn create() -> Self {
        Self {
            control_buffer: [0; Self::MAX_PACKET_SIZE],
            descriptor_bos: [0; Self::DESCRIPTOR_SIZE],
            descriptor_config: [0; Self::DESCRIPTOR_SIZE],
            descriptor_device: [0; Self::DESCRIPTOR_SIZE],
            descriptor_msos: [0; Self::DESCRIPTOR_SIZE],
        }
    }
}

pub(crate) struct USBHelper;

impl USBHelper {
    fn get_config<'a>() -> embassy_usb::Config<'a> {
        let mut config = embassy_usb::Config::new(crate::USB_VENDOR_ID, crate::USB_PRODUCT_ID);
        config.manufacturer = super::Option::Some(crate::USB_VENDOR_NAME);
        config.product = super::Option::Some(crate::USB_PRODUCT_NAME);
        config.serial_number = super::Option::Some(crate::USB_SERIAL_NUMBER);
        config.max_power = crate::USB_MAX_POWER;
        config.max_packet_size_0 = crate::USB_MAX_PACKET_SIZE;
        config.device_class = crate::USB_DEVICE_CLASS;
        config.device_sub_class = crate::USB_DEVICE_SUB_CLASS;
        config.device_protocol = crate::USB_DEVICE_PROTOCOL;
        config.composite_with_iads = true;

        config
    }

    fn get_driver<'a>(
        usb_peripheral: embassy_rp::peripherals::USB,
    ) -> embassy_rp::usb::Driver<'a, embassy_rp::peripherals::USB> {
        embassy_rp::usb::Driver::new(usb_peripheral, crate::IRQHandlerUSB)
    }
}

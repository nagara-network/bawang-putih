mod core0;
mod core1;
mod crypto;
mod flash;
mod led;

const MEM_TOTAL_SIZE: usize = 0x40000;
const MEM_GLOBAL_SIZE: usize = 0x20000;
const MEM_CORE0_SIZE: usize = MEM_GLOBAL_SIZE;
const MEM_CORE1_SIZE: usize = MEM_TOTAL_SIZE - MEM_CORE0_SIZE;
const MEM_MAX_WORK_SIZE: usize = 512 + 4096;
const MEM_MAX_CHUNK_SIZE: usize = crate::USB_MAX_PACKET_SIZE as usize;
const MEM_MAX_QUEUE_COUNT: usize = (MEM_MAX_WORK_SIZE * 2) / MEM_MAX_CHUNK_SIZE;

use embassy_usb::driver::EndpointIn as IUSBWriter;
use embassy_usb::driver::EndpointOut as IUSBReader;

type Result<T> = core::result::Result<T, BawangPutihError>;
type Option<T> = core::option::Option<T>;

type AuxiliaryCPU = embassy_rp::peripherals::CORE1;
type BulkEndpointReader<'a> =
    embassy_rp::usb::Endpoint<'a, embassy_rp::peripherals::USB, embassy_rp::usb::Out>;
type BulkEndpointWriter<'a> =
    embassy_rp::usb::Endpoint<'a, embassy_rp::peripherals::USB, embassy_rp::usb::In>;
type ChunkedBuffer = RawBuffer<MEM_MAX_CHUNK_SIZE>;
type Core1StackMemory = embassy_rp::multicore::Stack<{ MEM_CORE1_SIZE }>;
type DataFromHostQueue = RawBufferChannel<MEM_MAX_QUEUE_COUNT>;
type DataToHostQueue = RawBufferChannel<MEM_MAX_QUEUE_COUNT>;
type Executor = static_cell::StaticCell<embassy_executor::Executor>;
type IndicatorLed = led::Ws2812<'static, embassy_rp::peripherals::PIO0, 0>;
type InterCoreChannel<T, const N: usize> = embassy_sync::channel::Channel<InterCoreMutex, T, N>;
type InterCoreMutex = embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
type InterCoreSignal<T> = embassy_sync::signal::Signal<InterCoreMutex, T>;
type ModeChangeSignal = InterCoreSignal<ModeChangeEvent>;
type ModeIndicatorSignal = InterCoreSignal<ModeIndicatorEvent>;
type RawBuffer<const N: usize> = arrayvec::ArrayVec<u8, N>;
type RawBufferChannel<const N: usize> = InterCoreChannel<ChunkedBuffer, N>;
type RawBufferIncoming = RawBuffer<MEM_MAX_WORK_SIZE>;
type RawBufferOutgoing = RawBuffer<MEM_MAX_WORK_SIZE>;
type USBPeripherals = embassy_rp::peripherals::USB;

static mut CORE1_MEM: Core1StackMemory = Core1StackMemory::new();

static CORE0_EXECUTOR: Executor = Executor::new();
static CORE1_EXECUTOR: Executor = Executor::new();
static MODE_CHANGE_SIGNAL: ModeChangeSignal = ModeChangeSignal::new();
static MODE_INDICATOR_SIGNAL: ModeIndicatorSignal = ModeIndicatorSignal::new();
static READ_QUEUE: DataFromHostQueue = DataFromHostQueue::new();
static WRITE_QUEUE: DataToHostQueue = DataToHostQueue::new();

#[repr(u8)]
#[derive(core::fmt::Debug, thiserror_no_std::Error)]
pub enum BawangPutihError {
    #[error("Unsupported mode")]
    UnsupportedMode,
    #[error("Length buffer must be 32-bit little endian")]
    LengthBufferNot32Bit,
    #[error("Invalid cipher details")]
    InvalidCipherDetails,
    #[error("Malformed public key")]
    MalformedPublicKey,
    #[error("Bad signature")]
    BadSignature,
    #[error("Big brother registry is full")]
    BigBrotherRegistryIsFull,
    #[error("Big brother already registered")]
    BigBrotherAlreadyRegistered,
    #[error("Big brother doesn't exist")]
    BigBrotherDoesntExist,
    #[error("Conntent hash compromised")]
    ContentHashCompromised,
    #[error("Catastrophic failure in DH operations")]
    DHOperationFailure,
}

#[derive(core::clone::Clone, core::marker::Copy)]
#[derive(core::cmp::Eq, PartialEq)]
pub(crate) enum ModeChangeEvent {
    Standby,
    GetInformation,
    BigBrotherAdd,
    BigBrotherRemove,
    Sign { total_size: u32 },
    TransformStorage2Wire { total_size: u32 },
    TransformWire2Storage { total_size: u32 },
}

impl ModeChangeEvent {
    const SIZE_BIG_BROTHER_OPS: usize = 128;

    fn get_length_from_request(usb_buffer: &[u8]) -> Result<u32> {
        if usb_buffer.len() != 4 {
            return Result::Err(BawangPutihError::LengthBufferNot32Bit);
        }

        let mut length_buffer = [0; 4];
        length_buffer.copy_from_slice(usb_buffer);

        Result::Ok(u32::from_le_bytes(length_buffer))
    }

    fn emit_indicator_signal(&self) {
        match self {
            Self::Standby => MODE_INDICATOR_SIGNAL.signal(ModeIndicatorEvent::Standby),
            Self::GetInformation => {
                MODE_INDICATOR_SIGNAL.signal(ModeIndicatorEvent::InformationQuery)
            }
            Self::BigBrotherAdd => {
                MODE_INDICATOR_SIGNAL.signal(ModeIndicatorEvent::BigBrotherRegistration)
            }
            Self::BigBrotherRemove => {
                MODE_INDICATOR_SIGNAL.signal(ModeIndicatorEvent::BigBrotherRegistration)
            }
            Self::Sign {
                ..
            } => MODE_INDICATOR_SIGNAL.signal(ModeIndicatorEvent::Signatory),
            Self::TransformStorage2Wire {
                ..
            } => MODE_INDICATOR_SIGNAL.signal(ModeIndicatorEvent::TransformEncryption),
            Self::TransformWire2Storage {
                ..
            } => MODE_INDICATOR_SIGNAL.signal(ModeIndicatorEvent::TransformEncryption),
        }
    }

    fn try_construct_from_control_out(
        usb_request: &embassy_usb::control::Request,
        usb_buffer: &[u8],
    ) -> Result<Self> {
        match usb_request.request {
            0x10 => Result::Ok(Self::Standby),
            0x11 => Result::Ok(Self::GetInformation),
            0x20 => Result::Ok(Self::BigBrotherAdd),
            0x21 => Result::Ok(Self::BigBrotherRemove),
            0x30 => {
                Result::Ok(Self::Sign {
                    total_size: Self::get_length_from_request(usb_buffer)?,
                })
            }
            0x40 => {
                Result::Ok(Self::TransformStorage2Wire {
                    total_size: Self::get_length_from_request(usb_buffer)?,
                })
            }
            0x41 => {
                Result::Ok(Self::TransformWire2Storage {
                    total_size: Self::get_length_from_request(usb_buffer)?,
                })
            }
            _ => Result::Err(BawangPutihError::UnsupportedMode),
        }
    }
}

#[derive(core::default::Default)]
#[derive(core::clone::Clone, core::marker::Copy)]
pub(crate) enum ModeIndicatorEvent {
    #[default]
    Standby,
    InformationQuery,
    BigBrotherRegistration,
    Signatory,
    TransformEncryption,
}

impl ModeIndicatorEvent {
    const BLINK_MS_OFF_LONG: u64 = 975;
    const BLINK_MS_OFF_SHORT: u64 = 75;
    const BLINK_MS_ON: u64 = 25;
    const COLOR_BLACK: smart_leds::RGB8 = smart_leds::RGB8::new(0, 0, 0);
    const COLOR_BLUE: smart_leds::RGB8 = smart_leds::RGB8::new(0, 0, 0xFF);
    const COLOR_GREEN: smart_leds::RGB8 = smart_leds::RGB8::new(0, 0xFF, 0);
    const COLOR_RED: smart_leds::RGB8 = smart_leds::RGB8::new(0xFF, 0, 0);
    const COLOR_WHITE: smart_leds::RGB8 = smart_leds::RGB8::new(0xFF, 0xFF, 0xFF);
    const COLOR_YELLOW: smart_leds::RGB8 = smart_leds::RGB8::new(0xFF, 0x80, 0);

    fn is_standby(&self) -> bool {
        core::matches!(self, Self::Standby)
    }

    fn get_color_and_sleep_time(
        &self,
        on_state: bool,
    ) -> ([smart_leds::RGB8; 1], embassy_time::Timer) {
        let sleep_time = match (self.is_standby(), on_state) {
            (_, true) => Self::BLINK_MS_ON,
            (false, false) => Self::BLINK_MS_OFF_SHORT,
            (true, false) => Self::BLINK_MS_OFF_LONG,
        };
        let sleep_time = embassy_time::Timer::after_millis(sleep_time);
        let color = if on_state {
            match self {
                Self::Standby => Self::COLOR_RED,
                Self::InformationQuery => Self::COLOR_YELLOW,
                Self::BigBrotherRegistration => Self::COLOR_WHITE,
                Self::Signatory => Self::COLOR_BLUE,
                Self::TransformEncryption => Self::COLOR_GREEN,
            }
        } else {
            Self::COLOR_BLACK
        };

        ([color], sleep_time)
    }
}

fn get_peripherals() -> (AuxiliaryCPU, USBPeripherals, IndicatorLed) {
    let peripherals = embassy_rp::init(Default::default());
    let indicator_led = {
        let embassy_rp::pio::Pio {
            mut common,
            sm0,
            ..
        } = embassy_rp::pio::Pio::new(peripherals.PIO0, crate::IRQHandlerPIO0);

        IndicatorLed::new(&mut common, sm0, peripherals.DMA_CH0, peripherals.PIN_16)
    };

    (peripherals.CORE1, peripherals.USB, indicator_led)
}

pub(super) fn run() -> ! {
    let (auxiliary_cpu, usb_peripheral, indicator_led) = get_peripherals();

    embassy_rp::multicore::spawn_core1(auxiliary_cpu, unsafe { &mut CORE1_MEM }, move || {
        let core1_executor = CORE1_EXECUTOR.init(embassy_executor::Executor::new());

        core1_executor.run(|core1_spawner| core1_spawner.spawn(core1::run()).unwrap());
    });

    let core0_executor = CORE0_EXECUTOR.init(embassy_executor::Executor::new());

    core0_executor.run(|core0_spawner| {
        core0_spawner
            .spawn(core0::run(core0_spawner, usb_peripheral, indicator_led))
            .unwrap()
    })
}

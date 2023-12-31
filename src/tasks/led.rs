pub(super) struct Ws2812<'dev, PIO: embassy_rp::pio::Instance + 'static, const SM: usize> {
    dma: embassy_rp::PeripheralRef<'dev, embassy_rp::dma::AnyChannel>,
    sm: embassy_rp::pio::StateMachine<'dev, PIO, SM>,
}

impl<'dev, PIO: embassy_rp::pio::Instance + 'static, const SM: usize> Ws2812<'dev, PIO, SM> {
    const BRIGHTNESS_LEVEL: u32 = 2;
    const CYCLES_PER_BIT: u32 = (Self::T1 + Self::T2 + Self::T3) as u32;
    const T1: u8 = 2;
    const T2: u8 = 5;
    const T3: u8 = 3;

    pub(super) fn new(
        pio_instance: &mut embassy_rp::pio::Common<'dev, PIO>,
        mut sm: embassy_rp::pio::StateMachine<'dev, PIO, SM>,
        dma: impl embassy_rp::Peripheral<P = impl embassy_rp::dma::Channel> + 'dev,
        pin: impl embassy_rp::pio::PioPin,
    ) -> Self {
        embassy_rp::into_ref!(dma);

        // prepare the PIO program
        let side_set = pio::SideSet::new(false, 1, false);
        let mut assembler: pio::Assembler<32> = pio::Assembler::new_with_side_set(side_set);
        let mut wrap_target = assembler.label();
        let mut wrap_source = assembler.label();
        let mut do_zero = assembler.label();
        assembler.set_with_side_set(pio::SetDestination::PINDIRS, 1, 0);
        assembler.bind(&mut wrap_target);
        // Do stop bit
        assembler.out_with_delay_and_side_set(pio::OutDestination::X, 1, Self::T3 - 1, 0);
        // Do start bit
        assembler.jmp_with_delay_and_side_set(
            pio::JmpCondition::XIsZero,
            &mut do_zero,
            Self::T1 - 1,
            1,
        );
        // Do data bit = 1
        assembler.jmp_with_delay_and_side_set(
            pio::JmpCondition::Always,
            &mut wrap_target,
            Self::T2 - 1,
            1,
        );
        assembler.bind(&mut do_zero);
        // Do data bit = 0
        assembler.nop_with_delay_and_side_set(Self::T2 - 1, 0);
        assembler.bind(&mut wrap_source);
        let program = assembler.assemble_with_wrap(wrap_source, wrap_target);
        let mut cfg = embassy_rp::pio::Config::default();

        // Pin config
        let out_pin = pio_instance.make_pio_pin(pin);
        cfg.set_out_pins(&[&out_pin]);
        cfg.set_set_pins(&[&out_pin]);
        cfg.use_program(&pio_instance.load_program(&program), &[&out_pin]);

        // Clock config, measured in kHz to avoid overflows
        let clock_freq = fixed::types::U24F8::from_num(embassy_rp::clocks::clk_sys_freq() / 1_000);
        let ws2812_freq = fixed_macro::fixed!(800: U24F8);
        let bit_freq = ws2812_freq * Self::CYCLES_PER_BIT;
        cfg.clock_divider = clock_freq / bit_freq;

        // FIFO config
        cfg.fifo_join = embassy_rp::pio::FifoJoin::TxOnly;
        cfg.shift_out = embassy_rp::pio::ShiftConfig {
            auto_fill: true,
            threshold: 24,
            direction: embassy_rp::pio::ShiftDirection::Left,
        };

        sm.set_config(&cfg);
        sm.set_enable(true);

        Self {
            dma: dma.map_into(),
            sm,
        }
    }

    pub(super) async fn set<const N: usize>(&mut self, colors: &[smart_leds::RGB8; N]) {
        let mut color_words = [0u32; N];

        for i in 0..N {
            let green = colors[i].g as u32 * Self::BRIGHTNESS_LEVEL / 255;
            let red = colors[i].r as u32 * Self::BRIGHTNESS_LEVEL / 255;
            let blue = colors[i].b as u32 * Self::BRIGHTNESS_LEVEL / 255;
            let word = (red << 24) | (green << 16) | (blue << 8);
            color_words[i] = word;
        }

        self.sm
            .tx()
            .dma_push(self.dma.reborrow(), &color_words)
            .await;
    }
}

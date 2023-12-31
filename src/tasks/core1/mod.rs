async fn flush_outgoing_buffer(outgoing_buffer: &super::RawBufferOutgoing) {
    for chunk in outgoing_buffer.chunks(super::MEM_MAX_CHUNK_SIZE) {
        let mut buffer = super::ChunkedBuffer::new();
        buffer.try_extend_from_slice(chunk).unwrap();
        super::WRITE_QUEUE.send(buffer).await;
    }
}

#[embassy_executor::task]
pub(super) async fn run() {
    let mut incoming_buffer = super::RawBufferIncoming::new();
    let mut outgoing_buffer = super::RawBufferOutgoing::new();
    let mut operator = super::crypto::CryptographicOperator::create().await;
    let mut current_mode = super::ModeChangeEvent::Standby;
    let mut signing_size_counter = 0;

    macro_rules! async_sleep {
        () => {
            embassy_time::Timer::after_millis(100).await
        };
    }

    macro_rules! clear_buffers {
        () => {
            incoming_buffer.clear();
            outgoing_buffer.clear();
            signing_size_counter = 0;
        };
    }

    macro_rules! emit_indicator_signal {
        () => {
            current_mode.emit_indicator_signal();
        };
    }

    macro_rules! clear_buffers_and_go_standby {
        () => {
            clear_buffers!();
            current_mode = super::ModeChangeEvent::Standby;
            emit_indicator_signal!();
        };
    }

    macro_rules! try_extend_incoming_buffer {
        () => {
            if let core::result::Result::Ok(new_chunk) = super::READ_QUEUE.try_receive() {
                let _ = incoming_buffer.try_extend_from_slice(new_chunk.as_slice());
            } else {
                async_sleep!();
            }
        };
    }

    loop {
        if super::MODE_CHANGE_SIGNAL.signaled() {
            if let super::Option::Some(new_mode) = super::MODE_CHANGE_SIGNAL.try_take() {
                current_mode = new_mode;
                clear_buffers!();
                emit_indicator_signal!();
            }
        }

        match current_mode {
            super::ModeChangeEvent::Standby => async_sleep!(),
            super::ModeChangeEvent::GetInformation => {
                operator.fill_device_info(&mut outgoing_buffer);
                flush_outgoing_buffer(&outgoing_buffer).await;
                clear_buffers_and_go_standby!();
            }
            super::ModeChangeEvent::BigBrotherAdd => {
                match incoming_buffer
                    .len()
                    .cmp(&super::ModeChangeEvent::SIZE_BIG_BROTHER_OPS)
                {
                    core::cmp::Ordering::Less => {
                        try_extend_incoming_buffer!();
                    }
                    core::cmp::Ordering::Greater => {
                        clear_buffers_and_go_standby!();
                    }
                    core::cmp::Ordering::Equal => {
                        operator
                            .add_big_brother(&incoming_buffer, &mut outgoing_buffer)
                            .await;
                        flush_outgoing_buffer(&outgoing_buffer).await;
                        clear_buffers_and_go_standby!();
                    }
                }
            }
            super::ModeChangeEvent::BigBrotherRemove => {
                match incoming_buffer
                    .len()
                    .cmp(&super::ModeChangeEvent::SIZE_BIG_BROTHER_OPS)
                {
                    core::cmp::Ordering::Less => {
                        try_extend_incoming_buffer!();
                    }
                    core::cmp::Ordering::Greater => {
                        clear_buffers_and_go_standby!();
                    }
                    core::cmp::Ordering::Equal => {
                        operator
                            .remove_big_brother(&incoming_buffer, &mut outgoing_buffer)
                            .await;
                        flush_outgoing_buffer(&outgoing_buffer).await;
                        clear_buffers_and_go_standby!();
                    }
                }
            }
            super::ModeChangeEvent::TransformStorage2Wire {
                total_size,
            } => {
                match incoming_buffer.len().cmp(&(total_size as usize)) {
                    core::cmp::Ordering::Less => {
                        try_extend_incoming_buffer!();
                    }
                    core::cmp::Ordering::Greater => {
                        clear_buffers_and_go_standby!();
                    }
                    core::cmp::Ordering::Equal => {
                        operator.transform_encryption_from_storage_to_wire(
                            &incoming_buffer,
                            &mut outgoing_buffer,
                        );
                        flush_outgoing_buffer(&outgoing_buffer).await;
                        clear_buffers_and_go_standby!();
                    }
                }
            }
            super::ModeChangeEvent::TransformWire2Storage {
                total_size,
            } => {
                match incoming_buffer.len().cmp(&(total_size as usize)) {
                    core::cmp::Ordering::Less => {
                        try_extend_incoming_buffer!();
                    }
                    core::cmp::Ordering::Greater => {
                        clear_buffers_and_go_standby!();
                    }
                    core::cmp::Ordering::Equal => {
                        operator.transform_encryption_from_wire_to_storage(
                            &incoming_buffer,
                            &mut outgoing_buffer,
                        );
                        flush_outgoing_buffer(&outgoing_buffer).await;
                        clear_buffers_and_go_standby!();
                    }
                }
            }
            super::ModeChangeEvent::Sign {
                total_size,
            } => {
                if signing_size_counter == 0 {
                    operator.reset_signer();
                }

                if signing_size_counter >= total_size as usize {
                    operator.sign_and_reset(&mut outgoing_buffer);
                    flush_outgoing_buffer(&outgoing_buffer).await;
                    clear_buffers_and_go_standby!();
                    continue;
                }

                if let core::result::Result::Ok(new_chunk) = super::READ_QUEUE.try_receive() {
                    operator.feed_signer(new_chunk.as_slice());
                    signing_size_counter += new_chunk.len();
                } else {
                    async_sleep!();
                }
            }
        }
    }
}

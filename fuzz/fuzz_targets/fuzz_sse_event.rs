//! Session SSE events.
//!
//! - `parse_event` never panics.
//! - A message event carries any text: `parse(format(text))` returns the text
//!   with line breaks normalized to `\n`, and no text can end the event
//!   early or change its type.
//! - `payment-need-voucher` and (with `--features tempo`) `payment-receipt`
//!   events round-trip with arbitrary field contents.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::server::sse::{
    format_message_event, format_need_voucher_event, parse_event, NeedVoucherEvent, SseEvent,
};

fuzz_target!(|text: &str| {
    if let Some(SseEvent::Message(data)) = parse_event(text) {
        let event = format_message_event(&data);
        assert_eq!(parse_event(&event), Some(SseEvent::Message(data)));
    }

    let event = format_message_event(text);
    assert!(event.ends_with("\n\n") && !event[..event.len() - 1].contains("\n\n"));
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    assert_eq!(parse_event(&event), Some(SseEvent::Message(normalized)));

    // Up to four lines of the input become the fields of the other events.
    let mut fields = text.splitn(4, '\n').map(str::to_owned);
    let mut field = || fields.next().unwrap_or_default();
    let voucher = NeedVoucherEvent {
        channel_id: field(),
        required_cumulative: field(),
        accepted_cumulative: field(),
        deposit: field(),
    };
    let event = format_need_voucher_event(&voucher);
    assert_eq!(event.matches('\n').count(), 3, "{event:?}");
    assert_eq!(
        parse_event(&event),
        Some(SseEvent::PaymentNeedVoucher(voucher.clone()))
    );

    #[cfg(feature = "tempo")]
    {
        use mpp::protocol::methods::tempo::SessionReceipt;
        use mpp::server::sse::format_receipt_event;

        let mut receipt = SessionReceipt::new(
            voucher.channel_id,
            voucher.required_cumulative,
            voucher.accepted_cumulative,
            voucher.deposit,
            text,
        );
        receipt.units = Some(text.len() as u64);
        receipt.tx_hash = Some(text.to_owned());
        let event = format_receipt_event(&receipt);
        assert_eq!(event.matches('\n').count(), 3, "{event:?}");
        assert_eq!(parse_event(&event), Some(SseEvent::PaymentReceipt(receipt)));
    }
});

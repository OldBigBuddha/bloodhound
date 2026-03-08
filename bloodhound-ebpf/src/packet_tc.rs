use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    helpers::{bpf_ktime_get_ns, bpf_skb_load_bytes},
    macros::classifier,
    programs::TcContext,
};
use bloodhound_common::*;

use crate::helpers::emit_event;
use crate::maps::{ASSEMBLY_BUF, EXCLUDED_PORTS};

// Ethernet header size
const ETH_HLEN: usize = 14;
// IP header offsets
const IP_PROTO_OFFSET: usize = ETH_HLEN + 9;
const IP_HEADER_MIN: usize = 20;

/// Fixed capture size for bpf_skb_load_bytes.
///
/// # BPF verifier constraint
///
/// `bpf_skb_load_bytes` rejects zero-length reads. The verifier must prove
/// `len > 0` at verification time. Aya's `SkBuff::load_bytes()` wrapper
/// computes the length at runtime as `min(skb.len - offset, dst.len())`,
/// which the verifier sees as `[0, dst.len()]` — includes zero → rejected.
///
/// Solution: pass a compile-time constant directly to the raw
/// `bpf_skb_load_bytes` helper. We use ETH_HLEN + IP_HEADER_MIN (34)
/// which is the minimum guaranteed by the function's entry check
/// (`data_len >= 34`), so every packet that reaches this code has
/// at least 34 bytes available.
const CAPTURE_SIZE: u32 = (ETH_HLEN + IP_HEADER_MIN) as u32; // = 34, guaranteed available

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    match unsafe { try_tc_capture(&ctx, EventKind::PacketIngress as u8) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match unsafe { try_tc_capture(&ctx, EventKind::PacketEgress as u8) } {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

unsafe fn try_tc_capture(ctx: &TcContext, kind: u8) -> Result<i32, i64> {
    let data_len = ctx.len() as usize;
    if data_len < ETH_HLEN + IP_HEADER_MIN {
        return Ok(TC_ACT_PIPE);
    }

    // Read IP protocol byte for port exclusion check
    let proto: u8 = ctx.load(IP_PROTO_OFFSET).map_err(|_| -1i64)?;

    // Check port exclusion for TCP (6) and UDP (17)
    if proto == 6 || proto == 17 {
        let transport_offset = ETH_HLEN + IP_HEADER_MIN;
        if data_len >= transport_offset + 4 {
            let sport: u16 = u16::from_be(ctx.load(transport_offset).map_err(|_| -1i64)?);
            let dport: u16 = u16::from_be(ctx.load(transport_offset + 2).map_err(|_| -1i64)?);

            if EXCLUDED_PORTS.get(&sport).is_some() || EXCLUDED_PORTS.get(&dport).is_some() {
                return Ok(TC_ACT_PIPE);
            }
        }
    }

    // Capture the first CAPTURE_SIZE bytes of each packet.
    //
    // We use ETH_HLEN + IP_HEADER_MIN (= 34 bytes) which is guaranteed
    // available by the `data_len >= ETH_HLEN + IP_HEADER_MIN` check at
    // function entry. This means `bpf_skb_load_bytes(len=34)` always
    // succeeds — no packet gets dropped due to insufficient length.
    //
    // The compile-time constant is critical for the BPF verifier:
    // aya's `SkBuff::load_bytes()` computes len at runtime as
    // `min(skb.len - offset, dst.len())`, so the verifier sees
    // `len ∈ [0, dst.len()]` — includes zero → rejected with:
    //   `R4 invalid zero-sized read: u64=[0, N]`
    // By passing a constant directly to `bpf_skb_load_bytes`,
    // the verifier sees `R4 = 34 > 0` → accepted.

    let timestamp_ns = bpf_ktime_get_ns();
    let pkt_header = PacketEventHeader {
        kind,
        _pad: [0; 3],
        timestamp_ns,
        ifindex: 0,
        data_len: CAPTURE_SIZE,
    };

    // Assemble in assembly buffer
    let total_size = PacketEventHeader::SIZE + CAPTURE_SIZE as usize;
    let asm = match ASSEMBLY_BUF.get_ptr_mut(0) {
        Some(s) => s,
        None => return Ok(TC_ACT_PIPE),
    };
    let out = &mut (*asm).buf;
    if total_size > out.len() {
        return Ok(TC_ACT_PIPE);
    }

    // Write packet header
    core::ptr::copy_nonoverlapping(
        &pkt_header as *const PacketEventHeader as *const u8,
        out.as_mut_ptr(),
        PacketEventHeader::SIZE,
    );

    // Copy packet data using raw bpf_skb_load_bytes with compile-time
    // constant CAPTURE_SIZE. This bypasses aya's SkBuff::load_bytes()
    // wrapper which computes len at runtime, causing the verifier to
    // see a possible zero-length read.
    let dst = out.as_mut_ptr().add(PacketEventHeader::SIZE);
    let ret = bpf_skb_load_bytes(
        ctx.skb.skb as *const _,
        0u32,
        dst as *mut _,
        CAPTURE_SIZE,
    );
    if ret != 0 {
        return Ok(TC_ACT_PIPE);
    }

    emit_event(&out[..total_size]);
    Ok(TC_ACT_PIPE)
}

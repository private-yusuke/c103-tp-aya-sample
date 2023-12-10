#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{TC_ACT_SHOT, TC_ACT_UNSPEC},
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

#[classifier]
pub fn c103_tp_aya_sample(ctx: TcContext) -> i32 {
    match try_c103_tp_aya_sample(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_c103_tp_aya_sample(ctx: TcContext) -> Result<i32, i32> {
    // IPv4 のパケット以外は処理しない
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_UNSPEC)?;
    if !matches!(ethhdr.ether_type, EtherType::Ipv4) {
        return Ok(TC_ACT_UNSPEC);
    }
    // ICMP のパケット以外は処理しない
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_UNSPEC)?;
    if ipv4hdr.proto != IpProto::Icmp {
        return Ok(TC_ACT_UNSPEC);
    }
    // ICMP のパケットのうち、宛先が 93.184.216.34 のものはドロップする
    if ipv4hdr.dst_addr.to_be() == 0x5db8d822 {
        info!(&ctx, "ICMP packet to 93.184.216.34 is dropped");
        return Ok(TC_ACT_SHOT);
    }
    Ok(TC_ACT_UNSPEC)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

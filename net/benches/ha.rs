use criterion::{black_box, criterion_group, criterion_main, Criterion};
use net::ha::{AddressInfo, Command, Family, Header, Protocol, Tlv, parse};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

fn header_ipv4() -> Header {
    Header {
        command: Command::Proxy,
        family: Family::Inet,
        protocol: Protocol::Stream,
        address: AddressInfo::Ipv4(
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 54321),
            SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 25565),
        ),
        tlvs: Vec::new(),
    }
}

fn header_ipv6() -> Header {
    Header {
        command: Command::Proxy,
        family: Family::Inet6,
        protocol: Protocol::Stream,
        address: AddressInfo::Ipv6(
            SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 54321, 0, 0),
            SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2), 25565, 0, 0),
        ),
        tlvs: Vec::new(),
    }
}

fn header_with_tlv() -> Header {
    Header {
        command: Command::Proxy,
        family: Family::Inet,
        protocol: Protocol::Stream,
        address: AddressInfo::Ipv4(
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 40000),
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 25565),
        ),
        tlvs: vec![
            Tlv::Alpn("h2".into()),
            Tlv::Authority("example.com".into()),
            Tlv::UniqueId(vec![1, 2, 3, 4, 5, 6, 7, 8].into_boxed_slice()),
            Tlv::Ssl {
                client: 0x01,
                verify: Some(0),
                version: Some("TLSv1.3".into()),
                cn: Some("example.com".into()),
                cipher: Some("TLS_AES_128_GCM_SHA256".into()),
                sig_alg: Some("rsa_pss_rsae_sha256".into()),
                key_alg: Some("rsa_pss_rsae_sha256".into()),
            },
            Tlv::Netns("lure".into()),
        ],
    }
}

fn bench_parse_header(c: &mut Criterion, name: &str, header: Header) {
    let bytes = header.serialize();
    c.bench_function(name, |b| {
        b.iter(|| {
            let parsed = parse(black_box(&bytes)).unwrap();
            black_box(parsed);
        })
    });
}

fn bench_parse_ipv4(c: &mut Criterion) {
    bench_parse_header(c, "ha_parse_v2_ipv4", header_ipv4());
}

fn bench_parse_ipv6(c: &mut Criterion) {
    bench_parse_header(c, "ha_parse_v2_ipv6", header_ipv6());
}

fn bench_parse_with_tlv(c: &mut Criterion) {
    bench_parse_header(c, "ha_parse_v2_tlv", header_with_tlv());
}

fn bench_parse_truncated(c: &mut Criterion) {
    let bytes = header_with_tlv().serialize();
    let truncated_len = bytes.len().saturating_sub(1);
    let truncated = &bytes[..truncated_len];
    c.bench_function("ha_parse_truncated", |b| {
        b.iter(|| {
            let errored = parse(black_box(truncated)).is_err();
            black_box(errored);
        })
    });
}

criterion_group!(
    benches,
    bench_parse_ipv4,
    bench_parse_ipv6,
    bench_parse_with_tlv,
    bench_parse_truncated
);
criterion_main!(benches);

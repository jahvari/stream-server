use ipnet::IpNet;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::LazyLock,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DestinationClass {
    Public,
    PrivateSource,
    AlwaysBlocked,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LocalNetworks {
    pub(crate) interfaces: Vec<IpNet>,
}

impl LocalNetworks {
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        self.interfaces.iter().any(|network| network.contains(&ip))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Nat64Prefix {
    pub(crate) network: Ipv6Addr,
    pub(crate) length: u8,
}

// IANA registry snapshot: 2026-08-19
// https://www.iana.org/assignments/iana-ipv4-special-registry
// https://www.iana.org/assignments/iana-ipv6-special-registry
const PRIVATE_V4: &[&str] = &[
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
];

const ALWAYS_BLOCKED_V4: &[&str] = &[
    "0.0.0.0/8",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.88.99.0/24",
    "192.175.48.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

const METADATA_V4: &[&str] = &[
    "168.63.129.16/32",
    "169.254.169.254/32",
    "169.254.170.2/32",
    "169.254.170.23/32",
    "100.100.100.200/32",
    "192.0.0.192/32",
];

const PRIVATE_V6: &[&str] = &["::1/128", "fc00::/7", "fe80::/10"];

const ALWAYS_BLOCKED_V6: &[&str] = &[
    "::/128",
    "100::/64",
    "100:0:0:1::/64",
    "2001::/23",
    "2001:db8::/32",
    "2620:4f:8000::/48",
    "3fff::/20",
    "5f00::/16",
    "ff00::/8",
];

const METADATA_V6: &[&str] = &["fd00:ec2::23/128", "fd00:ec2::254/128", "fd20:ce::254/128"];

static PRIVATE_V4_NETS: LazyLock<Vec<IpNet>> = LazyLock::new(|| parse_networks(PRIVATE_V4));
static ALWAYS_BLOCKED_V4_NETS: LazyLock<Vec<IpNet>> =
    LazyLock::new(|| parse_networks(ALWAYS_BLOCKED_V4));
static METADATA_V4_NETS: LazyLock<Vec<IpNet>> = LazyLock::new(|| parse_networks(METADATA_V4));
static PRIVATE_V6_NETS: LazyLock<Vec<IpNet>> = LazyLock::new(|| parse_networks(PRIVATE_V6));
static ALWAYS_BLOCKED_V6_NETS: LazyLock<Vec<IpNet>> =
    LazyLock::new(|| parse_networks(ALWAYS_BLOCKED_V6));
static METADATA_V6_NETS: LazyLock<Vec<IpNet>> = LazyLock::new(|| parse_networks(METADATA_V6));

fn parse_networks(values: &[&str]) -> Vec<IpNet> {
    values
        .iter()
        .map(|value| value.parse().expect("hard-coded IP network is valid"))
        .collect()
}

fn contains(networks: &[IpNet], ip: IpAddr) -> bool {
    networks.iter().any(|network| network.contains(&ip))
}

fn classify_v4(ip: Ipv4Addr, local: &LocalNetworks) -> DestinationClass {
    let ip = IpAddr::V4(ip);
    if contains(&METADATA_V4_NETS, ip) || contains(&ALWAYS_BLOCKED_V4_NETS, ip) {
        DestinationClass::AlwaysBlocked
    } else if local.contains(ip) || contains(&PRIVATE_V4_NETS, ip) {
        DestinationClass::PrivateSource
    } else {
        DestinationClass::Public
    }
}

fn extract_6to4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = ip.octets();
    (octets[..2] == [0x20, 0x02]).then(|| Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]))
}

fn extract_teredo_client(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = ip.octets();
    (octets[..4] == [0x20, 0x01, 0x00, 0x00])
        .then(|| Ipv4Addr::new(!octets[12], !octets[13], !octets[14], !octets[15]))
}

fn extract_ipv4_compatible(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = ip.octets();
    if octets[..12].iter().all(|byte| *byte == 0) {
        let embedded = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        if embedded != Ipv4Addr::UNSPECIFIED && embedded != Ipv4Addr::new(0, 0, 0, 1) {
            return Some(embedded);
        }
    }
    None
}

fn extract_ipv4_translatable(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = ip.octets();
    (octets[..8].iter().all(|byte| *byte == 0) && octets[8..12] == [0xff, 0xff, 0x00, 0x00])
        .then(|| Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]))
}

pub(crate) fn extract_rfc6052(ip: Ipv6Addr, prefix: Nat64Prefix) -> Option<Ipv4Addr> {
    const VALID_LENGTHS: &[u8] = &[32, 40, 48, 56, 64, 96];
    if !VALID_LENGTHS.contains(&prefix.length) {
        return None;
    }

    let length = u32::from(prefix.length);
    let mask = if length == 0 {
        0
    } else {
        u128::MAX << (128 - length)
    };
    if u128::from(ip) & mask != u128::from(prefix.network) & mask {
        return None;
    }

    let bytes = ip.octets();
    let embedded = match prefix.length {
        32 => [bytes[4], bytes[5], bytes[6], bytes[7]],
        40 => [bytes[5], bytes[6], bytes[7], bytes[9]],
        48 => [bytes[6], bytes[7], bytes[9], bytes[10]],
        56 => [bytes[7], bytes[9], bytes[10], bytes[11]],
        64 => [bytes[9], bytes[10], bytes[11], bytes[12]],
        96 => [bytes[12], bytes[13], bytes[14], bytes[15]],
        _ => return None,
    };
    if prefix.length != 96 && bytes[8] != 0 {
        return None;
    }
    Some(embedded.into())
}

fn embedded_nat64(ip: Ipv6Addr, prefixes: &[Nat64Prefix]) -> Option<Ipv4Addr> {
    const WELL_KNOWN: Nat64Prefix = Nat64Prefix {
        network: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0),
        length: 96,
    };
    const LOCAL_USE: Nat64Prefix = Nat64Prefix {
        network: Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0),
        length: 48,
    };

    extract_rfc6052(ip, WELL_KNOWN)
        // RFC 8215 reserves a /48. Existing Stremio clients commonly encode the
        // IPv4 value in the low 32 bits, so inspect that form as well as RFC 6052.
        .or_else(|| {
            let value = u128::from(ip);
            let prefix = u128::from(LOCAL_USE.network);
            let mask = u128::MAX << 80;
            if value & mask != prefix & mask {
                return None;
            }
            let rfc6052 = extract_rfc6052(ip, LOCAL_USE)?;
            if rfc6052 == Ipv4Addr::UNSPECIFIED {
                Some(Ipv4Addr::from(value as u32))
            } else {
                Some(rfc6052)
            }
        })
        .or_else(|| {
            prefixes
                .iter()
                .find_map(|prefix| extract_rfc6052(ip, *prefix))
        })
}

pub(crate) fn normalized_embedded_ipv4(ip: Ipv6Addr, nat64: &[Nat64Prefix]) -> Option<Ipv4Addr> {
    ip.to_ipv4_mapped().or_else(|| embedded_nat64(ip, nat64))
}

fn classify_v6(ip: Ipv6Addr, local: &LocalNetworks, nat64: &[Nat64Prefix]) -> DestinationClass {
    if let Some(embedded) = ip.to_ipv4_mapped() {
        return classify_v4(embedded, local);
    }
    if extract_ipv4_compatible(ip).is_some()
        || extract_ipv4_translatable(ip).is_some()
        || extract_6to4(ip).is_some()
        || extract_teredo_client(ip).is_some()
    {
        return DestinationClass::AlwaysBlocked;
    }
    if let Some(embedded) = embedded_nat64(ip, nat64) {
        return classify_v4(embedded, local);
    }

    let ip = IpAddr::V6(ip);
    if contains(&METADATA_V6_NETS, ip) || contains(&ALWAYS_BLOCKED_V6_NETS, ip) {
        DestinationClass::AlwaysBlocked
    } else if local.contains(ip) || contains(&PRIVATE_V6_NETS, ip) {
        DestinationClass::PrivateSource
    } else {
        DestinationClass::Public
    }
}

pub(crate) fn classify_ip(
    ip: IpAddr,
    local: &LocalNetworks,
    nat64: &[Nat64Prefix],
) -> DestinationClass {
    match ip {
        IpAddr::V4(ip) => classify_v4(ip, local),
        IpAddr::V6(ip) => classify_v6(ip, local, nat64),
    }
}

#[cfg(test)]
mod tests {
    use super::{DestinationClass, LocalNetworks, Nat64Prefix, classify_ip};

    #[test]
    fn ipv4_special_purpose_ranges_are_not_public() {
        let local = LocalNetworks::default();
        let private = [
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.0.1",
        ];
        let always_blocked = [
            "0.0.0.0",
            "192.0.0.1",
            "192.0.2.1",
            "192.31.196.1",
            "192.52.193.1",
            "192.88.99.1",
            "192.175.48.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ];

        for value in private {
            assert_eq!(
                classify_ip(value.parse().unwrap(), &local, &[]),
                DestinationClass::PrivateSource,
                "{value}"
            );
        }
        for value in always_blocked {
            assert_eq!(
                classify_ip(value.parse().unwrap(), &local, &[]),
                DestinationClass::AlwaysBlocked,
                "{value}"
            );
        }
    }

    #[test]
    fn ipv4_metadata_precedes_private_source_ranges() {
        let local = LocalNetworks::default();
        for value in [
            "168.63.129.16",
            "169.254.169.254",
            "169.254.170.2",
            "169.254.170.23",
            "100.100.100.200",
            "192.0.0.192",
        ] {
            assert_eq!(
                classify_ip(value.parse().unwrap(), &local, &[]),
                DestinationClass::AlwaysBlocked,
                "{value}"
            );
        }
    }

    #[test]
    fn ipv4_public_boundaries_remain_public() {
        let local = LocalNetworks::default();
        for value in [
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "223.255.255.255",
        ] {
            assert_eq!(
                classify_ip(value.parse().unwrap(), &local, &[]),
                DestinationClass::Public,
                "{value}"
            );
        }
    }

    #[test]
    fn ipv6_special_purpose_ranges_are_not_public() {
        let local = LocalNetworks::default();
        let private = ["::1", "fc00::1", "fdff:ffff::1", "fe80::1", "febf:ffff::1"];
        let always_blocked = [
            "::",
            "100::1",
            "100:0:0:1::1",
            "2001:db8::1",
            "2620:4f:8000::1",
            "3fff::1",
            "5f00::1",
            "ff00::1",
        ];

        for value in private {
            assert_eq!(
                classify_ip(value.parse().unwrap(), &local, &[]),
                DestinationClass::PrivateSource,
                "{value}"
            );
        }
        for value in always_blocked {
            assert_eq!(
                classify_ip(value.parse().unwrap(), &local, &[]),
                DestinationClass::AlwaysBlocked,
                "{value}"
            );
        }
    }

    #[test]
    fn ipv6_encodings_cannot_hide_private_ipv4() {
        let local = LocalNetworks::default();
        let cases = [
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "2002:7f00:0001::",
            "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
            "64:ff9b::7f00:1",
            "64:ff9b:1::7f00:1",
            "64:ff9b:1:7f00:0:100::",
        ];
        for value in cases {
            assert_ne!(
                classify_ip(value.parse().unwrap(), &local, &[]),
                DestinationClass::Public,
                "{value}"
            );
        }
    }

    #[test]
    fn obsolete_ipv6_wrappers_are_always_blocked_even_for_public_ipv4() {
        let local = LocalNetworks::default();
        for value in [
            "::93.184.216.34",
            "::ffff:0:93.184.216.34",
            "2002:5db8:d822::",
            "2001:0000:4136:e378:8000:63bf:a247:27dd",
        ] {
            assert_eq!(
                classify_ip(value.parse().unwrap(), &local, &[]),
                DestinationClass::AlwaysBlocked,
                "{value}"
            );
        }
    }

    #[test]
    fn discovered_nat64_prefix_cannot_override_an_obsolete_wrapper() {
        let local = LocalNetworks::default();
        let translated_prefix = [Nat64Prefix {
            network: "::ffff:0:0:0".parse().unwrap(),
            length: 96,
        }];
        assert_eq!(
            classify_ip(
                "::ffff:0:93.184.216.34".parse().unwrap(),
                &local,
                &translated_prefix,
            ),
            DestinationClass::AlwaysBlocked
        );

        let compatible_prefix = [Nat64Prefix {
            network: "::".parse().unwrap(),
            length: 96,
        }];
        assert_eq!(
            classify_ip(
                "::93.184.216.34".parse().unwrap(),
                &local,
                &compatible_prefix,
            ),
            DestinationClass::AlwaysBlocked
        );
    }

    #[test]
    fn mapped_and_nat64_public_ipv4_remain_public() {
        let local = LocalNetworks::default();
        let discovered = [Nat64Prefix {
            network: "2001:db8:64::".parse().unwrap(),
            length: 96,
        }];
        for (value, prefixes) in [
            ("::ffff:93.184.216.34", &[][..]),
            ("64:ff9b::5db8:d822", &[][..]),
            ("64:ff9b:1::5db8:d822", &[][..]),
            ("64:ff9b:1:5db8:d8:2200::", &[][..]),
            ("2001:db8:64::5db8:d822", &discovered[..]),
        ] {
            assert_eq!(
                classify_ip(value.parse().unwrap(), &local, prefixes),
                DestinationClass::Public,
                "{value}"
            );
        }
    }

    #[test]
    fn ipv6_metadata_precedes_private_source_ranges() {
        let local = LocalNetworks::default();
        for value in ["fd00:ec2::23", "fd00:ec2::254", "fd20:ce::254"] {
            assert_eq!(
                classify_ip(value.parse().unwrap(), &local, &[]),
                DestinationClass::AlwaysBlocked,
                "{value}"
            );
        }
    }

    #[test]
    fn directly_connected_public_prefixes_are_private_sources() {
        let local = LocalNetworks {
            interfaces: vec![
                "8.8.8.8/29".parse().unwrap(),
                "2001:4860:4860::8888/64".parse().unwrap(),
            ],
        };

        for value in ["8.8.8.10", "2001:4860:4860::1"] {
            assert_eq!(
                classify_ip(value.parse().unwrap(), &local, &[]),
                DestinationClass::PrivateSource,
                "{value}"
            );
        }
        for value in ["8.8.8.16", "2001:4860:4861::1"] {
            assert_eq!(
                classify_ip(value.parse().unwrap(), &local, &[]),
                DestinationClass::Public,
                "{value}"
            );
        }
    }

    #[test]
    fn an_always_blocked_range_cannot_be_reclassified_as_local() {
        let local = LocalNetworks {
            interfaces: vec!["203.0.113.8/29".parse().unwrap()],
        };
        assert_eq!(
            classify_ip("203.0.113.10".parse().unwrap(), &local, &[]),
            DestinationClass::AlwaysBlocked
        );
    }
}

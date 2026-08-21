use super::ip::{DestinationClass, LocalNetworkEntry, LocalNetworks, Nat64Prefix, extract_rfc6052};
use async_trait::async_trait;
use std::{
    io,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::{Duration, Instant},
};
use url::{Host, Url};

const VALIDATION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_ANSWERS: usize = 32;
const NAT64_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OutboundPolicy {
    pub(crate) allow_private_network_sources: bool,
}

#[async_trait]
pub(crate) trait DnsResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

#[async_trait]
pub(crate) trait LocalNetworkProvider: Send + Sync {
    async fn current(&self) -> io::Result<LocalNetworks>;
}

pub(crate) trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub(crate) struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let mut addresses: Vec<_> = tokio::net::lookup_host((host, port)).await?.collect();
        if addresses.is_empty() || addresses.len() > MAX_DNS_ANSWERS {
            return Err(io::Error::other("DNS answer count is outside policy"));
        }
        addresses.sort_unstable();
        addresses.dedup();
        Ok(addresses)
    }
}

pub(crate) struct SystemLocalNetworkProvider;

#[async_trait]
impl LocalNetworkProvider for SystemLocalNetworkProvider {
    async fn current(&self) -> io::Result<LocalNetworks> {
        tokio::task::spawn_blocking(|| {
            let interfaces = if_addrs::get_if_addrs()?;
            let mut networks: Vec<_> = interfaces
                .iter()
                .filter_map(network_for_interface)
                .collect();
            networks.sort_unstable();
            networks.dedup();
            Ok(LocalNetworks {
                interfaces: networks,
            })
        })
        .await
        .map_err(|error| io::Error::other(format!("interface worker failed: {error}")))?
    }
}

fn network_for_interface(interface: &if_addrs::Interface) -> Option<LocalNetworkEntry> {
    if matches!(
        interface.oper_status,
        if_addrs::IfOperStatus::Down
            | if_addrs::IfOperStatus::NotPresent
            | if_addrs::IfOperStatus::LowerLayerDown
    ) {
        return None;
    }

    let (ip, prefix) = match &interface.addr {
        if_addrs::IfAddr::V4(address) => (IpAddr::V4(address.ip), address.prefixlen),
        if_addrs::IfAddr::V6(address) => (IpAddr::V6(address.ip), address.prefixlen),
    };
    let network = ipnet::IpNet::new(ip, prefix).ok()?;
    Some(LocalNetworkEntry {
        network,
        name: interface.name.clone(),
        index: interface.index,
        adapter_id: adapter_id(interface),
    })
}

#[cfg(windows)]
fn adapter_id(interface: &if_addrs::Interface) -> Option<String> {
    Some(interface.adapter_name.clone())
}

#[cfg(not(windows))]
fn adapter_id(_interface: &if_addrs::Interface) -> Option<String> {
    None
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedDestination {
    pub(crate) url: Url,
    pub(crate) domain: Option<String>,
    pub(crate) addrs: Vec<SocketAddr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ListenerBinding {
    pub(crate) socket: SocketAddr,
}

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub(crate) enum DestinationError {
    #[error("unsupported URL scheme")]
    UnsupportedScheme,
    #[error("target host is missing")]
    MissingHost,
    #[error("target name did not resolve")]
    ResolutionFailed,
    #[error("target address is blocked")]
    Blocked,
    #[error("local network state is unavailable")]
    LocalNetworkUnavailable,
}

pub(crate) struct DestinationValidator {
    resolver: Arc<dyn DnsResolver>,
    local_networks: Arc<dyn LocalNetworkProvider>,
    clock: Arc<dyn Clock>,
    listeners: Vec<ListenerBinding>,
    nat64_cache: tokio::sync::Mutex<Option<CachedNat64Prefixes>>,
    nat64_refresh: tokio::sync::Mutex<()>,
}

struct CachedNat64Prefixes {
    expires_at: Instant,
    prefixes: Vec<Nat64Prefix>,
    failed: bool,
    local_networks: LocalNetworks,
}

impl DestinationValidator {
    pub(crate) fn new(
        resolver: Arc<dyn DnsResolver>,
        local_networks: Arc<dyn LocalNetworkProvider>,
        clock: Arc<dyn Clock>,
        listeners: Vec<ListenerBinding>,
    ) -> Self {
        Self {
            resolver,
            local_networks,
            clock,
            listeners: listeners
                .into_iter()
                .map(|listener| ListenerBinding {
                    socket: normalize_socket(listener.socket),
                })
                .collect(),
            nat64_cache: tokio::sync::Mutex::new(None),
            nat64_refresh: tokio::sync::Mutex::new(()),
        }
    }

    pub(crate) async fn validate(
        &self,
        url: &Url,
        policy: OutboundPolicy,
    ) -> Result<ResolvedDestination, DestinationError> {
        tokio::time::timeout(VALIDATION_TIMEOUT, self.validate_inner(url, policy))
            .await
            .map_err(|_| DestinationError::ResolutionFailed)?
    }

    async fn validate_inner(
        &self,
        url: &Url,
        policy: OutboundPolicy,
    ) -> Result<ResolvedDestination, DestinationError> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(DestinationError::UnsupportedScheme);
        }
        let host = url.host().ok_or(DestinationError::MissingHost)?;
        let port = url
            .port_or_known_default()
            .ok_or(DestinationError::MissingHost)?;

        let mut canonical_url = url.clone();
        canonical_url.set_fragment(None);

        let (domain, addresses) = match host {
            Host::Ipv4(ip) => (None, vec![SocketAddr::new(IpAddr::V4(ip), port)]),
            Host::Ipv6(ip) => (None, vec![SocketAddr::new(IpAddr::V6(ip), port)]),
            Host::Domain(domain) => {
                let domain = domain.to_owned();
                let work = async {
                    tokio::join!(
                        self.local_networks.current(),
                        self.resolver.resolve(&domain, port)
                    )
                };
                let (local, resolved) = work.await;
                let local = local.map_err(|_| DestinationError::LocalNetworkUnavailable)?;
                let mut resolved = resolved.map_err(|_| DestinationError::ResolutionFailed)?;
                if resolved.is_empty() || resolved.len() > MAX_DNS_ANSWERS {
                    return Err(DestinationError::ResolutionFailed);
                }
                for address in &mut resolved {
                    address.set_port(port);
                    *address = normalize_socket(*address);
                }
                resolved.sort_unstable();
                resolved.dedup();
                let nat64 = self.nat64_prefixes_for(&resolved, &local, policy).await?;
                self.validate_addresses(&resolved, &local, &nat64, policy)?;
                return Ok(ResolvedDestination {
                    url: canonical_url,
                    domain: Some(domain),
                    addrs: resolved,
                });
            }
        };

        let local = self
            .local_networks
            .current()
            .await
            .map_err(|_| DestinationError::LocalNetworkUnavailable)?;
        let nat64 = self.nat64_prefixes_for(&addresses, &local, policy).await?;
        self.validate_addresses(&addresses, &local, &nat64, policy)?;
        Ok(ResolvedDestination {
            url: canonical_url,
            domain,
            addrs: addresses,
        })
    }

    fn validate_addresses(
        &self,
        addresses: &[SocketAddr],
        local: &LocalNetworks,
        nat64: &[Nat64Prefix],
        policy: OutboundPolicy,
    ) -> Result<(), DestinationError> {
        for address in addresses {
            if let SocketAddr::V6(address) = address
                && address.ip().is_unicast_link_local()
                && address.scope_id() == 0
            {
                return Err(DestinationError::Blocked);
            }
            if self.matches_listener(*address, local, nat64) {
                return Err(DestinationError::Blocked);
            }
            match super::ip::classify_ip(address.ip(), local, nat64) {
                DestinationClass::Public => {}
                DestinationClass::PrivateSource if policy.allow_private_network_sources => {}
                DestinationClass::PrivateSource | DestinationClass::AlwaysBlocked => {
                    return Err(DestinationError::Blocked);
                }
            }
        }
        Ok(())
    }

    fn matches_listener(
        &self,
        target: SocketAddr,
        local: &LocalNetworks,
        nat64: &[Nat64Prefix],
    ) -> bool {
        let target = normalize_socket(target);
        let target_candidates = listener_socket_candidates(target, nat64);
        self.listeners.iter().any(|listener| {
            if listener.socket.port() != target.port() {
                return false;
            }

            if listener.socket.ip().is_unspecified() {
                return target_candidates.iter().any(|candidate| {
                    let candidate_ip = candidate.ip();
                    match listener.socket {
                        SocketAddr::V4(_) => {
                            candidate.is_ipv4()
                                && (candidate_ip.is_loopback()
                                    || local.contains_address(candidate_ip))
                        }
                        SocketAddr::V6(_) => {
                            candidate_ip.is_loopback() || local.contains_address(candidate_ip)
                        }
                    }
                });
            }

            let listener_candidates = listener_socket_candidates(listener.socket, nat64);
            listener_candidates.iter().any(|listener_candidate| {
                target_candidates.iter().any(|target_candidate| {
                    listener_endpoint_matches(*listener_candidate, *target_candidate)
                })
            })
        })
    }

    async fn nat64_prefixes_for(
        &self,
        addresses: &[SocketAddr],
        local: &LocalNetworks,
        policy: OutboundPolicy,
    ) -> Result<Vec<Nat64Prefix>, DestinationError> {
        let needs_discovery = addresses.iter().any(|address| match address.ip() {
            IpAddr::V4(_) => false,
            IpAddr::V6(ip) => {
                if super::ip::normalized_embedded_ipv4(ip, &[]).is_some() {
                    return false;
                }
                if super::ip::is_rfc8215_address(ip) {
                    return true;
                }
                match super::ip::classify_ip(IpAddr::V6(ip), local, &[]) {
                    DestinationClass::Public => true,
                    DestinationClass::PrivateSource => {
                        policy.allow_private_network_sources
                            && !ip.is_loopback()
                            && !ip.is_unicast_link_local()
                    }
                    DestinationClass::AlwaysBlocked => false,
                }
            }
        });
        if !needs_discovery {
            return Ok(Vec::new());
        }

        if let Some(prefixes) = self.cached_nat64_prefixes(local).await {
            return prefixes;
        }

        let _refresh = self.nat64_refresh.lock().await;
        if let Some(prefixes) = self.cached_nat64_prefixes(local).await {
            return prefixes;
        }

        let discovered = match self.resolver.resolve("ipv4only.arpa.", 0).await {
            Ok(answers) if answers.len() <= MAX_DNS_ANSWERS => discover_nat64_prefixes(&answers),
            Ok(_) | Err(_) => Err(DestinationError::ResolutionFailed),
        };

        let expires_at = self
            .clock
            .now()
            .checked_add(NAT64_CACHE_TTL)
            .unwrap_or_else(|| self.clock.now());
        *self.nat64_cache.lock().await = Some(CachedNat64Prefixes {
            expires_at,
            prefixes: discovered.as_ref().cloned().unwrap_or_default(),
            failed: discovered.is_err(),
            local_networks: local.clone(),
        });
        discovered
    }

    async fn cached_nat64_prefixes(
        &self,
        local: &LocalNetworks,
    ) -> Option<Result<Vec<Nat64Prefix>, DestinationError>> {
        let cache = self.nat64_cache.lock().await;
        cache
            .as_ref()
            .filter(|cached| {
                self.clock.now() < cached.expires_at && cached.local_networks == *local
            })
            .map(|cached| {
                if cached.failed {
                    Err(DestinationError::ResolutionFailed)
                } else {
                    Ok(cached.prefixes.clone())
                }
            })
    }
}

fn normalize_socket(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(_) => address,
        SocketAddr::V6(address) => SocketAddr::V6(SocketAddrV6::new(
            *address.ip(),
            address.port(),
            0,
            if address.ip().is_unicast_link_local() {
                address.scope_id()
            } else {
                0
            },
        )),
    }
}

fn listener_socket_candidates(socket: SocketAddr, nat64: &[Nat64Prefix]) -> Vec<SocketAddr> {
    let socket = normalize_socket(socket);
    let mut candidates = vec![socket];
    if let SocketAddr::V6(address) = socket {
        candidates.extend(
            super::ip::embedded_ipv4_candidates(*address.ip(), nat64)
                .into_iter()
                .map(|ip| SocketAddr::new(IpAddr::V4(ip), address.port())),
        );
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

fn listener_endpoint_matches(listener: SocketAddr, target: SocketAddr) -> bool {
    if listener.port() != target.port() {
        return false;
    }
    match (listener, target) {
        (SocketAddr::V4(listener), SocketAddr::V4(target)) => listener.ip() == target.ip(),
        (SocketAddr::V6(listener), SocketAddr::V6(target)) => {
            listener.ip() == target.ip()
                && (!listener.ip().is_unicast_link_local()
                    || listener.scope_id() == 0
                    || listener.scope_id() == target.scope_id())
        }
        _ => false,
    }
}

fn discover_nat64_prefixes(answers: &[SocketAddr]) -> Result<Vec<Nat64Prefix>, DestinationError> {
    const IPV4ONLY: [std::net::Ipv4Addr; 2] = [
        std::net::Ipv4Addr::new(192, 0, 0, 170),
        std::net::Ipv4Addr::new(192, 0, 0, 171),
    ];
    const LENGTHS: [u8; 6] = [32, 40, 48, 56, 64, 96];

    if answers.is_empty() {
        return Err(DestinationError::ResolutionFailed);
    }
    let mut seen_ipv4 = [false; 2];
    let mut ipv6_answers = Vec::new();
    for answer in answers {
        match answer.ip() {
            IpAddr::V4(ip) if ip == IPV4ONLY[0] => seen_ipv4[0] = true,
            IpAddr::V4(ip) if ip == IPV4ONLY[1] => seen_ipv4[1] = true,
            IpAddr::V4(_) => return Err(DestinationError::ResolutionFailed),
            IpAddr::V6(ip) => ipv6_answers.push(ip),
        }
    }
    if seen_ipv4 != [false, false] && seen_ipv4 != [true, true] {
        return Err(DestinationError::ResolutionFailed);
    }
    if ipv6_answers.is_empty() {
        return (seen_ipv4 == [true, true])
            .then(Vec::new)
            .ok_or(DestinationError::ResolutionFailed);
    }

    let mut prefixes = Vec::new();
    for length in LENGTHS {
        let mask = u128::MAX << (128 - u32::from(length));
        for address in &ipv6_answers {
            let prefix = Nat64Prefix {
                network: std::net::Ipv6Addr::from(u128::from(*address) & mask),
                length,
            };
            if !super::ip::nat64_prefix_is_usable(prefix) {
                continue;
            }
            let mut seen = [false; 2];
            for candidate in &ipv6_answers {
                if let Some(extracted) = extract_rfc6052(*candidate, prefix) {
                    if extracted == IPV4ONLY[0] {
                        seen[0] = true;
                    } else if extracted == IPV4ONLY[1] {
                        seen[1] = true;
                    }
                }
            }
            if seen == [true, true] && !prefixes.contains(&prefix) {
                prefixes.push(prefix);
            }
        }
    }
    prefixes.sort_unstable_by_key(|prefix| (prefix.length, u128::from(prefix.network)));
    let all_ipv6_answers_accounted_for = ipv6_answers.iter().all(|answer| {
        prefixes.iter().any(|prefix| {
            extract_rfc6052(*answer, *prefix).is_some_and(|embedded| IPV4ONLY.contains(&embedded))
        })
    });
    if prefixes.is_empty() || !all_ipv6_answers_accounted_for {
        return Err(DestinationError::ResolutionFailed);
    }

    prefixes.retain(|prefix| {
        !(prefix.network == std::net::Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0)
            && prefix.length == 96)
    });
    Ok(prefixes)
}

#[cfg(test)]
mod tests {
    use super::super::ip::{LocalNetworkEntry, LocalNetworks, Nat64Prefix};
    use super::{
        Clock, DestinationError, DestinationValidator, DnsResolver, ListenerBinding,
        LocalNetworkProvider, OutboundPolicy, discover_nat64_prefixes, network_for_interface,
    };
    use async_trait::async_trait;
    use std::{
        io,
        net::{Ipv6Addr, SocketAddr, SocketAddrV6},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };
    use url::Url;

    struct FakeResolver {
        answer: Vec<SocketAddr>,
        fail: bool,
        calls: AtomicUsize,
    }

    struct BlockingResolver {
        answer: Vec<SocketAddr>,
        calls: AtomicUsize,
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    struct SlowThenStalledResolver;

    struct RecordingResolver {
        answer: Vec<SocketAddr>,
        hosts: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DnsResolver for RecordingResolver {
        async fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            self.hosts.lock().unwrap().push(host.to_owned());
            Ok(self.answer.clone())
        }
    }

    #[async_trait]
    impl DnsResolver for SlowThenStalledResolver {
        async fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            if host == "slow.example" {
                tokio::time::sleep(Duration::from_secs(4)).await;
                Ok(vec!["[2001:4860:4860::8888]:80".parse().unwrap()])
            } else {
                std::future::pending().await
            }
        }
    }

    #[async_trait]
    impl DnsResolver for BlockingResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            self.release.notified().await;
            Ok(self.answer.clone())
        }
    }

    impl FakeResolver {
        fn new(answer: Vec<SocketAddr>) -> Arc<Self> {
            Arc::new(Self {
                answer,
                fail: false,
                calls: AtomicUsize::new(0),
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                answer: Vec::new(),
                fail: true,
                calls: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl DnsResolver for FakeResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(io::Error::other("synthetic resolver failure"))
            } else {
                Ok(self.answer.clone())
            }
        }
    }

    struct StaticLocalNetworks(LocalNetworks);

    #[async_trait]
    impl LocalNetworkProvider for StaticLocalNetworks {
        async fn current(&self) -> io::Result<LocalNetworks> {
            Ok(self.0.clone())
        }
    }

    struct MutableResolver {
        answer: Mutex<Vec<SocketAddr>>,
        calls: AtomicUsize,
    }

    impl MutableResolver {
        fn replace(&self, answer: Vec<SocketAddr>) {
            *self.answer.lock().unwrap() = answer;
        }
    }

    #[async_trait]
    impl DnsResolver for MutableResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.answer.lock().unwrap().clone())
        }
    }

    struct MutableLocalNetworks(Mutex<LocalNetworks>);

    impl MutableLocalNetworks {
        fn replace(&self, networks: LocalNetworks) {
            *self.0.lock().unwrap() = networks;
        }
    }

    #[async_trait]
    impl LocalNetworkProvider for MutableLocalNetworks {
        async fn current(&self) -> io::Result<LocalNetworks> {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    struct FixedClock(Instant);

    impl Clock for FixedClock {
        fn now(&self) -> Instant {
            self.0
        }
    }

    struct ManualClock(Mutex<Instant>);

    impl ManualClock {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Instant::now())))
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.0.lock().unwrap();
            *now = now.checked_add(duration).unwrap();
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }

    fn validator(resolver: Arc<FakeResolver>) -> DestinationValidator {
        DestinationValidator::new(
            resolver,
            Arc::new(StaticLocalNetworks(LocalNetworks::default())),
            Arc::new(FixedClock(Instant::now())),
            Vec::new(),
        )
    }

    fn validator_with_listeners(
        resolver: Arc<FakeResolver>,
        local: LocalNetworks,
        listeners: Vec<ListenerBinding>,
    ) -> DestinationValidator {
        DestinationValidator::new(
            resolver,
            Arc::new(StaticLocalNetworks(local)),
            Arc::new(FixedClock(Instant::now())),
            listeners,
        )
    }

    #[tokio::test]
    async fn unsupported_scheme_is_rejected_before_resolution() {
        let resolver = FakeResolver::new(vec!["93.184.216.34:80".parse().unwrap()]);
        let validator = validator(resolver.clone());
        let result = validator
            .validate(
                &Url::parse("file:///etc/passwd").unwrap(),
                OutboundPolicy::default(),
            )
            .await;
        assert_eq!(result.unwrap_err(), DestinationError::UnsupportedScheme);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn alternate_ipv4_loopback_spellings_are_blocked_before_connect() {
        let resolver = FakeResolver::new(Vec::new());
        let validator = validator(resolver.clone());
        for target in [
            "http://2130706433/",
            "http://0x7f000001/",
            "http://017700000001/",
            "http://127.1/",
        ] {
            let result = validator
                .validate(&Url::parse(target).unwrap(), OutboundPolicy::default())
                .await;
            assert_eq!(result.unwrap_err(), DestinationError::Blocked, "{target}");
        }
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mixed_public_and_loopback_dns_answer_is_rejected() {
        let validator = validator(FakeResolver::new(vec![
            "93.184.216.34:80".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        ]));
        let result = validator
            .validate(
                &Url::parse("http://mixed.example/").unwrap(),
                OutboundPolicy::default(),
            )
            .await;
        assert_eq!(result.unwrap_err(), DestinationError::Blocked);
    }

    #[tokio::test]
    async fn private_answers_require_opt_in_but_metadata_never_does() {
        let private_url = Url::parse("http://private.example/").unwrap();
        let private = validator(FakeResolver::new(vec!["10.1.2.3:80".parse().unwrap()]));
        assert_eq!(
            private
                .validate(&private_url, OutboundPolicy::default())
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
        assert!(
            private
                .validate(
                    &private_url,
                    OutboundPolicy {
                        allow_private_network_sources: true,
                    },
                )
                .await
                .is_ok()
        );

        let metadata = validator(FakeResolver::new(vec![
            "169.254.169.254:80".parse().unwrap(),
        ]));
        assert_eq!(
            metadata
                .validate(
                    &Url::parse("http://metadata.example/").unwrap(),
                    OutboundPolicy {
                        allow_private_network_sources: true,
                    },
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
    }

    #[tokio::test]
    async fn ibm_metadata_literal_and_dns_answer_remain_blocked_with_private_opt_in() {
        let policy = OutboundPolicy {
            allow_private_network_sources: true,
        };
        let literal_resolver = FakeResolver::new(Vec::new());
        let literal = validator(literal_resolver.clone());
        assert_eq!(
            literal
                .validate(&Url::parse("http://169.254.169.253/").unwrap(), policy)
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
        assert_eq!(literal_resolver.calls.load(Ordering::SeqCst), 0);

        let dns = validator(FakeResolver::new(vec![
            "169.254.169.253:80".parse().unwrap(),
        ]));
        assert_eq!(
            dns.validate(&Url::parse("http://metadata.example/").unwrap(), policy)
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
    }

    #[tokio::test]
    async fn empty_failed_and_oversized_dns_answers_fail_closed() {
        for resolver in [
            FakeResolver::new(Vec::new()),
            FakeResolver::failing(),
            FakeResolver::new(
                (1..=33)
                    .map(|last| SocketAddr::from(([93, 184, 216, last], 80)))
                    .collect(),
            ),
        ] {
            let result = validator(resolver)
                .validate(
                    &Url::parse("http://failure.example/").unwrap(),
                    OutboundPolicy::default(),
                )
                .await;
            assert_eq!(result.unwrap_err(), DestinationError::ResolutionFailed);
        }
    }

    #[tokio::test]
    async fn canonical_result_strips_fragments_and_deduplicates_pinned_addresses() {
        let validator = validator(FakeResolver::new(vec![
            "93.184.216.34:1234".parse().unwrap(),
            "93.184.216.34:4321".parse().unwrap(),
        ]));
        let result = validator
            .validate(
                &Url::parse("HTTP://ExAmPle.COM.:8080/path#never-forwarded").unwrap(),
                OutboundPolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(result.url.as_str(), "http://example.com.:8080/path");
        assert_eq!(result.domain.as_deref(), Some("example.com."));
        assert_eq!(result.addrs, vec!["93.184.216.34:8080".parse().unwrap()]);
    }

    #[tokio::test]
    async fn scoped_link_local_answers_require_opt_in_and_preserve_normalized_scope() {
        let ip: Ipv6Addr = "fe80::1234".parse().unwrap();
        let resolver = FakeResolver::new(vec![
            SocketAddr::V6(SocketAddrV6::new(ip, 1234, 7, 2)),
            SocketAddr::V6(SocketAddrV6::new(ip, 4321, 11, 2)),
        ]);
        let validator = validator(resolver);
        let target = Url::parse("http://link-local.example:8080/").unwrap();

        assert_eq!(
            validator
                .validate(&target, OutboundPolicy::default())
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
        let resolved = validator
            .validate(
                &target,
                OutboundPolicy {
                    allow_private_network_sources: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            resolved.addrs,
            vec![SocketAddr::V6(SocketAddrV6::new(ip, 8080, 0, 2))]
        );
    }

    #[tokio::test]
    async fn link_local_answers_with_zero_scope_are_always_blocked() {
        let validator = validator(FakeResolver::new(vec!["[fe80::1234]:80".parse().unwrap()]));

        assert_eq!(
            validator
                .validate(
                    &Url::parse("http://link-local.example/").unwrap(),
                    OutboundPolicy {
                        allow_private_network_sources: true,
                    },
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
    }

    #[tokio::test]
    async fn link_local_url_literals_are_rejected_without_dns() {
        let resolver = FakeResolver::new(Vec::new());
        let validator = validator(resolver.clone());

        assert_eq!(
            validator
                .validate(
                    &Url::parse("http://[fe80::1234]/").unwrap(),
                    OutboundPolicy {
                        allow_private_network_sources: true,
                    },
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        for target in ["http://[fe80::1234%2]/", "http://[fe80::1234%252]/"] {
            assert!(Url::parse(target).is_err(), "{target}");
        }
    }

    #[tokio::test]
    async fn link_local_answers_on_different_nonzero_scopes_remain_distinct() {
        let ip: Ipv6Addr = "fe80::1234".parse().unwrap();
        let validator = validator(FakeResolver::new(vec![
            SocketAddr::V6(SocketAddrV6::new(ip, 80, 0, 3)),
            SocketAddr::V6(SocketAddrV6::new(ip, 80, 0, 2)),
        ]));

        let resolved = validator
            .validate(
                &Url::parse("http://link-local.example/").unwrap(),
                OutboundPolicy {
                    allow_private_network_sources: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            resolved.addrs,
            vec![
                SocketAddr::V6(SocketAddrV6::new(ip, 80, 0, 2)),
                SocketAddr::V6(SocketAddrV6::new(ip, 80, 0, 3)),
            ]
        );
    }

    #[tokio::test]
    async fn exact_and_wildcard_self_listeners_are_always_blocked() {
        let local = LocalNetworks {
            interfaces: vec!["8.8.8.8/29".parse().unwrap()],
        };
        let policy = OutboundPolicy {
            allow_private_network_sources: true,
        };

        let exact = validator_with_listeners(
            FakeResolver::new(vec!["93.184.216.34:11470".parse().unwrap()]),
            LocalNetworks::default(),
            vec![ListenerBinding {
                socket: "93.184.216.34:11470".parse().unwrap(),
            }],
        );
        assert_eq!(
            exact
                .validate(&Url::parse("http://self.example:11470/").unwrap(), policy)
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );

        let wildcard = validator_with_listeners(
            FakeResolver::new(vec!["8.8.8.8:11470".parse().unwrap()]),
            local,
            vec![ListenerBinding {
                socket: "0.0.0.0:11470".parse().unwrap(),
            }],
        );
        assert_eq!(
            wildcard
                .validate(
                    &Url::parse("http://local-interface.example:11470/").unwrap(),
                    policy,
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
    }

    #[tokio::test]
    async fn wildcard_listener_blocks_only_this_hosts_interface_address() {
        let local = LocalNetworks {
            interfaces: vec!["8.8.8.9/29".parse().unwrap()],
        };
        let listeners = vec![ListenerBinding {
            socket: "0.0.0.0:11470".parse().unwrap(),
        }];
        let policy = OutboundPolicy {
            allow_private_network_sources: true,
        };

        let own_address = validator_with_listeners(
            FakeResolver::new(vec!["8.8.8.9:11470".parse().unwrap()]),
            local.clone(),
            listeners.clone(),
        );
        assert_eq!(
            own_address
                .validate(&Url::parse("http://own.example:11470/").unwrap(), policy)
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );

        let neighbor = validator_with_listeners(
            FakeResolver::new(vec!["8.8.8.10:11470".parse().unwrap()]),
            local,
            listeners,
        );
        assert!(
            neighbor
                .validate(
                    &Url::parse("http://neighbor.example:11470/").unwrap(),
                    policy,
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn ipv6_wildcard_listener_blocks_ipv4_mapped_local_interfaces() {
        let validator = validator_with_listeners(
            FakeResolver::new(vec!["[::ffff:8.8.8.8]:11470".parse().unwrap()]),
            LocalNetworks {
                interfaces: vec!["8.8.8.8/29".parse().unwrap()],
            },
            vec![ListenerBinding {
                socket: "[::]:11470".parse().unwrap(),
            }],
        );
        assert_eq!(
            validator
                .validate(
                    &Url::parse("http://self-via-mapped.example:11470/").unwrap(),
                    OutboundPolicy {
                        allow_private_network_sources: true,
                    },
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
    }

    #[tokio::test]
    async fn a_different_port_on_the_listener_host_remains_eligible() {
        let validator = validator_with_listeners(
            FakeResolver::new(vec!["93.184.216.34:8080".parse().unwrap()]),
            LocalNetworks::default(),
            vec![ListenerBinding {
                socket: "93.184.216.34:11470".parse().unwrap(),
            }],
        );
        assert!(
            validator
                .validate(
                    &Url::parse("http://same-host.example:8080/").unwrap(),
                    OutboundPolicy::default(),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn mapped_and_nat64_forms_cannot_hide_an_exact_self_listener() {
        let validator = validator_with_listeners(
            FakeResolver::new(Vec::new()),
            LocalNetworks::default(),
            vec![ListenerBinding {
                socket: "93.184.216.34:80".parse().unwrap(),
            }],
        );
        for target in [
            "http://[::ffff:93.184.216.34]/",
            "http://[64:ff9b::5db8:d822]/",
        ] {
            assert_eq!(
                validator
                    .validate(&Url::parse(target).unwrap(), OutboundPolicy::default())
                    .await
                    .unwrap_err(),
                DestinationError::Blocked,
                "{target}"
            );
        }
    }

    #[tokio::test]
    async fn exact_link_local_listener_matches_only_its_nonzero_scope() {
        let ip: Ipv6Addr = "fe80::1234".parse().unwrap();
        let local = LocalNetworks {
            interfaces: vec!["fe80::1234/64".parse().unwrap()],
        };
        let listeners = vec![ListenerBinding {
            socket: SocketAddr::V6(SocketAddrV6::new(ip, 11470, 77, 2)),
        }];
        let policy = OutboundPolicy {
            allow_private_network_sources: true,
        };

        let same_scope = validator_with_listeners(
            FakeResolver::new(vec![SocketAddr::V6(SocketAddrV6::new(ip, 11470, 42, 2))]),
            local.clone(),
            listeners.clone(),
        );
        assert_eq!(
            same_scope
                .validate(
                    &Url::parse("http://same-scope.example:11470/").unwrap(),
                    policy
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );

        let different_scope = validator_with_listeners(
            FakeResolver::new(vec![SocketAddr::V6(SocketAddrV6::new(ip, 11470, 11, 3))]),
            local,
            listeners,
        );
        assert!(
            different_scope
                .validate(
                    &Url::parse("http://different-scope.example:11470/").unwrap(),
                    policy,
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn zero_scope_and_wildcard_ipv6_listeners_block_scoped_local_targets() {
        let ip: Ipv6Addr = "fe80::1234".parse().unwrap();
        let local = LocalNetworks {
            interfaces: vec!["fe80::1234/64".parse().unwrap()],
        };
        let policy = OutboundPolicy {
            allow_private_network_sources: true,
        };

        for socket in [
            SocketAddr::V6(SocketAddrV6::new(ip, 11470, 9, 0)),
            "[::]:11470".parse().unwrap(),
        ] {
            for scope in [2, 3] {
                let validator = validator_with_listeners(
                    FakeResolver::new(vec![SocketAddr::V6(SocketAddrV6::new(ip, 11470, 0, scope))]),
                    local.clone(),
                    vec![ListenerBinding { socket }],
                );
                assert_eq!(
                    validator
                        .validate(
                            &Url::parse("http://scoped-local.example:11470/").unwrap(),
                            policy,
                        )
                        .await
                        .unwrap_err(),
                    DestinationError::Blocked,
                    "listener={socket}, scope={scope}"
                );
            }
        }
    }

    #[tokio::test]
    async fn non_link_local_listener_scope_and_ipv6_flowinfo_are_not_endpoint_identity() {
        let ip: Ipv6Addr = "64:ff9b::5db8:d822".parse().unwrap();
        let validator = validator_with_listeners(
            FakeResolver::new(vec![SocketAddr::V6(SocketAddrV6::new(ip, 11470, 3, 8))]),
            LocalNetworks::default(),
            vec![ListenerBinding {
                socket: SocketAddr::V6(SocketAddrV6::new(ip, 11470, 99, 4)),
            }],
        );
        assert_eq!(
            validator
                .validate(
                    &Url::parse("http://same-native-ip.example:11470/").unwrap(),
                    OutboundPolicy::default(),
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
    }

    #[tokio::test]
    async fn ipv6_wildcard_keeps_native_identity_when_nat64_also_decodes_target() {
        let validator = validator_with_listeners(
            FakeResolver::new(vec![
                "[2001:4860:64::c000:aa]:0".parse().unwrap(),
                "[2001:4860:64::c000:ab]:0".parse().unwrap(),
            ]),
            LocalNetworks {
                interfaces: vec!["2001:4860:64::5db8:d822/128".parse().unwrap()],
            },
            vec![ListenerBinding {
                socket: "[::]:80".parse().unwrap(),
            }],
        );
        assert_eq!(
            validator
                .validate(
                    &Url::parse("http://[2001:4860:64::5db8:d822]/").unwrap(),
                    OutboundPolicy {
                        allow_private_network_sources: true,
                    },
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
    }

    #[tokio::test]
    async fn discovered_nat64_prefix_exposes_embedded_metadata_and_is_cached() {
        let resolver = FakeResolver::new(vec![
            "[2001:4860:64::c000:aa]:0".parse().unwrap(),
            "[2001:4860:64::c000:ab]:0".parse().unwrap(),
        ]);
        let validator = validator(resolver.clone());
        let target = Url::parse("http://[2001:4860:64::a9fe:a9fe]/").unwrap();
        let policy = OutboundPolicy {
            allow_private_network_sources: true,
        };

        for _ in 0..2 {
            assert_eq!(
                validator.validate(&target, policy).await.unwrap_err(),
                DestinationError::Blocked
            );
        }
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pref64_discovery_uses_the_absolute_ipv4only_name() {
        let resolver = Arc::new(RecordingResolver {
            answer: vec![
                "192.0.0.170:0".parse().unwrap(),
                "192.0.0.171:0".parse().unwrap(),
            ],
            hosts: Mutex::new(Vec::new()),
        });
        let validator = DestinationValidator::new(
            resolver.clone(),
            Arc::new(StaticLocalNetworks(LocalNetworks::default())),
            Arc::new(FixedClock(Instant::now())),
            Vec::new(),
        );

        assert!(
            validator
                .validate(
                    &Url::parse("http://[2001:4860:4860::8888]/").unwrap(),
                    OutboundPolicy::default(),
                )
                .await
                .is_ok()
        );
        assert_eq!(
            *resolver.hosts.lock().unwrap(),
            vec!["ipv4only.arpa.".to_owned()]
        );
    }

    #[test]
    fn strict_pref64_discovery_accepts_complete_public_ula_and_reserved_pairs() {
        let cases = [
            (
                vec!["192.0.0.170:0", "192.0.0.171:0"],
                Vec::<Nat64Prefix>::new(),
            ),
            (
                vec!["[64:ff9b::c000:aa]:0", "[64:ff9b::c000:ab]:0"],
                Vec::new(),
            ),
            (
                vec!["[2001:4860:64::c000:aa]:0", "[2001:4860:64::c000:ab]:0"],
                vec![Nat64Prefix {
                    network: "2001:4860:64::".parse().unwrap(),
                    length: 96,
                }],
            ),
            (
                vec!["[fd12:3456:789a::c000:aa]:0", "[fd12:3456:789a::c000:ab]:0"],
                vec![Nat64Prefix {
                    network: "fd12:3456:789a::".parse().unwrap(),
                    length: 96,
                }],
            ),
            (
                vec!["[64:ff9b:1:1::c000:aa]:0", "[64:ff9b:1:1::c000:ab]:0"],
                vec![Nat64Prefix {
                    network: "64:ff9b:1:1::".parse().unwrap(),
                    length: 96,
                }],
            ),
        ];

        for (answers, expected) in cases {
            let answers = answers
                .into_iter()
                .map(|value| value.parse().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(discover_nat64_prefixes(&answers).unwrap(), expected);
        }
    }

    #[test]
    fn strict_pref64_discovery_accepts_every_allowed_rfc6052_length_in_reserved_space() {
        fn embed(prefix: Nat64Prefix, ipv4: std::net::Ipv4Addr) -> Ipv6Addr {
            let mut bytes = prefix.network.octets();
            let ipv4 = ipv4.octets();
            match prefix.length {
                32 => bytes[4..8].copy_from_slice(&ipv4),
                40 => {
                    bytes[5..8].copy_from_slice(&ipv4[..3]);
                    bytes[9] = ipv4[3];
                }
                48 => {
                    bytes[6..8].copy_from_slice(&ipv4[..2]);
                    bytes[9..11].copy_from_slice(&ipv4[2..]);
                }
                56 => {
                    bytes[7] = ipv4[0];
                    bytes[9..12].copy_from_slice(&ipv4[1..]);
                }
                64 => bytes[9..13].copy_from_slice(&ipv4),
                96 => bytes[12..16].copy_from_slice(&ipv4),
                _ => panic!("unsupported test prefix length"),
            }
            Ipv6Addr::from(bytes)
        }

        for prefix in [
            Nat64Prefix {
                network: "64:ff9b:1:100::".parse().unwrap(),
                length: 56,
            },
            Nat64Prefix {
                network: "64:ff9b:1:1::".parse().unwrap(),
                length: 64,
            },
            Nat64Prefix {
                network: "64:ff9b:1:1::".parse().unwrap(),
                length: 96,
            },
        ] {
            let answers = [
                embed(prefix, std::net::Ipv4Addr::new(192, 0, 0, 170)),
                embed(prefix, std::net::Ipv4Addr::new(192, 0, 0, 171)),
            ]
            .map(|ip| SocketAddr::new(ip.into(), 0));
            let discovered = discover_nat64_prefixes(&answers).unwrap();
            assert!(discovered.contains(&prefix), "prefix={prefix:?}");
        }
    }

    #[test]
    fn strict_pref64_discovery_rejects_incomplete_poisoned_and_unusable_answers() {
        let invalid = [
            vec![],
            vec!["192.0.0.170:0"],
            vec!["198.51.100.10:0", "192.0.0.170:0", "192.0.0.171:0"],
            vec![
                "[64:ff9b::c000:aa]:0",
                "[64:ff9b::c000:ab]:0",
                "198.51.100.10:0",
            ],
            vec![
                "[2001:4860:64::c000:aa]:0",
                "[2001:4860:64::c000:ab]:0",
                "[2606:4700:64::c000:aa]:0",
            ],
            vec!["[fe80::c000:aa]:0", "[fe80::c000:ab]:0"],
            vec!["[2001:db8::c000:aa]:0", "[2001:db8::c000:ab]:0"],
            vec!["[fd00:42::c000:aa]:0", "[fd00:42::c000:ab]:0"],
            vec![
                "[2001:4860:64:0:100::c000:aa]:0",
                "[2001:4860:64:0:100::c000:ab]:0",
            ],
            vec![
                "[2001:4860:64::c000:aa]:0",
                "[2001:4860:64::c000:ab]:0",
                "[fe80::c000:aa]:0",
                "[fe80::c000:ab]:0",
            ],
        ];

        for values in invalid {
            let answers = values
                .into_iter()
                .map(|value| value.parse().unwrap())
                .collect::<Vec<_>>();
            assert!(
                discover_nat64_prefixes(&answers).is_err(),
                "unexpected valid answers: {answers:?}"
            );
        }
    }

    #[tokio::test]
    async fn nat64_cache_identity_preserves_address_to_interface_assignment() {
        fn entry(network: &str, name: &str, index: u32) -> LocalNetworkEntry {
            LocalNetworkEntry {
                network: network.parse().unwrap(),
                name: name.to_owned(),
                index: Some(index),
                adapter_id: Some(format!("adapter-{index}")),
            }
        }

        let resolver = Arc::new(MutableResolver {
            answer: Mutex::new(vec![
                "[2001:4860:64::c000:aa]:0".parse().unwrap(),
                "[2001:4860:64::c000:ab]:0".parse().unwrap(),
            ]),
            calls: AtomicUsize::new(0),
        });
        let local = Arc::new(MutableLocalNetworks(Mutex::new(LocalNetworks {
            interfaces: vec![
                entry("192.168.1.10/24", "ethernet", 1),
                entry("10.0.0.10/24", "wifi", 2),
            ],
        })));
        let validator = DestinationValidator::new(
            resolver.clone(),
            local.clone(),
            Arc::new(FixedClock(Instant::now())),
            Vec::new(),
        );
        let policy = OutboundPolicy {
            allow_private_network_sources: true,
        };

        assert_eq!(
            validator
                .validate(
                    &Url::parse("http://[2001:4860:64::a9fe:a9fd]/").unwrap(),
                    policy,
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
        local.replace(LocalNetworks {
            interfaces: vec![
                entry("10.0.0.10/24", "ethernet", 1),
                entry("192.168.1.10/24", "wifi", 2),
            ],
        });
        assert_eq!(
            validator
                .validate(
                    &Url::parse("http://[2001:4860:64::a9fe:a9fd]/").unwrap(),
                    policy,
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn discovered_ula_nat64_prefix_exposes_embedded_metadata() {
        let resolver = FakeResolver::new(vec![
            "[fd12:3456:789a::c000:aa]:0".parse().unwrap(),
            "[fd12:3456:789a::c000:ab]:0".parse().unwrap(),
        ]);
        let validator = validator(resolver.clone());
        let target = Url::parse("http://[fd12:3456:789a::a9fe:a9fe]/").unwrap();

        assert_eq!(
            validator
                .validate(
                    &target,
                    OutboundPolicy {
                        allow_private_network_sources: true,
                    },
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn nat64_discovery_failure_rejects_unclassifiable_public_ipv6() {
        let resolver = FakeResolver::failing();
        let validator = validator(resolver.clone());
        for _ in 0..2 {
            assert_eq!(
                validator
                    .validate(
                        &Url::parse("http://[2001:4860:4860::8888]/").unwrap(),
                        OutboundPolicy::default(),
                    )
                    .await
                    .unwrap_err(),
                DestinationError::ResolutionFailed
            );
        }
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn discovered_more_specific_rfc8215_prefix_can_authorize_public_embedding() {
        let resolver = FakeResolver::new(vec![
            "[64:ff9b:1:1::c000:aa]:0".parse().unwrap(),
            "[64:ff9b:1:1::c000:ab]:0".parse().unwrap(),
        ]);
        let validator = validator(resolver.clone());
        let resolved = validator
            .validate(
                &Url::parse("http://[64:ff9b:1:1::5db8:d822]/").unwrap(),
                OutboundPolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            resolved.addrs,
            vec!["[64:ff9b:1:1::5db8:d822]:80".parse().unwrap()]
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn well_known_nat64_public_target_never_triggers_discovery() {
        let resolver = FakeResolver::failing();
        let validator = validator(resolver.clone());
        assert!(
            validator
                .validate(
                    &Url::parse("http://[64:ff9b::5db8:d822]/").unwrap(),
                    OutboundPolicy::default(),
                )
                .await
                .is_ok()
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn nat64_discovery_failure_does_not_hide_standard_prefixes() {
        let validator = validator(FakeResolver::failing());
        assert_eq!(
            validator
                .validate(
                    &Url::parse("http://[64:ff9b::a9fe:a9fe]/").unwrap(),
                    OutboundPolicy {
                        allow_private_network_sources: true,
                    },
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
    }

    #[tokio::test]
    async fn nat64_discovery_cache_refreshes_after_five_minutes() {
        let resolver = FakeResolver::new(vec![
            "[2001:4860:64::c000:aa]:0".parse().unwrap(),
            "[2001:4860:64::c000:ab]:0".parse().unwrap(),
        ]);
        let clock = ManualClock::new();
        let validator = DestinationValidator::new(
            resolver.clone(),
            Arc::new(StaticLocalNetworks(LocalNetworks::default())),
            clock.clone(),
            Vec::new(),
        );
        let target = Url::parse("http://[2001:4860:64::a9fe:a9fe]/").unwrap();
        let policy = OutboundPolicy {
            allow_private_network_sources: true,
        };

        assert!(validator.validate(&target, policy).await.is_err());
        clock.advance(Duration::from_secs(299));
        assert!(validator.validate(&target, policy).await.is_err());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        clock.advance(Duration::from_secs(2));
        assert!(validator.validate(&target, policy).await.is_err());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn nat64_cache_is_not_reused_after_the_local_network_changes() {
        let resolver = Arc::new(MutableResolver {
            answer: Mutex::new(vec![
                "[2001:4860:64::c000:aa]:0".parse().unwrap(),
                "[2001:4860:64::c000:ab]:0".parse().unwrap(),
            ]),
            calls: AtomicUsize::new(0),
        });
        let local = Arc::new(MutableLocalNetworks(Mutex::new(LocalNetworks {
            interfaces: vec!["192.168.1.0/24".parse().unwrap()],
        })));
        let validator = DestinationValidator::new(
            resolver.clone(),
            local.clone(),
            Arc::new(FixedClock(Instant::now())),
            Vec::new(),
        );
        let policy = OutboundPolicy {
            allow_private_network_sources: true,
        };

        assert_eq!(
            validator
                .validate(
                    &Url::parse("http://[2001:4860:64::a9fe:a9fe]/").unwrap(),
                    policy,
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );

        resolver.replace(vec![
            "[2600:1900:64::c000:aa]:0".parse().unwrap(),
            "[2600:1900:64::c000:ab]:0".parse().unwrap(),
        ]);
        local.replace(LocalNetworks {
            interfaces: vec!["10.0.0.0/24".parse().unwrap()],
        });

        assert_eq!(
            validator
                .validate(
                    &Url::parse("http://[2600:1900:64::a9fe:a9fe]/").unwrap(),
                    policy,
                )
                .await
                .unwrap_err(),
            DestinationError::Blocked
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_nat64_cache_misses_share_one_discovery() {
        let resolver = Arc::new(BlockingResolver {
            answer: vec![
                "[2001:4860:64::c000:aa]:0".parse().unwrap(),
                "[2001:4860:64::c000:ab]:0".parse().unwrap(),
            ],
            calls: AtomicUsize::new(0),
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let validator = Arc::new(DestinationValidator::new(
            resolver.clone(),
            Arc::new(StaticLocalNetworks(LocalNetworks::default())),
            Arc::new(FixedClock(Instant::now())),
            Vec::new(),
        ));
        let target = Url::parse("http://[2001:4860:64::a9fe:a9fe]/").unwrap();
        let policy = OutboundPolicy {
            allow_private_network_sources: true,
        };
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let validator = validator.clone();
            let target = target.clone();
            tasks.push(tokio::spawn(async move {
                validator.validate(&target, policy).await
            }));
        }

        resolver.started.notified().await;
        tokio::task::yield_now().await;
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        resolver.release.notify_waiters();
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap_err(), DestinationError::Blocked);
        }
    }

    #[test]
    fn local_interface_snapshots_ignore_down_links_but_fail_closed_on_unknown_status() {
        fn interface(
            ip: std::net::Ipv4Addr,
            prefixlen: u8,
            oper_status: if_addrs::IfOperStatus,
        ) -> if_addrs::Interface {
            if_addrs::Interface {
                name: "test".to_owned(),
                addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                    ip,
                    netmask: std::net::Ipv4Addr::UNSPECIFIED,
                    prefixlen,
                    broadcast: None,
                }),
                index: None,
                oper_status,
                is_p2p: false,
                #[cfg(windows)]
                adapter_name: "test".to_owned(),
            }
        }

        let up = interface("8.8.8.8".parse().unwrap(), 24, if_addrs::IfOperStatus::Up);
        assert_eq!(
            network_for_interface(&up).unwrap().network.to_string(),
            "8.8.8.8/24"
        );

        let down = interface("8.8.4.4".parse().unwrap(), 24, if_addrs::IfOperStatus::Down);
        assert!(network_for_interface(&down).is_none());

        let unknown_loopback = interface(
            std::net::Ipv4Addr::LOCALHOST,
            8,
            if_addrs::IfOperStatus::Unknown,
        );
        assert!(network_for_interface(&unknown_loopback).is_some());

        let unknown_public = interface(
            "1.1.1.1".parse().unwrap(),
            24,
            if_addrs::IfOperStatus::Unknown,
        );
        assert!(network_for_interface(&unknown_public).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn dns_interfaces_and_nat64_share_one_five_second_budget() {
        let validator = Arc::new(DestinationValidator::new(
            Arc::new(SlowThenStalledResolver),
            Arc::new(StaticLocalNetworks(LocalNetworks::default())),
            Arc::new(FixedClock(Instant::now())),
            Vec::new(),
        ));
        let task = tokio::spawn(async move {
            validator
                .validate(
                    &Url::parse("http://slow.example/").unwrap(),
                    OutboundPolicy::default(),
                )
                .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert!(task.is_finished(), "validation exceeded the per-hop budget");
        assert_eq!(
            task.await.unwrap().unwrap_err(),
            DestinationError::ResolutionFailed
        );
    }
}

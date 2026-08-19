use super::ip::{DestinationClass, LocalNetworks, Nat64Prefix, extract_rfc6052};
use async_trait::async_trait;
use std::{
    io,
    net::{IpAddr, SocketAddr},
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
            Ok(LocalNetworks {
                interfaces: interfaces
                    .iter()
                    .filter_map(network_for_interface)
                    .collect(),
            })
        })
        .await
        .map_err(|error| io::Error::other(format!("interface worker failed: {error}")))?
    }
}

fn network_for_interface(interface: &if_addrs::Interface) -> Option<ipnet::IpNet> {
    let eligible = interface.is_oper_up()
        || (interface.is_loopback() && interface.oper_status == if_addrs::IfOperStatus::Unknown);
    if !eligible {
        return None;
    }

    let (ip, prefix) = match &interface.addr {
        if_addrs::IfAddr::V4(address) => (IpAddr::V4(address.ip), address.prefixlen),
        if_addrs::IfAddr::V6(address) => (IpAddr::V6(address.ip), address.prefixlen),
    };
    ipnet::IpNet::new(ip, prefix)
        .ok()
        .map(|network| network.trunc())
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedDestination {
    pub(crate) url: Url,
    pub(crate) domain: Option<String>,
    pub(crate) addrs: Vec<SocketAddr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ListenerBinding {
    pub(crate) address: IpAddr,
    pub(crate) port: u16,
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
            listeners,
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
                }
                resolved.sort_unstable();
                resolved.dedup();
                let nat64 = self.nat64_prefixes_for(&resolved).await;
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
        let nat64 = self.nat64_prefixes_for(&addresses).await;
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
        let target_ip = normalized_listener_ip(target.ip(), nat64);
        self.listeners.iter().any(|listener| {
            if listener.port != target.port() {
                return false;
            }

            let listener_ip = normalized_listener_ip(listener.address, nat64);
            if listener.address.is_unspecified() {
                return match (listener.address, target_ip) {
                    (IpAddr::V4(_), IpAddr::V4(ip)) => {
                        ip.is_loopback() || local.contains(IpAddr::V4(ip))
                    }
                    (IpAddr::V6(_), IpAddr::V6(ip)) => {
                        ip.is_loopback() || local.contains(IpAddr::V6(ip))
                    }
                    _ => false,
                };
            }

            listener_ip == target_ip
        })
    }

    async fn nat64_prefixes_for(&self, addresses: &[SocketAddr]) -> Vec<Nat64Prefix> {
        if !addresses.iter().any(SocketAddr::is_ipv6) {
            return Vec::new();
        }

        if let Some(prefixes) = self.cached_nat64_prefixes().await {
            return prefixes;
        }

        let _refresh = self.nat64_refresh.lock().await;
        if let Some(prefixes) = self.cached_nat64_prefixes().await {
            return prefixes;
        }

        let prefixes = self
            .resolver
            .resolve("ipv4only.arpa", 0)
            .await
            .ok()
            .filter(|answers| !answers.is_empty() && answers.len() <= MAX_DNS_ANSWERS)
            .map(|answers| discover_nat64_prefixes(&answers))
            .unwrap_or_default();

        let expires_at = self
            .clock
            .now()
            .checked_add(NAT64_CACHE_TTL)
            .unwrap_or_else(|| self.clock.now());
        *self.nat64_cache.lock().await = Some(CachedNat64Prefixes {
            expires_at,
            prefixes: prefixes.clone(),
        });
        prefixes
    }

    async fn cached_nat64_prefixes(&self) -> Option<Vec<Nat64Prefix>> {
        let cache = self.nat64_cache.lock().await;
        cache
            .as_ref()
            .filter(|cached| self.clock.now() < cached.expires_at)
            .map(|cached| cached.prefixes.clone())
    }
}

fn normalized_listener_ip(ip: IpAddr, nat64: &[Nat64Prefix]) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => super::ip::normalized_embedded_ipv4(ip, nat64)
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn discover_nat64_prefixes(answers: &[SocketAddr]) -> Vec<Nat64Prefix> {
    const IPV4ONLY: [std::net::Ipv4Addr; 2] = [
        std::net::Ipv4Addr::new(192, 0, 0, 170),
        std::net::Ipv4Addr::new(192, 0, 0, 171),
    ];
    const LENGTHS: [u8; 6] = [32, 40, 48, 56, 64, 96];

    let ipv6_answers: Vec<_> = answers
        .iter()
        .filter_map(|answer| match answer.ip() {
            IpAddr::V6(ip) => Some(ip),
            IpAddr::V4(_) => None,
        })
        .collect();
    let mut prefixes = Vec::new();
    for length in LENGTHS {
        let mask = u128::MAX << (128 - u32::from(length));
        for address in &ipv6_answers {
            let prefix = Nat64Prefix {
                network: std::net::Ipv6Addr::from(u128::from(*address) & mask),
                length,
            };
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
            if seen == [true, true]
                && !prefixes.contains(&prefix)
            {
                prefixes.push(prefix);
            }
        }
    }
    prefixes.sort_unstable_by_key(|prefix| (prefix.length, u128::from(prefix.network)));
    prefixes
}

#[cfg(test)]
mod tests {
    use super::super::ip::LocalNetworks;
    use super::{
        Clock, DestinationError, DestinationValidator, DnsResolver, ListenerBinding,
        LocalNetworkProvider, OutboundPolicy, network_for_interface,
    };
    use async_trait::async_trait;
    use std::{
        io,
        net::SocketAddr,
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
    async fn integer_loopback_is_blocked_before_connect() {
        let resolver = FakeResolver::new(Vec::new());
        let validator = validator(resolver.clone());
        let result = validator
            .validate(
                &Url::parse("http://2130706433/").unwrap(),
                OutboundPolicy::default(),
            )
            .await;
        assert_eq!(result.unwrap_err(), DestinationError::Blocked);
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
                address: "93.184.216.34".parse().unwrap(),
                port: 11470,
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
            FakeResolver::new(vec!["8.8.8.10:11470".parse().unwrap()]),
            local,
            vec![ListenerBinding {
                address: "0.0.0.0".parse().unwrap(),
                port: 11470,
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
    async fn a_different_port_on_the_listener_host_remains_eligible() {
        let validator = validator_with_listeners(
            FakeResolver::new(vec!["93.184.216.34:8080".parse().unwrap()]),
            LocalNetworks::default(),
            vec![ListenerBinding {
                address: "93.184.216.34".parse().unwrap(),
                port: 11470,
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
                address: "93.184.216.34".parse().unwrap(),
                port: 80,
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
    fn local_interface_snapshots_ignore_down_links_but_keep_unknown_loopback() {
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
            network_for_interface(&up).unwrap().to_string(),
            "8.8.8.0/24"
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
        assert!(network_for_interface(&unknown_public).is_none());
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

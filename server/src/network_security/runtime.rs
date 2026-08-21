use super::resolver::{
    DestinationError, DestinationValidator, OutboundPolicy, ResolvedDestination,
};
use axum::http::{HeaderMap, HeaderValue};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};
#[cfg(test)]
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use url::Url;

pub(crate) const PROXY_HOP_HEADER_NAME: &str = "x-stream-server-proxy-hop";
const MAX_CONCURRENT_PROXY_REQUESTS: usize = 64;
const MAX_CONCURRENT_PROXY_REQUESTS_PER_PEER: usize = 16;
const MAX_CONCURRENT_PLAYLISTS: usize = 8;
const MAX_CONCURRENT_PLAYLISTS_PER_PEER: usize = 4;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProxyPolicySettings {
    pub(crate) allow_private_network_sources: bool,
    pub(crate) allow_invalid_proxy_tls_certificates: bool,
}

pub(crate) struct ProxyRequestContext {
    pub(crate) settings: ProxyPolicySettings,
    pub(crate) cancellation: CancellationToken,
    capacity: ProxyCapacityPermit,
    #[cfg(test)]
    producer_probe: Option<ProxyProducerProbe>,
    #[cfg(test)]
    playlist_body_polls: Arc<AtomicUsize>,
}

pub(crate) struct ProxyProducerLease {
    cancellation: CancellationToken,
    _capacity: ProxyCapacityPermit,
    _playlist_capacity: Option<ProxyPlaylistPermit>,
    playlist_delivery_deadline: Option<tokio::time::Instant>,
    #[cfg(test)]
    producer_probe: Option<ProxyProducerProbe>,
}

pub(crate) struct ProxyPlaylistPermit {
    _capacity: ProxyCapacityPermit,
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ProxyProducerProbe {
    state: Arc<ProxyProducerProbeState>,
}

#[cfg(test)]
struct ProxyProducerProbeState {
    signals: Mutex<ProxyProducerProbeSignals>,
    notify: Notify,
}

#[cfg(test)]
struct ProxyProducerProbeSignals {
    outcome: ProxyProducerProbeOutcome,
    published_chunks: usize,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum ProxyProducerProbeOutcome {
    Pending,
    Ready,
    Terminated,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProxyProducerProbeTerminated;

#[cfg(test)]
impl ProxyProducerProbe {
    fn new() -> Self {
        Self {
            state: Arc::new(ProxyProducerProbeState {
                signals: Mutex::new(ProxyProducerProbeSignals {
                    outcome: ProxyProducerProbeOutcome::Pending,
                    published_chunks: 0,
                }),
                notify: Notify::new(),
            }),
        }
    }

    fn lock_signals(&self) -> std::sync::MutexGuard<'_, ProxyProducerProbeSignals> {
        self.state
            .signals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn outcome(
        signals: &ProxyProducerProbeSignals,
    ) -> Option<Result<(), ProxyProducerProbeTerminated>> {
        match signals.outcome {
            ProxyProducerProbeOutcome::Pending => None,
            ProxyProducerProbeOutcome::Ready => Some(Ok(())),
            ProxyProducerProbeOutcome::Terminated => Some(Err(ProxyProducerProbeTerminated)),
        }
    }

    async fn wait_for(
        &self,
        ready: impl Fn(&ProxyProducerProbeSignals) -> Option<Result<(), ProxyProducerProbeTerminated>>,
    ) -> Result<(), ProxyProducerProbeTerminated> {
        loop {
            let notified = self.state.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let outcome = ready(&self.lock_signals());
            if let Some(outcome) = outcome {
                return outcome;
            }
            notified.await;
        }
    }

    fn update(&self, update: impl FnOnce(&mut ProxyProducerProbeSignals)) {
        update(&mut self.lock_signals());
        self.state.notify.notify_waiters();
    }

    pub(crate) fn is_full_deadline_armed(&self) -> bool {
        self.lock_signals().outcome == ProxyProducerProbeOutcome::Ready
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.lock_signals().outcome == ProxyProducerProbeOutcome::Pending
    }

    pub(crate) async fn wait_for_full_deadline_armed(
        &self,
    ) -> Result<(), ProxyProducerProbeTerminated> {
        self.wait_for(Self::outcome).await
    }

    pub(crate) async fn wait_for_published_chunks(
        &self,
        expected: usize,
    ) -> Result<(), ProxyProducerProbeTerminated> {
        self.wait_for(|signals| {
            if signals.published_chunks >= expected {
                Some(Ok(()))
            } else if signals.outcome == ProxyProducerProbeOutcome::Terminated {
                Some(Err(ProxyProducerProbeTerminated))
            } else {
                None
            }
        })
        .await
    }

    pub(crate) fn mark_chunk_published(&self) {
        self.update(|signals| {
            signals.published_chunks = signals
                .published_chunks
                .checked_add(1)
                .expect("proxy producer test publication counter overflow");
        });
    }

    pub(crate) fn mark_full_deadline_armed(&self) {
        self.update(|signals| {
            if signals.outcome == ProxyProducerProbeOutcome::Pending {
                signals.outcome = ProxyProducerProbeOutcome::Ready;
            }
        });
    }

    pub(crate) fn mark_terminated_before_ready(&self) {
        self.update(|signals| {
            if signals.outcome == ProxyProducerProbeOutcome::Pending {
                signals.outcome = ProxyProducerProbeOutcome::Terminated;
            }
        });
    }
}

impl ProxyRequestContext {
    #[cfg(test)]
    pub(crate) fn playlist_body_polls(&self) -> Arc<AtomicUsize> {
        self.playlist_body_polls.clone()
    }

    pub(crate) fn into_producer_lease(self) -> ProxyProducerLease {
        ProxyProducerLease {
            cancellation: self.cancellation,
            _capacity: self.capacity,
            _playlist_capacity: None,
            playlist_delivery_deadline: None,
            #[cfg(test)]
            producer_probe: self.producer_probe,
        }
    }

    pub(crate) fn into_playlist_producer_lease(
        self,
        playlist_capacity: ProxyPlaylistPermit,
        delivery_deadline: tokio::time::Instant,
    ) -> ProxyProducerLease {
        ProxyProducerLease {
            cancellation: self.cancellation,
            _capacity: self.capacity,
            _playlist_capacity: Some(playlist_capacity),
            playlist_delivery_deadline: Some(delivery_deadline),
            #[cfg(test)]
            producer_probe: self.producer_probe,
        }
    }
}

impl ProxyProducerLease {
    pub(crate) fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    pub(crate) fn playlist_delivery_deadline(&self) -> Option<tokio::time::Instant> {
        self.playlist_delivery_deadline
    }

    #[cfg(test)]
    pub(crate) fn producer_probe(&self) -> Option<ProxyProducerProbe> {
        self.producer_probe.clone()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProxyCapacityError;

struct ProxyGeneration {
    settings: ProxyPolicySettings,
    cancellation: CancellationToken,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ProxyPeer {
    Known(IpAddr),
    Unknown,
}

#[derive(Default)]
struct ProxyCapacityState {
    global: usize,
    peers: HashMap<ProxyPeer, usize>,
}

#[derive(Default)]
struct ProxyCapacity {
    state: Mutex<ProxyCapacityState>,
}

struct ProxyCapacityPermit {
    capacity: Arc<ProxyCapacity>,
    peer: ProxyPeer,
}

impl ProxyCapacity {
    fn try_acquire(
        self: &Arc<Self>,
        peer: Option<IpAddr>,
        global_limit: usize,
        peer_limit: usize,
    ) -> Result<ProxyCapacityPermit, ProxyCapacityError> {
        self.try_acquire_normalized(normalize_peer(peer), global_limit, peer_limit)
    }

    fn try_acquire_normalized(
        self: &Arc<Self>,
        peer: ProxyPeer,
        global_limit: usize,
        peer_limit: usize,
    ) -> Result<ProxyCapacityPermit, ProxyCapacityError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let peer_active = state.peers.get(&peer).copied().unwrap_or(0);
        if state.global >= global_limit || peer_active >= peer_limit {
            return Err(ProxyCapacityError);
        }
        state.global += 1;
        *state.peers.entry(peer).or_insert(0) += 1;
        drop(state);
        Ok(ProxyCapacityPermit {
            capacity: self.clone(),
            peer,
        })
    }
}

impl Drop for ProxyCapacityPermit {
    fn drop(&mut self) {
        let mut state = self
            .capacity
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.global = state
            .global
            .checked_sub(1)
            .expect("proxy global capacity permit underflow");
        let remove_peer = {
            let active = state
                .peers
                .get_mut(&self.peer)
                .expect("proxy peer capacity permit without counter");
            *active = active
                .checked_sub(1)
                .expect("proxy peer capacity permit underflow");
            *active == 0
        };
        if remove_peer {
            state.peers.remove(&self.peer);
        }
    }
}

fn normalize_peer(peer: Option<IpAddr>) -> ProxyPeer {
    match peer {
        Some(IpAddr::V6(address)) => address
            .to_ipv4_mapped()
            .map(|address| ProxyPeer::Known(IpAddr::V4(address)))
            .unwrap_or(ProxyPeer::Known(IpAddr::V6(address))),
        Some(address) => ProxyPeer::Known(address),
        None => ProxyPeer::Unknown,
    }
}

pub(crate) struct ProxyRuntime {
    validator: Arc<DestinationValidator>,
    hop_marker: HeaderValue,
    capacity: Arc<ProxyCapacity>,
    playlist_capacity: Arc<ProxyCapacity>,
    generation: Mutex<ProxyGeneration>,
    #[cfg(test)]
    next_producer_probe: Mutex<Option<ProxyProducerProbe>>,
    #[cfg(test)]
    playlist_body_polls: Arc<AtomicUsize>,
}

impl ProxyRuntime {
    pub(crate) fn new(settings: ProxyPolicySettings, validator: Arc<DestinationValidator>) -> Self {
        let marker = uuid::Uuid::new_v4().to_string();
        let marker = HeaderValue::from_str(&marker).expect("UUID v4 is a valid HTTP header value");
        Self::with_hop_marker(settings, validator, marker)
    }

    fn with_hop_marker(
        settings: ProxyPolicySettings,
        validator: Arc<DestinationValidator>,
        mut hop_marker: HeaderValue,
    ) -> Self {
        hop_marker.set_sensitive(true);
        Self {
            validator,
            hop_marker,
            capacity: Arc::new(ProxyCapacity::default()),
            playlist_capacity: Arc::new(ProxyCapacity::default()),
            generation: Mutex::new(ProxyGeneration {
                settings,
                cancellation: CancellationToken::new(),
            }),
            #[cfg(test)]
            next_producer_probe: Mutex::new(None),
            #[cfg(test)]
            playlist_body_polls: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_hop_marker(
        settings: ProxyPolicySettings,
        validator: Arc<DestinationValidator>,
        hop_marker: HeaderValue,
    ) -> Self {
        Self::with_hop_marker(settings, validator, hop_marker)
    }

    pub(crate) fn hop_marker(&self) -> &HeaderValue {
        &self.hop_marker
    }

    pub(crate) fn matches_inbound_hop_marker(&self, headers: &HeaderMap) -> bool {
        use subtle::ConstantTimeEq;

        headers
            .get_all(PROXY_HOP_HEADER_NAME)
            .iter()
            .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
            .map(trim_http_ows)
            .any(|value| bool::from(value.ct_eq(self.hop_marker.as_bytes())))
    }

    #[cfg(test)]
    pub(crate) fn try_request(&self) -> Result<ProxyRequestContext, ProxyCapacityError> {
        self.try_request_for_peer(None)
    }

    pub(crate) fn try_request_for_peer(
        &self,
        peer: Option<IpAddr>,
    ) -> Result<ProxyRequestContext, ProxyCapacityError> {
        let capacity = self.capacity.try_acquire(
            peer,
            MAX_CONCURRENT_PROXY_REQUESTS,
            MAX_CONCURRENT_PROXY_REQUESTS_PER_PEER,
        )?;
        let generation = self
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(test)]
        let producer_probe = self
            .next_producer_probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        Ok(ProxyRequestContext {
            settings: generation.settings,
            cancellation: generation.cancellation.clone(),
            capacity,
            #[cfg(test)]
            producer_probe,
            #[cfg(test)]
            playlist_body_polls: self.playlist_body_polls.clone(),
        })
    }

    pub(crate) fn try_playlist(
        &self,
        context: &ProxyRequestContext,
    ) -> Result<ProxyPlaylistPermit, ProxyCapacityError> {
        self.playlist_capacity
            .try_acquire_normalized(
                context.capacity.peer,
                MAX_CONCURRENT_PLAYLISTS,
                MAX_CONCURRENT_PLAYLISTS_PER_PEER,
            )
            .map(|capacity| ProxyPlaylistPermit {
                _capacity: capacity,
            })
    }

    #[cfg(test)]
    pub(crate) fn probe_next_request_producer(&self) -> ProxyProducerProbe {
        let probe = ProxyProducerProbe::new();
        let previous = self
            .next_producer_probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(probe.clone());
        assert!(
            previous.is_none(),
            "proxy runtime already has an unclaimed producer probe"
        );
        probe
    }

    #[cfg(test)]
    pub(crate) fn capacity_snapshot(&self) -> (usize, usize) {
        let state = self
            .capacity
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.global, state.peers.len())
    }

    #[cfg(test)]
    pub(crate) fn playlist_capacity_snapshot(&self) -> (usize, usize) {
        let state = self
            .playlist_capacity
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.global, state.peers.len())
    }

    #[cfg(test)]
    pub(crate) fn playlist_body_poll_count(&self) -> usize {
        self.playlist_body_polls.load(Ordering::SeqCst)
    }

    pub(crate) async fn validate(
        &self,
        context: &ProxyRequestContext,
        url: &Url,
    ) -> Result<ResolvedDestination, DestinationError> {
        let policy = OutboundPolicy {
            allow_private_network_sources: context.settings.allow_private_network_sources,
        };
        tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => Err(DestinationError::ResolutionFailed),
            result = self.validator.validate(url, policy) => result,
        }
    }

    pub(crate) fn begin_reconfigure(&self, next: ProxyPolicySettings) {
        let mut generation = self
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let intersection = ProxyPolicySettings {
            allow_private_network_sources: generation.settings.allow_private_network_sources
                && next.allow_private_network_sources,
            allow_invalid_proxy_tls_certificates: generation
                .settings
                .allow_invalid_proxy_tls_certificates
                && next.allow_invalid_proxy_tls_certificates,
        };
        if intersection != generation.settings {
            generation.cancellation.cancel();
            *generation = ProxyGeneration {
                settings: intersection,
                cancellation: CancellationToken::new(),
            };
        }
    }

    pub(crate) fn finish_reconfigure(&self, next: ProxyPolicySettings) {
        let mut generation = self
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if generation.settings == next {
            return;
        }
        let restrictive = (generation.settings.allow_private_network_sources
            && !next.allow_private_network_sources)
            || (generation.settings.allow_invalid_proxy_tls_certificates
                && !next.allow_invalid_proxy_tls_certificates);
        if restrictive {
            generation.cancellation.cancel();
        }
        *generation = ProxyGeneration {
            settings: next,
            cancellation: CancellationToken::new(),
        };
    }
}

fn trim_http_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::super::{
        ip::LocalNetworks,
        resolver::{Clock, DestinationValidator, DnsResolver, LocalNetworkProvider},
    };
    use super::{ProxyPolicySettings, ProxyRuntime};
    use async_trait::async_trait;
    use axum::http::{HeaderMap, HeaderValue};
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::{Arc, Barrier},
        time::Instant,
    };

    struct NoDns;

    #[async_trait]
    impl DnsResolver for NoDns {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            Err(io::Error::other("unused"))
        }
    }

    struct NoLocalNetworks;

    #[async_trait]
    impl LocalNetworkProvider for NoLocalNetworks {
        async fn current(&self) -> io::Result<LocalNetworks> {
            Ok(LocalNetworks::default())
        }
    }

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> Instant {
            Instant::now()
        }
    }

    fn runtime(settings: ProxyPolicySettings) -> ProxyRuntime {
        let validator = Arc::new(DestinationValidator::new(
            Arc::new(NoDns),
            Arc::new(NoLocalNetworks),
            Arc::new(FixedClock),
            Vec::new(),
        ));
        ProxyRuntime::new(settings, validator)
    }

    fn runtime_with_marker(marker: HeaderValue) -> ProxyRuntime {
        let validator = Arc::new(DestinationValidator::new(
            Arc::new(NoDns),
            Arc::new(NoLocalNetworks),
            Arc::new(FixedClock),
            Vec::new(),
        ));
        ProxyRuntime::new_with_hop_marker(ProxyPolicySettings::default(), validator, marker)
    }

    #[test]
    fn hop_marker_is_stable_across_requests_and_reconfiguration_but_unique_per_runtime() {
        let first_runtime = runtime(ProxyPolicySettings::default());
        let marker = first_runtime.hop_marker().clone();
        let request = first_runtime.try_request().unwrap();
        assert_eq!(first_runtime.hop_marker(), &marker);
        drop(request);

        first_runtime.begin_reconfigure(ProxyPolicySettings {
            allow_private_network_sources: true,
            allow_invalid_proxy_tls_certificates: false,
        });
        first_runtime.finish_reconfigure(ProxyPolicySettings {
            allow_private_network_sources: true,
            allow_invalid_proxy_tls_certificates: false,
        });
        assert_eq!(first_runtime.hop_marker(), &marker);
        assert_ne!(
            first_runtime.hop_marker(),
            runtime(ProxyPolicySettings::default()).hop_marker()
        );
        assert!(first_runtime.hop_marker().is_sensitive());
    }

    #[test]
    fn inbound_hop_marker_matches_raw_repeated_and_comma_coalesced_fields() {
        let runtime = runtime_with_marker(HeaderValue::from_static("test-marker"));
        let mut headers = HeaderMap::new();
        headers.append(
            "x-stream-server-proxy-hop",
            HeaderValue::from_bytes(b"\x80-not-utf8, other").unwrap(),
        );
        headers.append(
            "x-stream-server-proxy-hop",
            HeaderValue::from_static("not-it,\ttest-marker \t"),
        );
        assert!(runtime.matches_inbound_hop_marker(&headers));

        headers.clear();
        headers.insert(
            "x-stream-server-proxy-hop",
            HeaderValue::from_static("not-test-marker"),
        );
        assert!(!runtime.matches_inbound_hop_marker(&headers));
    }

    #[test]
    fn sixty_fifth_request_is_rejected_without_waiting() {
        let runtime = runtime(ProxyPolicySettings::default());
        let permits: Vec<_> = (0..64)
            .map(|index| {
                runtime
                    .try_request_for_peer(Some(IpAddr::V6(Ipv6Addr::from(index + 1))))
                    .unwrap()
            })
            .collect();
        assert!(
            runtime
                .try_request_for_peer(Some(IpAddr::V6(Ipv6Addr::from(65))))
                .is_err()
        );
        drop(permits);
        assert!(
            runtime
                .try_request_for_peer(Some(IpAddr::V6(Ipv6Addr::from(65))))
                .is_ok()
        );
    }

    #[test]
    fn unknown_peer_is_limited_to_sixteen_active_requests() {
        let runtime = runtime(ProxyPolicySettings::default());
        let permits: Vec<_> = (0..16).map(|_| runtime.try_request().unwrap()).collect();

        assert!(runtime.try_request().is_err());

        drop(permits);
        assert!(runtime.try_request().is_ok());
    }

    #[test]
    fn one_peer_is_limited_without_blocking_another_peer() {
        let runtime = runtime(ProxyPolicySettings::default());
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let permits: Vec<_> = (0..16)
            .map(|_| runtime.try_request_for_peer(Some(first)).unwrap())
            .collect();

        assert!(runtime.try_request_for_peer(Some(first)).is_err());
        assert!(runtime.try_request_for_peer(Some(second)).is_ok());
        drop(permits);
    }

    #[test]
    fn ipv4_mapped_ipv6_shares_the_ipv4_peer_quota() {
        let runtime = runtime(ProxyPolicySettings::default());
        let ipv4 = Ipv4Addr::new(192, 0, 2, 10);
        let permits: Vec<_> = (0..8)
            .map(|_| {
                runtime
                    .try_request_for_peer(Some(IpAddr::V4(ipv4)))
                    .unwrap()
            })
            .chain((0..8).map(|_| {
                runtime
                    .try_request_for_peer(Some(IpAddr::V6(ipv4.to_ipv6_mapped())))
                    .unwrap()
            }))
            .collect();

        assert!(
            runtime
                .try_request_for_peer(Some(IpAddr::V4(ipv4)))
                .is_err()
        );
        assert!(
            runtime
                .try_request_for_peer(Some(IpAddr::V6(ipv4.to_ipv6_mapped())))
                .is_err()
        );
        drop(permits);
    }

    #[test]
    fn dropping_last_permits_removes_idle_peer_entries() {
        let runtime = runtime(ProxyPolicySettings::default());

        for host in 1..=200 {
            let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, host));
            drop(runtime.try_request_for_peer(Some(peer)).unwrap());
        }

        assert_eq!(runtime.capacity_snapshot(), (0, 0));
        let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert!(runtime.try_request_for_peer(Some(peer)).is_ok());
    }

    #[test]
    fn concurrent_last_drop_and_reacquire_cannot_split_a_peer_quota() {
        let runtime = Arc::new(runtime(ProxyPolicySettings::default()));
        let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        for _ in 0..100 {
            let mut permits: Vec<_> = (0..16)
                .map(|_| runtime.try_request_for_peer(Some(peer)).unwrap())
                .collect();
            let last = permits.pop().unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let drop_barrier = barrier.clone();
            let dropper = std::thread::spawn(move || {
                drop_barrier.wait();
                drop(last);
            });

            barrier.wait();
            let replacement = (0..10_000)
                .find_map(|_| {
                    let acquired = runtime.try_request_for_peer(Some(peer)).ok();
                    if acquired.is_none() {
                        std::thread::yield_now();
                    }
                    acquired
                })
                .expect("the released peer slot must remain reacquirable");
            dropper.join().unwrap();

            assert!(runtime.try_request_for_peer(Some(peer)).is_err());
            drop(replacement);
            drop(permits);
            assert_eq!(runtime.capacity_snapshot(), (0, 0));
        }
    }

    #[test]
    fn playlist_admission_limits_one_peer_to_four_without_blocking_another() {
        let runtime = runtime(ProxyPolicySettings::default());
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21));
        let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 22));
        let first_contexts: Vec<_> = (0..5)
            .map(|_| runtime.try_request_for_peer(Some(first)).unwrap())
            .collect();
        let permits: Vec<_> = first_contexts[..4]
            .iter()
            .map(|context| runtime.try_playlist(context).unwrap())
            .collect();

        assert!(runtime.try_playlist(&first_contexts[4]).is_err());
        let other = runtime.try_request_for_peer(Some(second)).unwrap();
        assert!(runtime.try_playlist(&other).is_ok());

        drop(permits);
        assert!(runtime.try_playlist(&first_contexts[4]).is_ok());
    }

    #[test]
    fn playlist_admission_limits_global_work_to_eight() {
        let runtime = runtime(ProxyPolicySettings::default());
        let contexts: Vec<_> = (1..=9)
            .map(|host| {
                runtime
                    .try_request_for_peer(Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, host))))
                    .unwrap()
            })
            .collect();
        let mut permits: Vec<_> = contexts[..8]
            .iter()
            .map(|context| runtime.try_playlist(context).unwrap())
            .collect();

        assert!(runtime.try_playlist(&contexts[8]).is_err());
        drop(permits.pop().unwrap());
        let replacement = runtime.try_playlist(&contexts[8]).unwrap();
        assert_eq!(runtime.playlist_capacity_snapshot(), (8, 8));
        drop(replacement);
        drop(permits);
        assert!(runtime.try_playlist(&contexts[8]).is_ok());
    }

    #[test]
    fn playlist_admission_normalizes_ipv4_mapped_peers() {
        let runtime = runtime(ProxyPolicySettings::default());
        let ipv4 = Ipv4Addr::new(203, 0, 113, 31);
        let contexts: Vec<_> = (0..2)
            .map(|_| {
                runtime
                    .try_request_for_peer(Some(IpAddr::V4(ipv4)))
                    .unwrap()
            })
            .chain((0..3).map(|_| {
                runtime
                    .try_request_for_peer(Some(IpAddr::V6(ipv4.to_ipv6_mapped())))
                    .unwrap()
            }))
            .collect();
        let permits: Vec<_> = contexts[..4]
            .iter()
            .map(|context| runtime.try_playlist(context).unwrap())
            .collect();

        assert!(runtime.try_playlist(&contexts[4]).is_err());
        drop(permits);
        assert!(runtime.try_playlist(&contexts[4]).is_ok());
    }

    #[test]
    fn dropping_last_playlist_permits_removes_idle_peer_entries() {
        let runtime = runtime(ProxyPolicySettings::default());

        for host in 1..=200 {
            let context = runtime
                .try_request_for_peer(Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, host))))
                .unwrap();
            drop(runtime.try_playlist(&context).unwrap());
        }

        assert_eq!(runtime.playlist_capacity_snapshot(), (0, 0));
    }

    #[tokio::test]
    async fn restrictive_reconfiguration_cancels_the_old_generation() {
        let runtime = runtime(ProxyPolicySettings {
            allow_private_network_sources: true,
            allow_invalid_proxy_tls_certificates: true,
        });
        let old = runtime.try_request().unwrap();
        let next = ProxyPolicySettings::default();
        runtime.begin_reconfigure(next);
        assert!(old.cancellation.is_cancelled());
        let during = runtime.try_request().unwrap();
        assert_eq!(during.settings, ProxyPolicySettings::default());
        runtime.finish_reconfigure(next);
        assert!(!during.cancellation.is_cancelled());
    }

    #[test]
    fn enabling_permissions_does_not_cancel_stricter_inflight_work() {
        let runtime = runtime(ProxyPolicySettings::default());
        let old = runtime.try_request().unwrap();
        let next = ProxyPolicySettings {
            allow_private_network_sources: true,
            allow_invalid_proxy_tls_certificates: true,
        };
        runtime.begin_reconfigure(next);
        assert!(!old.cancellation.is_cancelled());
        assert_eq!(
            runtime.try_request().unwrap().settings,
            ProxyPolicySettings::default()
        );
        runtime.finish_reconfigure(next);
        assert!(!old.cancellation.is_cancelled());
        assert_eq!(runtime.try_request().unwrap().settings, next);
    }

    #[test]
    fn mixed_transition_exposes_only_the_old_new_intersection_until_publish() {
        let old = ProxyPolicySettings {
            allow_private_network_sources: true,
            allow_invalid_proxy_tls_certificates: false,
        };
        let next = ProxyPolicySettings {
            allow_private_network_sources: false,
            allow_invalid_proxy_tls_certificates: true,
        };
        let runtime = runtime(old);
        let old_request = runtime.try_request().unwrap();
        runtime.begin_reconfigure(next);
        assert!(old_request.cancellation.is_cancelled());
        assert_eq!(
            runtime.try_request().unwrap().settings,
            ProxyPolicySettings::default()
        );
        runtime.finish_reconfigure(next);
        assert_eq!(runtime.try_request().unwrap().settings, next);
    }
}

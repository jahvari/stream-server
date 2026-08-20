use super::resolver::{
    DestinationError, DestinationValidator, OutboundPolicy, ResolvedDestination,
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};
#[cfg(test)]
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use url::Url;

const MAX_CONCURRENT_PROXY_REQUESTS: usize = 64;
const MAX_CONCURRENT_PROXY_REQUESTS_PER_PEER: usize = 16;

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
}

pub(crate) struct ProxyProducerLease {
    cancellation: CancellationToken,
    _capacity: ProxyCapacityPermit,
    #[cfg(test)]
    producer_probe: Option<ProxyProducerProbe>,
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
    pub(crate) fn into_producer_lease(self) -> ProxyProducerLease {
        ProxyProducerLease {
            cancellation: self.cancellation,
            _capacity: self.capacity,
            #[cfg(test)]
            producer_probe: self.producer_probe,
        }
    }
}

impl ProxyProducerLease {
    pub(crate) fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
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
    ) -> Result<ProxyCapacityPermit, ProxyCapacityError> {
        let peer = normalize_peer(peer);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let peer_active = state.peers.get(&peer).copied().unwrap_or(0);
        if state.global >= MAX_CONCURRENT_PROXY_REQUESTS
            || peer_active >= MAX_CONCURRENT_PROXY_REQUESTS_PER_PEER
        {
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
    capacity: Arc<ProxyCapacity>,
    generation: Mutex<ProxyGeneration>,
    #[cfg(test)]
    next_producer_probe: Mutex<Option<ProxyProducerProbe>>,
}

impl ProxyRuntime {
    pub(crate) fn new(settings: ProxyPolicySettings, validator: Arc<DestinationValidator>) -> Self {
        Self {
            validator,
            capacity: Arc::new(ProxyCapacity::default()),
            generation: Mutex::new(ProxyGeneration {
                settings,
                cancellation: CancellationToken::new(),
            }),
            #[cfg(test)]
            next_producer_probe: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn try_request(&self) -> Result<ProxyRequestContext, ProxyCapacityError> {
        self.try_request_for_peer(None)
    }

    pub(crate) fn try_request_for_peer(
        &self,
        peer: Option<IpAddr>,
    ) -> Result<ProxyRequestContext, ProxyCapacityError> {
        let capacity = self.capacity.try_acquire(peer)?;
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

#[cfg(test)]
mod tests {
    use super::super::{
        ip::LocalNetworks,
        resolver::{Clock, DestinationValidator, DnsResolver, LocalNetworkProvider},
    };
    use super::{ProxyPolicySettings, ProxyRuntime};
    use async_trait::async_trait;
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

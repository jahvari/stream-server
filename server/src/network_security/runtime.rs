use super::resolver::{
    DestinationError, DestinationValidator, OutboundPolicy, ResolvedDestination,
};
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use url::Url;

const MAX_CONCURRENT_PROXY_REQUESTS: usize = 64;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProxyPolicySettings {
    pub(crate) allow_private_network_sources: bool,
    pub(crate) allow_invalid_proxy_tls_certificates: bool,
}

pub(crate) struct ProxyRequestContext {
    pub(crate) settings: ProxyPolicySettings,
    pub(crate) cancellation: CancellationToken,
    pub(crate) capacity: OwnedSemaphorePermit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProxyCapacityError;

struct ProxyGeneration {
    settings: ProxyPolicySettings,
    cancellation: CancellationToken,
}

pub(crate) struct ProxyRuntime {
    validator: Arc<DestinationValidator>,
    capacity: Arc<Semaphore>,
    generation: Mutex<ProxyGeneration>,
}

impl ProxyRuntime {
    pub(crate) fn new(settings: ProxyPolicySettings, validator: Arc<DestinationValidator>) -> Self {
        Self {
            validator,
            capacity: Arc::new(Semaphore::new(MAX_CONCURRENT_PROXY_REQUESTS)),
            generation: Mutex::new(ProxyGeneration {
                settings,
                cancellation: CancellationToken::new(),
            }),
        }
    }

    pub(crate) fn try_request(&self) -> Result<ProxyRequestContext, ProxyCapacityError> {
        let capacity = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| ProxyCapacityError)?;
        let generation = self
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(ProxyRequestContext {
            settings: generation.settings,
            cancellation: generation.cancellation.clone(),
            capacity,
        })
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
    use std::{io, net::SocketAddr, sync::Arc, time::Instant};

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
        let permits: Vec<_> = (0..64).map(|_| runtime.try_request().unwrap()).collect();
        assert!(runtime.try_request().is_err());
        drop(permits);
        assert!(runtime.try_request().is_ok());
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

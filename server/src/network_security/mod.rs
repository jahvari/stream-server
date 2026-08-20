mod ip;
mod resolver;
mod runtime;

pub(crate) use resolver::{
    DestinationError, DestinationValidator, ListenerBinding, SystemClock, SystemDnsResolver,
    SystemLocalNetworkProvider,
};
pub(crate) use runtime::{
    ProxyCapacityPermit, ProxyPolicySettings, ProxyRequestContext, ProxyRuntime,
};

#[cfg(test)]
pub(crate) use ip::LocalNetworks;
#[cfg(test)]
pub(crate) use resolver::{Clock, DnsResolver, LocalNetworkProvider};

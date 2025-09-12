
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use std::sync::Arc;
use lru::LruCache;
use tokio::sync::{Mutex, RwLock, OnceCell};
use trust_dns_resolver::AsyncResolver;
use trust_dns_resolver::config::*;

static CACHE2: OnceCell<Arc<RwLock<LruCache<String, DnsRecord>>>> = OnceCell::const_new();

async fn load_cache() -> Arc<RwLock<LruCache<String, DnsRecord>>> {
    CACHE2.get_or_init(|| async {
        Arc::new(RwLock::new(LruCache::new(NonZeroUsize::new(1000).unwrap())))
    }).await.clone()
}

#[derive(Debug, Clone)]
struct DnsRecord {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}


struct CachedDotResolver {
    cache: Mutex<LruCache<String, DnsRecord>>,
}

impl CachedDotResolver {
    fn new(capacity: usize) -> Self {
        let size = if capacity > 100 { capacity } else { 100 };
        Self {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(size).unwrap())),
        }
    }

    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, std::io::Error> {
        
        if let Some(ips) = self.get(domain).await {
            return Ok(ips);
        }

        let resolver = AsyncResolver::tokio(
            ResolverConfig::cloudflare_tls(), 
            ResolverOpts::default(),
        );

        let response = resolver.lookup_ip(domain).await?;
  
        let ips: Vec<IpAddr> = response.iter().collect();
        
        self.set(domain.to_string(), ips.clone(), Duration::from_secs(300)).await;
        
        Ok(ips)
    }

    async fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.lock().await;
        if let Some(record) = cache.get(domain) {
            if record.expires_at > Instant::now() {
                Some(record.ips.clone())
            } else {
                cache.pop(domain);
                None
            }
        } else {
            None
        }
    }

    async fn set(&self, domain: String, ips: Vec<IpAddr>, ttl: Duration) {
        let record = DnsRecord {
            ips,
            expires_at: Instant::now() + ttl,
        };
        let mut cache = self.cache.lock().await;
        cache.put(domain, record);
    }
}


async fn resolve_dns(domain: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    let resolver = AsyncResolver::tokio(
        ResolverConfig::cloudflare_tls(), 
        ResolverOpts::default(),
    );

    let response = resolver.lookup_ip(domain).await?;
    Ok(response.iter().collect())
}

pub async fn resolve_with_cache(domain: &str) -> Result<Vec<IpAddr>,  std::io::Error> {

    let cache = load_cache().await;
    
    if let Ok(guard) = cache.try_read() {
        if let Some(record) = guard.peek(domain) {
            if record.expires_at > Instant::now() {
                return Ok(record.ips.clone());
            }
        }
    }

    let ips = resolve_dns(domain).await?;
    
    if let Ok(mut guard) = cache.try_write() {
        guard.put(domain.to_string(), DnsRecord {
            ips: ips.clone(),
            expires_at: Instant::now() + Duration::from_secs(600),
        });
    }
    
    Ok(ips)
}
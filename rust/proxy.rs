//! The proxy every installer client uses.
//!
//! Proxies come from HTTPS_PROXY/HTTP_PROXY/ALL_PROXY/NO_PROXY (either case)
//! as reqwest reads them. When none of those is set, the system proxy that
//! browsers and the PowerShell bootstrap use applies too:
//! - macOS: reqwest's `system-proxy` feature (a macOS-only dependency in
//!   Cargo.toml) reads the SystemConfiguration HTTP/HTTPS proxies.
//! - Windows: Internet Settings in the registry, read and parsed here.
//!   reqwest's own reader takes `ProxyServer` as one URL, so the
//!   per-protocol form `https=proxy:443` became the proxy host "https=proxy"
//!   and the connection failed.
//!
//! A system value that cannot be used means a direct connection, as before
//! the system proxy was read.
// Parsing is used on Windows and tested everywhere.
#![cfg_attr(not(windows), allow(dead_code))]

use reqwest::ClientBuilder;

const PROXY_VARS: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Apply the proxy configuration to a client builder.
pub(crate) fn configure(builder: ClientBuilder) -> ClientBuilder {
    if env_proxy_set(|name| std::env::var_os(name)) {
        return builder;
    }
    system(builder)
}

/// Whether any proxy variable is set (to anything, as reqwest reads it).
/// NO_PROXY alone selects no proxy, so it does not count.
fn env_proxy_set(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    PROXY_VARS.iter().any(|name| var(name).is_some())
}

#[cfg(windows)]
fn system(builder: ClientBuilder) -> ClientBuilder {
    let Ok(settings) = windows_registry::CURRENT_USER
        .open("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
    else {
        return builder;
    };
    if settings.get_u32("ProxyEnable").unwrap_or(0) == 0 {
        return builder;
    }
    let server = settings.get_string("ProxyServer").unwrap_or_default();
    let overrides = settings.get_string("ProxyOverride").unwrap_or_default();
    apply(builder, &windows_proxies(&server, &overrides))
}

#[cfg(not(windows))]
fn system(builder: ClientBuilder) -> ClientBuilder {
    builder
}

/// The proxies a Windows `ProxyServer` / `ProxyOverride` pair selects.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct WindowsProxies {
    pub http: Option<String>,
    pub https: Option<String>,
    /// NO_PROXY syntax, comma-separated.
    pub no_proxy: String,
}

/// Parse Internet Settings the way WinINET does.
///
/// `ProxyServer` is either one `host:port` for every protocol, or
/// `proto=host:port` entries separated by `;`. In the second form a protocol
/// without its own entry goes direct; only `http` and `https` are used here
/// (`socks`, `ftp` and unknown protocols are ignored). A value that is not a
/// plain `host[:port]`, optionally with an `http://` prefix, is ignored.
pub(crate) fn windows_proxies(server: &str, overrides: &str) -> WindowsProxies {
    let server = server.trim();
    let (http, https) = if server.contains('=') {
        let mut http = None;
        let mut https = None;
        for entry in server.split(';') {
            let Some((protocol, value)) = entry.split_once('=') else {
                continue;
            };
            match protocol.trim().to_ascii_lowercase().as_str() {
                "http" => http = proxy_url(value),
                "https" => https = proxy_url(value),
                _ => {}
            }
        }
        (http, https)
    } else {
        let all = proxy_url(server);
        (all.clone(), all)
    };
    WindowsProxies {
        http,
        https,
        no_proxy: no_proxy(overrides),
    }
}

/// `host[:port]` (or `http://host[:port]`) as a proxy URL; port 80 if absent.
fn proxy_url(value: &str) -> Option<String> {
    let value = value.trim();
    let rest = match value.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,
        Some(_) => return None,
        None => value,
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ';', ',', '=', ' ']) {
        return None;
    }
    let url = reqwest::Url::parse(&format!("http://{rest}")).ok()?;
    let host = url.host_str()?;
    let port = url.port_or_known_default()?;
    Some(format!("http://{host}:{port}"))
}

/// `ProxyOverride` (`;`-separated, `*` wildcards, `<local>`) as NO_PROXY.
///
/// `*.corp` and `.corp` become `.corp`; `10.*` and `192.168.*` become CIDR
/// ranges; `*` bypasses everything. `<local>` (host names without a dot) has
/// no NO_PROXY form, so it bypasses `localhost` only. Other wildcard patterns
/// are dropped: they keep using the proxy, as before this was read.
fn no_proxy(overrides: &str) -> String {
    let mut out = Vec::new();
    for entry in overrides
        .split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        if entry == "*" {
            out.push("*".to_owned());
        } else if entry.eq_ignore_ascii_case("<local>") {
            out.push("localhost".to_owned());
        } else if let Some(domain) = entry.strip_prefix("*.") {
            if !domain.contains('*') && !domain.is_empty() {
                out.push(format!(".{domain}"));
            }
        } else if let Some(prefix) = entry.strip_suffix(".*") {
            if let Some(range) = ipv4_prefix(prefix) {
                out.push(range);
            }
        } else if !entry.contains('*') {
            out.push(entry.to_owned());
        }
    }
    out.join(",")
}

/// `10` → `10.0.0.0/8`, `192.168` → `192.168.0.0/16`, `10.1.2` → `10.1.2.0/24`.
fn ipv4_prefix(prefix: &str) -> Option<String> {
    let octets: Vec<u8> = prefix
        .split('.')
        .map(|octet| octet.parse().ok())
        .collect::<Option<_>>()?;
    if octets.is_empty() || octets.len() > 3 {
        return None;
    }
    let mut address = [0_u8; 4];
    address[..octets.len()].copy_from_slice(&octets);
    let [a, b, c, d] = address;
    Some(format!("{a}.{b}.{c}.{d}/{}", octets.len() * 8))
}

/// Set the parsed proxies on the builder. Adding a proxy turns off reqwest's
/// automatic lookup; it only read the (unset) environment on Windows anyway.
fn apply(mut builder: ClientBuilder, proxies: &WindowsProxies) -> ClientBuilder {
    let no_proxy = || reqwest::NoProxy::from_string(&proxies.no_proxy);
    if let Some(url) = &proxies.http
        && let Ok(proxy) = reqwest::Proxy::http(url)
    {
        builder = builder.proxy(proxy.no_proxy(no_proxy()));
    }
    if let Some(url) = &proxies.https
        && let Ok(proxy) = reqwest::Proxy::https(url)
    {
        builder = builder.proxy(proxy.no_proxy(no_proxy()));
    }
    builder
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn proxies(http: Option<&str>, https: Option<&str>, no_proxy: &str) -> WindowsProxies {
        WindowsProxies {
            http: http.map(str::to_owned),
            https: https.map(str::to_owned),
            no_proxy: no_proxy.to_owned(),
        }
    }

    #[test]
    fn one_server_is_used_for_both_protocols() {
        assert_eq!(
            windows_proxies("proxy.corp:8080", ""),
            proxies(
                Some("http://proxy.corp:8080"),
                Some("http://proxy.corp:8080"),
                ""
            )
        );
        assert_eq!(
            windows_proxies("http://10.0.0.1:3128/", ""),
            proxies(
                Some("http://10.0.0.1:3128"),
                Some("http://10.0.0.1:3128"),
                ""
            )
        );
        assert_eq!(
            windows_proxies("proxy.corp", ""),
            proxies(
                Some("http://proxy.corp:80"),
                Some("http://proxy.corp:80"),
                ""
            )
        );
    }

    #[test]
    fn per_protocol_entries_are_read_by_protocol() {
        assert_eq!(
            windows_proxies("http=a.corp:80;https=b.corp:443;ftp=c.corp:21", ""),
            proxies(Some("http://a.corp:80"), Some("http://b.corp:443"), "")
        );
        assert_eq!(
            windows_proxies(" HTTPS = b.corp:443 ; socks=s.corp:1080 ", ""),
            proxies(None, Some("http://b.corp:443"), "")
        );
    }

    #[test]
    fn a_single_per_protocol_entry_never_becomes_a_proxy_host() {
        // The failure reqwest's own reader had: "https=b" taken as a host.
        assert_eq!(
            windows_proxies("https=b:443", ""),
            proxies(None, Some("http://b:443"), "")
        );
        // Only http set: https goes direct, as in WinINET.
        assert_eq!(
            windows_proxies("http=a:80", ""),
            proxies(Some("http://a:80"), None, "")
        );
        assert_eq!(windows_proxies("socks=s:1080", ""), proxies(None, None, ""));
    }

    #[test]
    fn unusable_values_mean_a_direct_connection() {
        for server in [
            "",
            "   ",
            "socks5://s:1080",
            "https://p:443",
            "a:80;b:81",
            "p:notaport",
            "p:99999",
            "user:pw@p:80",
            "p:80/path",
            "https=",
            "https=p:80/x",
            "=;=",
        ] {
            let parsed = windows_proxies(server, "");
            assert_eq!((parsed.http, parsed.https), (None, None), "{server:?}");
        }
    }

    #[test]
    fn overrides_become_no_proxy() {
        assert_eq!(
            windows_proxies(
                "p:80",
                "*.corp.example;intranet;10.*;192.168.*;172.16.5.*;<local>"
            )
            .no_proxy,
            ".corp.example,intranet,10.0.0.0/8,192.168.0.0/16,172.16.5.0/24,localhost"
        );
        assert_eq!(windows_proxies("p:80", "*").no_proxy, "*");
        assert_eq!(windows_proxies("p:80", "*corp*;a.*.b;300.*;;").no_proxy, "");
    }

    #[test]
    fn any_proxy_variable_keeps_the_system_proxy_out() {
        let set = |names: &'static [&'static str]| {
            move |name: &str| names.contains(&name).then(|| std::ffi::OsString::from("x"))
        };
        assert!(!env_proxy_set(set(&[])));
        assert!(!env_proxy_set(set(&["NO_PROXY", "no_proxy"])));
        for name in PROXY_VARS {
            let names: &'static [&'static str] = Box::leak(Box::new([name]));
            assert!(env_proxy_set(set(names)), "{name}");
        }
    }

    /// The parsed https proxy is what the client actually connects to.
    #[tokio::test]
    async fn the_parsed_https_proxy_receives_the_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                request.push(byte[0]);
            }
            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
            String::from_utf8_lossy(&request).into_owned()
        });
        let parsed = windows_proxies(&format!("http=127.0.0.1:9;https=127.0.0.1:{port}"), "");
        let client = apply(reqwest::Client::builder().no_proxy(), &parsed)
            .build()
            .unwrap();
        assert!(client.get("https://hands.example/").send().await.is_err());
        assert!(
            seen.join()
                .unwrap()
                .starts_with("CONNECT hands.example:443 ")
        );
    }

    #[tokio::test]
    async fn no_proxy_entries_bypass_the_parsed_proxy() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = proxy.local_addr().unwrap().port();
        proxy.set_nonblocking(true).unwrap();
        let parsed = windows_proxies(&format!("127.0.0.1:{port}"), "*.example");
        let client = apply(reqwest::Client::builder().no_proxy(), &parsed)
            .build()
            .unwrap();
        // Direct: the .example name does not resolve, and the proxy sees nothing.
        let _ = client
            .get("https://hands.example/")
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;
        assert!(proxy.accept().is_err(), "bypassed host went to the proxy");
    }
}

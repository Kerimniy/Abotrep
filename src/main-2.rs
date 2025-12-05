mod captcha;
use rand::random;
use std::cell::RefMut;
use std::net::{AddrParseError, SocketAddr};
use std::path::PathBuf;
use axum::{response::IntoResponse, routing::get, Router, response::{Response}, extract::Path, extract::ConnectInfo, body::{Bytes}, Extension};
use axum::http::{
status::StatusCode,
    HeaderValue,
HeaderMap
};
use reqwest::{Body, Client};

use std::sync::Arc;
use std::time::Instant;
use once_cell::sync::Lazy;
use tower_cookies::{Cookies, Cookie, CookieManagerLayer, Key};
use time::{Duration, OffsetDateTime};
use axum::http::{Request, request::Parts};
use askama::Template;
use dashmap::DashMap;
use radix_trie::{SubTrie, Trie, TrieCommon};
use tokio::sync::RwLock;
use serde_json::json;
use serde::{Serialize,Deserialize};
use std::collections::HashMap;
use std::ops::Deref;
use axum::routing::post;
use time::format_description::well_known::iso8601::Config;
use tokio::task::{JoinHandle};
use tower_http::services::ServeDir;
use futures::future;
use sha2::{Sha256, Digest};


#[derive(Clone)]
enum AntibotTypes{
    CAPTCHA,
    PoW,
    CUSTOM,
    NONE
}
impl AntibotTypes{
    fn from_string(s: String) -> AntibotTypes{
        let s = s.to_lowercase();
        if s == "captcha"{
            return  AntibotTypes::CAPTCHA;
        }
        else if s == "pow"{
            return  AntibotTypes::PoW;
        }
        else if s == "custom"{
            return  AntibotTypes::CUSTOM;
        }
        else {  return AntibotTypes::NONE; }
    }
}

type SafeTrie<T,V> = Arc<RwLock<Trie<T, V>>>;


const BASE_CUSTOM_CAPTCHA_CONFIG_EXAMPLE: &str= r##"{
  "verify_url": "",
  "secret_key": ""
}"##;

const BASE_CONFIG_EXAMPLE: &str = r##"
[
  [
    {
      "url": "url_str",
      "proxy_host": "0.0.0.0:0000",
      "is_blacklist_rate_limit": true,
      "rate_limit": {
        "/path1": {
          "limit": 15,
          "window": 10
        },
        "/path2": {
          "limit": 5,
          "window": 10
        }
      },
      "default_rate_limit": {
        "limit": 10,
        "window": 5
      },

      "is_blacklist_antibot": false,
      "antibot": {
        "/path3": "CAPTCHA",
        "/path4": "CUSTOM",
        "/path5": "PoW"
      },
      "default_antibot": "PoW",
      "is_secure": true,
      "cert_path": "ssl/cert.pem",
      "cert_key_path": "ssl/key.pem"
    },
    {
      "url": "url_str2",
      "proxy_host": "0.0.0.0:0001",
      "is_blacklist_rate_limit": true,
      "rate_limit": {
        "/path1": {
          "limit": 15,
          "window": 10
        },
        "/path2": {
          "limit": 5,
          "window": 10
        }
      },
      "default_rate_limit": {
        "limit": 10,
        "window": 5
      },

      "is_blacklist_antibot": false,
      "antibot": {
        "/path3": "CAPTCHA",
        "/path4": "CUSTOM",
        "/path5": "PoW"
      },
      "default_antibot": "PoW",
      "is_secure": false,
      "cert_path": "",
      "cert_key_path": ""
    }
  ]
]
"##;


#[derive(Clone)]
struct Conf {
    url: String,
    proxy_host: String,
    is_blacklist_rate_limit: bool,
    rate_limit_state: SafeTrie<String, RateLimitState>,
    default_rate_limit_state: RateLimitState,

    is_blacklist_antibot: bool,
    antibot: SafeTrie<String, AntibotTypes>,
    default_antibot: AntibotTypes,

    is_secure: bool,
    cert_path: String,
    cert_key_path: String
}
impl Conf {
    fn default()-> Self{
        Self{
            url: "".to_string(),
            proxy_host: "".to_string(),
            is_blacklist_rate_limit: false,
            rate_limit_state: SafeTrie::<String, RateLimitState>::new(RwLock::<Trie<String,RateLimitState>>::new(Trie::<String, crate::RateLimitState>::new())),
            default_rate_limit_state: RateLimitState::new(0,0),

            is_blacklist_antibot: false,
            antibot: SafeTrie::<String, AntibotTypes>::new(RwLock::<Trie<String,AntibotTypes>>::new(Trie::<String, crate::AntibotTypes>::new())),

            default_antibot: AntibotTypes::CUSTOM,

            is_secure: false,

            cert_path: "".to_string(),
            cert_key_path: "".to_string()
        }
    }
    async fn from_raw(raw_config: ConfRawBlock) -> Self{
        let mut rate_limit_state: SafeTrie<String,RateLimitState> = SafeTrie::new(RwLock::new(Trie::new()));
        {
            let mut write_cursor = rate_limit_state.write().await;
            for e in raw_config.rate_limit {
                write_cursor.insert(e.0, RateLimitState::from_conf(e.1));
            }
        }
        let default_rate_limit = RateLimitState::from_conf(raw_config.default_rate_limit);

        let mut antibot: SafeTrie<String,AntibotTypes> = SafeTrie::new(RwLock::new(Trie::new()));
        {
            let mut write_cursor = antibot.write().await;
            for e in raw_config.antibot {
                write_cursor.insert(e.0, AntibotTypes::from_string(e.1));
            }
        }
        let default_antibot = AntibotTypes::from_string(raw_config.default_antibot);

        Self{
            url: raw_config.url,
            proxy_host: raw_config.proxy_host,
            is_blacklist_rate_limit: raw_config.is_blacklist_rate_limit,
            rate_limit_state: rate_limit_state,
            default_rate_limit_state: default_rate_limit,

            is_blacklist_antibot: raw_config.is_blacklist_antibot,
            antibot: antibot,

            default_antibot: default_antibot,

            is_secure: raw_config.is_secure,

            cert_path: raw_config.cert_path,
            cert_key_path: raw_config.cert_key_path
        }
    }
}

#[derive(Clone,Deserialize,Debug)]
struct RateLimitConf{
    limit: usize,
    window: u32,
}

#[derive(Clone)]
struct RateLimitState {
    hits: Arc<DashMap<String, (usize, std::time::Instant)>>,
    limit: usize,
    window: u32,
}
impl RateLimitState {
    pub fn new(_limit: usize, _window: u32) -> Self {
        Self{
            hits: Arc::new(DashMap::new()),
            limit: _limit,
            window: _window,
        }
    }
    pub fn from_conf(conf: RateLimitConf) -> Self {
        Self{
            hits: Arc::new(DashMap::new()),
            limit: conf.limit,
            window: conf.window,
        }
    }
    pub fn check_rate_limit(&self, ip: &String) -> usize{

        let mut session  = self.hits.entry(ip.to_string()).or_insert((0, Instant::now()));


        let ( count, mut start) = *session;
        session.value_mut().0+=1;
        if (start.elapsed()>std::time::Duration::from_secs(self.window as u64)){
            session.value_mut().1= Instant::now();
            session.value_mut().0 =1;
        }
        if (session.value_mut().0>self.limit){
           return 429
        }
        200
    }
}

#[derive(Deserialize,Debug)]
struct ConfRawBlock {
    url: String,
    proxy_host: String,

    is_blacklist_rate_limit: bool,
    rate_limit: HashMap<String, RateLimitConf>,
    default_rate_limit: RateLimitConf,

    is_blacklist_antibot: bool,
    antibot: HashMap<String, String>,
    default_antibot: String,
    is_secure: bool,
    cert_path: String,
    cert_key_path: String
}

#[derive(Deserialize,Debug)]
struct RawConfig{
    body: Vec<ConfRawBlock>,
}

static CLIENT: Lazy<Arc<Client>> = Lazy::new(|| {
    let client = Client::builder()
        .no_gzip()
        .no_deflate()
        .pool_max_idle_per_host(50)
        .build()
        .expect("PANIC! Failed to create reqwest client");

    Arc::new(client)
});

static SECRET_KEY: Lazy<tower_cookies::cookie::Key> = Lazy::new(||Key::from(&read_secret_key(".SECRETKEY")));
#[derive(Template)]
#[template(path = "502.html")]
struct E502Template;

#[derive(Template)]
#[template(path = "500.html")]
struct E500Template;


#[derive(Template)]
#[template(path = "504.html")]
struct E504Template;

#[derive(Template)]
#[template(path = "429.html")]
struct E429Template;

#[derive(Template)]
#[template(path = "custom.html")]
struct CustomTemplate;

#[derive(Template)]
#[template(path = "captcha.html")]
struct CaptchaTemplate;

#[derive(Template)]
#[template(path = "PoW.html")]
struct PoWTemplate;

#[derive(Deserialize)]
struct TokenRequest {
    token: String,
}

#[derive(Deserialize)]
struct TurnstileResponse {
    success: bool,
    #[serde(default)]
    challenge_ts: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    error_codes: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct PoWRequest{
    bits: u32,
    token: String,
    nonce: u32,
}
#[derive(Deserialize,Clone)]
struct custom_captcha_conf{
    verify_url: String,
    secret_key: String
}
impl custom_captcha_conf{
    fn default()->Self{
        Self{
            verify_url: "".to_string(),
            secret_key: "".to_string(),
        }
    }
}

static E502: Lazy<String> = Lazy::<String>::new(|| E502Template.render().unwrap_or("502".to_string()));

static E500: Lazy<String> = Lazy::<String>::new(|| E500Template.render().unwrap_or("500".to_string()));
static E504: Lazy<String> = Lazy::<String>::new(|| E504Template.render().unwrap_or("504".to_string()));
static E429: Lazy<String> = Lazy::<String>::new(|| E429Template.render().unwrap_or("429".to_string()));

static Custom: Lazy<String> = Lazy::<String>::new(|| CustomTemplate.render().unwrap_or("500".to_string()));

static Captcha: Lazy<String> = Lazy::<String>::new(|| CaptchaTemplate.render().unwrap_or("500".to_string()));

static PoW: Lazy<String> = Lazy::<String>::new(|| PoWTemplate.render().unwrap_or("500".to_string()));

async fn index_p(Path(path): Path<PathBuf>,ConnectInfo(addr): ConnectInfo<SocketAddr>,headers: HeaderMap,Extension(conf): Extension<Conf>,) -> impl IntoResponse {
    let client = CLIENT.clone();

    let mut req = client.get(format!("{}/{}",conf.url, path.to_string_lossy()));

    for (name, value) in headers.iter() {
        if name != "host" && name != "content-length" && name != "date" && name!="Transfer-Encoding"&& name != "connection" && name != "content-encoding" && name != "date"  {
            req = req.header(name, value);
        }
    }
    let client_xff = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_xff = if client_xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", client_xff, addr)
    };

    req = req.header("X-Forwarded-For", new_xff);
    let result = match req.send().await{
        Ok(r) => r,
        Err(error) => {

            if error.is_timeout() {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::response::Html(E504.as_str())
                ).into_response();
            }

             return (
                    StatusCode::BAD_GATEWAY,
                    axum::response::Html(E502.as_str())
                ).into_response();
        }
    };



    let status = result.status();

    let rc = result.headers().clone();


    let body = Body::wrap_stream(result.bytes_stream());
    let mut response = Response::new(body);

    for z in rc.iter(){
        response.headers_mut().insert(z.0, z.1.clone());

    }

    *response.status_mut() = StatusCode::from_u16(status.as_u16()).unwrap_or_default();

    let xff = response
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_value = if xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", xff, addr)
    };

    response.headers_mut().insert(
        "X-Forwarded-For",
        HeaderValue::from_str(&new_value).unwrap_or(HeaderValue::from_static("")),
    );


    response.into_response()
}

async fn index(ConnectInfo(addr): ConnectInfo<SocketAddr>,headers: HeaderMap,Extension(conf): Extension<Conf>) -> impl IntoResponse {
    let client = CLIENT.clone();

    let mut req = client.get(conf.url);

    for (name, value) in headers.iter() {
        if name != "host" && name != "content-length" && name != "date" && name!="Transfer-Encoding"&& name != "connection" && name != "content-encoding" && name != "date" {
            req = req.header(name, value);
        }
    }

    let client_xff = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_xff = if client_xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", client_xff, addr)
    };

    req = req.header("X-Forwarded-For", new_xff);

    let result = match req.send().await{
        Ok(r) => r,
        Err(error) => {

            if error.is_timeout() {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::response::Html(E504.as_str())
                ).into_response();
            }

             return (
                    StatusCode::BAD_GATEWAY,
                    axum::response::Html(E502.as_str())
                ).into_response();
        }
    };


    let status = result.status();


    let rc = result.headers().clone();

    let body = Body::wrap_stream(result.bytes_stream());
    let mut response = Response::new(body).into_response();


    *response.status_mut() =  status;
    let xff = response
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_value = if xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", xff, addr)
    };

    for z in rc.iter(){
        response.headers_mut().insert(z.0, z.1.clone());

    }


    response.headers_mut().insert(
        "X-Forwarded-For",
        HeaderValue::from_str(&new_value).unwrap_or(HeaderValue::from_static("")),
    );

    response
}

async fn post_index(ConnectInfo(addr): ConnectInfo<SocketAddr>,Extension(conf): Extension<Conf>,headers: HeaderMap, body: Bytes) -> impl IntoResponse {



    let client = CLIENT.clone();

    let mut  req = client.post(conf.url).body(body);


    for (name, value) in headers.iter() {
        if name != "host" && name != "content-length" && name != "date" && name!="Transfer-Encoding"&& name != "connection" && name != "content-encoding" && name != "date" {
            req = req.header(name, value);
        }
    }

    let client_xff = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_xff = if client_xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", client_xff, addr)
    };

    req = req.header("X-Forwarded-For", new_xff);

    let result = match req.send().await{
        Ok(r) => r,
        Err(error) => {

            if error.is_timeout() {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::response::Html(E504.as_str())
                ).into_response();
            }

             return (
                    StatusCode::BAD_GATEWAY,
                    axum::response::Html(E502.as_str())
                ).into_response();
        }
    };

    let status = result.status();
    let rc = result.headers().clone();

    let body = Body::wrap_stream(result.bytes_stream());
    let mut response = Response::new(body);

    for z in rc.iter(){
        response.headers_mut().insert(z.0, z.1.clone());

    }
    *response.status_mut() =  status;

    let xff = response
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_value = if xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", xff, addr)
    };

    response.headers_mut().insert(
        "X-Forwarded-For",
        HeaderValue::from_str(&new_value).unwrap_or(HeaderValue::from_static("")),
    );




    response.into_response()

}

async fn post_index_p(Path(path): Path<PathBuf>,ConnectInfo(addr): ConnectInfo<SocketAddr>,headers: HeaderMap,Extension(conf): Extension<Conf>, body: Bytes) -> impl IntoResponse {

    let client = CLIENT.clone();

    let mut  req = client.post(format!("{}/{}",conf.url,path.to_string_lossy())).body(body);


    for (name, value) in headers.iter() {
        if name != "host" && name != "content-length" && name != "date" && name!="Transfer-Encoding"&& name != "connection" && name != "content-encoding" && name != "date" {
            req = req.header(name, value);
        }
    }

    let client_xff = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_xff = if client_xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", client_xff, addr)
    };

    req = req.header("X-Forwarded-For", new_xff);

    let result = match req.send().await{
        Ok(r) => r,
        Err(error) => {

            if error.is_timeout() {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::response::Html(E504.as_str())
                ).into_response();
            }

             return (
                    StatusCode::BAD_GATEWAY,
                    axum::response::Html(E502.as_str())
                ).into_response();
        }
    };

    let status = result.status();
    let rc = result.headers().clone();

    let body = Body::wrap_stream(result.bytes_stream());
    let mut response = Response::new(body);

    for z in rc.iter(){
        response.headers_mut().insert(z.0, z.1.clone());

    }
    *response.status_mut() =  status;

    let xff = response
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_value = if xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", xff, addr)
    };

    response.headers_mut().insert(
        "X-Forwarded-For",
        HeaderValue::from_str(&new_value).unwrap_or(HeaderValue::from_static("")),
    );


    response.into_response()

}

async fn put_index_p(Path(path): Path<PathBuf>,ConnectInfo(addr): ConnectInfo<SocketAddr>,Extension(conf): Extension<Conf>,headers: HeaderMap, body: Bytes) -> impl IntoResponse {

    let client = CLIENT.clone();

    let mut  req = client.put(format!("{}/{}",conf.url, path.to_string_lossy())).body(body);


    for (name, value) in headers.iter() {
        if name != "host" && name != "content-length" && name != "date" && name!="Transfer-Encoding"&& name != "connection" && name != "content-encoding" && name != "date" {
            req = req.header(name, value);
        }
    }

    let client_xff = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_xff = if client_xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", client_xff, addr)
    };

    req = req.header("X-Forwarded-For", new_xff);

    let result = match req.send().await{
        Ok(r) => r,
        Err(error) => {

            if error.is_timeout() {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::response::Html(E504.as_str())
                ).into_response();
            }

             return (
                    StatusCode::BAD_GATEWAY,
                    axum::response::Html(E502.as_str())
                ).into_response();
        }
    };

    let status = result.status();
    let rc = result.headers().clone();

    let body = Body::wrap_stream(result.bytes_stream());
    let mut response = Response::new(body);

    for z in rc.iter(){
        response.headers_mut().insert(z.0, z.1.clone());

    }
    *response.status_mut() =  status;

    let xff = response
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_value = if xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", xff, addr)
    };

    response.headers_mut().insert(
        "X-Forwarded-For",
        HeaderValue::from_str(&new_value).unwrap_or(HeaderValue::from_static("")),
    );


    response.into_response()

}

async fn put_index(ConnectInfo(addr): ConnectInfo<SocketAddr>,Extension(conf): Extension<Conf>,headers: HeaderMap, body: Bytes) -> impl IntoResponse {

    let client = CLIENT.clone();

    let mut  req = client.put(conf.url).body(body);


    for (name, value) in headers.iter() {
        if name != "host" && name != "content-length" && name != "date" && name!="Transfer-Encoding"&& name != "connection" && name != "content-encoding" && name != "date" {
            req = req.header(name, value);
        }
    }

    let client_xff = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_xff = if client_xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", client_xff, addr)
    };

    req = req.header("X-Forwarded-For", new_xff);

    let result = match req.send().await{
        Ok(r) => r,
        Err(error) => {

            if error.is_timeout() {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::response::Html(E504.as_str())
                ).into_response();
            }

             return (
                    StatusCode::BAD_GATEWAY,
                    axum::response::Html(E502.as_str())
                ).into_response();
        }
    };
    let status = result.status();
    let rc = result.headers().clone();

    let body = Body::wrap_stream(result.bytes_stream());
    let mut response = Response::new(body);

    for z in rc.iter(){
        response.headers_mut().insert(z.0, z.1.clone());

    }
    *response.status_mut() =  status;

    let xff = response
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_value = if xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", xff, addr)
    };

    response.headers_mut().insert(
        "X-Forwarded-For",
        HeaderValue::from_str(&new_value).unwrap_or(HeaderValue::from_static("")),
    );




    response.into_response()

}

async fn patch_index(ConnectInfo(addr): ConnectInfo<SocketAddr>,Extension(conf): Extension<Conf>,headers: HeaderMap, body: Bytes) -> impl IntoResponse {

    let client = CLIENT.clone();

    let mut  req = client.patch(conf.url).body(body);


    for (name, value) in headers.iter() {
        if name != "host" && name != "content-length" && name != "date" && name!="Transfer-Encoding"&& name != "connection" && name != "content-encoding" && name != "date" {
            req = req.header(name, value);
        }
    }

    let client_xff = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_xff = if client_xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", client_xff, addr)
    };

    req = req.header("X-Forwarded-For", new_xff);

    let result = match req.send().await{
        Ok(r) => r,
        Err(error) => {

            if error.is_timeout() {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::response::Html(E504.as_str())
                ).into_response();
            }

             return (
                    StatusCode::BAD_GATEWAY,
                    axum::response::Html(E502.as_str())
                ).into_response();
        }
    };

    let status = result.status();
    let rc = result.headers().clone();

    let body = Body::wrap_stream(result.bytes_stream());
    let mut response = Response::new(body);

    for z in rc.iter(){
        response.headers_mut().insert(z.0, z.1.clone());

    }
    *response.status_mut() =  status;

    let xff = response
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_value = if xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", xff, addr)
    };

    response.headers_mut().insert(
        "X-Forwarded-For",
        HeaderValue::from_str(&new_value).unwrap_or(HeaderValue::from_static("")),
    );




    response.into_response()

}

async fn patch_index_p(Path(path): Path<PathBuf>,ConnectInfo(addr): ConnectInfo<SocketAddr>,Extension(conf): Extension<Conf>,headers: HeaderMap, body: Bytes) -> impl IntoResponse {

    let client = CLIENT.clone();

    let mut  req = client.patch(format!("{}/{}",conf.url, path.to_string_lossy())).body(body);


    for (name, value) in headers.iter() {
        if name != "host" && name != "content-length" && name != "date" && name!="Transfer-Encoding"&& name != "connection" && name != "content-encoding" && name != "date" {
            req = req.header(name, value);
        }
    }

    let client_xff = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_xff = if client_xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", client_xff, addr)
    };

    req = req.header("X-Forwarded-For", new_xff);

    let result = match req.send().await{
        Ok(r) => r,
        Err(error) => {

            if error.is_timeout() {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::response::Html(E504.as_str())
                ).into_response();
            }

             return (
                    StatusCode::BAD_GATEWAY,
                    axum::response::Html(E502.as_str())
                ).into_response();
        }
    };

    let status = result.status();
    let rc = result.headers().clone();

    let body = Body::wrap_stream(result.bytes_stream());
    let mut response = Response::new(body);

    for z in rc.iter(){
        response.headers_mut().insert(z.0, z.1.clone());

    }
    *response.status_mut() =  status;

    let xff = response
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_value = if xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", xff, addr)
    };

    response.headers_mut().insert(
        "X-Forwarded-For",
        HeaderValue::from_str(&new_value).unwrap_or(HeaderValue::from_static("")),
    );


    response.into_response()

}

async fn delete_index(ConnectInfo(addr): ConnectInfo<SocketAddr>,Extension(conf): Extension<Conf>,headers: HeaderMap, body: Bytes) -> impl IntoResponse {

    let client = CLIENT.clone();

    let mut  req = client.delete(conf.url).body(body);


    for (name, value) in headers.iter() {
        if name != "host" && name != "content-length" && name != "date" && name!="Transfer-Encoding"&& name != "connection" && name != "content-encoding" && name != "date" {
            req = req.header(name, value);
        }
    }

    let client_xff = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_xff = if client_xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", client_xff, addr)
    };

    req = req.header("X-Forwarded-For", new_xff);

    let result = match req.send().await{
        Ok(r) => r,
        Err(error) => {

            if error.is_timeout() {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::response::Html(E504.as_str())
                ).into_response();
            }

            return (
                    StatusCode::BAD_GATEWAY,
                    axum::response::Html(E502.as_str())
                ).into_response();

        }
    };

    let status = result.status();
    let rc = result.headers().clone();

    let body = Body::wrap_stream(result.bytes_stream());
    let mut response = Response::new(body);

    for z in rc.iter(){
        response.headers_mut().insert(z.0, z.1.clone());

    }
    *response.status_mut() =  status;

    let xff = response
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_value = if xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", xff, addr)
    };

    response.headers_mut().insert(
        "X-Forwarded-For",
        HeaderValue::from_str(&new_value).unwrap_or(HeaderValue::from_static("")),
    );




    response.into_response()

}

async fn delete_index_p(Path(path): Path<PathBuf>,ConnectInfo(addr): ConnectInfo<SocketAddr>,Extension(conf): Extension<Conf>,headers: HeaderMap, body: Bytes) -> impl IntoResponse {

    let client = CLIENT.clone();

    let mut  req = client.delete(format!("{}/{}",conf.url,path.to_string_lossy())).body(body);

    for (name, value) in headers.iter() {
        if name != "host" && name != "content-length" && name != "date" && name!="Transfer-Encoding"&& name != "connection" && name != "content-encoding" && name != "date" {
            req = req.header(name, value);
        }
    }

    let client_xff = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_xff = if client_xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", client_xff, addr)
    };

    req = req.header("X-Forwarded-For", new_xff);

    let result = match req.send().await{
        Ok(r) => r,
        Err(error) => {

            if error.is_timeout() {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    axum::response::Html(E504.as_str())
                ).into_response();
            }

             return (
                    StatusCode::BAD_GATEWAY,
                    axum::response::Html(E502.as_str())
                ).into_response();
        }
    };

    let status = result.status();
    let rc = result.headers().clone();

    let body = Body::wrap_stream(result.bytes_stream());
    let mut response = Response::new(body);

    for z in rc.iter(){
        response.headers_mut().insert(z.0, z.1.clone());

    }
    *response.status_mut() =  status;

    let xff = response
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_value = if xff.is_empty() {
        addr.to_string()
    } else {
        format!("{}, {}", xff, addr)
    };

    response.headers_mut().insert(
        "X-Forwarded-For",
        HeaderValue::from_str(&new_value).unwrap_or(HeaderValue::from_static("")),
    );


    response.into_response()

}

async fn check_cookie(ConnectInfo(addr): ConnectInfo<SocketAddr>, request: axum::http::Request<axum::body::Body>, next: axum::middleware::Next) -> impl IntoResponse {
    let cookies = request.extensions().get::<Cookies>().unwrap_or(&Cookies::default()).clone();
    let ip = addr.ip().to_string();


    let conf = match request.extensions().get::<Conf>(){
        Some(conf) => conf,
        None =>{println!("NO CONFIG. RETURNED 500"); return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::response::Html(E500.as_str())
        ).into_response()}
    };
    let request_path = std::path::Path::new(request.uri().path());

    // ===== RATE LIMIT =====
    if conf.is_blacklist_rate_limit == true {
        let state = conf.rate_limit_state.read().await;

        match state.get_ancestor(request.uri().path()) {
            Some(h) => {
                for (key, _rate_limit_state) in h.iter() {
                    let config_path = std::path::Path::new(key);
                    if request_path.starts_with(config_path) {
                        if _rate_limit_state.check_rate_limit(&ip) == 429 {
                            return (
                                StatusCode::TOO_MANY_REQUESTS,
                                axum::response::Html(E429.as_str())
                            ).into_response();
                        }
                        break;
                    }
                }
            }
            None => {}
        }


    } else {
        let state = conf.rate_limit_state.read().await;
        let mut empty = true;
        match state.get_ancestor(request.uri().path()) {
            Some(h) => {
                for (key, _rate_limit_state) in h.iter() {
                    let config_path = std::path::Path::new(key);
                    if request_path.starts_with(config_path) {

                        empty = false;
                        break;
                    }
                }
            }
            None => {}
        }
        if empty {
            let state = &conf.default_rate_limit_state;
            if state.check_rate_limit(&ip) == 429 {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    axum::response::Html(E429.as_str())
                ).into_response();

            }
        }
    }

    // ===== ANTIBOT =====
    let user_cookie = cookies.signed(&SECRET_KEY).get("checked")
        .map(|c| c.value().to_string())
        .unwrap_or("none".into());

    if conf.is_blacklist_antibot == false {
        let state = conf.antibot.read().await;

        match state.get_ancestor(request.uri().path()) {
            Some(h) => {
                for (key, antbt) in h.iter() {
                    let config_path = std::path::Path::new(key);
                    if request_path.starts_with(config_path) {
                        if matches!( antbt , AntibotTypes::PoW) && user_cookie != "1" {
                            return (
                                StatusCode::OK,
                                axum::response::Html(PoW.as_str())
                            ).into_response();
                        }
                        else if matches!( antbt , AntibotTypes::CAPTCHA) && user_cookie != "1" {
                            return (
                                StatusCode::OK,
                                axum::response::Html(Captcha.as_str())
                            ).into_response();
                        }
                        else if user_cookie != "1" {
                            return (
                                StatusCode::OK,
                                axum::response::Html(Custom.as_str())
                            ).into_response();
                        }
                        break
                    }
                }


            }
            None => {}
        }



    } else {
        let state = conf.antibot.read().await;
        let mut empty = true;

        match state.get_ancestor(request.uri().path()) {
            Some(h) => {
                for (key, _antibot_type) in state.iter() {
                    let config_path = std::path::Path::new(key);
                    if request_path.starts_with(config_path) {
                        empty = false;
                        break;
                    }
                }
            }
            None => {}
        }

        if empty {
            if matches!(conf.default_antibot , AntibotTypes::PoW) && user_cookie != "1" {
                return (
                    StatusCode::OK,
                    axum::response::Html(PoW.as_str())
                ).into_response();
            }
            else if matches!(conf.default_antibot , AntibotTypes::CAPTCHA) && user_cookie != "1" {
                return (
                    StatusCode::OK,
                    axum::response::Html(Captcha.as_str())
                ).into_response();
            }
            else if matches!(conf.default_antibot , AntibotTypes::CUSTOM) && user_cookie != "1" {
                return (
                    StatusCode::OK,
                    axum::response::Html(Custom.as_str())
                ).into_response();
            }
        }
    }

    next.run(request).await
}

async fn check_fs_rate_limit(ConnectInfo(addr): ConnectInfo<SocketAddr>, request: axum::http::Request<axum::body::Body>, next: axum::middleware::Next) -> impl IntoResponse {
    let ip = addr.ip().to_string();


    let conf = match request.extensions().get::<Conf>(){
        Some(conf) => conf,
        None =>{println!("NO CONFIG. RETURNED 500"); return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::response::Html(E500.as_str())
        ).into_response()}
    };

    let state = &conf.default_rate_limit_state;
    if state.check_rate_limit(&ip) == 429 {
        return E429Template.render().unwrap_or("429".to_string()).into_response()

    }

    next.run(request).await
}

async fn tokenver( request: axum::http::Request<axum::body::Body>)-> Response{
    let client = CLIENT.clone();
    let cookies = request.extensions().get::<Cookies>().unwrap_or(&Cookies::default()).clone();
    let ccf = request.extensions().get::<custom_captcha_conf>().unwrap_or(&custom_captcha_conf::default()).clone();
    let b = request.into_body();
    let bytes: Bytes = match axum::body::to_bytes(b,1024 * 64).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let payload: TokenRequest = match serde_json::from_slice(&bytes){
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let params = [("secret", ccf.secret_key), ("response", payload.token)];

    let mut req = client.post(ccf.verify_url).form(&params);

    let result = match req.send().await{
        Ok(r) => r,
        Err(error) => {

            if error.is_timeout() {
                return (StatusCode::GATEWAY_TIMEOUT).into_response();
            }

            return (StatusCode::BAD_GATEWAY).into_response();
        }
    };

    let json: TurnstileResponse = result.json().await.unwrap_or(TurnstileResponse {
        success: false,
        challenge_ts: None,
        hostname: None,
        error_codes: None,
    });

    if json.success {
        let mut ck = Cookie::new("checked", "1");
        ck.set_path("/");
        ck.set_max_age(Duration::hours(36));
        ck.set_same_site(tower_cookies::cookie::SameSite::Strict);
        cookies.signed(&SECRET_KEY).add(ck);
        return (StatusCode::OK).into_response();
    }

    return (StatusCode::BAD_REQUEST).into_response();
}

async fn powver( request: axum::http::Request<axum::body::Body>)-> Response{
    let cookies = request.extensions().get::<Cookies>().unwrap_or(&Cookies::default()).clone();
    let b = request.into_body();
    let bytes: Bytes = match axum::body::to_bytes(b,1024 * 64).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let payload: PoWRequest = match serde_json::from_slice(&bytes){
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };


    let mut hasher = sha2::Sha256::new();

    let str = format!("{}{}",payload.token,payload.nonce);

    hasher.update(str.as_bytes());

    let fullbytes = payload.bits/8;
    let lastbits = payload.bits%8;

    let hash = hasher.finalize();

    for i in 0..fullbytes as usize {
        if hash[i]!=0{
            return (StatusCode::BAD_REQUEST).into_response();
        }
    }
    let mask = 0xFFu8 << (8 - lastbits);
    if lastbits>0 && hash[fullbytes as usize] & mask !=0 {
        return (StatusCode::BAD_REQUEST).into_response();
    }



    let mut ck = Cookie::new("checked", "1");
    ck.set_path("/");
    ck.set_same_site(tower_cookies::cookie::SameSite::Strict);
    ck.set_max_age(Duration::hours(36));

    cookies.signed(&SECRET_KEY).add(ck);
    return (StatusCode::OK).into_response();



}

async fn verify_captcha(request: axum::http::Request<axum::body::Body>, ) -> impl IntoResponse {

    let cookies = request.extensions().get::<Cookies>().unwrap_or(&Cookies::default()).clone();
    let b = request.into_body();
    let bytes: Bytes = match axum::body::to_bytes(b,1024 * 64).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };


    let payload: captcha::HumanCheckRequest = match serde_json::from_slice(&bytes){
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };


    if captcha::is_human(payload) {
        let mut cookie = Cookie::new("checked", "1");
        cookie.set_path("/");
        cookie.set_http_only(true);
        cookie.set_max_age(Duration::hours(72));
        cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);

        cookies.signed(&SECRET_KEY).add(cookie);

        return (StatusCode::OK).into_response();

    } ;
    StatusCode::BAD_REQUEST.into_response()


}


#[tokio::main]
async fn main() {

    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .expect("install ring provider");

    let cfg = read_file_content_as_string("config.json");

    if cfg == "<config_created>".to_string() {
        println!("\nConfig file created. Name: config.json\n"); return;
    }

    let json = match serde_json::from_str::<RawConfig>(&cfg){
        Ok(json) => json,
        Err(E) => { println!("\nInvalid config file. Delete to restore structure\n"); return; }
    };

    let cfg = read_file_content_as_string("custom-captcha-config.json");

    if cfg == "<config_created>".to_string() {
        println!("\nConfig file created. Name: custom-captcha-config.json\n"); return;
    }

    let json_custom = match serde_json::from_str::<custom_captcha_conf>(&cfg){
        Ok(json) => json,
        Err(E) => { println!("\nInvalid config file. Delete to restore structure\n"); return; }
    };

    let mut handles:Vec<JoinHandle<()>> = vec![];
    let mut configs: Vec<Conf> = Vec::new();
    for e in json.body {
        configs.push(Conf::from_raw(e).await);
    }

    for e in configs {

        let fs:Router<> = Router::new()
            .route("/abotrep/verify-captcha", post(verify_captcha)).route("/abotrep/verify-token", post(tokenver)).route("/abotrep/verify-pow", post(powver)).nest_service("/abotrep/static",  ServeDir::new("static")).layer(CookieManagerLayer::new()).layer(axum::middleware::from_fn(check_fs_rate_limit)).layer(Extension(e.clone())).layer(Extension(json_custom.clone()));;

        let app = Router::new()
            .route("/{*path}",
                   get(index_p)
                       .post(post_index_p)
                       .delete(delete_index_p)
                       .put(put_index_p)
                       .patch(patch_index_p))
            .layer(axum::middleware::from_fn(check_cookie)).layer(CookieManagerLayer::new()).layer(Extension(e.clone()))

            .route("/", get(index)
                .post(post_index)
                .delete(delete_index)
                .put(put_index)
                .patch(patch_index))
            .layer(axum::middleware::from_fn(check_cookie)).layer(CookieManagerLayer::new()).layer(Extension(e.clone()));





        if e.is_secure==false {
            let handle = tokio::spawn(async move {
                match tokio::net::TcpListener::bind(&e.clone().proxy_host).await {
                    Ok(listener) => {
                        println!("Listening on http://{}", e.clone().proxy_host);
                        if let Err(err) = axum::serve(listener, fs.clone().merge(app.clone()).into_make_service_with_connect_info::<SocketAddr>()).await {
                            eprintln!("Server error: {:?}", err);
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to bind {}: {:?}", e.clone().proxy_host, err);
                        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                    }
                }
            });
            handles.push(handle);
        }
        else {
            let config = match axum_server::tls_rustls::RustlsConfig::from_pem_file(
                e.cert_path.as_str(),
                e.cert_key_path.as_str()
            ).await{
                Ok(config) => config,
                Err(_) => {println!("Invalid certificate"); return;}
            };


            let addr:Result<SocketAddr,AddrParseError> = e.proxy_host.parse();
            let handle = tokio::spawn(async move {
                match addr {
                    Ok(listener) => {
                        println!("Listening on https://{}", e.clone().proxy_host);
                        if let Err(err) = axum_server::tls_rustls::bind_rustls(listener,config).serve(fs.clone().merge(app.clone()).into_make_service_with_connect_info::<SocketAddr>()).await {
                            eprintln!("Server error: {:?}", err);
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to bind {}: {:?}", e.clone().proxy_host, err);
                        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                    }
                }
            });
            handles.push(handle);

        }
    }


    futures::future::join_all(handles).await;

}


fn read_file_content_as_string(path: &str) -> String {

    let str_content =match std::fs::read_to_string(path){
        Ok(string_content) => string_content,
        Err(_) => {
            if path == "config.json" {
                std::fs::write("config.json", BASE_CONFIG_EXAMPLE);
            }
            else {
                std::fs::write(path, BASE_CUSTOM_CAPTCHA_CONFIG_EXAMPLE);
            }
            "<config_created>".to_string()
        }
    };

    str_content
}

fn read_secret_key(path: &str) -> [u8;64]{
    let content =match std::fs::read(path){
        Ok(string_content) => string_content,
        Err(_) => {

            let key: [u8;64] = random();
            std::fs::write(".SECRETKEY", key);
            return key;
            key.to_vec()
        }
    };

    let mut key:[u8;64] = [0;64];

    if content.len() !=64{
        key = random();
        std::fs::write(".SECRETKEY", key);

    }
    else {
        for i in 0..64{
            key[i] = content[i];
        }
    }

    key
}
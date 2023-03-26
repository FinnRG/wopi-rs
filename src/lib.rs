use std::ops::Deref;

use bytes::Bytes;
use http::HeaderMap;
use thiserror::Error;

pub mod container;
pub mod content;
pub mod ecosystem;
pub mod file;

#[derive(Debug, Hash, Clone, Default)]
pub struct WopiRequest<T> {
    pub request: T,
    // Authorization
    pub access_token: Option<String>,
    // X-Request-ID
    pub request_id: Option<String>,
    // X-WOPI-AppEndpoint
    pub app_endpoint: Option<String>,
    // X-WOPI-RequestingApplication
    pub requesting_application: Option<String>,
    // X-WOPI-ClinetVersion
    pub client_version: Option<String>,
    // X-WOPI-CorrelationId
    pub correlation_id: Option<String>,
    // X-WOPI-DeviceId
    pub device_id: Option<String>,
    // X-WOPI-SessionId
    pub session_id: Option<String>,
    // X-WOPI-MachineName
    pub machine_name: Option<String>,
    // X-WOPI-Proof
    pub proof: Option<String>,
    // X-WOPI-ProofOld
    pub proof_old: Option<String>,
    // X-WOPI-TimeStamp
    pub time_stamp: Option<u64>,
}

impl<T> Deref for WopiRequest<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

impl<T: TryFrom<http::Request<B>>, B> TryFrom<http::Request<B>> for WopiRequest<T> {
    type Error = T::Error;

    fn try_from(value: http::Request<B>) -> Result<Self, Self::Error> {
        // I'm truly sorry for this abomination
        let binding = value.uri().clone();
        let binding = binding.query();
        let access_token = try_get_query(&binding, "access_token").map(ToOwned::to_owned);
        let request = value.try_into()?;
        // TODO: Add remaining properties
        Ok(Self {
            request,
            access_token,
            request_id: None,
            app_endpoint: None,
            requesting_application: None,
            client_version: None,
            correlation_id: None,
            device_id: None,
            session_id: None,
            machine_name: None,
            proof: None,
            proof_old: None,
            time_stamp: None,
        })
    }
}

#[derive(Debug, Clone, Copy, Hash)]
pub enum WopiResponse<T> {
    /// Success
    Ok(T),
    /// Invalid access token
    Unauthorized,
    /// Resource not found or user unauthorized
    NotFound,
    /// Server error
    InternalServerError,
}

impl<T> WopiResponse<T> {
    pub fn map_body<B, F: FnOnce(T) -> B>(self, f: F) -> WopiResponse<B> {
        match self {
            Self::Ok(b) => WopiResponse::Ok(f(b)),
            Self::Unauthorized => WopiResponse::Unauthorized,
            Self::NotFound => WopiResponse::NotFound,
            Self::InternalServerError => WopiResponse::InternalServerError,
        }
    }
}

impl<T: Into<http::Response<Bytes>>> From<WopiResponse<T>> for http::Response<Bytes> {
    fn from(value: WopiResponse<T>) -> Self {
        let status = match value {
            WopiResponse::Ok(resp) => return resp.into(),
            WopiResponse::Unauthorized => 401,
            WopiResponse::NotFound => 404,
            WopiResponse::InternalServerError => 500,
        };
        http::Response::builder()
            .status(status)
            .body(Bytes::new())
            .unwrap()
    }
}

#[derive(Debug, Hash, Clone)]
pub struct FileBody<B, T> {
    pub body: B,
    pub request: T,
}

impl<B, T: TryFrom<http::request::Parts, Error = WopiRequestError>> TryFrom<http::Request<B>>
    for FileBody<B, T>
{
    type Error = WopiRequestError;

    fn try_from(value: http::Request<B>) -> Result<Self, Self::Error> {
        let (parts, body) = value.into_parts();
        Ok(FileBody {
            body,
            request: T::try_from(parts)?,
        })
    }
}

impl<B, T: Into<http::Response<B>>> From<FileBody<B, T>> for http::Response<B> {
    fn from(value: FileBody<B, T>) -> Self {
        let b = value.body;
        let resp: http::Response<B> = value.request.into();
        let (parts, _) = resp.into_parts();
        http::Response::from_parts(parts, b)
    }
}

#[derive(Debug, Clone, Error)]
pub enum WopiRequestError {
    #[error("header {0} is missing")]
    MissingHeader(String),
    #[error("query parameter {0} is missing")]
    MissingQueryParameter(String),
    #[error("invalid value for header {0}")]
    InvalidHeaderValue(String),
    #[error("bad path or missing query parameter")]
    BadRequest,
}

pub(crate) fn try_get_header<'a>(
    parts: &'a impl ParameterProvider,
    header: &str,
) -> Result<&'a str, WopiRequestError> {
    parts
        .get_headers()
        .get(header)
        .ok_or(WopiRequestError::MissingHeader(header.into()))?
        .to_str()
        .map_err(|_| WopiRequestError::InvalidHeaderValue(header.into()))
}

trait ParameterProvider {
    fn get_headers(&self) -> &HeaderMap;
    fn get_query(&self) -> Option<&str>;
}

impl<T> ParameterProvider for http::Request<T> {
    fn get_headers(&self) -> &HeaderMap {
        self.headers()
    }

    fn get_query(&self) -> Option<&str> {
        self.uri().query()
    }
}

impl ParameterProvider for http::request::Parts {
    fn get_headers(&self) -> &HeaderMap {
        &self.headers
    }

    fn get_query(&self) -> Option<&str> {
        self.uri.query()
    }
}

impl ParameterProvider for &str {
    fn get_headers(&self) -> &HeaderMap {
        unimplemented!()
    }

    fn get_query(&self) -> Option<&str> {
        Some(self)
    }
}

impl<T: ParameterProvider> ParameterProvider for Option<T> {
    fn get_headers(&self) -> &HeaderMap {
        unimplemented!()
    }

    fn get_query(&self) -> Option<&str> {
        self.as_ref().and_then(ParameterProvider::get_query)
    }
}

#[allow(unused)]
pub(crate) fn try_get_query<'a>(req: &'a impl ParameterProvider, param: &str) -> Option<&'a str> {
    let prefix = String::from(param) + "=";
    req.get_query()?
        .split('&')
        .find(|x| x.starts_with(&prefix))?
        .split('=')
        .nth(1)
}

mod macros {
    macro_rules! derive_ref {
        ($t:ty) => {
            impl From<$t> for http::Response<bytes::Bytes> {
                fn from(value: $t) -> Self {
                    (&value).into()
                }
            }
        };
    }
    pub(crate) use derive_ref;
}

#[cfg(test)]
mod tests {

    fn run_try_get_query(query: &str, param: &str) -> Option<String> {
        let req = http::Request::builder()
            .method("GET")
            .uri(&format!("https://example.com?{}", query))
            .body(())
            .unwrap();
        super::try_get_query(&req, param).map(|x| String::from(x))
    }

    #[test]
    fn test_simple_query() {
        let res = run_try_get_query("param1=Test", "param1");
        assert_eq!(res, Some("Test".into()));
    }

    #[test]
    fn test_empty_query() {
        let res = run_try_get_query("param1=&param2=Test", "param2");
        assert_eq!(res, Some("Test".into()));
    }

    #[test]
    fn test_empty_query2() {
        let res = run_try_get_query("param1=&param2=", "param2");
        assert_eq!(res, Some("".into()));
    }

    #[test]
    fn test_multi_query() {
        let res = run_try_get_query("param1=Check&param2=Test", "param2");
        assert_eq!(res, Some("Test".into()));
    }

    #[test]
    fn test_prefix_query() {
        let res = run_try_get_query("para=Check&param=Test", "param");
        assert_eq!(res, Some("Test".into()));
    }

    #[test]
    fn test_nonexistent_query() {
        let res = run_try_get_query("param=C&param2=D", "param3");
        assert_eq!(res, None);
    }
}

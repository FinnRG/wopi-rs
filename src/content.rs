use bytes::Bytes;

use crate::{
    file::{GetFileRequest, GetFileResponse},
    macros::derive_ref,
    try_get_header, FileBody, WopiRequestError,
};

derive_ref!(PutFileResponse);

#[derive(Debug, Clone, Hash)]
pub struct FileContentRequest<B> {
    pub file_id: String,
    pub request: FileContentRequestType<B>,
}

#[derive(Debug, Clone, Hash)]
pub struct FileContentResponse<B> {
    pub response: FileContentResponseType<B>,
}

impl<B> TryFrom<http::Request<B>> for FileContentRequest<B> {
    type Error = WopiRequestError;

    fn try_from(req: http::Request<B>) -> Result<Self, Self::Error> {
        let file_id = req
            .uri()
            .path()
            .split('/')
            .rev()
            .nth(1)
            .ok_or(WopiRequestError::BadRequest)?;
        Ok(FileContentRequest {
            file_id: file_id.to_owned(),
            request: req.try_into()?,
        })
    }
}

impl From<FileContentResponse<Bytes>> for http::Response<Bytes> {
    fn from(value: FileContentResponse<Bytes>) -> Self {
        value.response.into()
    }
}

#[derive(Debug, Clone, Hash, derive_more::From)]
pub enum FileContentRequestType<B> {
    GetFile(GetFileRequest),
    PutFile(FileBody<B, PutFileRequest>),
}

#[derive(Debug, Clone, Hash)]
pub enum FileContentResponseType<B> {
    GetFile(FileBody<B, GetFileResponse>),
    PutFile(PutFileResponse),
}

impl<B> TryFrom<http::Request<B>> for FileContentRequestType<B> {
    type Error = WopiRequestError;

    fn try_from(req: http::Request<B>) -> Result<Self, Self::Error> {
        let resp = match try_get_header(&req, "X-WOPI-Override").unwrap_or_default() {
            "PUT" => {
                let (parts, body) = req.into_parts();
                let request = PutFileRequest::try_from(parts)?;
                FileContentRequestType::PutFile(FileBody { body, request })
            }
            _ => FileContentRequestType::GetFile(GetFileRequest::try_from(req.into_parts().0)?),
        };
        Ok(resp)
    }
}

impl From<FileContentResponseType<Bytes>> for http::Response<Bytes> {
    fn from(value: FileContentResponseType<Bytes>) -> Self {
        match value {
            FileContentResponseType::GetFile(e) => e.into(),
            FileContentResponseType::PutFile(e) => e.into(),
        }
    }
}

#[derive(Debug, Clone, Hash)]
pub struct PutFileRequest {
    /// A string provided by the WOPI client in a previous Lock request. This
    /// header isn't included during document creation.
    pub lock: Option<String>,
    /// A list of UserId values representing all the users who contributed
    /// changes to the document in this PutFile request.
    pub editors: Vec<String>,
}

/// PutFile Response
///
/// The PutFile operation updates a file’s binary contents.
#[derive(Debug, Clone, Hash)]
pub enum PutFileResponse {
    Ok {
        /// An optional string value indicating the version of the file. Its
        /// value should be the same as Version value in CheckFileInfo.
        item_version: Option<String>,
    },
    ///  Lock mismatch or locked by another interface.
    Conflict {
        /// A string value identifying the current lock on the file.
        lock: String,

        /// An optional string value indicating the cause of a lock failure.
        /// There's no standard for how this string is formatted, and it must
        /// only be used for logging purposes.
        lock_failure_reason: Option<String>,
    },

    /// File is too large. The maximum file size is host-specific.
    TooLarge,
}

impl TryFrom<http::request::Parts> for PutFileRequest {
    type Error = WopiRequestError;

    fn try_from(req: http::request::Parts) -> Result<Self, Self::Error> {
        let lock = match try_get_header(&req, "X-WOPI-Lock") {
            Ok(l) => Some(l.to_owned()),
            Err(WopiRequestError::MissingHeader(_)) => None,
            Err(e) => return Err(e),
        };

        let editors = match try_get_header(&req, "X-WOPI-Editors") {
            Ok(e) => e,
            Err(WopiRequestError::MissingHeader(_)) => "",
            Err(e) => return Err(e),
        };

        let editors: Vec<String> = editors
            .split_terminator(',')
            .map(str::to_owned)
            .collect::<Vec<_>>();

        Ok(PutFileRequest { lock, editors })
    }
}

impl From<&PutFileResponse> for http::Response<Bytes> {
    fn from(value: &PutFileResponse) -> Self {
        let mut resp = http::Response::builder();
        match value {
            PutFileResponse::TooLarge => {
                resp = resp.status(http::StatusCode::PAYLOAD_TOO_LARGE);
            }
            PutFileResponse::Conflict {
                lock,
                lock_failure_reason,
            } => {
                resp = resp
                    .header("X-WOPI-Lock", lock)
                    .status(http::StatusCode::CONFLICT);
                if let Some(fail) = lock_failure_reason {
                    resp = resp.header("X-WOPI-LockFailureReason", fail);
                }
            }
            PutFileResponse::Ok { item_version } => {
                if let Some(item_version) = item_version {
                    resp = resp.header("X-WOPI-ItemVersion", item_version);
                }
            }
        };
        resp.body(Bytes::new()).unwrap()
    }
}

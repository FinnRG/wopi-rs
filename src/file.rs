use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::{macros::derive_ref, try_get_header, FileBody, WopiRequestError};

derive_ref!(CheckFileInfoResponse);
derive_ref!(LockResponse);
derive_ref!(PutRelativeFileResponse);
derive_ref!(GetFileResponse);

#[derive(Debug, Clone, Hash)]
pub struct FileRequest<B> {
    pub file_id: String,
    pub request: FileRequestType<B>,
}

#[derive(Debug, Clone, Hash)]
pub struct FileResponse<B> {
    pub response: FileResponseType<B>,
}

fn is_content(s: &str) -> bool {
    s.split('/')
        .rev()
        .nth(1)
        .map(|s| s == "content")
        .unwrap_or_default()
}

impl<B> TryFrom<http::Request<B>> for FileRequest<B> {
    type Error = WopiRequestError;

    fn try_from(req: http::Request<B>) -> Result<Self, Self::Error> {
        let path = req.uri().path();
        let mut file_id = path.split('/').last().ok_or(WopiRequestError::BadRequest)?;
        if file_id == "contents" {
            file_id = path
                .split('/')
                .rev()
                .nth(1)
                .ok_or(WopiRequestError::BadRequest)?;
        }
        Ok(FileRequest {
            file_id: file_id.to_owned(),
            request: req.try_into()?,
        })
    }
}

impl From<FileResponse<Bytes>> for http::Response<Bytes> {
    fn from(value: FileResponse<Bytes>) -> Self {
        value.response.into()
    }
}

#[derive(Debug, Clone, Hash, derive_more::From)]
pub enum FileRequestType<B> {
    CheckFileInfo(CheckFileInfoRequest),
    Lock(LockRequest),
    PutRelativeFile(FileBody<B, PutRelativeFileRequest>),
    GetFile(GetFileRequest),
}

#[derive(Debug, Clone, Hash)]
pub enum FileResponseType<B> {
    CheckFileInfo(Box<CheckFileInfoResponse>),
    Lock(LockResponse),
    PutRelativeFile(PutRelativeFileResponse),
    GetFile(FileBody<B, GetFileResponse>),
}

impl From<FileResponseType<Bytes>> for http::Response<Bytes> {
    fn from(value: FileResponseType<Bytes>) -> Self {
        match value {
            FileResponseType::CheckFileInfo(e) => (*e).into(),
            FileResponseType::Lock(e) => e.into(),
            FileResponseType::PutRelativeFile(e) => e.into(),
            FileResponseType::GetFile(e) => e.into(),
        }
    }
}

impl<B> TryFrom<http::Request<B>> for FileRequestType<B> {
    type Error = WopiRequestError;

    fn try_from(req: http::Request<B>) -> Result<Self, Self::Error> {
        let resp = match try_get_header(&req, "X-WOPI-Override").unwrap_or_default() {
            "LOCK" => FileRequestType::Lock(LockRequest::try_from(req.into_parts().0)?),
            "PUT_RELATIVE" => FileRequestType::PutRelativeFile(req.try_into()?),
            _ => {
                if is_content(&req.uri().to_string()) {
                    FileRequestType::GetFile(GetFileRequest::try_from(req.into_parts().0)?)
                } else {
                    FileRequestType::CheckFileInfo(CheckFileInfoRequest::try_from(
                        req.into_parts().0,
                    )?)
                }
            }
        };
        Ok(resp)
    }
}

/// CheckFileInfo Request
#[derive(Debug, Clone, Copy, Hash)]
pub struct CheckFileInfoRequest {}

impl TryFrom<http::request::Parts> for CheckFileInfoRequest {
    type Error = WopiRequestError;

    fn try_from(_: http::request::Parts) -> Result<Self, Self::Error> {
        Ok(CheckFileInfoRequest {})
    }
}

/// CheckFileInfo Response
///
/// CheckFileInfo response properties are a key way that a WOPI host
/// communicates capabilities and expected behaviors to WOPI clients. Many of
/// the properties in the CheckFileInfo response are required. Even properties
/// that are optional provide important ways for the host to direct the end-user
/// client experience.
#[derive(Debug, Clone, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CheckFileInfoResponse {
    /// The string name of the file, including extension, without a path. Used
    /// for display in user interface (UI), and determining the extension of the
    /// file.
    pub base_file_name: String,

    /// A string that uniquely identifies the owner of the file. In most cases,
    /// the user who uploaded or created the file is considered the owner.
    pub owner_id: String,

    /// The size of the file in bytes
    pub size: i64,

    /// A string value uniquely identifying the user currently accessing the
    /// file.
    pub user_id: String,

    /// The current version of the file based on the server's file version
    /// schema, as a string. This value must change when the file changes, and
    /// version values must never repeat for a given file.
    pub version: String,

    /// An array of strings containing the Share URL types supported by the
    /// host.
    ///
    /// These types are passed in the X-WOPI-UrlType request header to signify
    /// which Share URL type to return for the GetShareUrl (files) operation.
    pub supported_share_url_types: Vec<ShareUrlType>,

    pub supports_containers: bool,

    pub supports_delete_file: bool,

    pub supports_ecosystem: bool,

    pub supports_extended_lock_length: bool,

    /// A Boolean value that indicates that the host supports the [🚧 GetFileWopiSrc (ecosystem)](https://learn.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/rest/ecosystem/getfilewopisrc) operation.
    pub supports_get_file_wopi_src: bool,

    /// A Boolean value that indicates that the host supports the [GetLock](https://learn.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/rest/files/getlock#getlock) operation.
    pub supports_get_lock: bool,

    pub supports_locks: bool,

    /// A Boolean value that indicates that the host supports the [RenameFile](https://learn.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/rest/files/renamefile) operation.
    pub supports_rename: bool,

    pub supports_update: bool,

    /// A Boolean value that indicates that the host supports the [PutUserInfo](https://learn.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/rest/files/putuserinfo#putuserinfo) operation.
    pub supports_user_info: bool,

    /// A Boolean value indicating whether the user is authenticated with the
    /// host or not. Hosts should always set this to true for unauthenticated
    /// users, so that clients are aware that the user is anonymous.
    pub is_anonymous_user: bool,

    /// A Boolean value indicating whether the user is an education user or not.
    pub is_edu_user: bool,

    /// A Boolean value indicating whether the user is a business user or not.
    pub license_check_for_edit_is_enabled: bool,

    /// A string that is the name of the user, suitable for displaying in UI.
    pub user_friendly_name: Option<String>,

    /// A string value containing information about the user. This string can be
    /// passed from a WOPI client to the host by means of a PutUserInfo
    /// operation. If the host has a UserInfo string for the user, they must
    /// include it in this property. See the PutUserInfo documentation for more
    /// details.
    pub user_info: Option<String>,

    /// A Boolean value that indicates that, for this user, the file cannot be
    /// changed.
    pub read_only: bool,

    /// A Boolean value that indicates that the user has permission to view a
    /// broadcast of this file.
    pub user_can_attend: bool,

    /// A Boolean value that indicates the user does not have sufficient
    /// permission to create new files on the WOPI server. Setting this to true
    /// tells the WOPI client that calls to PutRelativeFile will fail for this
    /// user on the current file.
    pub user_can_not_write_relative: bool,

    /// A Boolean value that indicates that the user has permission to broadcast
    /// this file to a set of users who have permission to broadcast or view a
    /// broadcast of the current file.
    pub user_can_present: bool,

    /// A Boolean value that indicates the user has permission to rename the
    /// current file.
    pub user_can_rename: bool,

    /// A Boolean value that indicates that the user has permission to alter the
    /// file. Setting this to true tells the WOPI client that it can call
    /// PutFile on behalf of the user.
    pub user_can_write: bool,

    /// A URI to a web page that the WOPI client should navigate to when the
    /// application closes, or in the event of an unrecoverable error.
    pub close_url: Option<String>,

    /// A user-accessible URI to the file intended to allow the user to download
    /// a copy of the file.
    pub download_url: Option<String>,

    /// A URI to a location that allows the user to create an embeddable URI to
    /// the file.
    pub file_embed_command_url: Option<String>,

    /// A URI to a location that allows the user to share the file.
    pub file_sharing_url: Option<String>,

    /// A URI to the file location that the WOPI client uses to get the file. If
    /// this is provided, the WOPI client may use this URI to get the file
    /// instead of a GetFile request. A host might set this property if it is
    /// easier or provides better performance to serve files from a different
    /// domain than the one handling standard WOPI requests. WOPI clients must
    /// not add or remove parameters from the URL; no other parameters,
    /// includhttps://learn.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/rest/files/checkfileinfo/checkfileinfo-response#hostediturling the access token, should be appended to the FileUrl before it
    /// is used.
    pub file_url: Option<String>,

    /// A URI to a location that lets the user view the version history for the
    /// file.
    pub file_version_url: Option<String>,

    /// A URI to a host page that loads the edit WOPI action.
    pub host_edit_url: Option<String>,

    /// A URI to a web page that provides access to a viewing experience for the
    /// file that can be embedded in another HTML page. This is typically a URI
    /// to a host page that loads the embedview WOPI action.
    pub host_embedded_view_url: Option<String>,

    /// A URI to a host page that loads the view WOPI action. This URL is used
    /// by Office for the web to navigate between view and edit mode.
    pub host_view_url: Option<String>,

    /// A URI that signs the current user out of the host’s authentication
    /// system.
    pub signout_url: Option<String>,
}

impl From<&CheckFileInfoResponse> for http::Response<Bytes> {
    fn from(val: &CheckFileInfoResponse) -> Self {
        let bytes = serde_json::to_vec(&val).unwrap();
        http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Bytes::from(bytes))
            .unwrap()
    }
}

#[derive(Debug, Copy, Clone, Hash, Serialize, Deserialize)]
#[serde(into = "&str")]
pub enum ShareUrlType {
    ReadOnly,
    ReadWrite,
}

impl From<ShareUrlType> for &'static str {
    fn from(value: ShareUrlType) -> Self {
        match value {
            ShareUrlType::ReadOnly => "ReadOnly",
            ShareUrlType::ReadWrite => "ReadWrite",
        }
    }
}

/// Lock Request
///
/// The Lock operation locks a file for editing by the WOPI client application
/// instance that requested the lock. To support editing files, WOPI clients
/// require that the WOPI host supports locking files. When locked, a file
/// shouldn't be writable by other applications.
///
/// If the file is currently unlocked, the host should lock the file and return
/// 200 OK.
///
/// If the file is currently locked and the X-WOPI-Lock value matches the lock
/// currently on the file, the host should treat the request as if it's a
/// `RefreshLock` request. That is, the host should refresh the lock timer and
/// return 200 OK.
///
/// In all other cases, the host must return a lock mismatch response (409
/// Conflict) and include an X-WOPI-Lock response header containing the value of
/// the current lock on the file.
///
/// In cases where the file is locked by someone other than a WOPI client, hosts
/// should still always include the current lock ID in the X-WOPI-Lock response
/// header. However, if the current lock ID isn't representable as a WOPI lock
/// (for example, it's longer than the maximum lock length), the X-WOPI-Lock
/// response header should be set to the empty string or omitted completely.
///
/// For more general information about locks, see [Lock](https://learn.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/rest/concepts#lock).
#[derive(Debug, Clone, Hash)]
pub struct LockRequest {
    /// A string provided by the WOPI client that the host uses to identify the
    /// lock on the file.
    pub lock: String,
}

/// Lock Response
///
/// The Lock operation locks a file for editing by the WOPI client application
/// instance that requested the lock.
#[derive(Debug, Clone, Hash)]
pub enum LockResponse {
    Ok {
        /// An optional string value indicating the version of the file. Its
        /// value should be the same as Version value in CheckFileInfo.
        item_version: Option<String>,
    },
    Conflict {
        /// A string value identifying the current lock on the file. This header
        /// must always be included when responding to the request with 409
        /// Conflict. It shouldn't be included when responding to the request
        /// with 200 OK.
        lock: String,

        /// An optional string value indicating the cause of a lock failure.
        /// This header might be included when responding to the request
        /// with 409 Conflict. There's no standard for how this string
        /// is formatted, and it must only be used for logging purposes.
        lock_failure_reason: Option<String>,
    },
}

impl TryFrom<http::request::Parts> for LockRequest {
    type Error = WopiRequestError;

    fn try_from(req: http::request::Parts) -> Result<Self, Self::Error> {
        let lock = try_get_header(&req, "X-WOPI-Lock")?;

        Ok(LockRequest { lock: lock.into() })
    }
}

impl From<&LockResponse> for http::Response<Bytes> {
    fn from(value: &LockResponse) -> Self {
        let mut resp = http::Response::builder();
        match value {
            LockResponse::Ok { item_version } => {
                if let Some(ver) = item_version {
                    resp = resp.header("X-WOPI-ItemVersion", ver);
                }
            }
            LockResponse::Conflict {
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
        };
        resp.body(Bytes::new()).unwrap()
    }
}

#[derive(Debug, Clone, Hash)]
pub enum PutRelativeFileRequest {
    Specific {
        relative_target: String,
        overwrite_relative_target: bool,
        size: u64,
        file_conversion: bool,
    },
    Suggested {
        suggested_target: String,
        size: u64,
        file_conversion: bool,
    },
}

#[derive(Debug, Clone, Hash)]
pub enum PutRelativeFileResponse {
    Ok(PutRelativeFileResponseBody),
    Locked {
        lock: String,
    },
    FileAlreadyExists {
        valid_relative_target: Option<String>,
    },
    Unsupported,
}

#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PutRelativeFileResponseBody {
    /// The string name of the file, including extension, without a path.
    name: String,
    /// A string URI of the form http://server/<...>/wopi/files/(file_id)?access_token=(access token), of the newly created file on the host.
    /// This URL is the WOPISrc for the new file with an access token appended.
    /// Or, stated differently, it's the URL to the host’s Files endpoint for
    /// the new file, along with an access token. A GET request to this URL
    /// invokes the CheckFileInfo operation.
    url: String,
    /// The [HostViewUrl](https://learn.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/rest/files/checkfileinfo/checkfileinfo-response#hostviewurl),
    /// as a string, for the newly created file.
    host_view_url: Option<String>,
    /// The [HostEditUrl](https://learn.microsoft.com/en-us/microsoft-365/cloud-storage-partner-program/rest/files/checkfileinfo/checkfileinfo-response#hostediturl), as a string,
    /// for the newly created file.
    host_edit_url: Option<String>,
}

impl From<&PutRelativeFileResponse> for http::Response<Bytes> {
    fn from(value: &PutRelativeFileResponse) -> Self {
        let mut resp = http::Response::builder();
        let mut body = None;
        match value {
            PutRelativeFileResponse::Ok(b) => {
                body = serde_json::to_vec(b).ok();
                resp = resp.status(200);
            }
            PutRelativeFileResponse::Locked { lock } => {
                resp = resp
                    .status(http::StatusCode::CONFLICT)
                    .header("X-WOPI-Lock", lock);
            }
            PutRelativeFileResponse::FileAlreadyExists {
                valid_relative_target,
            } => {
                resp = resp.status(http::StatusCode::CONFLICT);
                if let Some(rel_tar) = valid_relative_target {
                    resp = resp.header("X-WOPI-ValidRelativeTarget", rel_tar);
                };
            }
            PutRelativeFileResponse::Unsupported => {
                resp = resp.status(http::StatusCode::NOT_IMPLEMENTED);
            }
        };
        resp.body(Bytes::from(body.unwrap_or_default())).unwrap()
    }
}

#[derive(Debug, Clone, Hash)]
pub enum SuggestedTarget {
    Extension(String),
    FileName(String),
}

impl<T> From<T> for SuggestedTarget
where
    T: AsRef<str>,
{
    fn from(value: T) -> Self {
        let s = value.as_ref();
        if let Some(s) = s.strip_prefix('*') {
            return SuggestedTarget::Extension(String::from(s));
        }
        SuggestedTarget::FileName(String::from(s))
    }
}

impl TryFrom<http::request::Parts> for PutRelativeFileRequest {
    type Error = WopiRequestError;

    fn try_from(req: http::request::Parts) -> Result<Self, Self::Error> {
        let file_conversion = req.headers.contains_key("X-WOPI-FileConversion");
        let size = try_get_header(&req, "X-WOPI-Size")?
            .parse()
            .map_err(|_| WopiRequestError::InvalidHeaderValue("X-WOPI-Size".into()))?;

        if req.headers.contains_key("X-WOPI-SuggestedTarget") {
            let suggested_target = try_get_header(&req, "X-WOPI-SuggestedTarget")?.into();

            return Ok(PutRelativeFileRequest::Suggested {
                suggested_target,
                size,
                file_conversion,
            });
        }

        let relative_target = try_get_header(&req, "X-WOPI-RelativeTarget")?.into();
        let overwrite_relative_target = try_get_header(&req, "X-WOPI-OverwriteRelativeTarget")?
            .parse()
            .map_err(|_| {
                WopiRequestError::InvalidHeaderValue("X-WOPI-OverwriteRelativeTarget".into())
            })?;
        Ok(PutRelativeFileRequest::Specific {
            relative_target,
            overwrite_relative_target,
            size,
            file_conversion,
        })
    }
}

#[derive(Debug, Clone, Hash)]
pub struct GetFileRequest {
    /// An integer specifying the upper bound of the expected size of the file
    /// being requested.
    max_expected_size: i32,
}

impl TryFrom<http::request::Parts> for GetFileRequest {
    type Error = WopiRequestError;

    fn try_from(value: http::request::Parts) -> Result<Self, Self::Error> {
        let max_expected_size = match try_get_header(&value, "X-WOPI-MaxExpectedSize") {
            Ok(s) => match s.parse() {
                Ok(s) => s,
                Err(_) => return Err(WopiRequestError::BadRequest),
            },
            Err(WopiRequestError::MissingHeader(_)) => i32::MAX,
            _ => return Err(WopiRequestError::BadRequest),
        };
        Ok(GetFileRequest { max_expected_size })
    }
}

#[derive(Debug, Clone, Hash)]
pub enum GetFileResponse {
    Ok { item_version: Option<String> },
    TooLarge,
}

impl From<&GetFileResponse> for http::Response<Bytes> {
    fn from(value: &GetFileResponse) -> Self {
        let mut resp = http::Response::builder();
        match value {
            GetFileResponse::Ok { item_version } => {
                if let Some(ver) = item_version {
                    resp = resp.header("X-WOPI-ItemVersion", ver);
                }
            }
            GetFileResponse::TooLarge => resp = resp.status(http::StatusCode::PRECONDITION_FAILED),
        };
        resp.body(Bytes::new()).unwrap()
    }
}

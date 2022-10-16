
"""
Error definitions for failure modes for which we can determine the cause,
mapped to HTTP status codes.

OSError notes:

[Errno 2]   | errno.ENOENT | No such file or directory (NFS mount issue)
[Errno 122] | errno.EDQUOT | Disk quota exceeded


References:
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
- https://httpwg.org/specs/rfc9110.html#overview.of.status.codes

"""

from http import HTTPStatus

class ApiError(Exception):

    desc = "API error"
    status = None

    def __init__(self, message: str = "API Error") -> None:
        self.message = message
        self.log_msg = f"{self.desc}, {self.status.phrase}, {self.message}"


# Client errors -  HTTP 4XX range
# -------------------------------

class ClientError(ApiError):
    desc = "Client error"
    status = HTTPStatus.BAD_REQUEST

class ClientIllegalFilenameError(ClientError):
    desc = "Filename not allowed"
    status = HTTPStatus.BAD_REQUEST

class ClientSnsPathError(ClientError):
    desc = "Wrong URL path for sns backend"
    status = HTTPStatus.BAD_REQUEST

class ClientAuthorizationError(ClientError):
    desc = "Client not authorized for request"
    status = HTTPStatus.FORBIDDEN


# Server errors - HTTP 5XX range
#-------------------------------

class ServerError(ApiError):
    desc = "Server error"
    status = HTTPStatus.INTERNAL_SERVER_ERROR

class ServerStorageTemporarilyUnavailableError(ServerError):
    desc = "Backend cannot be used during migration"
    status = HTTPStatus.SERVICE_UNAVAILABLE

class ServerStorageNotMountedError(ServerError):
    desc = "errno.ENOENT, NFS mount missing"
    status = HTTPStatus.INTERNAL_SERVER_ERROR

class ServerSnsError(ServerError):
    desc = "Issue contructing sns storage path"
    status = HTTPStatus.INTERNAL_SERVER_ERROR

class ServerDiskQuotaExceededError(ServerError):
    desc = "errno.EDQUOT, Project has run out of disk quota"
    status = HTTPStatus.INSUFFICIENT_STORAGE

class ServerMaintenanceError(ServerError):
    desc = "Server down for maintenance"
    status = HTTPStatus.SERVICE_UNAVAILABLE

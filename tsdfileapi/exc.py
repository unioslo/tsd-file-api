
"""Error definitions for failure modes for which we can determine the cause."""


class ApiError(Exception):

    desc = "API error"
    sc = None

    def __init__(self, message: str = "", status: int = 500) -> None:
        self.message = message or self.desc
        self.sc = self.sc or status


# Client errors -  HTTP 4XX range
# -------------------------------

class ClientError(ApiError):
    desc = "Client error"
    sc = 400

class ClientIllegalFilenameError(ClientError):
    desc = "Filename not allowed"
    sc = 400

class ClientSnsPathError(ClientError):
    desc = "Wrong URL path for sns backend"
    sc = 400


# Server errors - HTTP 5XX range
#-------------------------------

class ServerError(ApiError):
    desc = "Server error"
    sc = 500

class ServerStorageTemporarilyUnavailableError(ServerError):
    desc = "Raised for backends which cannot be used during migration"
    sc = 503

class ServerStorageNotMountedError(ServerError):
    desc = "NFS mount missing"
    sc = 500

class ServerSnsError(ServerError):
    desc = "Issue contructing sns storage path"
    sc = 500

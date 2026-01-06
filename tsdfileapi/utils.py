import contextvars
import datetime
import errno
import functools
import hashlib
import itertools
import logging
import os
import pathlib
import re
import reprlib
import shlex
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from ipaddress import ip_network
from typing import Callable
from typing import Mapping
from typing import Optional
from typing import Union
from uuid import uuid4

import tornado.log
import tornado.options
import tornado.web
from tornado.httputil import HTTPServerRequest as Request

from tsdfileapi.exc import ClientIllegalFilenameError
from tsdfileapi.exc import ClientIllegalFiletypeError
from tsdfileapi.exc import ClientSnsPathError
from tsdfileapi.exc import ServerSnsError
from tsdfileapi.exc import ServerStorageNotMountedError

VALID_FORMID = re.compile(r"^[0-9]+$")
PGP_KEY_FINGERPRINT = re.compile(r"^[0-9A-Z]{16}$")
VALID_UUID = re.compile(r"([a-f\d0-9-]{32,36})")

logger = logging.getLogger(__name__)


def days_since_mod(path: str) -> int:
    """
    Calculate the amount of days that have elapsed
    since the given path was modified.

    """
    current_moment = datetime.datetime.now()
    mtime_moment = datetime.datetime.fromtimestamp(os.stat(path).st_mtime)
    days_since = (current_moment - mtime_moment).days
    return days_since


def _rwxrwx___() -> int:
    u = stat.S_IREAD | stat.S_IWRITE | stat.S_IXUSR
    g = stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP
    return u | g


def _rwxrws___() -> int:
    return _rwxrwx___() | stat.S_ISGID


def _find_ess_dir(
    pnum: str,
    root: str = "/ess",
) -> Optional[str]:
    sub_dir = None
    for projects_dir in os.listdir(root):
        if pnum in os.listdir(f"{root}/{projects_dir}"):
            sub_dir = projects_dir
            break
    return None if not sub_dir else f"{root}/{sub_dir}/{pnum}/data/durable"


def find_tenant_storage_path(
    tenant: str,
    endpoint_backend: str,
    opts: tornado.options.OptionParser,
    root: str = "/ess",
) -> str:
    """
    Either one of these: /ess/projects0{1|2|3|...|n}/{pnum}/data/durable
    Results are cached in a dict stored on options.
    Returns the base path which the endpoint_backend should use.

    """
    cache = opts.tenant_storage_cache.copy()
    if not cache.get(tenant):
        storage_path_ess = _find_ess_dir(tenant, root=root)
        if not storage_path_ess:
            return None

        cache[tenant] = {
            "storage_backend": "ess",
            "storage_paths": {
                "ess": storage_path_ess,
            },
        }
        opts.tenant_storage_cache = cache.copy()
    out = opts.tenant_storage_cache[tenant]["storage_paths"]["ess"]
    return out


def choose_storage(
    *,
    tenant: str,
    endpoint_backend: str,
    opts: tornado.options.OptionParser,
    directory: str,
) -> str:
    if not directory.startswith("/tsd"):
        return directory
    split_on = "data/durable"
    storage_path = find_tenant_storage_path(
        tenant,
        endpoint_backend,
        opts,
    ).split(split_on)
    in_dir = directory.split(split_on)
    out_dir = "".join([storage_path[0], split_on, in_dir[-1]])
    return out_dir


def call_request_hook(path: str, params: list, as_sudo: bool = True) -> None:
    if as_sudo:
        cmd = ["sudo"]
    else:
        cmd = []
    cmd.append(shlex.quote(path))
    cmd.extend(params)
    subprocess.call(cmd)


def tenant_from_url(url: str) -> list:
    if "v1" in url:
        idx = 2
    else:
        idx = 1
    return url.split("/")[idx]


def check_filename(filename: str, disallowed_start_chars: list = []) -> str:
    start_char = filename[0]
    if disallowed_start_chars:
        if start_char in disallowed_start_chars:
            raise ClientIllegalFilenameError(
                f"Filename: {filename} has illegal start character: {start_char}"
            )
    return filename


def sns_dir(
    base_pattern: str,
    tenant: str,
    uri: str,
    tenant_string_pattern: str,
    test: bool = False,
    options: tornado.options.OptionParser = None,
) -> str:
    """
    Construct and create a path for sns uploads.

    """
    try:
        uri_parts = uri.split("/")
        formid = uri_parts[-1]
        keyid = uri_parts[-2]
        if not VALID_FORMID.match(formid):
            raise ClientSnsPathError(f"invalid form ID: {formid}")
        if not PGP_KEY_FINGERPRINT.match(keyid):
            raise ClientSnsPathError(f"invalid PGP fingerprint: {keyid}")
        directory = (
            base_pattern.replace(tenant_string_pattern, tenant)
            .replace("KEYID", keyid)
            .replace("FORMID", formid)
        )
        sns_dir = choose_storage(
            tenant=tenant,
            endpoint_backend="sns",
            opts=options,
            directory=directory,
        )
        try:
            if not os.path.lexists(sns_dir):
                os.makedirs(sns_dir)
                subprocess.call(["sudo", "chmod", "2770", sns_dir])
                logger.info(f"Created: {sns_dir}")
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise ServerStorageNotMountedError(
                    f"NFS mount missing for {sns_dir}"
                ) from e
            else:
                raise e
        return sns_dir
    except Exception as e:
        logger.error(e)
        raise ServerSnsError from e


def md5sum(filename: str, blocksize: int = 65536) -> str:
    _hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            _hash.update(block)
    return _hash.hexdigest()


def move_data_to_folder(path: str, dest: str) -> Union[str, bool]:
    """
    Move file/dir at path into and folder at dest.

    """
    try:
        if not dest:
            return path
        filename = os.path.basename(path)
        new_path = os.path.normpath(dest + "/" + filename)
        if os.path.isdir(path):
            if os.path.lexists(new_path):
                # idempotency
                shutil.rmtree(new_path)
            shutil.move(path, new_path)
        else:
            os.rename(path, new_path)
        return new_path
    except Exception as e:
        logger.error(e)
        logger.error("could not move file: %s", path)
        return False


def set_mtime(path: str, mtime: int) -> None:
    mtime = mtime
    atime = mtime
    os.utime(path, (mtime, atime))


def any_path_islink(
    path: Union[str, pathlib.Path],
    opts: tornado.options.OptionParser,
) -> bool:
    """Check if any part of a given path is a symlink.
    Args:
        path (str): path to check
    Raises:
        ClientIllegalFiletypeError: if a symlink is found in the path
    Returns:
        bool: function returns false if no part of path is a symlink
    """
    allowed_symlinks = [pathlib.Path(path) for path in opts.allowed_symlinks]
    if isinstance(path, str):
        path = pathlib.Path(path)
    while path != path.parent:
        if path.is_symlink() and path not in allowed_symlinks:
            raise ClientIllegalFiletypeError(
                f"Path '{path}' is a symlink to '{os.readlink(path)}'."
            )
        path = path.parent
    return False


def cidr_to_set(ip: str) -> set:
    """Converts a CIDR to a set of IP addresses."""
    return {str(x) for x in ip_network(ip)}


def trusted_proxies_to_trusted_downstream(
    trusted_proxies: list = None,
) -> Optional[list]:
    """Convert our trusted_proxies (CIDR supported) format to a list of IP addresses.

    Tornado expects a list of IP addresses, so we must expand CIDR network
    ranges to lists of IP addresses that it can support.
    """
    if not trusted_proxies:
        return None
    trusted_downstream = set()
    for proxy in trusted_proxies:
        trusted_downstream = trusted_downstream | cidr_to_set(proxy)
    return list(trusted_downstream)


class LoggedObjectRepr(reprlib.Repr):
    """
    Formatters of objects for logging purposes.

    For logging purposes, `repr` often doesn't cut it, so this convenience is offered to add information on logged objects that could be interesting / relevant for e.g. troubleshooting.

    See `reprlib.Repr` which largely explains the entire framework and what problems it helps solve.
    """

    def repr_call(self, callable, args, kwargs) -> str:
        """
        Compile a representation of a _call_.

        The representation is geared for being featured in logs for troubleshooting purposes.

        E.g. compiles and returns "foo(1, 2, 3)" for a callable `foo` that takes `1`, `2` and `3` for positional arguments.
        """
        return (
            self.repr(callable)
            + "("
            + ", ".join(self.repr(arg) for arg in args)
            + (
                (
                    ", "
                    + ", ".join(
                        (name + "=" + self.repr(value))
                        for name, value in kwargs.items()
                    )
                )
                if kwargs
                else ""
            )
            + ")"
        )

    @staticmethod
    def repr_bytes(obj: bytes, *_):
        """
        Compile representation of a `bytes`-type object (a read-only buffer).
        """
        return f"<{len(obj)} byte(s)>"


logged_object_repr = LoggedObjectRepr()
logged_object_repr.maxother = sys.maxsize  # No limit, it's bad enough for our purposes that data is otherwise cut off from the middle


def with_logged_calls(logger: logging.Logger, level: Union[int | str]) -> Callable:
    """
    A decorator that makes calling an object (normally a function) produce a log message.
    """
    if not isinstance(level, int):
        level = logging.getLevelNamesMapping()[
            level
        ]  # Not available on Python 3.10, so level names cannot be used before 3.11

    def decorator(callable):
        @functools.wraps(callable)
        def wrapper(*args, **kwargs):
            logger.log(
                level, logged_object_repr.repr_call(callable, args, kwargs)
            )  # TODO: This message uses utils.py as origin while it'd be preferable the call site of `decorator` was used instead
            return callable(*args, **kwargs)

        return wrapper

    return decorator


@dataclass
class ParametrisedField:
    """
    Parsed elements of values of HTTP request headers like `Prefer` (et al. -- the same syntax is reused across HTTP)

    See `parse_http_request_handling_preference` which does the parsing and returns an object of this class.
    """

    name: str
    value: str
    params: dict[str, str]


def parse_http_prefer_header_values(
    *header_values: str,
) -> Mapping[str, ParametrisedField]:
    """
    Parse one or several HTTP headers like the `Prefer` request header.

    Input may be text like "foo=1; bar=baz, hello-world" which if parsed "breadth first" contains 2 elements `foo=1; bar=baz` and `hello-world`, each of these superficially resembling the syntax shared with the `Content-Type` header, with the former parsed further into `foo=1`, with `foo` being the principal key or name of the element and `1` being the value, and `bar=baz` and any other `;`-separated pair(s) called parameters, each being a key-value pair much like `foo=1`; `hello-world` not featuring a `=` followed by a value is equivalent to `hello-world=` where the value is the empty string, and no parameters (empty list).

    Returns the set of parsed fields, as a dictionary, keyed by the field name (matching the value of the `name` attribute).
    """
    return {
        pref.name: pref
        for pref in (
            parse_http_request_handling_preference(pref_text)
            for pref_text in itertools.chain.from_iterable(
                re.split(r"\s*,\s*", header_value) for header_value in header_values
            )
        )
    }


def parse_http_request_handling_preference(text: str) -> ParametrisedField:
    """
    Parse a single component (field) of a HTTP header like the `Prefer` request header.

    E.g. `parse_http_request_handling_preference("foo=1; bar=baz")` produces a single so-called field, an element with a key, a value and one or multiple parameters.
    """
    first, *rest = (re.split(r"\s*=\s*", part) for part in re.split(r"\s*;\s*", text))
    return ParametrisedField(
        name=first[0], value=first[1] if len(first) > 1 else "", params=dict(rest)
    )


class RequestHandler(tornado.web.RequestHandler):
    """
    A base (abstract) request handler class gathering utilities and useful features common to all API request handler sub-classes.

    Quoting Tornado's own [User Guide](https://www.tornadoweb.org/en/latest/guide/structure.html#subclassing-requesthandler):

    > Many methods in `RequestHandler` are designed to be overridden in subclasses and be used throughout the application. It is common to define a "BaseHandler" class that overrides methods such as `write_error` and `get_current_user` and then subclass your own "BaseHandler" instead of `RequestHandler` for all your specific handlers.
    """

    # For tracking of requests across their processing context
    _request_context_var: Request = contextvars.ContextVar("request")
    _request_context_var_token: contextvars.Token
    _request_processing_context: contextvars.Context

    def __init_subclass__(cls):
        """Wraps certain methods of every sub-class of this request handler class, so that the request is "automagically" made available from the context, for the lifetime of processing the request.

        This mechanism of hooking into sub-class initialisation, allows request handler classes inheriting this class to not have to explicitly have `super().<method-name>(...)` as part of their override, if any. Given how _every_ request should have identifier logging, needing such explicit statements is arguably not a net-benefit -- this procedure alone ensures business logic remains as-is, and allows the application to continue following Tornado's convention which doesn't require e.g. `super().initialise()` or `super().prepare()` etc. Admittedly, explicitly calling the super-class method is both an OOP convention _and_ in line with Python's "explicit is better than implicit" best practice, it's just that it's either this approach or sprinkling _every_ overriden method in every request handler class, with `super()....` which would have cost of its own.
        """

        def initialize(handler, wrapped, *args, **kwargs):
            RequestHandler.initialize(handler, *args, **kwargs)
            return wrapped(handler, *args, **kwargs)

        def prepare(handler, wrapped):
            RequestHandler.prepare(handler)
            return wrapped(handler)

        def on_finish(handler, wrapped):
            try:
                return wrapped(handler)
            finally:
                RequestHandler.on_finish(handler)

        # If the sub-class doesn't have its own method then there is nothing to wrap as the method then is of `RequestHandler` (usable as-is)
        if cls.initialize != RequestHandler.initialize:
            cls.initialize = functools.partialmethod(initialize, cls.initialize)
        if cls.prepare != RequestHandler.prepare:
            cls.prepare = functools.partialmethod(prepare, cls.prepare)
        if cls.on_finish != RequestHandler.on_finish:
            cls.on_finish = functools.partialmethod(on_finish, cls.on_finish)

    @staticmethod
    def enable_request_id_logging(handler: logging.Handler) -> None:
        """Enable logging of request IDs in log records emitted by the specified handler.

        The good old `logging` module doesn't necessarily facilitate the kind of operation, and yet we don't want to override Tornado's logging set-up (use of e.g. `colorama`) but instead build on top of that -- and that isn't trivial.
        """

        def log_record_filter(record: logging.LogRecord) -> bool:
            """Attach an identifier to a log record.

            This procedure is a _filter_ -- to be registered using the `logging` API and invoked by the latter automatically. Despite it being a filter, per documentation of `logging` it is permitted (and recommended for the use case) to use filters for adding attributes to log records."""
            # Not feeling great about mixing value types for the `request-id` variable, but it will have to do for now as it's less work than crafting and using a `logging.Formatter` sub-class
            record.request_id = getattr(
                RequestHandler._request_context_var.get(None), "_id", "-"
            )
            return True  # Do not filter the record

        handler.addFilter(log_record_filter)
        formatter = handler.formatter  # Not documented (because initialised by the constructor and otherwise not declared by the class) and yet `formatter` is a "public" attribute
        if (
            not isinstance(formatter, tornado.log.LogFormatter)
            or formatter._fmt
            != "%(color)s[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d]%(end_color)s %(message)s"
        ):
            # We cannot modify an arbitrary formatter to include request IDs because a) we don't know where to put the request ID in the format string [we aren't parsing], and b) `_fmt` is subject to change and generally may not be available, so _modification_ of formatter objects already in use isn't in fact facilitated by any known APIs, unfortunately
            raise NotImplementedError(
                "The formatter used on the logger isn't the expected, default Tornado formatter"
            )
        # Knowing the _exact_ format string, we can confidently patch it to include a `%{request_id}s` in a good location of our choosing
        formatter._fmt = "%(color)s[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d %(request_id)s]%(end_color)s %(message)s"
        # `_style` is a cache -- need to re-built it; another necessity courtesy of using mechanisms not intended for general use
        formatter._style = type(formatter._style)(formatter._fmt)

    @staticmethod
    def run_in_request_processing_context(method):
        """
        Decorate a method to execute with the context associated with the request this handler was created to process.

        Because request handler's methods may be invoked by Tornado (depending on the method, of course), Tornado determines the context, which for some methods was empirically discovered to differ from the prepared context, for reasons hidden in Tornado's architecture. This "helper" is offered for "correcting" these methods. This effectively enables logging of the request ID, also from within the Tornado (the critical difference to e.g. binding a logger of `structlog` which does nothing for log messages originating in Tornado).
        """

        @functools.wraps(method)
        def wrapper(self: RequestHandler, *args, **kwargs):
            return self._request_processing_context.run(method, self, *args, **kwargs)

        return wrapper

    def initialize(self, *args, **kwargs):
        self.request._id = (
            self.request.headers.get("Request-ID") or uuid4()
        )  # Assign a unique identifier to the request being handled

    def prepare(self):
        self._request_context_var_token = self._request_context_var.set(self.request)
        self._request_processing_context = contextvars.copy_context()

    def on_finish(self):
        # A missing token value signifies there is a context mismatch -- the variable was _not_ set in current context so resetting it is neither necessary nor will it work (the call will raise an error); we therefore "look before we leap" instead of taking a chance on handling an e.g. `ValueError` assuming `reset` failed because of context mismatch specifically; a context mismatch may happen in cases where a `prepare` call (in a sub-class) raises an error, as Tornado apparently executes error handling in a _different_ (copy of) context than the one used for processing the request
        if self._request_context_var_token.old_value != contextvars.Token.MISSING:
            # Restore original value of the variable stored with the context -- Tornado is free to reuse tasks and thus contexts _between_ requests (crucially, one task cannot by nature process two requests at once though), which makes restoration mandatory so that logging done in context of the same task that finished processing this request, won't be "related" (through the context) to the "finished" request any longer -- it's just the right thing to do conceptually
            self._request_context_var.reset(self._request_context_var_token)

    parse_http_prefer_header_values = staticmethod(parse_http_prefer_header_values)

    @functools.cached_property
    def prefs(self) -> Mapping[str, ParametrisedField]:
        """
        Return client preferences for handling the request.

        The preferences would have been specified in the form of the well-known `Prefer` HTTP request header.

        The set of preferences is cached, so only parsed once when first accessed, as a performance optimisation (the request is for practical purposes immutable so the memoisation arguably makes sense).
        """
        return self.parse_http_prefer_header_values(
            *self.request.headers.get_list("Prefer")
        )

    @staticmethod
    def enable_per_request_log_level_control(
        logger: logging.Logger | type[logging.Logger],
    ) -> None:
        """
        Makes logging done by the specified logger be filtered depending on the request's level, if specified.

        The request's level may be specified with the `Log-Level` request header, made available with the context. If not specified with the request or specified a `0`/`logging.NOTSET`, the filter works as pass-through (i.e. a no-op).

        Instead of one single _logger_, Python's OOP inheritance model easily facilitates passing e.g. `logging.Logger` (the class) to implicitly enable the behaviour for _every_ logger (existing or not yet).
        """

        def wrap(original):
            def isEnabledFor(self, level):
                request = RequestHandler._request_context_var.get(None)
                if request and "Log-Level" in request.headers:
                    requested_level_header_value = request.headers["Log-Level"]
                    levels_by_name = logging.getLevelNamesMapping()
                    requested_level = (
                        levels_by_name[requested_level_header_value]
                        if requested_level_header_value in levels_by_name
                        else int(requested_level_header_value)
                    )
                    return level >= requested_level
                else:
                    return original(self, level)

            return isEnabledFor

        logger.isEnabledFor = wrap(logger.isEnabledFor)  # type: ignore[method-assign]

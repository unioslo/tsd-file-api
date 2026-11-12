"""A Pytest application for [unit] testing of `tsdfileapi.http`.

Targets RFC 9110 compliance.
"""

import re
from functools import partial
from typing import Any
from typing import Callable
from typing import Mapping
from typing import MutableMapping
from typing import Sequence
from typing import cast
from typing import override

import pytest

from tsdfileapi import http
from tsdfileapi.http import ContentRange
from tsdfileapi.http import Range

bytes_unit_re = re.compile(r"bytes")


class Request:
    """Mock requests strictly for exercising tests in this module, see `RequestHandler` below."""

    def __init__(self, *, method: str, headers: Mapping[str, str] = {}) -> None:
        self.method = method
        self.headers = headers


class RequestHandler(http.RequestHandler[Request, MutableMapping[str, str]]):
    """Mock request handlers strictly for exercising tests in this module -- `http.RequestHandler` is an abstract class and `tornado.web.RequestHandler` requires setting up or mocking TCP connections etc, which would require more scaffolding here just to be able to use the latter in tests here. Mocking explicitly gives us visibility into the test anatomy and we don't want to have the module explicitly depend on Tornado because we're not testing the latter."""

    _status_code = 200

    def __init__(self, request: Request) -> None:
        self._headers = {}
        self.request = request

    def set_header(self, name: str, value: Any) -> None:
        assert isinstance(value, str)
        self._headers[name] = value

    def set_status(self, code: int, reason: str | None = None) -> None:
        self._status_code = code

    def get_status(self) -> int:
        return self._status_code

    @override
    def is_supported_range_unit(self, unit: str) -> bool:
        return bool(bytes_unit_re.fullmatch(unit))

    @override
    def applicable_ranges(self, ranges: Sequence[Range]) -> Sequence[Range]:
        return (
            ranges if len(ranges) == 1 else ()
        )  # Refuse to apply any range if _multiple_ ranges were requested


def requested_range_ignored(
    request_handler: RequestHandler, applied_content_range: ContentRange | None
) -> None:
    """Assert that the request handler ignored requested range(s), correctly."""
    assert not applied_content_range
    assert request_handler.get_status() == 200
    assert "Content-Range" not in request_handler._headers


def requested_range_applied(
    request_handler: RequestHandler,
    applied_content_range: ContentRange | None,
    *,
    expected_content_range: ContentRange,
    expected_content_range_header_value: str,
) -> None:
    """Assert that the request handler applied requested range(s), correctly."""
    assert applied_content_range == expected_content_range
    assert request_handler.get_status() == 206
    assert (
        request_handler._headers.get("Content-Range")
        == expected_content_range_header_value
    )


def requested_range_unsatisfiable(
    request_handler: RequestHandler,
    applied_content_range: ContentRange | None,
    *,
    expected_content_range_header_value: str,
) -> None:
    """Assert that the request handler rejected the request, due to [presence of] unsatisfiable range(s), correctly."""
    assert not applied_content_range
    assert request_handler.get_status() == 416
    assert (
        request_handler._headers.get("Content-Range")
        == expected_content_range_header_value
    )


@pytest.mark.parametrize(
    ("request_kwargs", "repr_length", "assert_handling"),
    (
        (
            dict(method="GET", headers={"Range": "bytes=5-4"}),
            10,
            requested_range_ignored,
        ),
        (
            dict(method="GET", headers={"Range": "bytes=5-4"}),
            0,
            requested_range_ignored,
        ),
        (
            dict(method="GET", headers={"Range": "bytes=5-5"}),
            10,
            partial(
                requested_range_applied,
                expected_content_range=("bytes", 5, 6),
                expected_content_range_header_value="bytes 5-5/10",
            ),
        ),
        (
            dict(method="GET", headers={"Range": "bytes=5-20"}),
            10,
            partial(
                requested_range_applied,
                expected_content_range=("bytes", 5, 10),
                expected_content_range_header_value="bytes 5-9/10",
            ),
        ),
        (
            dict(method="POST", headers={"Range": "bytes=5-5"}),
            10,
            requested_range_ignored,
        ),
        (
            dict(method="HEAD", headers={"Range": "bytes=5-5"}),
            10,
            requested_range_ignored,
        ),
        (
            dict(method="GET", headers={"Range": "buckazoids=5-5"}),
            10,
            requested_range_ignored,
        ),
        (
            dict(method="GET", headers={"Range": "bytes=10-"}),
            10,
            partial(
                requested_range_unsatisfiable,
                expected_content_range_header_value="bytes */10",
            ),
        ),
    ),
)
def test_apply_range(
    request_kwargs: Mapping[str, Any],
    repr_length: int,
    assert_handling: Callable[[RequestHandler, ContentRange | None], None],
) -> None:
    """Assert that [end-to-end] handling of range requests (such that feature `Range`, `If-Range` etc), is correct."""
    request_handler = RequestHandler(Request(**request_kwargs))
    applied_content_range = request_handler.apply_requested_range(
        repr_length=repr_length
    )
    assert_handling(request_handler, applied_content_range)


@pytest.mark.parametrize(
    ("range_spec", "unit", "method", "repr_length", "expected_result"),
    tuple(
        (range_spec, "bytes", "GET", repr_length, expected_result)
        for range_spec, repr_length, expected_result in (
            ("-0", None, ((None, 0), None, False, None)),
            ("1-0", None, ((1, 1), True, None, None)),
            ("0-0", 10, ((0, 1), False, True, (0, 1))),
            ("-1", 10, ((-1, None), None, True, (9, 10))),
            ("-1", 0, ((-1, None), None, True, None)),
            ("-1,0", None, (None, None, None, None)),
            ("0,-1", None, (None, None, None, None)),
            ("0,-1", None, (None, None, None, None)),
            ("5-4", None, ((5, 5), True, None, None)),
        )
    ),
)
def test_content_range_resolution(
    range_spec: str,
    *,
    unit: str,
    method: str,
    repr_length: int,
    expected_result: tuple[
        # Parsed range, its invalidity and satisfiability states (if determinable), and the result of applying it (as expressed with `Content-Range` on the response)
        Range | None, bool | None, bool | None, ContentRange | None
    ],
) -> None:
    """Assert that parsing, validation, satisfiability and applying of a single range specifier (`range-spec`), are correct."""
    match = http.range_spec_re.fullmatch(range_spec)
    range = http.range_from_match_groups(match.groups()) if match else None
    is_range_invalid = http.is_invalid_range(range) if range else None
    is_range_satisfiable = (
        http.is_satisfiable_range(
            range, unit=unit, method=method, repr_length=repr_length
        )
        if (range and not is_range_invalid)
        else None
    )
    assert (
        range,
        is_range_invalid,
        is_range_satisfiable,
        (
            http.content_range(
                cast(Range, range), unit=unit, method=method, repr_length=repr_length
            )
            if (not is_range_invalid) and is_range_satisfiable and repr_length
            else None
        ),
    ) == expected_result


@pytest.mark.parametrize(
    ("ranges_spec", "expected_result"),
    (
        ("bytes", None),
        ("bytes-", None),
        ("bytes=", None),
        ("bytes=0", None),
        ("bytes=0-1", ("bytes", ((0, 2),))),
        ("bytes=5-4", ("bytes", ((5, 5),))),
        *(
            (text, ("bytes", ((0, 2), (2, 1))))
            for text in (
                "bytes=0-1,2-0",
                "bytes=0-1,2-0,",
                "bytes=0-1,2-0,,",
                "bytes=,0-1,2-0,,",
                "bytes=,,0-1,2-0,,",
            )
        ),
        ("bytes=0-", ("bytes", ((0, None),))),
        ("foo=0-1", ("foo", ((0, 2),))),
    ),
)
def test_ranges_spec_fullmatch(
    ranges_spec: str, expected_result: tuple[str, tuple[http.Range, ...]] | None
) -> None:
    """Assert that parsing of `ranges-specifier` (full-match mode -- no unparsed text at the end permitted by parser), is correct.

    The `ranges-specifier` HTTP grammar element defines the set of all syntactically correct `Range` header values.
    """
    match = http.ranges_spec_matcher.fullmatch(ranges_spec)
    if match is not None:
        unit_match, _, range_set_match = match.elements
        assert (
            unit_match.group(),
            tuple(
                http.range_from_match_groups(match.groups())
                for match in range_set_match.elements
                if match.re == http.range_spec_re
            ),
        ) == (expected_result or ((None,) * 2))
    else:
        assert expected_result is None

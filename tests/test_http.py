"""A Pytest application for unit testing of `tsdfileapi.http`.

Targets RFC 9110 compliance.
"""

from functools import partial
from typing import Callable
from typing import Mapping
from typing import TypeAlias

import pytest

from tsdfileapi import http

ContentRangeTestResult: TypeAlias = tuple[
    http.Range | None, bool | None, bool | None, tuple[int, int] | None
]


class Request:
    def __init__(self, *, method: str, headers: Mapping[str, str] = {}):
        self.method = method
        self.headers = headers


class RequestHandler(http.RequestHandler):
    _headers: Mapping
    _status_code = 200

    def __init__(self, request: Request):
        self._headers = {}
        self.request = request

    def set_header(self, name: str, value) -> None:
        assert isinstance(value, str)
        self._headers[name] = value

    def set_status(self, code: int, *args) -> None:
        self._status_code = code

    def get_status(self) -> int:
        return self._status_code


def requested_range_ignored(
    request_handler: RequestHandler, range: tuple[int, int] | None
) -> None:
    assert not range
    assert request_handler.get_status() == 200
    assert "Content-Range" not in request_handler._headers


def requested_range_applied(
    request_handler: RequestHandler,
    range: tuple[int, int] | None,
    *,
    expected_range: tuple[int, int],
    expected_content_range_header_value: str,
) -> None:
    assert range == expected_range
    assert request_handler.get_status() == 206
    assert (
        request_handler._headers.get("Content-Range")
        == expected_content_range_header_value
    )


def requested_range_unsatisfiable(
    request_handler: RequestHandler,
    range: tuple[int, int] | None,
    *,
    expected_content_range_header_value: str,
) -> None:
    assert not range
    assert request_handler.get_status() == 416
    assert (
        request_handler._headers.get("Content-Range")
        == expected_content_range_header_value
    )


@pytest.mark.parametrize(
    ("request_kwargs", "repr_length", "check"),
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
                expected_range=(5, 6),
                expected_content_range_header_value="bytes 5-5/10",
            ),
        ),
        (
            dict(method="GET", headers={"Range": "bytes=5-20"}),
            10,
            partial(
                requested_range_applied,
                expected_range=(5, 10),
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
    request_kwargs: Mapping,
    repr_length: int,
    check: Callable[[RequestHandler, tuple[int, int] | None], None],
):
    request_handler = RequestHandler(Request(**request_kwargs))
    content_range = request_handler.apply_requested_range(repr_length=repr_length)
    check(request_handler, content_range)


@pytest.mark.parametrize(
    ("range_spec", "unit", "method", "repr_length", "expected_test_result"),
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
    expected_test_result: ContentRangeTestResult,
) -> None:
    """Test computing of `Content-Range` values from single range specifiers, exercising the `http.content_range` function."""

    def _get_result(
        range_spec: str, *, unit: str, method: str, repr_length: int
    ) -> ContentRangeTestResult:
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
        return (
            range,
            is_range_invalid,
            is_range_satisfiable,
            (
                http.content_range(
                    range, unit=unit, method=method, repr_length=repr_length
                )
                if (not is_range_invalid) and is_range_satisfiable and repr_length
                else None
            ),
        )  # type: ignore[arg-type]

    assert (
        _get_result(range_spec, unit=unit, method=method, repr_length=repr_length)
        == expected_test_result
    )


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
):
    """Test the `ranges-specifier` parser in full-match mode.

    The `ranges-specifier` HTTP grammar element defines the set of all syntactically valid `Range` header values.
    """
    if match := http.ranges_spec_matcher.fullmatch(ranges_spec):
        unit_match, _, range_set_match = match
        assert (
            unit_match.group(),
            tuple(
                http.range_from_match_groups(match.groups())
                for match in range_set_match
                if match.re == http.range_spec_re
            ),
        ) == (expected_result or ((None,) * 2))
    else:
        assert match == expected_result

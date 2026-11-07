from functools import partial
from typing import Callable
from typing import Mapping

import pytest

from tsdfileapi import utils


class Request:
    def __init__(self, *, method: str, headers: Mapping[str, str] = {}):
        self.method = method
        self.headers = headers


class RequestHandler:
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

    for name in (
        "apply_requested_range",
        "is_range_request",
    ):
        locals()[name] = getattr(utils.RequestHandler, name)


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
    try:
        content_range = request_handler.apply_requested_range(repr_length=repr_length)
    except utils.ClientContentRangeError as error:
        request_handler.set_status(416)
        for name, value in error.headers.items():
            request_handler.set_header(name, value)
        content_range = None
    check(request_handler, content_range)

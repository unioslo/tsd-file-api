"""A Pytest application for unit testing of `tsdfileapi.http`.

Targets RFC 9110 compliance.
"""

from typing import TypeAlias

import pytest

from tsdfileapi import http

ContentRangeTestResult: TypeAlias = tuple[
    http.Range | None, bool | None, bool | None, tuple[int, int] | None
]


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

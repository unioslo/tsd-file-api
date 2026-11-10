"""All things HTTP in general, following relevant RFCs.

Is destined to be a stand-alone package but hasn't moved out of the parents' house yet.
"""

if __debug__:
    import logging

import re
import sys
from datetime import datetime
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING
from typing import Iterable
from typing import Protocol
from typing import Sequence
from typing import TypeAlias

if __debug__:
    logger = logging.getLogger(__name__)

Range: TypeAlias = tuple[
    int | None, int | None
]  # A 2-tuple of start and end (_exclusive_) positions defining a [strictly continous] range; note how this is compatible with Python's own `slice` and `range` (assuming [the default] step of 1), where in contrast to the "last position" semantics employed by HTTP, an _exclusive_ end position is used (i.e. a `Range` value of `(0, 1)` has the length of 1, starting at 0 and ending at 1 where the latter index is _not_ included in the range)

comma_list_sep_re = re.compile(
    r"[\x20\x09]*,[\x20\x09]*"
)  # The well-known "comma surrounded by optional white-space" HTTP grammar element (see the `#` addition to ABNF in HTTP)
eq_re = re.compile(
    "="
)  # For consistency to provide `re.Match` even for simplest of patterns matched (otherwise we'd need to have our own `Match` implementation)
range_spec_re = re.compile(
    r"(\d+)-(\d+)?|-(\d+)", flags=re.ASCII
)  # The `range-spec` HTTP grammar element
token_re = re.compile(
    r"[\w\x21\x23-\x27\x2a-\x2b\x2d-\x2e\x5e-\x60\x7c\x7e]+", flags=re.ASCII
)  # The well-known `token` HTTP grammar element


class Match(Protocol):
    """Result of pattern matching, a sub-set of `re.Match` (for consistency)."""

    def end(self) -> int: ...


class CompoundMatch(Match):
    """Composite (compound) match results.

    Offered as ergonomy for our matchers specifically.
    """

    def __init__(self, matches: Sequence["Match"]):
        self.matches = matches

    def __getitem__(self, index: int):
        return self.matches[index]

    def __iter__(self):
        yield from self.matches

    def end(self):
        return self.matches[-1].end()


class Matcher(Protocol):
    """Objects that offer methods much like `re.Pattern`, for API compatibility."""

    def match(
        self, value: str, pos: int = 0, endpos: int = sys.maxsize
    ) -> Match | None: ...

    def fullmatch(
        self, value: str, pos: int = 0, endpos: int = sys.maxsize
    ) -> Match | None: ...


class FullMatcherMixin:
    """Adds a `fullmatch` method compatible with `re.Pattern.fullmatch`."""

    def fullmatch(
        self, value: str, pos: int = 0, endpos: int = sys.maxsize
    ) -> Match | None:
        match = self.match(value, pos, endpos)
        return match if (match and (match.end() == min(len(value), endpos))) else None


class RangeSetMatcher(FullMatcherMixin, Matcher):
    """Matches the `range-set` production (a list of `range-spec` separated with comma surrounded by optional white-space)."""

    def match(self, value: str, *args) -> Match | None:
        elements = tuple(self.match_iter(value, *args))
        return CompoundMatch(elements) if elements else None

    def match_iter(self, value: str, pos=0, *args) -> Iterable[Match]:
        while True:
            match = range_spec_re.match(value, pos, *args)
            if match:
                yield match
                pos = match.end()
            match = comma_list_sep_re.match(value, pos, *args)
            if not match:
                return None
            yield match
            pos = match.end()


range_set_matcher = RangeSetMatcher()  # The `range-set` HTTP grammar element


class ByteRangesSpecMatcher(FullMatcherMixin, Matcher):
    """The `ranges` HTTP grammar production matcher.

    This is really a regular "concatenation" matcher (A followed by B followed by C etc), but general parsing construct utilities go beyond the scope of this module so we just cut it short and straight to defining specifically the `ranges` production with a dedicated class.
    """

    def match(self, value: str, pos=0, endpos: int = sys.maxsize) -> Match | None:
        unit_match = token_re.match(value, pos, endpos)
        if not unit_match:
            return None
        eq_match = eq_re.match(value, pos := unit_match.end(), endpos)
        if not eq_match:
            return None
        range_set_match = range_set_matcher.match(value, pos := eq_match.end(), endpos)
        if not range_set_match:
            return None
        return CompoundMatch((unit_match, eq_match, range_set_match))


range_header_matcher = ranges_spec_matcher = ByteRangesSpecMatcher()


def content_range(
    range: Range, repr_length: int, *, unit: str, method: str
) -> tuple[int, int]:
    """
    Compute range (first and last positions) for use as `range-resp` in the `Content-Range` header.

    Assumes `repr_length` is not zero (because `Content-Range` cannot represent an empty range), and that `range_spec` is a _satisfiable_ range specifier (`is_satisfiable_range` can be used to assert that).

    Content ranges computed by this function, always feature an _exclusive_ end position -- one that marks "true" end of the range, meaning that its value is always exactly one more than the last position.
    """
    assert (
        repr_length > 0
    )  # Specifically zero-length representation cannot produce results usable with `Content-Range`
    assert not is_invalid_range(
        range
    )  # HTTP does not define validity for `suffix-range` specifiers at all so `is_invalid_range` always returns `None` (indeterminate) for these, while satisfiability is defined for "valid" range specifiers _including_ `suffix-range` specifiers (mentioned explicitly), which seems confusing/contradictory; to be able to implement determination of satisfiability for the latter we must necessarily permit indeterminate validity (`None`)
    assert is_satisfiable_range(
        range, unit=unit, method=method, repr_length=repr_length
    )
    if TYPE_CHECKING:
        assert (range[1] != 0) and (range[0] is not None)
    abs_start = start if (start := range[0]) >= 0 else max(0, repr_length + start)
    abs_end = min(end, repr_length) if (end := range[1]) is not None else repr_length
    assert abs_end > abs_start
    return abs_start, abs_end


def is_invalid_range(range: Range) -> bool | None:
    """
    Determine whether a range is invalid.

    Assumes `range` was parsed from the `Range` header -- this module concerns itself with HTTP which by grammar necessarily leaves out subset(s) of otherwise possible `Range` values (e.g. `(-1, -2)` or `(None, -1)`), which we don't need to support.

    Returns `True` if the range is invalid, `False` if it is valid, and `None` if it is neither because no criteria that would classify it as either, apply. This follows in the same vein as "satisfiability" (see `is_satisfiable_range`).
    """
    start, end = range
    if (
        (start is not None) and (end is not None)
    ):  # "An `int-range` is invalid if the `last-pos` is present ..."; with our `Range` semantics, an `int-range` is effectively one where the first element of the 2-tuple is a natural number (incl. zero) and end is not `None` or `0`; the `(None, 0)` tuple (parsed only from `-0`) is explicitly excluded because although permissible through the grammar, validity isn't defined for it
        assert start >= 0
        assert end >= 0
        return end <= start  # "... and less than the `first-pos`"
    assert (start is not None) or (end == 0)
    return None


def is_satisfiable_range(
    range: Range, *, unit: str, method: str, repr_length: int
) -> bool | None:
    """Determine whether a range is satisfiable (per the RFC).

    Assumes the range is not invalid.

    Returns `True` if the range is satisfiable, `False` if it is unsatisfiable, and `None` if it is neither because no criteria that would classify it as either, apply.
    """
    if (method == "GET") and (unit.lower() == "bytes"):
        assert not is_invalid_range(
            range
        )  # Satisfiability only defined for valid range specifiers ("... a valid bytes range-spec is satisfiable if ..."), and instead of returning `None` we choose to be strict and demand invalid ranges aren't attempted checked for satisfiability (implying we want the caller to have checked validity [explicitly] _before_ checking satisfiability)
        start, end = range
        if TYPE_CHECKING:
            assert (range[1] != 0) and (range[0] is not None)
        return (
            (range[0] < repr_length)
            if (range[1] != 0) and (range[0] >= 0)
            else bool(range[0])
        )
    return None


def parse_datetime(value: str) -> datetime | None:
    """
    Parse an `HTTP-date` value (RFC 9110 §5.6.7).

    Returns an aware UTC `datetime`, or `None` if the value is not an `HTTP-date`.

    Senders are required to generate the `IMF-fixdate` format, while recipients are required to accept the two obsolete formats (RFC 850 and ANSI C's asctime) as well. When no zone is indicated (the asctime format carries none, and an explicit `-0000` means UTC but with an unknown source zone), the value is still defined as UTC, so the result is always made UTC-aware.
    """
    try:
        parsed = parsedate_to_datetime(value)
    except ValueError:
        return None
    return (
        parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    )  # No zone ("asctime") or an explicit `-0000` both yield a so-called "naive" `datetime`, so must "normalise" because `HTTP-date` implies UTC


def range_from_match_groups(groups: Sequence[str | None]) -> Range:
    """Parse a sequence of groups of a `Match` object (presumably obtained with calling `range_spec_re.match`)."""
    a, b, c = groups
    assert (
        (a and not c) or (c and not b)
    )  # To ensure we're interpreting the groups in accordange with the regular expression
    return (
        (int(a), (int(b) + 1) if b else None)
        if a
        else ((-x, None) if (x := int(c)) else (None, 0))
    )  # type: ignore[arg-type]


class RequestHandler:
    """Implement HTTP (RFC) as a "request handler" (de-facto compatible with `tornado.web.RequestHandler` _as a mix-in / super-class_)."""

    def apply_requested_range(
        self,
        *,
        repr_length: int,
    ) -> tuple[int, int] | None:
        """
        Handle the range specified in the request [being handled], by applying it to the response.

        Uses representation length (aka "resource length" or "full file size") to resolve the requested values as normalised (counted from first byte as `0`) and applicable specifically to the representation.

        Applies resolved range by setting appropriate status code and header(s) like `Content-Range`, returning the former for convenience (so that `Content-Range` doesn't have to be parsed by caller to determine the applied range). If the range cannot be applied, `None` is returned, ether because the range was ignored or because it was rejected as unsatisfiable, with appropriate status code and header(s) set on the response.

        This procedure returns _half-open_ ranges (index matching the "end" value is not part of the range) -- in accordance and for consistency with semantics of Python's own `slice` and `range`.
        """
        assert self.is_range_request()
        if not self.is_range_handling_defined():
            if __debug__:
                logger.debug("Range handling not defined")
            return None
        if repr_length == 0:
            if __debug__:
                logger.debug(
                    "Empty representation (cannot be represented with `Content-Range`)"
                )
            return None
        if not (
            range_header_match := range_header_matcher.fullmatch(
                self.request.headers["Range"]
            )
        ):
            if __debug__:
                logger.debug("Does not conform to the grammar")
            return None
        unit_match, _, range_set_match = (
            range_header_match  # NOTE: `range_header_match` is a `[http.]Match`, not a `re.Match` object -- the former implements only a sub-set of the latter's interface; methods like `groups`, for example, are omitted in large part because they don't apply as well to matches obtained through `Matcher` objects (e.g. `range_header_matcher`) which implement relatively _opaque_ "patterns" compared to `re.Pattern` that they partially model (for consistency and to leverage familiarity with `re`)
        )
        unit = unit_match.group().lower()
        if unit != "bytes":
            if __debug__:
                logger.debug("Unsupported range unit")
            return None
        ranges = (
            range_from_match_groups(match.groups())
            for match in range_set_match
            if match.re == range_spec_re
        )
        range = next(ranges)
        if next(ranges, None):
            if __debug__:
                logger.debug("Multiple ranges are not supported")
            return None
        if is_invalid_range(range):
            if __debug__:
                logger.debug("Invalid range")
            return None
        method = self.request.method
        if not is_satisfiable_range(
            range,
            unit=unit,
            method=method,
            repr_length=repr_length,
        ):
            self.set_status(416)
            self.set_header("Content-Range", f"{unit} */{repr_length}")
            return None
        content_start, content_end = content_range(
            range,
            repr_length,
            unit=unit,
            method=method,
        )
        self.set_status(206)
        self.set_header(
            "Content-Range", f"{unit} {content_start}-{content_end - 1}/{repr_length}"
        )
        return content_start, content_end

    def if_range_matches(self) -> bool:
        """Determine if condition expressed with the `If-Range` request header, applies.

        Note that although clients are explicitly prohibited by the RFC to send _weak_ entity tag values in `If-Range`, evaluation of the condition _is defined_ for these values, i.e. is no cause for aborting (the procedure returns `False`).
        """
        assert (
            "Range" in self.request.headers
        )  # Assert since use of `If-Range` is conditional on presence of `Range`
        if_range = self.request.headers["If-Range"]
        if if_range[:2].lower() == "w/":
            if __debug__:
                logger.debug("Client used a weak entity tag in `If-Range`")
            return False
        return (
            (if_range == self._headers.get("ETag"))
            if '"' in if_range[0:3]
            else (
                parse_datetime(if_range)
                == parse_datetime(self._headers.get("Last-Modified"))
            )
        )

    def is_range_handling_defined(self) -> bool | None:
        return self.request.method == "GET"

    def is_range_request(self) -> bool:
        """Determine if the request being handled is a so-called HTTP range request, i.e. warrants resolving of requested (partial) content range."""
        return self.request.headers.get("Range") and (
            (not self.request.headers.get("If-Range")) or self.if_range_matches()
        )

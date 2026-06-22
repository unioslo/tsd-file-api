from aiofiles.threadpool.binary import (
    AsyncBufferedIOBase as BufferedRandom,  # noqa: F401
)  # In `aiofiles`' (https://github.com/Tinche/aiofiles/blob/348f5ef6561c2b2c8a7497bd10487eab4102332f/src/aiofiles/threadpool/binary.py#L25), `AsyncBufferedIOBase` implements `seek` and `tell` among other things that qualify it as the equivalent of Python's own `io.BufferedRandom`, although I'd prefer the name mimicked the latter, e.g. `AsyncBufferedRandom`
from aiofiles.threadpool.binary import (
    AsyncFileIO as RawIOBase,  # noqa: F401
)  # Similar story as above

"""mpubsub -- brokerless IPv6-multicast pub/sub, in pure Python.

Two layers:

* :mod:`mpubsub.wire` -- the wire format (framing, ChaCha20-Poly1305 AEAD,
  replay guard). Stdlib-only; a byte-identical copy of the protocol's
  reference implementation, so it moves in lockstep with the C++, Go and
  Home Assistant implementations.
* :mod:`mpubsub.aio` -- an asyncio client that subscribes and publishes.

    import asyncio
    from mpubsub import MpubsubClient

    async def main():
        async with MpubsubClient(scope="link-local") as client:
            await client.subscribe("home/kitchen/temp", print)
            await asyncio.sleep(3600)

    asyncio.run(main())
"""

from . import wire
from .aio import (
    Message,
    MpubsubClient,
    MpubsubError,
    TopicError,
    resolve_scope,
    validate_topic,
)
from .wire import (
    DEFAULT_PORT,
    ENCODING_PROTOBUF,
    ENCODING_RAW,
    MAX_PAYLOAD,
    WireError,
    decode,
    derive_key,
    encode,
    topic_crc32,
    topic_to_group,
)

__all__ = [
    "DEFAULT_PORT",
    "ENCODING_PROTOBUF",
    "ENCODING_RAW",
    "MAX_PAYLOAD",
    "Message",
    "MpubsubClient",
    "MpubsubError",
    "TopicError",
    "WireError",
    "decode",
    "derive_key",
    "encode",
    "resolve_scope",
    "topic_crc32",
    "topic_to_group",
    "validate_topic",
    "wire",
]

__version__ = "0.1.0"

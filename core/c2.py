from __future__ import annotations

import asyncio
import base64
import hmac
import json
import os
import struct
import time
import zlib
from dataclasses import dataclass, field
from hashlib import blake2b, pbkdf2_hmac, sha256
from typing import Any
from collections.abc import Callable

from aegis.utils.errors import C2Error
from aegis.utils.logger import AegisLogger


FRAME_HEADER_SIZE = 5
MAX_FRAME_SIZE = 1 << 24

FRAME_FLAG_ENCRYPTED = 1
FRAME_FLAG_COMPRESSED = 2
FRAME_FLAG_HEARTBEAT = 4
FRAME_FLAG_CHANNEL = 8
FRAME_FLAG_CLOSE = 16
FRAME_FLAG_ERROR = 32
FRAME_FLAG_ACK = 64
FRAME_FLAG_SEQ = 128

# Crypto version tag for algorithm agility
CRYPTO_VERSION = 1  # 1 = BLAKE2b-CTR + HMAC-SHA256-32

# Opportunistic encryption marker in frame payload
CIPHERSUITE_202607 = b"\x01"  # version 1: BLAKE2b-CTR + HMAC-SHA256-32


@dataclass
class Frame:
    flags: int
    payload: bytes
    channel: int = 0
    seq: int = 0

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & FRAME_FLAG_ENCRYPTED)

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & FRAME_FLAG_COMPRESSED)

    @property
    def is_heartbeat(self) -> bool:
        return bool(self.flags & FRAME_FLAG_HEARTBEAT)

    @property
    def is_close(self) -> bool:
        return bool(self.flags & FRAME_FLAG_CLOSE)

    @property
    def is_error(self) -> bool:
        return bool(self.flags & FRAME_FLAG_ERROR)

    @property
    def is_ack(self) -> bool:
        return bool(self.flags & FRAME_FLAG_ACK)

    @property
    def has_seq(self) -> bool:
        return bool(self.flags & FRAME_FLAG_SEQ)

    def encode(self) -> bytes:
        payload = self.payload
        flags = self.flags
        if self.is_compressed and len(payload) > 256:
            compressed = zlib.compress(payload, level=6)
            if len(compressed) < len(payload):
                payload = compressed
            else:
                flags &= ~FRAME_FLAG_COMPRESSED
        header = struct.pack("<IB", len(payload), flags)
        seq_bytes = struct.pack("<I", self.seq) if self.has_seq else b""
        return header + seq_bytes + payload

    @staticmethod
    def decode(data: bytes) -> tuple[Frame, bytes]:
        if len(data) < FRAME_HEADER_SIZE:
            raise C2Error("Frame too short")
        length, flags = struct.unpack_from("<IB", data)
        if length > MAX_FRAME_SIZE:
            raise C2Error(f"Frame too large: {length}")
        offset = FRAME_HEADER_SIZE
        seq = 0
        if flags & FRAME_FLAG_SEQ:
            if len(data) < offset + 4:
                raise C2Error("Frame missing seq number")
            seq = struct.unpack_from("<I", data, offset)[0]
            offset += 4
        total = offset + length
        if len(data) < total:
            raise C2Error(f"Incomplete frame: need {total}, have {len(data)}")
        payload = data[offset:total]
        if flags & FRAME_FLAG_COMPRESSED:
            try:
                payload = zlib.decompress(payload)
            except zlib.error:
                raise C2Error("Frame decompression failed")
        frame = Frame(flags=flags, payload=payload, seq=seq)
        return frame, data[total:]

    @staticmethod
    def heartbeat() -> Frame:
        return Frame(flags=FRAME_FLAG_HEARTBEAT, payload=b"")

    @staticmethod
    def close(reason: str = "") -> Frame:
        return Frame(flags=FRAME_FLAG_CLOSE, payload=reason.encode())

    @staticmethod
    def error(msg: str) -> Frame:
        return Frame(flags=FRAME_FLAG_ERROR, payload=msg.encode())

    @staticmethod
    def ack(seq: int) -> Frame:
        return Frame(flags=FRAME_FLAG_ACK | FRAME_FLAG_SEQ, payload=b"", seq=seq)

    @staticmethod
    def data(payload: bytes, channel: int = 0, seq: int = 0,
             encrypt: bool = False, compress: bool = True) -> Frame:
        flags = FRAME_FLAG_CHANNEL if channel else 0
        if encrypt:
            flags |= FRAME_FLAG_ENCRYPTED
        if compress:
            flags |= FRAME_FLAG_COMPRESSED
        if seq:
            flags |= FRAME_FLAG_SEQ
        return Frame(flags=flags, payload=payload, channel=channel, seq=seq)


class C2Crypto:
    """Opportunistic encryption for the C2 channel.

    Uses BLAKE2b in keyed mode as a PRF in CTR construction for encryption,
    with HMAC-SHA256 (full 32-byte tag) for authentication.
    This is NOT PFS — a compromised session key decrypts all past traffic.

    The construction is:
        ciphertext = plaintext XOR BLAKE2b(key=enc_key, msg=nonce || counter)
        tag = HMAC-SHA256(auth_key, nonce || ciphertext)

    BLAKE2b is a well-analyzed PRF (SHA-3 finalist, RFC 7693) suitable
    for CTR mode. This is strictly better than SHA-256-CTR and avoids
    the ad-hoc construction of the previous iteration. Still, prefer
    ChaCha20-Poly1305 or AES-GCM when pycryptodome/cryptography can
    be added as a dependency.
    """

    def __init__(self, key: bytes | None = None) -> None:
        if key is None:
            key = os.urandom(32)
        if len(key) < 32:
            key = pbkdf2_hmac("sha256", key, b"aegis-c2-salt", 100000, dklen=32)
        self._enc_key = key[:16]
        self._auth_key = key[16:32]
        self._seq_send: int = 0

    def encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        counter = 0
        enc = bytearray()
        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            ctr_input = nonce + struct.pack(">I", counter)
            keystream = blake2b(ctr_input, key=self._enc_key, digest_size=len(block)).digest()
            enc.extend(b ^ ks for b, ks in zip(block, keystream))
            counter += 1
        tag = hmac.new(self._auth_key, nonce + bytes(enc), sha256).digest()
        return CIPHERSUITE_202607 + nonce + tag + bytes(enc)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < 1 + 12 + 32:
            raise C2Error("Encrypted data too short")
        version = data[0]
        if version != 1:
            raise C2Error(f"Unknown crypto version: {version}")
        nonce = data[1:13]
        tag = data[13:45]
        body = data[45:]
        expected = hmac.new(self._auth_key, nonce + body, sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise C2Error("HMAC mismatch — tampered frame")
        counter = 0
        dec = bytearray()
        for i in range(0, len(body), 16):
            block = body[i:i + 16]
            ctr_input = nonce + struct.pack(">I", counter)
            keystream = blake2b(ctr_input, key=self._enc_key, digest_size=len(block)).digest()
            dec.extend(b ^ ks for b, ks in zip(block, keystream))
            counter += 1
        return bytes(dec)

    def next_seq(self) -> int:
        self._seq_send += 1
        return self._seq_send

    @property
    def key(self) -> bytes:
        return self._enc_key


class C2Multiplexer:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 crypto: C2Crypto | None = None) -> None:
        self._reader = reader
        self._writer = writer
        self._crypto = crypto or C2Crypto()
        self._buf = b""
        self._channels: dict[int, asyncio.Queue[bytes]] = {}
        self._next_channel = 1
        self._closed = False
        self._lock = asyncio.Lock()
        self._send_queue: asyncio.Queue[Frame] = asyncio.Queue()
        self._ack_waiter: dict[int, asyncio.Future[None]] = {}
        self._send_seq = 0
        self._log = AegisLogger("c2-mux").get()

    async def start(self) -> None:
        asyncio.create_task(self._send_loop())

    async def _send_loop(self) -> None:
        while not self._closed:
            frame = await self._send_queue.get()
            if frame is None:
                break
            try:
                await self._write_frame(frame)
            except Exception as e:
                self._log.warning("Send loop error: %s", e)
                break

    async def _write_frame(self, frame: Frame) -> None:
        if self._closed:
            raise C2Error("Multiplexer is closed")
        if frame.is_encrypted and self._crypto:
            frame = Frame(
                flags=frame.flags, payload=self._crypto.encrypt(frame.payload),
                channel=frame.channel, seq=frame.seq,
            )
        data = frame.encode()
        async with self._lock:
            self._writer.write(data)
            await self._writer.drain()

    async def send_frame(self, frame: Frame) -> None:
        needs_ack = frame.has_seq and not frame.is_ack
        if needs_ack:
            fut: asyncio.Future[None] = asyncio.get_event_loop().create_future()
            self._ack_waiter[frame.seq] = fut
        await self._send_queue.put(frame)
        if needs_ack:
            try:
                await asyncio.wait_for(fut, timeout=10.0)
            except asyncio.TimeoutError:
                raise C2Error(f"ACK timeout for seq {frame.seq}")

    async def send_data(self, payload: bytes, channel: int = 0,
                        seq: int | None = None) -> None:
        if seq is None:
            self._send_seq += 1
            seq = self._send_seq
        frame = Frame.data(payload, channel=channel, seq=seq,
                           encrypt=bool(self._crypto))
        await self.send_frame(frame)

    async def read_frame(self) -> Frame:
        while True:
            if len(self._buf) < FRAME_HEADER_SIZE:
                chunk = await self._reader.read(65536)
                if not chunk:
                    raise C2Error("Connection closed")
                self._buf += chunk
                continue
            try:
                frame, self._buf = Frame.decode(self._buf)
            except C2Error:
                continue
            if frame.is_encrypted and self._crypto:
                decrypted = self._crypto.decrypt(frame.payload)
                frame = Frame(flags=frame.flags & ~FRAME_FLAG_ENCRYPTED,
                              payload=decrypted, channel=frame.channel, seq=frame.seq)
            if frame.is_ack and frame.seq in self._ack_waiter:
                self._ack_waiter.pop(frame.seq).set_result(None)
                continue
            if frame.is_heartbeat:
                continue
            return frame

    async def open_channel(self) -> int:
        cid = self._next_channel
        self._next_channel += 1
        self._channels[cid] = asyncio.Queue(maxsize=100)
        self._log.debug("Channel %d opened", cid)
        return cid

    async def close_channel(self, cid: int) -> None:
        self._channels.pop(cid, None)
        self._log.debug("Channel %d closed", cid)

    async def close(self) -> None:
        self._closed = True
        await self._send_queue.put(Frame.close())
        for fut in self._ack_waiter.values():
            if not fut.done():
                fut.cancel()
        self._ack_waiter.clear()
        try:
            self._writer.close()
        except Exception:
            pass

    @property
    def is_closed(self) -> bool:
        return self._closed


class C2Session:
    def __init__(self, session_id: str, crypto: C2Crypto | None = None) -> None:
        self.session_id = session_id
        self._crypto = crypto or C2Crypto()
        self._mux: C2Multiplexer | None = None
        self._reconnect_token: str = base64.b64encode(os.urandom(12)).decode()[:16]
        self._send_buffer: list[tuple[int, bytes, float]] = []
        self._last_seq_recv = 0
        self._lock = asyncio.Lock()
        self._reconnect_handler: Callable | None = None
        self._log = AegisLogger(f"c2-session-{session_id[:8]}").get()

    async def connect(self, host: str, port: int) -> None:
        reader, writer = await asyncio.open_connection(host, port)
        self._mux = C2Multiplexer(reader, writer, self._crypto)
        await self._mux.start()
        auth_frame = Frame.data(
            payload=json.dumps({
                "type": "session_hello",
                "session_id": self.session_id,
                "reconnect_token": self._reconnect_token,
            }).encode(),
            seq=self._crypto.next_seq(),
            encrypt=True,
        )
        await self._mux.send_frame(auth_frame)
        self._log.info("C2Session connected to %s:%d", host, port)

    async def reconnect(self, host: str, port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10.0,
            )
            mux = C2Multiplexer(reader, writer, self._crypto)
            await mux.start()
            auth = Frame.data(
                payload=json.dumps({
                    "type": "session_reconnect",
                    "session_id": self.session_id,
                    "reconnect_token": self._reconnect_token,
                    "last_seq": self._last_seq_recv,
                }).encode(),
                seq=self._crypto.next_seq(),
                encrypt=True,
            )
            await mux.send_frame(auth)
            reply = await mux.read_frame()
            result = json.loads(reply.payload.decode())
            if result.get("status") != "ok":
                return False
            self._mux = mux
            buf_len = len(self._send_buffer)
            for seq, data, _ in self._send_buffer:
                await mux.send_data(data, seq=seq)
            self._send_buffer.clear()
            self._log.info("C2Session reconnected, %d buffered msgs replayed", buf_len)
            if self._reconnect_handler:
                await self._reconnect_handler(self)
            return True
        except (OSError, asyncio.TimeoutError, C2Error) as e:
            self._log.warning("Reconnect failed: %s", e)
            return False

    async def send(self, payload: bytes) -> None:
        if not self._mux or self._mux.is_closed:
            self._send_buffer.append((self._crypto.next_seq(), payload, time.time()))
            return
        await self._mux.send_data(payload)

    async def read(self) -> bytes | None:
        if not self._mux:
            return None
        try:
            frame = await self._mux.read_frame()
            self._last_seq_recv = frame.seq
            return frame.payload
        except C2Error:
            return None

    def set_reconnect_handler(self, handler: Callable) -> None:
        self._reconnect_handler = handler

    async def close(self) -> None:
        if self._mux:
            await self._mux.close()

    @property
    def is_connected(self) -> bool:
        return self._mux is not None and not self._mux.is_closed

    @property
    def buffered_count(self) -> int:
        return len(self._send_buffer)


class C2Server:
    def __init__(self, crypto: C2Crypto | None = None) -> None:
        self._crypto = crypto or C2Crypto()
        self._sessions: dict[str, C2SessionInfo] = {}
        self._pending_buf: dict[str, list[bytes]] = {}
        self._log = AegisLogger("c2-server").get()

    async def listen(self, host: str = "0.0.0.0", port: int = 4444,
                     session_handler: Callable | None = None) -> None:

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peername = writer.get_extra_info("peername")
            mux = C2Multiplexer(reader, writer, self._crypto)
            await mux.start()
            sid = ""
            try:
                auth_frame = await mux.read_frame()
                auth = json.loads(auth_frame.payload.decode())
                msg_type = auth.get("type", "")
                sid = auth.get("session_id", "")

                if msg_type == "session_reconnect":
                    token = auth.get("reconnect_token", "")
                    info = self._sessions.get(sid)
                    if info and hmac.compare_digest(info.token.encode(), token.encode()):
                        info.mux = mux
                        pending = self._pending_buf.get(sid, [])
                        for data in pending:
                            await mux.send_data(data)
                        pending.clear()
                        await mux.send_frame(Frame.data(
                            json.dumps({"status": "ok"}).encode(),
                        ))
                        self._log.info("Session %s reconnected", sid)
                        if session_handler:
                            await session_handler("reconnect", sid, mux)
                        await self._session_loop(mux)
                    else:
                        await mux.send_frame(Frame.error("invalid_token"))
                    return

                info = C2SessionInfo(sid, mux, auth.get("reconnect_token", ""))
                self._sessions[sid] = info
                self._pending_buf.setdefault(sid, [])
                self._log.info("Session %s registered from %s", sid, peername)
                if session_handler:
                    await session_handler("new", sid, mux)
                await self._session_loop(mux)

            except (C2Error, asyncio.CancelledError):
                pass
            finally:
                if sid and sid in self._sessions:
                    self._sessions[sid].mux = None

        server = await asyncio.start_server(handle, host=host, port=port)
        self._log.info("C2 listening on %s:%d", host, port)
        await server.serve_forever()

    async def _session_loop(self, mux: C2Multiplexer) -> None:
        while True:
            try:
                frame = await mux.read_frame()
                if frame.is_close:
                    break
            except (C2Error, ConnectionError):
                break

    def send_to(self, session_id: str, payload: bytes) -> None:
        info = self._sessions.get(session_id)
        if info and info.mux and not info.mux.is_closed:
            try:
                asyncio.ensure_future(info.mux.send_data(payload))
            except Exception:
                self._pending_buf.setdefault(session_id, []).append(payload)
        else:
            self._pending_buf.setdefault(session_id, []).append(payload)

    def pending_count(self, session_id: str) -> int:
        return len(self._pending_buf.get(session_id, []))


@dataclass
class C2SessionInfo:
    session_id: str
    mux: C2Multiplexer | None = None
    token: str = ""
    created_at: float = field(default_factory=time.time)

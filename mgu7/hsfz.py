import select
import socket
import struct
import threading
import time
ENET_PORT = 6801
TESTER = 244
MGU = 99
GATEWAY = 223
TYPE_DIAG = 1
TYPE_ECHO = 2
TYPE_REJECT = 255
MAX_FRAME = 1048576
DEFAULT_GATEWAY = '169.254.0.2'

class HsfzError(Exception):
    pass

class UdsReject(HsfzError):

    def __init__(self, message, sid=0, nrc=0):
        super().__init__(message)
        self.sid = sid
        self.nrc = nrc

class T:
    __slots__ = ('type', 'src', 'dst', 'payload')

    def __init__(self, ftype, src, dst, payload):
        self.type = ftype
        self.src = src
        self.dst = dst
        self.payload = bytes(payload)

    def raw(self):
        body = bytes((self.src, self.dst)) + self.payload
        if len(body) > MAX_FRAME:
            raise HsfzError('HSFZ frame exceeds the supported size.')
        return struct.pack('>IH', len(body), self.type) + body

    @staticmethod
    def parse(data):
        if len(data) < 8:
            raise HsfzError('HSFZ frame is shorter than its header.')
        length, ftype = struct.unpack('>IH', data[0:6])
        if length < 2 or length > MAX_FRAME:
            raise HsfzError('HSFZ frame contains an invalid body length.')
        if len(data) != 6 + length:
            raise HsfzError('HSFZ frame length does not match its header.')
        return T(ftype, data[6], data[7], data[8:])

    @staticmethod
    def total_length(header):
        if len(header) < 6:
            raise HsfzError('The ENET gateway returned a truncated HSFZ header.')
        length = struct.unpack('>I', header[0:4])[0]
        if length < 2 or length > MAX_FRAME:
            raise HsfzError('The ENET gateway returned an invalid HSFZ frame length.')
        return 6 + length

class X:
    __slots__ = ('data', 'negative', 'sid', 'nrc')

    def __init__(self, payload):
        self.data = bytes(payload or b'')
        self.negative = len(self.data) >= 3 and self.data[0] == 127
        if self.negative:
            self.sid = self.data[1]
            self.nrc = self.data[2]
        else:
            self.sid = 0
            self.nrc = 0

    def is_pending(self):
        return self.negative and self.nrc == 120

    def require(self, request):
        if isinstance(request, (bytes, bytearray)):
            payload = bytes(request)
            request_sid = payload[0] if payload else 0
        else:
            payload = None
            request_sid = request
        if len(self.data) == 0:
            raise UdsReject('The ECU returned an empty UDS response.', request_sid, 0)
        if self.negative:
            raise UdsReject('The ECU rejected service 0x%02X with NRC 0x%02X.' % (self.sid, self.nrc), self.sid, self.nrc)
        if self.data[0] != request_sid + 64 & 255:
            raise UdsReject('Unexpected UDS response service 0x%02X; expected 0x%02X.' % (self.data[0], request_sid + 64 & 255), request_sid, 0)
        if payload is not None:
            check_echo(self.data, payload)
_ECHO_BYTES = {34: 2, 46: 2, 49: 3, 16: 1, 17: 1, 25: 1, 39: 1, 40: 1, 54: 1, 62: 1, 133: 1}

def check_echo(response, request):
    sid = request[0]
    n = _ECHO_BYTES.get(sid, 0)
    if n == 0:
        return
    if len(request) < 1 + n or len(response) < 1 + n:
        raise UdsReject('The positive UDS response is too short to verify its echoed identifier.', sid, 0)
    for i in range(n):
        if response[1 + i] != request[1 + i]:
            raise UdsReject('The positive UDS response echoes a different subfunction or identifier.', sid, 0)

def match_response(frames, src, dst=TESTER):
    result = None
    for f in frames:
        if isinstance(f, T) and f.type == TYPE_DIAG and (f.src == src) and (f.dst == dst):
            result = X(f.payload)
    return result

def require_response(frames, request, src, dst=TESTER, allow_missing=False):
    x = match_response(frames, src, dst)
    if x is None and (not allow_missing):
        raise UdsReject('The ECU returned no complete diagnostic response for service 0x%02X.' % request[0], request[0], 0)
    if x is not None:
        x.require(request[0])
    return x

class Profile:
    __slots__ = ('name', 'overall_ms', 'quiet_ms', 'slice_us', 'sleep_ms', 'require_complete')

    def __init__(self, name, overall_ms, quiet_ms, slice_us, sleep_ms, require_complete=False):
        self.name = name
        self.overall_ms = overall_ms
        self.quiet_ms = quiet_ms
        self.slice_us = slice_us * 1000
        self.sleep_ms = sleep_ms
        self.require_complete = require_complete
P_MAIN = Profile('delphi-main', 8001, 251, 100, 0)
P_READ_IP = Profile('delphi-read-ip', 2001, 201, 50, 0)
P_ADVANCED = Profile('delphi-advanced', 10000, 300, 60, 1, True)
P_SVK = Profile('delphi-svk', 10000, 300, 60, 0)
P_ISTEP = Profile('delphi-istep', 5001, 301, 50, 0)
P_FA = Profile('delphi-fa', 6000, 1200, 100, 0)
P_FLASH_TAIL = Profile('flash-functional-tail', 15000, 251, 100, 0, True)
P_NBT_CLOSE = Profile('nbt-ssh-close', 6001, 151, 100, 0)

class Response:
    __slots__ = ('frame', 'payload', 'pending', 'timeout')

    def __init__(self, frame=None, pending=0, timeout=False):
        self.frame = frame
        self.payload = X(frame.payload) if frame is not None else None
        self.pending = pending
        self.timeout = timeout

    @property
    def type(self):
        return self.frame.type if self.frame is not None else 0

    @property
    def src(self):
        return self.frame.src if self.frame is not None else 0

    @property
    def dst(self):
        return self.frame.dst if self.frame is not None else 0

def _is_route_ok(frame, req_src, req_dst):
    if frame.type != TYPE_DIAG or frame.dst != req_src:
        return False
    if req_dst != GATEWAY:
        return frame.src == req_dst
    return frame.src not in (0, req_src, req_dst)

class EnetClient:

    def __init__(self, gateway=DEFAULT_GATEWAY, port=ENET_PORT, log=None):
        self.gateway = gateway
        self.port = port
        self.log = log or (lambda direction, frame: None)
        self.sock = None
        self.buf = b''
        self.profile = None
        self.lock = threading.Lock()

    def connected(self):
        return self.sock is not None

    def connect(self):
        self.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.connect((self.gateway, self.port))
        self.sock = s
        self.buf = b''

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            self.buf = b''
            self.profile = None

    def send_suppressed(self, dst, request):
        with self.lock:
            if not self.connected():
                raise HsfzError('The ENET gateway is not connected.')
            self.send_frame(T(TYPE_DIAG, TESTER, dst, request))

    def send_frame(self, frame):
        if self.sock is None:
            raise HsfzError('The ENET gateway is not connected.')
        self.sock.sendall(frame.raw())
        self.log('tx', frame)

    def _read_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise HsfzError('The ENET connection was closed.')
            self.buf += chunk
        out, self.buf = (self.buf[:n], self.buf[n:])
        return out

    def _read_frame(self):
        head = self._read_exact(6)
        total = T.total_length(head)
        body = self._read_exact(total - 6)
        frame = T.parse(head + body)
        self.log('rx', frame)
        return frame

    def _receive(self, profile, require_data=True):
        frames = []
        last_data = None
        deadline = time.monotonic() + profile.overall_ms / 1000.0
        complete = False
        while True:
            now = time.monotonic()
            if now >= deadline:
                break
            if frames and last_data is not None and (now - last_data >= profile.quiet_ms / 1000.0):
                complete = True
                break
            if self.sock is None:
                raise HsfzError('The ENET connection was closed.')
            remain = min(deadline - now, profile.slice_us / 1000000.0)
            readable, _, _ = select.select([self.sock], [], [], max(remain, 0.0))
            if readable:
                try:
                    chunk = self.sock.recv(262144)
                except (ConnectionResetError, ConnectionAbortedError):
                    if not frames:
                        raise HsfzError('The ENET connection was closed.')
                    break
                if not chunk:
                    if not frames:
                        raise HsfzError('The ENET connection was closed.')
                    break
                self.buf += chunk
                last_data = time.monotonic()
            data, self.buf = (self.buf, b'')
            pos = 0
            while pos + 6 <= len(data):
                try:
                    total = T.total_length(data[pos:pos + 6])
                except HsfzError:
                    break
                if total > len(data) - pos:
                    break
                frame = T.parse(data[pos:pos + total])
                frames.append(frame)
                self.log('rx', frame)
                pos += total
            if pos < len(data):
                self.buf = data[pos:]
                last_data = time.monotonic()
            if profile.sleep_ms:
                time.sleep(profile.sleep_ms / 1000.0)
        if require_data and (not frames):
            raise HsfzError('No diagnostic response arrived within %d ms.' % profile.overall_ms)
        if frames and profile.require_complete and (not complete):
            raise HsfzError('The diagnostic response did not finish within the receive window.')
        return frames

    def request(self, dst, request, profile):
        if not request:
            raise HsfzError('A UDS request is required.')
        with self.lock:
            if not self.connected():
                raise HsfzError('The ENET gateway is not connected.')
            self.profile = profile
            try:
                self.send_frame(T(TYPE_DIAG, TESTER, dst, request))
                frames = self._receive(profile)
            except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                self.log('rx-reset', T(0, 0, 0, b''))
                try:
                    self.close()
                    self.connect()
                    self.profile = profile
                    self.send_frame(T(TYPE_DIAG, TESTER, dst, request))
                    frames = self._receive(profile)
                except (ConnectionResetError, ConnectionAbortedError, OSError) as e2:
                    raise HsfzError('The ENET gateway connection failed: %s' % e2)
            for f in frames:
                if f.type == TYPE_REJECT:
                    raise HsfzError('The ENET gateway rejected the diagnostic frame.')
            return frames

    def await_one(self, dst, request, timeout_ms):
        if not request:
            raise HsfzError('A UDS request is required.')
        if timeout_ms < 1:
            raise HsfzError('timeout must be positive')
        with self.lock:
            if not self.connected():
                raise HsfzError('The ENET gateway is not connected.')
            self.send_frame(T(TYPE_DIAG, TESTER, dst, request))
            pending = 0
            deadline = time.monotonic() + timeout_ms / 1000.0
            while True:
                remain = deadline - time.monotonic()
                if remain <= 0:
                    return Response(None, pending, True)
                self.sock.settimeout(max(remain, 0.001))
                try:
                    frame = self._read_frame()
                except (socket.timeout, TimeoutError):
                    return Response(None, pending, True)
                except HsfzError as e:
                    if 'closed' in str(e):
                        return Response(None, pending, True)
                    raise
                if frame.type == TYPE_ECHO:
                    deadline = time.monotonic() + timeout_ms / 1000.0
                    continue
                payload = X(frame.payload)
                if not (payload.is_pending() and payload.sid == request[0] and _is_route_ok(frame, TESTER, dst)):
                    return Response(frame, pending, False)
                pending += 1
                deadline = time.monotonic() + timeout_ms / 1000.0

    def await_routine(self, request, profile=None):
        if not request or len(request) < 4 or request[0] != 49:
            raise HsfzError('A RoutineControl request with a routine identifier is required.')
        profile = profile or self.profile or P_FLASH_TAIL
        with self.lock:
            if not self.connected():
                raise HsfzError('The ENET gateway is not connected.')
            src, dst = (TESTER, GATEWAY)
            self.send_frame(T(TYPE_DIAG, src, dst, request))
            try:
                frames = self._receive(profile)
            except HsfzError as e:
                if 'No diagnostic response' in str(e):
                    return Response(None, 0, True)
                raise
        positive = None
        negative = None
        pending = 0
        for f in frames:
            if f.type != TYPE_DIAG or f.dst != src or f.src in (0, src, dst):
                continue
            data = f.payload
            if len(data) >= 3 and data[0] == 127 and (data[1] == request[0]):
                if data[2] == 120:
                    pending += 1
                elif negative is None:
                    negative = f
            elif len(data) >= 4 and data[0] == 113 and (data[1] == request[1]) and (data[2] == request[2]) and (data[3] == request[3]) and (positive is None):
                positive = f
        chosen = positive if positive is not None else negative
        if chosen is None:
            return Response(None, pending, True)
        return Response(chosen, pending, False)

    def await_reset(self, dst, request, timeout_ms):
        if len(request) != 2 or request[0] != 17 or request[1] != 1:
            raise HsfzError('An ECUReset hard-reset request is required.')
        if timeout_ms < 1:
            raise HsfzError('timeout must be positive')
        with self.lock:
            if not self.connected():
                raise HsfzError('The ENET gateway is not connected.')
            self.send_frame(T(TYPE_DIAG, TESTER, dst, request))
            pending = 0
            saw_echo = False
            deadline = time.monotonic() + timeout_ms / 1000.0
            while True:
                remain = deadline - time.monotonic()
                if remain <= 0:
                    return Response(None, pending, True)
                self.sock.settimeout(max(remain, 0.001))
                try:
                    frame = self._read_frame()
                except (socket.timeout, TimeoutError):
                    return Response(None, pending, True)
                except HsfzError as e:
                    if 'closed' in str(e):
                        return Response(None, pending, True)
                    raise
                if frame.type == TYPE_ECHO:
                    if frame.src == TESTER and frame.dst == dst:
                        saw_echo = True
                    continue
                if not saw_echo:
                    continue
                if frame.type != TYPE_DIAG or frame.src != dst or frame.dst != TESTER:
                    continue
                data = frame.payload
                if len(data) >= 3 and data[0] == 127 and (data[1] == 17) and (data[2] == 120):
                    pending += 1
                    continue
                if len(data) >= 2 and data[0] == 81 and (data[1] == 1) or (len(data) >= 3 and data[0] == 127 and (data[1] == 17)):
                    return Response(frame, pending, False)

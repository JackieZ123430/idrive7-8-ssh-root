import ctypes
import ctypes.wintypes
import platform
import socket
import struct
DISCOVERY_PORT = 6811
PROBE = b'\x00\x00\x00\x00\x00\x11'
MARKER = b'BMWVIN'
FALLBACK_BROADCASTS = ('255.255.255.255', '169.254.255.255')

class Gateway:

    def __init__(self, ip, vin=''):
        self.ip = ip
        self.vin = (vin or '')[:17]

    def __repr__(self):
        return 'Gateway(%s%s)' % (self.ip, ', vin=%s' % self.vin if self.vin else '')

def parse_reply(data):
    if not data:
        return None
    text = data.replace(b'\x00', b'').decode('ascii', 'replace')
    i = text.find('BMWVIN')
    if i < 0:
        return None
    return text[i + 6:i + 6 + 17]

def windows_broadcast_addresses():
    try:
        if platform.system() != 'Windows':
            return []
        import ctypes
        from ctypes import wintypes
        AF_INET = 2
        GAA_FLAGS = 8 | 16 | 512

        class SOCKET_ADDRESS(ctypes.Structure):
            _fields_ = [('lpSockaddr', ctypes.c_void_p), ('iSockaddrLength', wintypes.INT)]

        class UNICAST(ctypes.Structure):
            _fields_ = [('Length', wintypes.ULONG), ('Flags', wintypes.ULONG), ('Next', ctypes.c_void_p), ('Address', SOCKET_ADDRESS), ('OnLinkPrefixLength', ctypes.c_ubyte), ('SiteIdPrefixLength', ctypes.c_ubyte)]

        class ADAPTER_ADDRESSES(ctypes.Structure):
            _fields_ = [('Length', wintypes.ULONG), ('IfIndex', wintypes.ULONG), ('Next', ctypes.c_void_p), ('AdapterName', ctypes.c_char_p), ('FirstUnicastAddress', ctypes.c_void_p)]
        size = ctypes.wintypes.ULONG(16 * 1024)
        buf = ctypes.create_string_buffer(size.value)
        for _ in range(4):
            ret = ctypes.windll.iphlpapi.GetAdaptersAddresses(AF_INET, GAA_FLAGS, None, buf, ctypes.byref(size))
            if ret == 0:
                break
            if ret != 111:
                return []
            buf = ctypes.create_string_buffer(size.value)
        else:
            return []
        broadcasts = []
        cur = ctypes.cast(buf, ctypes.POINTER(ADAPTER_ADDRESSES))
        while cur:
            adapter = cur.contents
            ua = ctypes.cast(adapter.FirstUnicastAddress, ctypes.POINTER(UNICAST)) if adapter.FirstUnicastAddress else None
            while ua:
                sa = ctypes.cast(ua.contents.Address.lpSockaddr, ctypes.c_void_p)
                if sa:
                    raw = ctypes.string_at(sa, ua.contents.Address.iSockaddrLength)
                    if len(raw) >= 8 and struct.unpack_from('<H', raw)[0] == AF_INET:
                        ip = struct.unpack_from('<I', raw, 4)[0]
                        prefix = ua.contents.OnLinkPrefixLength
                        if 0 <= prefix <= 32:
                            mask = 4294967295 << 32 - prefix & 4294967295 if prefix else 0
                            bcast = ip | ~mask & 4294967295
                            text = '.'.join((str(bcast >> s & 255) for s in (24, 16, 8, 0)))
                            if text not in broadcasts:
                                broadcasts.append(text)
                ua = ctypes.cast(ua.contents.Next, ctypes.POINTER(UNICAST)) if ua.contents.Next else None
            cur = ctypes.cast(adapter.Next, ctypes.POINTER(ADAPTER_ADDRESSES)) if adapter.Next else None
        return broadcasts
    except Exception:
        return []

def discover(timeout_ms=500, overall_ms=None, broadcasts=None, log=None):
    log = log or (lambda *a, **k: None)
    overall_ms = overall_ms or timeout_ms * 4
    targets = broadcasts if broadcasts is not None else windows_broadcast_addresses()
    for fb in FALLBACK_BROADCASTS:
        if fb not in targets:
            targets.append(fb)
    results = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        import time as _time
        deadline = _time.monotonic() + overall_ms / 1000.0
        for target in list(targets):
            try:
                sock.sendto(PROBE, (target, DISCOVERY_PORT))
                log('ENET discovery broadcast -> %s:%d' % (target, DISCOVERY_PORT))
            except OSError:
                pass
        sock.settimeout(min(timeout_ms, 100) / 1000.0)
        seen_order = []
        import time as _time
        while _time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                if seen_order:
                    break
                continue
            except OSError:
                break
            vin = parse_reply(data)
            if vin is None:
                continue
            ip = addr[0]
            if ip not in results:
                results[ip] = vin
                seen_order.append(ip)
        return [Gateway(ip, results[ip]) for ip in seen_order]
    finally:
        sock.close()

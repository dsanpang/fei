"""Schannel SSPI client via ctypes: handshake + encrypt/decrypt round-trip
against the Fei Go gateway. Reference implementation to diff the ASM agent.

Usage: python sspi_client.py [port]
"""
import ctypes
import ctypes.wintypes as wt
import socket
import struct
import sys

secur32 = ctypes.WinDLL("secur32")

SEC_E_OK = 0
SEC_I_CONTINUE_NEEDED = 0x00090312
SEC_E_INCOMPLETE_MESSAGE = 0x80090318
SEC_E_INCOMPLETE_CREDENTIALS = 0x00090320

SECBUFFER_VERSION = 0
SECBUFFER_DATA = 1
SECBUFFER_TOKEN = 2
SECBUFFER_EXTRA = 5
SECBUFFER_STREAM_TRAILER = 6
SECBUFFER_STREAM_HEADER = 7
SECBUFFER_EMPTY = 0

SP_PROT_TLS1_2_CLIENT = 0x00000800
SP_PROT_TLS1_3_CLIENT = 0x00002000
SCH_CRED_NO_DEFAULT_CREDS = 0x00000010
SCH_CRED_MANUAL_CRED_VALIDATION = 0x00000008
SCH_USE_STRONG_CRYPTO = 0x00400000

ISC_REQ_FLAGS = (0x08 | 0x04 | 0x10 | 0x100 | 0x4000 | 0x8000 | 0x10000)  # SEQ|REPLAY|CONF|ALLOC|EXTERR|STREAM|INTEGRITY

UNISP_NAME = b"Microsoft Unified Security Protocol Provider"


class SecHandle(ctypes.Structure):
    _fields_ = [("dwLower", ctypes.c_void_p), ("dwUpper", ctypes.c_void_p)]


class TimeStamp(ctypes.c_int64):
    pass


class SecBuffer(ctypes.Structure):
    _fields_ = [
        ("cbBuffer", ctypes.c_ulong),
        ("BufferType", ctypes.c_ulong),
        ("pvBuffer", ctypes.c_void_p),
    ]


class SecBufferDesc(ctypes.Structure):
    _fields_ = [
        ("ulVersion", ctypes.c_ulong),
        ("cBuffers", ctypes.c_ulong),
        ("pBuffers", ctypes.c_void_p),
    ]


class SchannelCred(ctypes.Structure):
    _fields_ = [
        ("dwVersion", ctypes.c_ulong),
        ("cCreds", ctypes.c_ulong),
        ("paCred", ctypes.c_void_p),
        ("hRootStore", ctypes.c_void_p),
        ("cMappers", ctypes.c_ulong),
        ("aphMappers", ctypes.c_void_p),
        ("cSupportedAlgs", ctypes.c_ulong),
        ("palgSupportedAlgs", ctypes.c_void_p),
        ("grbitEnabledProtocols", ctypes.c_ulong),
        ("dwMinimumCipherStrength", ctypes.c_ulong),
        ("dwMaximumCipherStrength", ctypes.c_ulong),
        ("dwSessionLifespan", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("dwCredFormat", ctypes.c_ulong),
    ]


class StreamSizes(ctypes.Structure):
    _fields_ = [
        ("cbHeader", ctypes.c_ulong),
        ("cbTrailer", ctypes.c_ulong),
        ("cbMaximumMessage", ctypes.c_ulong),
        ("cBuffers", ctypes.c_ulong),
        ("cbBlockSize", ctypes.c_ulong),
    ]


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4433

    cred = SchannelCred()
    cred.dwVersion = 4
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT
    cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_USE_STRONG_CRYPTO

    hcred = SecHandle()
    ts = TimeStamp()
    rc = secur32.AcquireCredentialsHandleA(
        None, UNISP_NAME, 2, None,
        ctypes.byref(cred), None, None,
        ctypes.byref(hcred), ctypes.byref(ts))
    print("ACH rc=%08x" % (rc & 0xFFFFFFFF))
    assert rc == SEC_E_OK

    sock = socket.create_connection(("127.0.0.1", port))

    phContext = SecHandle()
    haveContext = False

    def make_desc(bufs):
        arr = (SecBuffer * len(bufs))(*bufs)
        d = SecBufferDesc(SECBUFFER_VERSION, len(arr), ctypes.cast(arr, ctypes.c_void_p))
        return d, arr

    # --- handshake ---
    outbuf = ctypes.create_string_buffer(16384)
    indata = b""
    first = True
    while True:
        ob = SecBuffer(0, SECBUFFER_TOKEN, ctypes.cast(outbuf, ctypes.c_void_p))
        od, oarr = make_desc([ob])
        if first:
            idd = None
            rc = secur32.InitializeSecurityContextA(
                ctypes.byref(hcred), None, b"127.0.0.1", ISC_REQ_FLAGS,
                0, 0, None, 0,
                ctypes.byref(phContext), ctypes.byref(od), ctypes.cast(ctypes.byref(ctypes.c_ulong()), ctypes.c_void_p), ctypes.byref(ts))
            first = False
        else:
            ib = SecBuffer(len(indata), SECBUFFER_DATA, ctypes.cast(ctypes.c_char_p(indata), ctypes.c_void_p))
            idd, _ = make_desc([ib])
            rc = secur32.InitializeSecurityContextA(
                ctypes.byref(hcred), ctypes.byref(phContext), None, ISC_REQ_FLAGS,
                0, 0, ctypes.byref(idd), 0,
                ctypes.byref(phContext), ctypes.byref(od), ctypes.cast(ctypes.byref(ctypes.c_ulong()), ctypes.c_void_p), ctypes.byref(ts))
        r = rc & 0xFFFFFFFF
        print("ISC rc=%08x outlen=%d" % (r, oarr[0].cbBuffer))
        if oarr[0].cbBuffer > 0:
            sock.send(outbuf[: oarr[0].cbBuffer])
        if r == SEC_E_OK:
            break
        if r == SEC_I_CONTINUE_NEEDED:
            # append recv
            chunk = sock.recv(16384)
            print("  recv %d bytes" % len(chunk))
            indata += chunk
            continue
        if r == SEC_E_INCOMPLETE_MESSAGE:
            chunk = sock.recv(16384)
            print("  recv(more) %d bytes" % len(chunk))
            indata += chunk
            continue
        raise SystemExit("handshake failed rc=%08x" % r)

    ss = StreamSizes()
    rc = secur32.QueryContextAttributesA(ctypes.byref(phContext), 4, ctypes.byref(ss))
    print("QCA rc=%08x header=%d trailer=%d maxmsg=%d" % (rc & 0xFFFFFFFF, ss.cbHeader, ss.cbTrailer, ss.cbMaximumMessage))

    # --- send one plaintext message ---
    msg = b"hello"
    header = ctypes.create_string_buffer(ss.cbHeader)
    data = ctypes.create_string_buffer(msg)
    trailer = ctypes.create_string_buffer(ss.cbTrailer)
    bufs = (SecBuffer * 4)(
        SecBuffer(ss.cbHeader, SECBUFFER_STREAM_HEADER, ctypes.cast(header, ctypes.c_void_p)),
        SecBuffer(len(msg), SECBUFFER_DATA, ctypes.cast(data, ctypes.c_void_p)),
        SecBuffer(ss.cbTrailer, SECBUFFER_STREAM_TRAILER, ctypes.cast(trailer, ctypes.c_void_p)),
        SecBuffer(0, SECBUFFER_EMPTY, None),
    )
    msgdesc = SecBufferDesc(SECBUFFER_VERSION, 4, ctypes.cast(bufs, ctypes.c_void_p))
    rc = secur32.EncryptMessage(ctypes.byref(phContext), 0, ctypes.byref(msgdesc), 0)
    print("Encrypt rc=%08x" % (rc & 0xFFFFFFFF))
    total = header.raw + data.raw[: len(msg)] + trailer.raw[: ss.cbTrailer]
    sock.sendall(total)
    print("sent %d encrypted bytes" % len(total))

    # --- receive and decrypt ---
    enc = b""
    while True:
        if enc:
            ib = SecBuffer(len(enc), SECBUFFER_DATA, ctypes.cast(ctypes.c_char_p(enc), ctypes.c_void_p))
            idd, iarr = make_desc([ib])
            rc = secur32.DecryptMessage(ctypes.byref(phContext), ctypes.byref(idd), 0, None)
            r = rc & 0xFFFFFFFF
            print("Decrypt rc=%08x" % r)
            if r == SEC_E_OK:
                print("decrypted:", bytes(ctypes.string_at(iarr[0].pvBuffer, iarr[0].cbBuffer)))
                break
            if r == SEC_E_INCOMPLETE_MESSAGE:
                pass
            else:
                raise SystemExit("decrypt failed")
        chunk = sock.recv(16384)
        if not chunk:
            raise SystemExit("connection closed")
        enc += chunk


if __name__ == "__main__":
    main()

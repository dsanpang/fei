# -*- coding: utf-8 -*-
"""sspi_lifecycle: full Schannel session lifecycle against the TLS gateway.

handshake -> N rounds of [seal FEI heartbeat -> EncryptMessage/send ->
recv -> DecryptMessage -> AEAD-open the ACK with the derived key].
Reports the exact failing call and the REAL SecBuffer layout after
DecryptMessage (type-scanned, not position-guessed).
"""
import ctypes
import socket
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SEC_E_OK = 0
SEC_I_CONTINUE_NEEDED = 0x00090312
SEC_E_INCOMPLETE_MESSAGE = 0x80090318
UNISP_NAME = b"Microsoft Unified Security Protocol Provider"
SECBUFFER_VERSION = 0
SECBUFFER_DATA = 1
SECBUFFER_TOKEN = 2
SECBUFFER_EXTRA = 5
SECBUFFER_STREAM_HEADER = 7
SECBUFFER_STREAM_TRAILER = 8
SECBUFFER_EMPTY = 0
SECBUFFER_ALERT = 17  # decrypt-only informational
# exact flags from entry.asm tls_connect
ISC_REQ_FLAGS = 0x8 | 0x4 | 0x10 | 0x100 | 0x4000 | 0x8000 | 0x10000
SP_PROT_TLS1_2_CLIENT = 0x800
SP_PROT_TLS1_3_CLIENT = 0x2000
SCH_CRED_NO_DEFAULT_CREDS = 0x10
SCH_CRED_MANUAL_CRED_VALIDATION = 0x8
SCH_USE_STRONG_CRYPTO = 0x400000

secur32 = ctypes.windll.secur32

DERIVED = bytes.fromhex(
    "b701bff55cbde9a10dbbc6a9c58269be2bc8519a4d0101b661f00762be9ee43b")
AGENT_ID = bytes.fromhex("deadbeefcafebabe")


class SecHandle(ctypes.Structure):
    _fields_ = [("dwLower", ctypes.c_size_t), ("dwUpper", ctypes.c_size_t)]


class SecBuffer(ctypes.Structure):
    _fields_ = [("cbBuffer", ctypes.c_ulong), ("BufferType", ctypes.c_ulong),
                ("pvBuffer", ctypes.c_void_p)]


class SecBufferDesc(ctypes.Structure):
    _fields_ = [("ulVersion", ctypes.c_ulong), ("cBuffers", ctypes.c_ulong),
                ("pBuffers", ctypes.c_void_p)]


class SchannelCred(ctypes.Structure):
    _fields_ = [("dwVersion", ctypes.c_ulong), ("cCreds", ctypes.c_ulong),
                ("paCred", ctypes.c_void_p), ("hRootStore", ctypes.c_void_p),
                ("cMappers", ctypes.c_ulong), ("aphMappers", ctypes.c_void_p),
                ("cSupportedAlgs", ctypes.c_ulong),
                ("palgSupportedAlgs", ctypes.c_void_p),
                ("grbitEnabledProtocols", ctypes.c_ulong),
                ("dwMinimumCipherStrength", ctypes.c_ulong),
                ("dwMaximumCipherStrength", ctypes.c_ulong),
                ("dwSessionLifespan", ctypes.c_ulong),
                ("dwFlags", ctypes.c_ulong),
                ("dwCredFormat", ctypes.c_ulong)]


class StreamSizes(ctypes.Structure):
    _fields_ = [("cbHeader", ctypes.c_ulong), ("cbTrailer", ctypes.c_ulong),
                ("cbMaximumMessage", ctypes.c_ulong),
                ("cBuffers", ctypes.c_ulong), ("cbBlockSize", ctypes.c_ulong)]


def seal_heartbeat(seq):
    # empty sealed heartbeat: len=0, pad=0 -> gateway plaintext fast path
    hdr = bytearray(36)
    struct.pack_into("<I", hdr, 0, 0x46454900)
    struct.pack_into("<H", hdr, 4, 0x0300)
    struct.pack_into("<H", hdr, 6, 0x0001)      # heartbeat
    struct.pack_into("<I", hdr, 8, seq)
    struct.pack_into("<I", hdr, 12, 0)          # length
    struct.pack_into("<H", hdr, 16, 0)          # padding
    hdr[18:26] = AGENT_ID
    struct.pack_into(">Q", hdr, 26, 0x0102030405060708)
    return bytes(hdr)                            # no body at all


def open_ack(hdr36, body, seq):
    nonce = struct.pack("<I", seq) + AGENT_ID
    aead = ChaCha20Poly1305(DERIVED)
    return aead.decrypt(nonce, body, hdr36)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4435
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 6

    cred = SchannelCred()
    print("cred size:", ctypes.sizeof(cred), "flags@", SchannelCred.dwFlags.offset, flush=True)
    cred.dwVersion = 4
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT
    cred.dwFlags = (SCH_CRED_NO_DEFAULT_CREDS |
                    SCH_CRED_MANUAL_CRED_VALIDATION |
                    SCH_USE_STRONG_CRYPTO)
    hcred = SecHandle()
    ts = ctypes.c_int64()
    rc = secur32.AcquireCredentialsHandleA(
        None, UNISP_NAME, 2, None, ctypes.byref(cred), None, None,
        ctypes.byref(hcred), ctypes.byref(ts))
    assert rc & 0xFFFFFFFF == SEC_E_OK, hex(rc & 0xFFFFFFFF)

    sock = socket.create_connection(("127.0.0.1", port))
    sock.settimeout(10)
    phContext = SecHandle()
    attrs = ctypes.c_ulong()
    outbuf = ctypes.create_string_buffer(16384)
    indata = b""
    first = True

    def make_desc(bufs):
        arr = (SecBuffer * len(bufs))(*bufs)
        d = SecBufferDesc(SECBUFFER_VERSION, len(arr),
                          ctypes.cast(arr, ctypes.c_void_p))
        return d, arr

    while True:
        ob = SecBuffer(0, SECBUFFER_TOKEN, ctypes.cast(outbuf, ctypes.c_void_p))
        od, oarr = make_desc([ob])
        if first:
            rc = secur32.InitializeSecurityContextA(
                ctypes.byref(hcred), None, None, ISC_REQ_FLAGS,
                0, 0, None, 0, ctypes.byref(phContext), ctypes.byref(od),
                ctypes.byref(attrs), ctypes.byref(ts))
            first = False
        else:
            ib = SecBuffer(len(indata), SECBUFFER_TOKEN,
                           ctypes.cast(ctypes.create_string_buffer(indata),
                                       ctypes.c_void_p))
            idd, _ = make_desc([ib])
            rc = secur32.InitializeSecurityContextA(
                ctypes.byref(hcred), ctypes.byref(phContext), None,
                ISC_REQ_FLAGS, 0, 0, ctypes.byref(idd), 0,
                ctypes.byref(phContext), ctypes.byref(od),
                ctypes.byref(attrs), ctypes.byref(ts))
        r = rc & 0xFFFFFFFF
        print('ISC rc=%08x out=%d' % (r, oarr[0].cbBuffer), flush=True)
        if oarr[0].cbBuffer > 0:
            # ALLOCATE_MEMORY: the token lives in SSPI memory, not outbuf
            sock.send(ctypes.string_at(oarr[0].pvBuffer, oarr[0].cbBuffer))
        if r == SEC_E_OK:
            break
        if r in (SEC_I_CONTINUE_NEEDED, SEC_E_INCOMPLETE_MESSAGE):
            indata += sock.recv(16384)
            continue
        raise SystemExit("handshake failed rc=%08x" % r)

    ss = StreamSizes()
    secur32.QueryContextAttributesA(ctypes.byref(phContext), 4,
                                    ctypes.byref(ss))
    print("handshake OK; header=%d trailer=%d maxmsg=%d block=%d" %
          (ss.cbHeader, ss.cbTrailer, ss.cbMaximumMessage, ss.cbBlockSize))

    enc_buf = b""
    txseq = 0

    for i in range(rounds):
        # ---- send: sealed empty heartbeat ----
        txseq += 1
        frame = seal_heartbeat(txseq)
        header = ctypes.create_string_buffer(ss.cbHeader)
        data = ctypes.create_string_buffer(frame)
        trailer = ctypes.create_string_buffer(ss.cbTrailer)
        bufs = (SecBuffer * 4)(
            SecBuffer(ss.cbHeader, SECBUFFER_STREAM_HEADER,
                      ctypes.cast(header, ctypes.c_void_p)),
            SecBuffer(len(frame), SECBUFFER_DATA,
                      ctypes.cast(data, ctypes.c_void_p)),
            SecBuffer(ss.cbTrailer, SECBUFFER_STREAM_TRAILER,
                      ctypes.cast(trailer, ctypes.c_void_p)),
            SecBuffer(0, SECBUFFER_EMPTY, None))
        md = SecBufferDesc(SECBUFFER_VERSION, 4, ctypes.cast(bufs, ctypes.c_void_p))
        rc = secur32.EncryptMessage(ctypes.byref(phContext), 0,
                                    ctypes.byref(md), 0)
        r = rc & 0xFFFFFFFF
        if r != SEC_E_OK:
            print("round %d: ENCRYPT FAILED rc=%08x" % (i, r))
            return
        # send the ACTUAL returned sizes, not the maxima
        sent = header.raw[:bufs[0].cbBuffer] + \
            data.raw[:bufs[1].cbBuffer] + \
            trailer.raw[:bufs[2].cbBuffer]
        sock.sendall(sent)
        print("round %d: sent %d bytes (hdr %d data %d trl %d/max %d)" %
              (i, len(sent), bufs[0].cbBuffer, bufs[1].cbBuffer,
               bufs[2].cbBuffer, ss.cbTrailer))

        # ---- receive: decrypt the ACK ----
        for _attempt in range(16):
            if enc_buf:
                eb = ctypes.create_string_buffer(enc_buf)
                ib = SecBuffer(len(enc_buf), SECBUFFER_DATA,
                               ctypes.cast(eb, ctypes.c_void_p))
                idd, iarr = make_desc([ib])
                rc = secur32.DecryptMessage(ctypes.byref(phContext),
                                            ctypes.byref(idd), 0, None)
                r = rc & 0xFFFFFFFF
                layout = [(iarr[k].BufferType, iarr[k].cbBuffer)
                          for k in range(idd.cBuffers)]
                if r == SEC_E_OK:
                    print("round %d: decrypt OK layout=%s" % (i, layout))
                    # type-scan for DATA and EXTRA
                    pdata = pextra = None
                    nextra = 0
                    for k in range(idd.cBuffers):
                        if iarr[k].BufferType == SECBUFFER_DATA and pdata is None:
                            pdata = ctypes.string_at(iarr[k].pvBuffer,
                                                     iarr[k].cbBuffer)
                        if iarr[k].BufferType == SECBUFFER_EXTRA:
                            nextra = iarr[k].cbBuffer
                            if iarr[k].pvBuffer:
                                pextra = ctypes.string_at(iarr[k].pvBuffer,
                                                          iarr[k].cbBuffer)
                    print("round %d: data=%r extra=%d" % (i, pdata, nextra))
                    # open the AEAD frame
                    if pdata and len(pdata) >= 36:
                        h = pdata[:36]
                        seq, ln = struct.unpack_from("<II", h, 8)[0:1], \
                            struct.unpack_from("<I", h, 12)[0]
                        body = pdata[36:36 + ln + 16]
                        try:
                            pt = open_ack(h, body, struct.unpack_from("<I", h, 8)[0])
                            print("round %d: AEAD open OK pt=%r" % (i, pt))
                        except Exception as e:
                            print("round %d: AEAD open FAILED: %s" % (i, e))
                    enc_buf = pextra if pextra is not None else b""
                    break
                if r == SEC_E_INCOMPLETE_MESSAGE:
                    pass
                else:
                    print("round %d: DECRYPT FAILED rc=%08x layout=%s" %
                          (i, r, layout))
                    return
            chunk = sock.recv(16384)
            if not chunk:
                print("round %d: connection closed by gateway" % i)
                return
            enc_buf += chunk


if __name__ == "__main__":
    main()

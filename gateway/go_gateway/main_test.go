package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"fei/gateway/internal/protocol"
)

func TestHeaderRoundTrip(t *testing.T) {
	hdr := protocol.NewHeader(protocol.TypeHeartbeat, 42, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, 0, 16)
	encoded := protocol.EncodeHeader(hdr)
	if len(encoded) != protocol.HeaderSize {
		t.Fatalf("expected %d bytes, got %d", protocol.HeaderSize, len(encoded))
	}
	decoded, err := protocol.DecodeHeader(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Magic != protocol.Magic {
		t.Errorf("magic: got 0x%x, want 0x%x", decoded.Magic, protocol.Magic)
	}
	if decoded.Type != protocol.TypeHeartbeat {
		t.Errorf("type: got 0x%x, want 0x%x", decoded.Type, protocol.TypeHeartbeat)
	}
	if decoded.Seq != 42 {
		t.Errorf("seq: got %d, want 42", decoded.Seq)
	}
	if decoded.PaddingLen != 16 {
		t.Errorf("padding: got %d, want 16", decoded.PaddingLen)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}

	agentID := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	plaintext := []byte("hello from agent, this is a test payload for ChaCha20-Poly1305")

	var buf bytes.Buffer
	err := protocol.WriteEncryptedFrame(&buf, psk, protocol.TypeExecReturn, 100, agentID, plaintext)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	frame, err := protocol.ReadEncryptedFrame(&buf, psk)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if frame.Header.Type != protocol.TypeExecReturn {
		t.Errorf("type: got 0x%x, want 0x%x", frame.Header.Type, protocol.TypeExecReturn)
	}
	if frame.Header.Seq != 100 {
		t.Errorf("seq: got %d, want 100", frame.Header.Seq)
	}
	if !bytes.Equal(frame.Payload, plaintext) {
		t.Errorf("payload mismatch: got %q, want %q", frame.Payload, plaintext)
	}
}

func TestTamperDetection(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}

	agentID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("sensitive data")

	var buf bytes.Buffer
	protocol.WriteEncryptedFrame(&buf, psk, protocol.TypeExecReturn, 1, agentID, plaintext)

	raw := buf.Bytes()
	if len(raw) > protocol.HeaderSize+5 {
		raw[protocol.HeaderSize+5] ^= 0xFF // tamper ciphertext
	}

	_, err := protocol.ReadEncryptedFrame(bytes.NewReader(raw), psk)
	if err == nil {
		t.Fatal("expected decryption error for tampered data")
	}
}

func TestTCPStickyPacketHandling(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}

	agentID := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	var combined bytes.Buffer
	for i := 0; i < 5; i++ {
		payload := []byte(fmt.Sprintf("frame-%d", i))
		protocol.WriteEncryptedFrame(&combined, psk, protocol.TypeExecReturn, uint32(i), agentID, payload)
	}

	reader := bytes.NewReader(combined.Bytes())
	for i := 0; i < 5; i++ {
		frame, err := protocol.ReadEncryptedFrame(reader, psk)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		expected := []byte(fmt.Sprintf("frame-%d", i))
		if !bytes.Equal(frame.Payload, expected) {
			t.Errorf("frame %d: got %q, want %q", i, frame.Payload, expected)
		}
	}
}

func TestPaddingRandomness(t *testing.T) {
	seen := make(map[uint16]bool)
	for i := 0; i < 50; i++ {
		p := protocol.RandomPaddingLen()
		seen[p] = true
	}
	if len(seen) < 10 {
		t.Errorf("padding not random enough: only %d distinct values in 50 samples", len(seen))
	}
}

func TestHeartbeatRoundTrip(t *testing.T) {
	agentID := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	hdr := protocol.NewHeartbeatHeader(agentID, 999)

	if hdr.Type != protocol.TypeHeartbeat {
		t.Errorf("type: got 0x%x, want 0x%x", hdr.Type, protocol.TypeHeartbeat)
	}
	if hdr.Seq != 999 {
		t.Errorf("seq: got %d, want 999", hdr.Seq)
	}
	if hdr.AgentID != agentID {
		t.Errorf("agent id mismatch")
	}
}

func TestSessionManagerConcurrency(t *testing.T) {
	gw := &Gateway{}
	gw.sessions = sync.Map{}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			agentIDHex := fmt.Sprintf("agent_%02d", id)
			sess := &AgentSession{
				AgentID:  [8]byte{byte(id)},
				Conn:     nil,
				LastSeen: time.Now(),
			}
			gw.sessions.Store(agentIDHex, sess)
			time.Sleep(10 * time.Millisecond)
			if _, ok := gw.sessions.Load(agentIDHex); !ok {
				t.Errorf("session %s not found", agentIDHex)
			}
		}(i)
	}
	wg.Wait()

	count := 0
	gw.sessions.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	if count != 20 {
		t.Errorf("expected 20 sessions, got %d", count)
	}
}

func TestNonceDerivation(t *testing.T) {
	agentID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	n1 := protocol.DeriveNonce(100, agentID)
	n2 := protocol.DeriveNonce(100, agentID)
	n3 := protocol.DeriveNonce(101, agentID)

	if !bytes.Equal(n1, n2) {
		t.Error("same inputs should produce same nonce")
	}
	if bytes.Equal(n1, n3) {
		t.Error("different seq should produce different nonce")
	}
	if len(n1) != 12 {
		t.Errorf("nonce size: got %d, want 12", len(n1))
	}
}

func TestHeaderValidation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*protocol.Header)
		wantErr error
	}{
		{"valid", func(h *protocol.Header) {}, nil},
		{"bad magic", func(h *protocol.Header) { h.Magic = 0x12345678 }, protocol.ErrBadMagic},
		{"bad version", func(h *protocol.Header) { h.ProtoVer = 0x0100 }, protocol.ErrBadVersion},
		{"too big", func(h *protocol.Header) { h.Length = 20 * 1024 * 1024 }, protocol.ErrPayloadTooBig},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := protocol.NewHeader(protocol.TypeHeartbeat, 1, [8]byte{}, 0, 0)
			tc.mutate(h)
			err := protocol.ValidateHeader(h)
			if err != tc.wantErr {
				t.Errorf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// 模拟 mTLS 连接场景: 通过 net.Pipe 进行真实的双向通信测试
func TestMTLSSimulation(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	agentID := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33}
	payload := []byte(`{"command":"whoami"}`)

	errCh := make(chan error, 1)
	go func() {
		err := protocol.WriteEncryptedFrame(client, psk, protocol.TypeExecReturn, 7, agentID, payload)
		errCh <- err
	}()

	frame, err := protocol.ReadEncryptedFrame(server, psk)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}

	if writeErr := <-errCh; writeErr != nil {
		t.Fatalf("client write: %v", writeErr)
	}

	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("payload: got %q, want %q", frame.Payload, payload)
	}
	if frame.Header.AgentID != agentID {
		t.Error("agent ID mismatch")
	}
}

// 边界测试: 空 payload
func TestEmptyPayload(t *testing.T) {
	psk := make([]byte, 32)
	agentID := [8]byte{}

	var buf bytes.Buffer
	err := protocol.WriteEncryptedFrame(&buf, psk, protocol.TypeHeartbeat, 1, agentID, nil)
	if err != nil {
		t.Fatalf("write empty: %v", err)
	}

	frame, err := protocol.ReadEncryptedFrame(&buf, psk)
	if err != nil {
		t.Fatalf("read empty: %v", err)
	}
	if len(frame.Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(frame.Payload))
	}
}

// 边界测试: 最大允许 payload
func TestLargePayload(t *testing.T) {
	psk := make([]byte, 32)
	agentID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

	largePayload := make([]byte, 64*1024) // 64KB
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	var buf bytes.Buffer
	err := protocol.WriteEncryptedFrame(&buf, psk, protocol.TypeExecReturn, 1, agentID, largePayload)
	if err != nil {
		t.Fatalf("write large: %v", err)
	}

	frame, err := protocol.ReadEncryptedFrame(&buf, psk)
	if err != nil {
		t.Fatalf("read large: %v", err)
	}
	if !bytes.Equal(frame.Payload, largePayload) {
		t.Error("large payload mismatch")
	}
}

// 辅助函数: 将 uint64 写入缓冲区
func writeUint64BE(buf *bytes.Buffer, v uint64) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	buf.Write(b)
}

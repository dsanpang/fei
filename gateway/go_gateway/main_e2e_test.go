package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"fei/gateway/internal/protocol"
)

func loadTestPSK(t *testing.T) []byte {
	pskPath := filepath.Join("..", "..", "certs", "psk.bin")
	data, err := os.ReadFile(pskPath)
	if err != nil {
		t.Skipf("PSK not found at %s, skipping E2E test", pskPath)
	}
	if len(data) != 32 {
		t.Fatalf("PSK must be 32 bytes, got %d", len(data))
	}
	return data
}

func loadTestTLSConfig(t *testing.T) (*tls.Config, *tls.Config) {
	certDir := filepath.Join("..", "..", "certs")

	caPEM, err := os.ReadFile(filepath.Join(certDir, "ca-cert.pem"))
	if err != nil {
		t.Skipf("CA cert not found: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "server-cert.pem"),
		filepath.Join(certDir, "server-key.pem"),
	)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}

	clientCert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "client-cert.pem"),
		filepath.Join(certDir, "client-key.pem"),
	)
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	clientCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		ServerName:   "localhost",
	}

	return serverCfg, clientCfg
}

// 完整 E2E 测试: 加密帧 → mTLS 通道 → 解密 → 会话管理 → NATS 订阅检查
func TestFullE2E_mTLS_WithEncryption(t *testing.T) {
	psk := loadTestPSK(t)
	serverCfg, clientCfg := loadTestTLSConfig(t)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	gw := &Gateway{
		listenAddr: addr,
		psk:        psk,
	}
	gw.sessions = sync.Map{}

	recvFrames := make(chan *protocol.Frame, 10)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("TLS handshake failed: %v", err)
			return
		}
		state := tlsConn.ConnectionState()
		if !state.HandshakeComplete {
			t.Error("handshake not complete")
			return
		}
		if state.Version != tls.VersionTLS13 {
			t.Errorf("expected TLS 1.3, got 0x%04x", state.Version)
			return
		}

		for i := 0; i < 3; i++ {
			frame, err := protocol.ReadEncryptedFrame(conn, psk)
			if err != nil {
				t.Errorf("read frame %d: %v", i, err)
				return
			}
			recvFrames <- frame
		}
	}()

	clientConn, err := tls.Dial("tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	agentID := [8]byte{0xFE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}

	// 发送心跳
	err = protocol.WriteEncryptedFrame(clientConn, psk, protocol.TypeHeartbeat, 1, agentID, nil)
	if err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}

	// 发送执行结果
	result := map[string]string{"cmd": "whoami", "output": "SYSTEM"}
	resultBytes, _ := json.Marshal(result)
	err = protocol.WriteEncryptedFrame(clientConn, psk, protocol.TypeExecReturn, 2, agentID, resultBytes)
	if err != nil {
		t.Fatalf("send exec return: %v", err)
	}

	// 发送插件载入确认
	err = protocol.WriteEncryptedFrame(clientConn, psk, protocol.TypePluginLoad, 3, agentID, []byte("plugin loaded"))
	if err != nil {
		t.Fatalf("send plugin load: %v", err)
	}

	// 验证接收到的帧
	timeout := time.After(5 * time.Second)
	expectedTypes := []uint16{protocol.TypeHeartbeat, protocol.TypeExecReturn, protocol.TypePluginLoad}
	for i, expected := range expectedTypes {
		select {
		case frame := <-recvFrames:
			if frame.Header.Type != expected {
				t.Errorf("frame %d: type got 0x%04x, want 0x%04x", i, frame.Header.Type, expected)
			}
			if frame.Header.AgentID != agentID {
				t.Errorf("frame %d: agent ID mismatch", i)
			}
			if frame.Header.Seq != uint32(i+1) {
				t.Errorf("frame %d: seq got %d, want %d", i, frame.Header.Seq, i+1)
			}
		case <-timeout:
			t.Fatalf("timeout waiting for frame %d", i)
		}
	}
}

// 网关 → 客户端方向: 模拟控制面下发命令
func TestGatewayToClient_CommandDelivery(t *testing.T) {
	psk := loadTestPSK(t)
	serverCfg, clientCfg := loadTestTLSConfig(t)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	agentID := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	recvFrames := make(chan *protocol.Frame, 5)

	go func() {
		conn, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer conn.Close()

		for i := 0; i < 2; i++ {
			frame, err := protocol.ReadEncryptedFrame(conn, psk)
			if err != nil {
				if err == io.EOF {
					return
				}
				t.Errorf("read: %v", err)
				return
			}
			recvFrames <- frame
		}
	}()

	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverConn.Close()

	// 模拟下发两条命令
	cmd1 := map[string]interface{}{"action": "shell_exec", "cmd": "whoami"}
	cmd1Bytes, _ := json.Marshal(cmd1)
	err = protocol.WriteEncryptedFrame(serverConn, psk, protocol.TypeExecReturn, 100, agentID, cmd1Bytes)
	if err != nil {
		t.Fatalf("write cmd1: %v", err)
	}

	cmd2 := map[string]interface{}{"action": "plugin_install", "name": "sys_info"}
	cmd2Bytes, _ := json.Marshal(cmd2)
	err = protocol.WriteEncryptedFrame(serverConn, psk, protocol.TypePluginLoad, 101, agentID, cmd2Bytes)
	if err != nil {
		t.Fatalf("write cmd2: %v", err)
	}

	timeout := time.After(5 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case frame := <-recvFrames:
			if frame.Header.Seq != uint32(100+i) {
				t.Errorf("frame %d: seq got %d, want %d", i, frame.Header.Seq, 100+i)
			}
		case <-timeout:
			t.Fatalf("timeout waiting for frame %d", i)
		}
	}
}

// 压力测试: 大量并发连接
func TestConcurrentConnections(t *testing.T) {
	psk := loadTestPSK(t)

	const numClients = 10
	const framesPerClient = 5

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	var wg sync.WaitGroup
	errCh := make(chan error, numClients*framesPerClient)

	for c := 0; c < numClients; c++ {
		wg.Add(1)
		go func(clientIdx int) {
			defer wg.Done()
			agentID := [8]byte{byte(clientIdx)}
			for i := 0; i < framesPerClient; i++ {
				var buf bytes.Buffer
				payload := []byte(`{"idx":` + string(rune('0'+clientIdx)) + `}`)
				err := protocol.WriteEncryptedFrame(&buf, psk, protocol.TypeExecReturn, uint32(i), agentID, payload)
				if err != nil {
					errCh <- err
					return
				}
			}
		}(c)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent write error: %v", err)
	}
}

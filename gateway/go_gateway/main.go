package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"fei/gateway/internal/protocol"

	"github.com/nats-io/nats.go"
)

type AgentSession struct {
	AgentID       [8]byte
	Conn          net.Conn
	LastSeen      time.Time
	SeqIn         uint32
	RxSeq         uint32 // highest sequence accepted from the agent
	HaveRxSeq     bool
	TxSeq         uint32 // gateway-originated frames use their own counter
	Hostname      string
	IPAddress     string
	OsInfo        string
	mu            sync.Mutex
	pendingTasks  []string // FIFO queue of task_ids for commands awaiting responses
}

type Gateway struct {
	listenAddr string
	certFile   string
	keyFile    string
	caFile     string
	pskFile    string
	natsURL    string
	mtlsMode   string

	devMode  bool

	psk      []byte
	sessions sync.Map
	nc       *nats.Conn
}

func main() {
	gw := &Gateway{}
	flag.StringVar(&gw.listenAddr, "listen", ":443", "listen address")
	flag.StringVar(&gw.certFile, "cert", "./certs/server-cert.pem", "server certificate")
	flag.StringVar(&gw.keyFile, "key", "./certs/server-key.pem", "server private key")
	flag.StringVar(&gw.caFile, "ca", "./certs/ca-cert.pem", "CA certificate for client verification")
	flag.StringVar(&gw.pskFile, "psk", "./certs/psk.bin", "ChaCha20-Poly1305 pre-shared key (32 bytes)")
	flag.StringVar(&gw.natsURL, "nats", nats.DefaultURL, "NATS server URL")
	// mtls-mode: "require" (default, full mTLS), "none" (server-auth TLS only —
	// needed until the ASM agent grows Schannel client-certificate support),
	// "request" (accept with-or-without client cert).
	flag.StringVar(&gw.mtlsMode, "mtls-mode", "require", "client certificate mode: require|request|none")
	flag.BoolVar(&gw.devMode, "dev", false, "development mode: plain TCP without TLS (PSK encryption only)")
	flag.Parse()

	if err := gw.loadPSK(); err != nil {
		log.Fatalf("load PSK: %v", err)
	}

	nc, err := nats.Connect(gw.natsURL, nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second))
	if err != nil {
		log.Fatalf("connect to NATS %s: %v", gw.natsURL, err)
	}
	gw.nc = nc
	defer nc.Close()
	log.Printf("connected to NATS at %s", gw.natsURL)

	var ln net.Listener
	if gw.devMode {
		ln, err = net.Listen("tcp", gw.listenAddr)
		if err != nil {
			log.Fatalf("listen %s: %v", gw.listenAddr, err)
		}
		log.Printf("WARNING: gateway listening on %s in DEV MODE (plain TCP, no mTLS)", gw.listenAddr)
	} else {
		tlsCfg, err := gw.buildTLSConfig()
		if err != nil {
			log.Fatalf("TLS config: %v", err)
		}
		ln, err = tls.Listen("tcp", gw.listenAddr, tlsCfg)
		if err != nil {
			log.Fatalf("listen %s: %v", gw.listenAddr, err)
		}
		log.Printf("gateway listening on %s (mTLS 1.3)", gw.listenAddr)
	}
	defer ln.Close()

	go gw.sessionCleaner()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go gw.handleConn(conn)
	}
}

func (gw *Gateway) loadPSK() error {
	data, err := os.ReadFile(gw.pskFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", gw.pskFile, err)
	}
	if len(data) != 32 {
		return fmt.Errorf("PSK must be exactly 32 bytes, got %d", len(data))
	}
	gw.psk = data
	return nil
}

func (gw *Gateway) buildTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(gw.certFile, gw.keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair %s/%s: %w", gw.certFile, gw.keyFile, err)
	}

	caCert, err := os.ReadFile(gw.caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	clientAuth := tls.RequireAndVerifyClientCert
	switch gw.mtlsMode {
	case "none":
		clientAuth = tls.NoClientCert
	case "request":
		clientAuth = tls.VerifyClientCertIfGiven
	case "require", "":
		clientAuth = tls.RequireAndVerifyClientCert
	default:
		return nil, fmt.Errorf("unknown -mtls-mode %q (want require|request|none)", gw.mtlsMode)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// TLS 1.3 preferred, but Windows 10 Schannel clients top out at 1.2;
		// the inner ChaCha20-Poly1305 layer is version-independent.
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   clientAuth,
		ClientCAs:    pool,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
		},
	}, nil
}

func extractTLSMetadata(conn net.Conn) (hostname string, ipAddress string) {
	ipAddress = "unknown"
	hostname = "unknown"

	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		ipAddress = host
	}

	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			if cert.Subject.CommonName != "" {
				hostname = cert.Subject.CommonName
			}
			if len(cert.DNSNames) > 0 && hostname == "unknown" {
				hostname = cert.DNSNames[0]
			}
		}
	}
	return
}

func (gw *Gateway) handleConn(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()
	log.Printf("new mTLS connection from %s", addr)

	hostname, ipAddress := extractTLSMetadata(conn)

	frame, err := protocol.ReadEncryptedFrame(conn, gw.psk)
	if err != nil {
		if err.Error() != "fei: read header: EOF" {
			log.Printf("[%s] first frame error: %v", addr, err)
		}
		return
	}

	agentIDHex := hex.EncodeToString(frame.Header.AgentID[:])
	session := &AgentSession{
		AgentID:      frame.Header.AgentID,
		Conn:         conn,
		LastSeen:     time.Now(),
		SeqIn:        frame.Header.Seq,
		Hostname:     hostname,
		IPAddress:    ipAddress,
		OsInfo:       "windows",
		pendingTasks: make([]string, 0),
	}
	gw.sessions.Store(agentIDHex, session)
	log.Printf("agent registered: %s from %s (hostname=%s, ip=%s)", agentIDHex, addr, hostname, ipAddress)

	subj := fmt.Sprintf("fei.cmd.%s", agentIDHex)
	// handleCommandFromControlPlane takes session.mu itself; locking here
	// too deadlocked every command delivery (Go mutexes are not reentrant)
	sub, err := gw.nc.Subscribe(subj, func(msg *nats.Msg) {
		gw.handleCommandFromControlPlane(session, msg.Data)
	})
	if err != nil {
		log.Printf("subscribe %s: %v", subj, err)
	}
	defer sub.Unsubscribe()

	gw.publishAgentEvent("agent_online", agentIDHex, map[string]interface{}{
		"hostname":   hostname,
		"ip_address": ipAddress,
		"os_info":    session.OsInfo,
	})
	gw.processFrame(session, frame, agentIDHex)

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		frame, err := protocol.ReadEncryptedFrame(conn, gw.psk)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("[%s] read timeout, closing", agentIDHex)
			} else {
				log.Printf("[%s] read error: %v", agentIDHex, err)
			}
			break
		}

		// anti-replay: agent frames must have strictly increasing sequence
		// numbers within a session (replayed captures are dropped)
		session.mu.Lock()
		replayed := session.HaveRxSeq && frame.Header.Seq <= session.RxSeq
		if !replayed {
			session.RxSeq = frame.Header.Seq
			session.HaveRxSeq = true
		}
		session.mu.Unlock()
		if replayed {
			log.Printf("[%s] replay detected: seq=%d <= %d, dropping frame",
				agentIDHex, frame.Header.Seq, session.RxSeq)
			continue
		}
		session.mu.Lock()
		session.LastSeen = time.Now()
		session.SeqIn = frame.Header.Seq
		session.mu.Unlock()

		gw.processFrame(session, frame, agentIDHex)
	}

	gw.sessions.Delete(agentIDHex)
	gw.publishAgentEvent("agent_offline", agentIDHex, nil)
	log.Printf("agent disconnected: %s", agentIDHex)
}

func (gw *Gateway) processFrame(session *AgentSession, frame *protocol.Frame, agentIDHex string) {
	log.Printf("[%s] frame type=%s seq=%d len=%d", agentIDHex, frame.Header.TypeString(), frame.Header.Seq, frame.Header.Length)
	switch frame.Header.Type {
	case protocol.TypeHeartbeat:
		session.mu.Lock()
		session.TxSeq++
		ackSeq := session.TxSeq
		err := protocol.WriteEncryptedFrame(session.Conn, gw.psk, protocol.TypeHeartbeat, ackSeq, session.AgentID, []byte("ack"))
		session.mu.Unlock()
		if err != nil {
			log.Printf("[%s] heartbeat ACK write failed: %v", agentIDHex, err)
		}

		gw.publishAgentEvent("heartbeat", agentIDHex, map[string]interface{}{
			"seq":       frame.Header.Seq,
			"timestamp": frame.Header.TimestampMs(),
		})

	case protocol.TypePluginLoad:
		gw.publishAgentEvent("plugin_load", agentIDHex, map[string]interface{}{
			"seq":          frame.Header.Seq,
			"payload_size": len(frame.Payload),
			"payload":      frame.Payload,
		})

	case protocol.TypeExecReturn:
		session.mu.Lock()
		var taskID string
		if len(session.pendingTasks) > 0 {
			taskID = session.pendingTasks[0]
			session.pendingTasks = session.pendingTasks[1:]
		}
		session.mu.Unlock()

		extra := map[string]interface{}{
			"seq":          frame.Header.Seq,
			"payload_size": len(frame.Payload),
			"payload":      frame.Payload,
		}
		if taskID != "" {
			extra["task_id"] = taskID
		}
		gw.publishAgentEvent("exec_return", agentIDHex, extra)

	case protocol.TypeException:
		gw.publishAgentEvent("exception", agentIDHex, map[string]interface{}{
			"seq":     frame.Header.Seq,
			"payload": frame.Payload,
		})

	case protocol.TypeDestroy:
		gw.publishAgentEvent("destroy", agentIDHex, map[string]interface{}{
			"seq": frame.Header.Seq,
		})

	default:
		log.Printf("[%s] unknown message type 0x%04x", agentIDHex, frame.Header.Type)
	}
}

func (gw *Gateway) handleCommandFromControlPlane(session *AgentSession, data []byte) {
	var cmd struct {
		Type    uint16 `json:"type"`
		Payload []byte `json:"payload"`
		TaskID  string `json:"task_id"`
	}
	if err := json.Unmarshal(data, &cmd); err != nil {
		log.Printf("invalid command from control plane: %v", err)
		return
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	session.TxSeq++
	seq := session.TxSeq
	if cmd.TaskID != "" {
		session.pendingTasks = append(session.pendingTasks, cmd.TaskID)
	}

	log.Printf("[%s] delivering command type=0x%04x seq=%d payload=%d bytes", hex.EncodeToString(session.AgentID[:]), cmd.Type, seq, len(cmd.Payload))
	err := protocol.WriteEncryptedFrame(session.Conn, gw.psk, cmd.Type, seq, session.AgentID, cmd.Payload)
	if err != nil {
		agentIDHex := hex.EncodeToString(session.AgentID[:])
		log.Printf("[%s] write command failed: %v", agentIDHex, err)
		// Rollback the queued task_id since the command was not sent.
		if cmd.TaskID != "" && len(session.pendingTasks) > 0 {
			session.pendingTasks = session.pendingTasks[:len(session.pendingTasks)-1]
		}
	}
}

func (gw *Gateway) publishAgentEvent(eventType, agentIDHex string, extra map[string]interface{}) {
	evt := map[string]interface{}{
		"event":    eventType,
		"agent_id": agentIDHex,
		"time":     time.Now().UnixMilli(),
	}
	for k, v := range extra {
		evt[k] = v
	}
	data, err := json.Marshal(evt)
	if err != nil {
		log.Printf("marshal event: %v", err)
		return
	}
	subj := fmt.Sprintf("fei.event.%s.%s", agentIDHex, eventType)
	if err := gw.nc.Publish(subj, data); err != nil {
		log.Printf("publish %s: %v", subj, err)
	}
}

func (gw *Gateway) sessionCleaner() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		gw.sessions.Range(func(key, value interface{}) bool {
			sess := value.(*AgentSession)
			sess.mu.Lock()
			idle := now.Sub(sess.LastSeen)
			sess.mu.Unlock()
			if idle > 5*time.Minute {
				agentIDHex := key.(string)
				log.Printf("session expired: %s (idle %v)", agentIDHex, idle)
				gw.sessions.Delete(key)
				sess.Conn.Close()
				gw.publishAgentEvent("agent_timeout", agentIDHex, nil)
			}
			return true
		})
	}
}

package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
)

type BusStats struct {
	EventsReceived uint64
	EventsValid    uint64
	EventsRejected uint64
	BytesProcessed uint64
}

type Bus struct {
	natsURL     string
	nc          *nats.Conn
	stats       BusStats
	startTime   time.Time
	validEvents map[string]bool
}

func newBus() *Bus {
	return &Bus{
		startTime: time.Now(),
		validEvents: map[string]bool{
			"agent_online":  true,
			"agent_offline": true,
			"agent_timeout": true,
			"heartbeat":     true,
			"plugin_load":   true,
			"exec_return":   true,
			"exception":     true,
			"destroy":       true,
		},
	}
}

func main() {
	bus := newBus()
	flag.StringVar(&bus.natsURL, "nats", nats.DefaultURL, "NATS server URL")
	flag.Parse()

	nc, err := nats.Connect(bus.natsURL,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		log.Fatalf("connect to NATS: %v", err)
	}
	bus.nc = nc
	defer nc.Close()
	log.Printf("connected to NATS at %s", bus.natsURL)

	sub, err := nc.Subscribe("fei.event.>", func(msg *nats.Msg) {
		bus.processEvent(msg)
	})
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	go bus.statsReporter()

	nc.Publish("fei.system.status", []byte(`{"component":"nats_bus","status":"ready"}`))
	log.Println("NATS bus ready, monitoring events")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down...")
	bus.printStats()
}

func (b *Bus) processEvent(msg *nats.Msg) {
	atomic.AddUint64(&b.stats.EventsReceived, 1)
	atomic.AddUint64(&b.stats.BytesProcessed, uint64(len(msg.Data)))

	parts := strings.Split(msg.Subject, ".")
	if len(parts) < 4 {
		atomic.AddUint64(&b.stats.EventsRejected, 1)
		log.Printf("reject: malformed subject %s", msg.Subject)
		return
	}

	eventType := parts[3]
	if !b.validEvents[eventType] {
		atomic.AddUint64(&b.stats.EventsRejected, 1)
		log.Printf("reject: unknown event type %s", eventType)
		return
	}

	var evt map[string]interface{}
	if err := json.Unmarshal(msg.Data, &evt); err != nil {
		atomic.AddUint64(&b.stats.EventsRejected, 1)
		log.Printf("reject: invalid JSON from %s: %v", msg.Subject, err)
		return
	}

	atomic.AddUint64(&b.stats.EventsValid, 1)

	agentID := parts[2]
	log.Printf("audit: %s from agent %s", eventType, agentID)
}

func (b *Bus) statsReporter() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		b.printStats()
	}
}

func (b *Bus) printStats() {
	recv := atomic.LoadUint64(&b.stats.EventsReceived)
	valid := atomic.LoadUint64(&b.stats.EventsValid)
	rejected := atomic.LoadUint64(&b.stats.EventsRejected)
	bytes := atomic.LoadUint64(&b.stats.BytesProcessed)
	uptime := time.Since(b.startTime).Truncate(time.Second)

	log.Printf("stats: uptime=%v received=%d valid=%d rejected=%d bytes=%d",
		uptime, recv, valid, rejected, bytes)
}

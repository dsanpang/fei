// derivekey: print the per-agent session key for certs/psk.bin + the
// deadbeefcafebabe test agent (runtime-forensics helper).
package main

import (
	"fmt"
	"os"

	"fei/gateway/internal/protocol"
)

func main() {
	master, err := os.ReadFile("certs/psk.bin")
	if err != nil {
		fmt.Println("read psk:", err)
		os.Exit(1)
	}
	var id [8]byte
	copy(id[:], []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})
	key, err := protocol.DeriveAgentPSK(master, id)
	if err != nil {
		fmt.Println("derive:", err)
		os.Exit(1)
	}
	fmt.Printf("%x\n", key)
}

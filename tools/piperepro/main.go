// piperepro: minimal reproducer for the agent->sandbox pipe boundary.
// Spawns sandbox.exe and writes a file_write command exactly the way
// agent entry.asm does: one WriteFile per <=4096-byte chunk, no delays.
//   piperepro <sandbox.exe> <hex-chars>
// Compare: -1 writes the whole frame in a single WriteFile.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: piperepro <sandbox.exe> <hex-chars> [single]")
		os.Exit(2)
	}
	sandbox := os.Args[1]
	n := 0
	fmt.Sscan(os.Args[2], &n)
	single := len(os.Args) > 3 && os.Args[3] == "single"

	// build the sandbox pipe frame: [cmd][len u32][data]
	cmdByte := byte(0x05)
	data := append([]byte(`C:\fei_probe\w.bin`), 0)
	data = append(data, strings.Repeat("41", n/2)...)
	if rd := os.Getenv("READ"); rd != "" {
		cmdByte = 0x04
		data = []byte(rd)
	}
	frame := make([]byte, 0, 5+len(data))
	frame = append(frame, cmdByte)
	var lenb [4]byte
	binary.LittleEndian.PutUint32(lenb[:], uint32(len(data)))
	frame = append(frame, lenb[:]...)
	frame = append(frame, data...)

	cmd := exec.Command(sandbox)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		panic(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}
	if err := cmd.Start(); err != nil {
		panic(err)
	}

	start := time.Now()
	// Optionally send a small command first to mimic the real agent flow
	// where the sandbox has already served prior commands.
	if warmup := os.Getenv("WARMUP"); warmup != "" {
		small := append([]byte(`C:\fei_probe\w.bin`), 0)
		small = append(small, strings.Repeat("42", 250)...)
		sf := []byte{0x05, byte(len(small)), byte(len(small) >> 8), byte(len(small) >> 16), 0}
		sf = append(sf, small...)
		if _, err := stdin.Write(sf); err != nil {
			fmt.Println("warmup write:", err)
		} else {
			var hdr [4]byte
			if _, err := io.ReadFull(stdout, hdr[:]); err == nil {
				rl := binary.LittleEndian.Uint32(hdr[:])
				io.CopyN(io.Discard, stdout, int64(rl))
				fmt.Println("warmup ok")
			} else {
				fmt.Println("warmup read:", err)
			}
		}
	}
	if single {
		_, err = stdin.Write(frame)
		fmt.Printf("write(1x%d): n=%d err=%v\n", len(frame), len(frame), err)
	} else {
		off := 0
		for off < len(frame) {
			chunk := 4096
			if off+chunk > len(frame) {
				chunk = len(frame) - off
			}
			var n2 int
			n2, err = stdin.Write(frame[off : off+chunk])
			fmt.Printf("write chunk @%d+%d: n=%d err=%v\n", off, chunk, n2, err)
			if err != nil {
				break
			}
			off += n2
		}
	}

	if err == nil {
		br := bufio.NewReader(stdout)
		var hdr [4]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			fmt.Println("read header:", err)
		} else {
			rlen := binary.LittleEndian.Uint32(hdr[:])
			body := make([]byte, rlen)
			if _, err := io.ReadFull(br, body); err != nil {
				fmt.Println("read body:", err)
			} else if len(body) > 120 {
				fmt.Printf("response[%d]: %s...\n", len(body), body[:120])
			} else {
				fmt.Printf("response[%d]: %s\n", len(body), body)
			}
		}
	}
	stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		fmt.Printf("sandbox exited (%.2fs): %v\n", time.Since(start).Seconds(), err)
	case <-time.After(8 * time.Second):
		cmd.Process.Kill()
		fmt.Println("sandbox still running after 8s (killed)")
	}
}

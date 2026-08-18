// sandboxtest: direct pipe-level exerciser for the no_std sandbox.
// Spawns sandbox.exe, sends each framed command, validates the response.
//
// Protocol (see agents/rust_no_std_sandbox/src/lib.rs):
//   request:  [cmd u8][payload_len u32 LE][payload]
//   response: [resp_len u32 LE][resp bytes]  (JSON)
package main

import (
	"strings"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"unicode/utf16"
	"unsafe"
	"time"
)

func main() {
	sandbox := "sandbox.exe"
	if len(os.Args) > 1 {
		sandbox = os.Args[1]
	}

	cmd := exec.Command(sandbox)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Println("stdin pipe:", err)
		os.Exit(1)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if f, ok := stdoutPipe.(*os.File); ok {
		f.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	stdout := stdoutPipe
	if err != nil {
		fmt.Println("stdout pipe:", err)
		os.Exit(1)
	}
	if err := cmd.Start(); err != nil {
		fmt.Println("start:", err)
		os.Exit(1)
	}
	defer cmd.Process.Kill()

	failures := 0
	check := func(name string, fn func() error) {
		if err := fn(); err != nil {
			fmt.Printf("FAIL %-14s %v\n", name, err)
			failures++
			return
		}
		fmt.Printf("PASS %-14s\n", name)
	}

	check("sysinfo", func() error {
		r, err := roundtrip(stdin, stdout, 0x01, nil)
		if err != nil {
			return err
		}
		return expectJSON(r, "os_version")
	})
	check("process_list", func() error {
		r, err := roundtrip(stdin, stdout, 0x02, nil)
		if err != nil {
			return err
		}
		return expectJSON(r, "processes")
	})
	check("dir_list", func() error {
		r, err := roundtrip(stdin, stdout, 0x03, []byte(`C:\Windows`))
		if err != nil {
			return err
		}
		if len(r) < 64 {
			return fmt.Errorf("suspiciously small listing (%d bytes): %s", len(r), r)
		}
		return expectJSON(r, "files")
	})
	check("file_read", func() error {
		r, err := roundtrip(stdin, stdout, 0x04, []byte(`C:\Windows\System32\drivers\etc\hosts`))
		if err != nil {
			return err
		}
		return expectJSON(r, "content_hex")
	})
	check("file_write", func() error {
		payload := append([]byte(`C:\Windows\Temp\fei_sbtest.txt`), 0)
		payload = append(payload, []byte("48656c6c6f20466569")...) // "Hello Fei"
		r, err := roundtrip(stdin, stdout, 0x05, payload)
		if err != nil {
			return err
		}
		return expectJSON(r, "bytes_written")
	})
	check("file_verify", func() error {
		r, err := roundtrip(stdin, stdout, 0x04, []byte(`C:\Windows\Temp\fei_sbtest.txt`))
		if err != nil {
			return err
		}
		if want := `"content_hex":"48656c6c6f20466569"`; string(r) != "{"+want+"}" {
			return fmt.Errorf("roundtrip mismatch: %s", r)
		}
		return nil
	})
	check("execute", func() error {
		r, err := roundtrip(stdin, stdout, 0x06, []byte(`cmd.exe /c echo fei-exec-ok`))
		if err != nil {
			return err
		}
		return expectJSON(r, "exit_code")
	})
	check("protect", func() error {
		// merge rules into a TEST key (custom path => create allowed);
		// then verify the merged REG_SZ values through the real registry
		const testPath = `\Registry\Machine\SOFTWARE\FeiProtectTest\Config`
		payload := []byte("agent.exe\x00C:\\fei_test\x00127.0.0.1\x00sandbox.exe\x00" + testPath)
		r, err := roundtrip(stdin, stdout, 0x08, payload)
		if err != nil {
			return err
		}
		if err := expectJSON(r, "protect"); err != nil {
			return err
		}
		return verifyProtectValues(map[string]string{
			"Process": "agent.exe;sandbox.exe",
			"Path":    `C:\fei_test`,
			"IP":      "127.0.0.1",
		})
	})
	check("protect_idem", func() error {
		// re-sending the same rules must not duplicate them
		const testPath = `\Registry\Machine\SOFTWARE\FeiProtectTest\Config`
		payload := []byte("agent.exe\x00C:\\fei_test\x00127.0.0.1\x00sandbox.exe\x00" + testPath)
		r, err := roundtrip(stdin, stdout, 0x08, payload)
		if err != nil {
			return err
		}
		if err := expectJSON(r, "protect"); err != nil {
			return err
		}
		return verifyProtectValues(map[string]string{
			"Process": "agent.exe;sandbox.exe",
			"Path":    `C:\fei_test`,
			"IP":      "127.0.0.1",
		})
	})

	stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		fmt.Println("sandbox exited cleanly on EOF")
	case <-time.After(3 * time.Second):
		fmt.Println("WARN sandbox did not exit after stdin close")
		cmd.Process.Kill()
	}

	if failures > 0 {
		fmt.Printf("%d FAILURE(S)\n", failures)
		os.Exit(1)
	}
	fmt.Println("ALL SANDBOX TESTS PASSED")
}

func roundtrip(stdin io.WriteCloser, stdout io.Reader, code byte, payload []byte) ([]byte, error) {
	req := make([]byte, 5+len(payload))
	req[0] = code
	binary.LittleEndian.PutUint32(req[1:5], uint32(len(payload)))
	copy(req[5:], payload)
	if _, err := stdin.Write(req); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	var lenbuf [4]byte
	if _, err := io.ReadFull(stdout, lenbuf[:]); err != nil {
		return nil, fmt.Errorf("read len: %w", err)
	}
	n := binary.LittleEndian.Uint32(lenbuf[:])
	if n > 65536 {
		return nil, fmt.Errorf("response too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(stdout, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return buf, nil
}

func expectJSON(body []byte, key string) error {
	s := string(body)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	for i := 0; i+len(key) < len(s); i++ {
		if s[i:i+len(key)] == key {
			return nil
		}
	}
	return fmt.Errorf("missing key %q in: %s", key, s)
}

// verifyProtectValues reads the merged Config values back through the
// real registry (advapi32) and compares them exactly.
func verifyProtectValues(want map[string]string) error {
	for name, wantVal := range want {
		got, err := regReadString(`SOFTWARE\FeiProtectTest\Config`, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		got = strings.TrimRight(got, "\x00") // REG_SZ keeps its NUL terminator
		if got != wantVal {
			return fmt.Errorf("%s = %q, want %q", name, got, wantVal)
		}
	}
	return nil
}

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyExW = modadvapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueExW = modadvapi32.NewProc("RegQueryValueExW")
	procRegCloseKey = modadvapi32.NewProc("RegCloseKey")
)

func regReadString(subkey, value string) (string, error) {
	var hkey syscall.Handle
	p, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return "", err
	}
	r1, _, _ := procRegOpenKeyExW.Call(
		uintptr(0x80000002), // HKEY_LOCAL_MACHINE
		uintptr(unsafe.Pointer(p)),
		0, 0x20019, // KEY_READ
		uintptr(unsafe.Pointer(&hkey)))
	if r1 != 0 {
		return "", fmt.Errorf("RegOpenKeyExW: %d", r1)
	}
	defer procRegCloseKey.Call(uintptr(hkey))

	vp, _ := syscall.UTF16PtrFromString(value)
	var typ uint32
	var size uint32
	r1, _, _ = procRegQueryValueExW.Call(
		uintptr(hkey), uintptr(unsafe.Pointer(vp)),
		0, uintptr(unsafe.Pointer(&typ)),
		0, uintptr(unsafe.Pointer(&size)))
	if r1 != 0 {
		return "", fmt.Errorf("RegQueryValueExW size: %d", r1)
	}
	if typ != 1 { // REG_SZ
		return "", fmt.Errorf("type %d, want REG_SZ", typ)
	}
	buf := make([]uint16, size/2)
	r1, _, _ = procRegQueryValueExW.Call(
		uintptr(hkey), uintptr(unsafe.Pointer(vp)),
		0, uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r1 != 0 {
		return "", fmt.Errorf("RegQueryValueExW: %d", r1)
	}
	return string(utf16.Decode(buf[:size/2])), nil
}

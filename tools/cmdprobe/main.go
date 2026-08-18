// cmdprobe: gRPC console client for ad-hoc SendCommand probes against the
// control plane. Primarily used to reproduce the agent ~3KB frame boundary:
//   cmdprobe -agent <id> -cmd file_write -path C:\t\w.bin -hex 4000
//   cmdprobe -agent <id> -sweep 1000,2000,3000,4000
// -hex N means N hex CHARACTERS (i.e. strings.Repeat("41", N/2)) — the count
// is in hex chars, not bytes, to match the DEBUG_NOTES tables.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "fei/control-plane/proto"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "control plane gRPC address")
	agent := flag.String("agent", "", "agent id")
	cmd := flag.String("cmd", "file_write", "semantic command")
	path := flag.String("path", `C:\fei_probe\w.bin`, "file_write path")
	hexN := flag.Int("hex", 0, "number of hex chars for file_write payload")
	sweep := flag.String("sweep", "", "comma-separated hex-char sizes to test sequentially")
	upload := flag.String("upload", "", "\"local|remote\" paths to upload")
	protect := flag.String("protect", "", "\"image,dir,gateway-ip\" merge hide rules via the kernel driver")
	download := flag.String("download", "", "\"remote|local\" paths to download")
	httpAddr := flag.String("http", "127.0.0.1:8080", "control plane HTTP API for task polling")
	flag.Parse()

	if *agent == "" {
		fmt.Fprintln(os.Stderr, "usage: cmdprobe -agent <id> [-hex N | -sweep n,n,...]")
		os.Exit(2)
	}

	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer conn.Close()
	client := pb.NewFeiControlServiceClient(conn)

	if *protect != "" {
		parts := strings.SplitN(*protect, ",", 3)
		if len(parts) != 3 {
			fmt.Fprintln(os.Stderr, "-protect wants \"image,dir,gateway-ip\"")
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		r, err := client.SendCommand(ctx, &pb.SendCommandRequest{
			AgentId:    *agent,
			Command:    "protect",
			Parameters: parts,
		})
		if err != nil {
			fmt.Println("protect rpc:", err)
			os.Exit(1)
		}
		fmt.Printf("protect success=%v: %s err=%s\n", r.Success, r.Result, r.Error)
		return
	}

	if *upload != "" {
		parts := strings.SplitN(*upload, "|", 2)
		if len(parts) != 2 {
			fmt.Fprintln(os.Stderr, "-upload wants \"local|remote\"")
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		start := time.Now()
		r, err := client.UploadFile(ctx, &pb.UploadFileRequest{AgentId: *agent, LocalPath: parts[0], RemotePath: parts[1]})
		if err != nil {
			fmt.Println("upload rpc:", err)
			os.Exit(1)
		}
		fmt.Printf("upload success=%v (%.1fs): %s err=%s\n", r.Success, time.Since(start).Seconds(), r.Message, r.Error)
		return
	}
	if *download != "" {
		parts := strings.SplitN(*download, "|", 2)
		if len(parts) != 2 {
			fmt.Fprintln(os.Stderr, "-download wants \"remote|local\"")
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		r, err := client.DownloadFile(ctx, &pb.DownloadFileRequest{AgentId: *agent, RemotePath: parts[0], LocalPath: parts[1]})
		if err != nil {
			fmt.Println("download rpc:", err)
			os.Exit(1)
		}
		fmt.Printf("download success=%v: %s err=%s\n", r.Success, r.Message, r.Error)
		return
	}

	if *sweep != "" {
		for _, tok := range strings.Split(*sweep, ",") {
			var n int
			fmt.Sscan(strings.TrimSpace(tok), &n)
			runOne(client, *httpAddr, *agent, *cmd, *path, n)
		}
		return
	}
	runOne(client, *httpAddr, *agent, *cmd, *path, *hexN)
}

func runOne(client pb.FeiControlServiceClient, httpAddr, agent, cmd, path string, hexN int) {
	label := fmt.Sprintf("hex=%d", hexN)
	if hexN <= 0 {
		label = "cmd=" + cmd
	}
	fmt.Printf("=== %s (%s) ===\n", label, time.Now().Format("15:04:05"))

	params := []string{path}
	if hexN > 0 {
		if hexN%2 != 0 {
			hexN++ // keep an integral number of bytes
		}
		params = append(params, strings.Repeat("41", hexN/2))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := client.SendCommand(ctx, &pb.SendCommandRequest{
		AgentId:    agent,
		Command:    cmd,
		Parameters: params,
	})
	if err != nil {
		fmt.Printf("  rpc error: %v\n", err)
		return
	}
	fmt.Printf("  success=%v task=%s\n", resp.Success, resp.TaskId)
	if r := resp.Result; r != "" {
		if len(r) > 160 {
			fmt.Printf("  result[%d]: %s...\n", len(r), r[:160])
		} else {
			fmt.Printf("  result[%d]: %q\n", len(r), r)
		}
	}

	// The inline wait is only 5s; poll the task record for the final state.
	if resp.TaskId != "" && !strings.HasPrefix(resp.Result, "Command queued") {
		fmt.Println("  (inline result returned, skip polling)")
		return
	}
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		st, result, reason := pollTask(httpAddr, agent, resp.TaskId)
		if st == "" {
			continue
		}
		switch st {
		case "sent", "pending":
			continue
		}
		fmt.Printf("  final: status=%s reason=%q resultLen=%d\n", st, reason, len(result))
		return
	}
	fmt.Println("  final: still 'sent' after 20s (agent never answered)")
}

func pollTask(httpAddr, agent, taskID string) (status, result, reason string) {
	url := fmt.Sprintf("http://%s/api/tasks?agent_id=%s", httpAddr, agent)
	resp, err := http.Get(url)
	if err != nil {
		return "", "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var env struct {
		Tasks []struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			Result   string `json:"result"`
			Err      string `json:"err_reason"`
			ErrRe    string `json:"errReason"`
			PayloadS string `json:"payload"`
		} `json:"tasks"`
	}
	if json.Unmarshal(body, &env) != nil {
		return "", "", ""
	}
	for i := len(env.Tasks) - 1; i >= 0; i-- {
		if env.Tasks[i].ID == taskID {
			return env.Tasks[i].Status, env.Tasks[i].Result, env.Tasks[i].Err + env.Tasks[i].ErrRe
		}
	}
	return "", "", ""
}

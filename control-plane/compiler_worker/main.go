package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

type Compiler struct {
	nasmPath    string
	templateDir string
	outputDir   string
}

type CompileRequest struct {
	SourceFile string
	OutputName string
	Format     string
}

func main() {
	c := &Compiler{}
	flag.StringVar(&c.nasmPath, "nasm", "nasm", "path to NASM assembler")
	flag.StringVar(&c.templateDir, "templates", "./templates", "ASM template directory")
	flag.StringVar(&c.outputDir, "output", "./output", "compiled output directory")
	flag.Parse()

	if err := os.MkdirAll(c.outputDir, 0755); err != nil {
		log.Fatalf("create output dir: %v", err)
	}

	if !c.checkNASM() {
		log.Fatalf("NASM not found at %s", c.nasmPath)
	}

	if flag.NArg() < 1 {
		fmt.Printf("Usage: %s [flags] <source.asm>\n", os.Args[0])
		fmt.Println("Flags:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	sourceFile := flag.Arg(0)
	outputName := strings.TrimSuffix(filepath.Base(sourceFile), filepath.Ext(sourceFile))

	req := CompileRequest{
		SourceFile: sourceFile,
		OutputName: outputName,
		Format:     "win64",
	}

	outputPath, err := c.Compile(req)
	if err != nil {
		log.Fatalf("compilation failed: %v", err)
	}

	log.Printf("compiled successfully: %s", outputPath)
}

func (c *Compiler) checkNASM() bool {
	cmd := exec.Command(c.nasmPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	log.Printf("NASM found: %s", strings.TrimSpace(string(out)))
	return true
}

func (c *Compiler) Compile(req CompileRequest) (string, error) {
	log.Printf("reading source: %s", req.SourceFile)
	source, err := os.ReadFile(req.SourceFile)
	if err != nil {
		return "", fmt.Errorf("read source: %w", err)
	}

	log.Printf("applying obfuscation...")
	obfuscated := c.obfuscateLabels(string(source))
	obfuscated = c.obfuscateConstants(obfuscated)
	obfuscated = c.flattenControlFlow(obfuscated)

	buildDir := filepath.Join(c.outputDir, "build_"+randomSuffix())
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		return "", fmt.Errorf("create build dir: %w", err)
	}

	obfSource := filepath.Join(buildDir, "obfuscated.asm")
	if err := os.WriteFile(obfSource, []byte(obfuscated), 0644); err != nil {
		return "", fmt.Errorf("write obfuscated source: %w", err)
	}

	objFile := filepath.Join(buildDir, req.OutputName+".obj")
	outputFile := filepath.Join(c.outputDir, req.OutputName+".bin")

	log.Printf("assembling: %s -> %s", obfSource, objFile)
	cmd := exec.Command(c.nasmPath, "-f", req.Format, "-o", objFile, obfSource)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("NASM assembly failed: %w", err)
	}

	if _, err := os.Stat(objFile); os.IsNotExist(err) {
		return "", fmt.Errorf("object file not created: %s", objFile)
	}

	log.Printf("extracting raw binary: %s -> %s", objFile, outputFile)
	if err := c.extractRawBinary(objFile, outputFile); err != nil {
		return "", fmt.Errorf("extract raw binary: %w", err)
	}

	info, err := os.Stat(outputFile)
	if err != nil {
		return "", fmt.Errorf("stat output: %w", err)
	}
	if info.Size() > 15*1024 {
		log.Printf("WARNING: output size %d bytes exceeds 15KB limit", info.Size())
	}

	log.Printf("output: %s (%d bytes)", outputFile, info.Size())
	return outputFile, nil
}

func (c *Compiler) obfuscateLabels(source string) string {
	labelPattern := regexp.MustCompile(`(?m)^([a-zA-Z_][a-zA-Z0-9_]*)(\s*:)`)
	references := make(map[string]string)

	obfuscated := labelPattern.ReplaceAllStringFunc(source, func(match string) string {
		parts := labelPattern.FindStringSubmatch(match)
		if len(parts) < 3 {
			return match
		}
		original := parts[1]

		if strings.HasPrefix(original, "_") || isReservedLabel(original) {
			return match
		}

		if _, exists := references[original]; !exists {
			references[original] = "L" + randomSuffix()
		}
		return references[original] + parts[2]
	})

	for original, replacement := range references {
		refPattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(original) + `\b`)
		obfuscated = refPattern.ReplaceAllString(obfuscated, replacement)
	}

	log.Printf("obfuscated %d labels", len(references))
	return obfuscated
}

func (c *Compiler) obfuscateConstants(source string) string {
	constPattern := regexp.MustCompile(`(?i)(\b0x[0-9A-Fa-f]{8,}\b)`)
	count := 0

	lines := strings.Split(source, "\n")
	var result []string
	inDataSection := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track section changes to avoid corrupting data/constants sections
		if strings.HasPrefix(trimmed, "section ") {
			lower := strings.ToLower(trimmed)
			inDataSection = strings.Contains(lower, ".data") ||
				strings.Contains(lower, ".bss") ||
				strings.Contains(lower, ".rdata") ||
				strings.Contains(lower, ".idata")
			result = append(result, line)
			continue
		}

		// Skip data declarations and critical protocol constants
		if inDataSection ||
			strings.Contains(strings.ToLower(line), "magic") ||
			strings.Contains(strings.ToLower(line), "proto_ver") ||
			strings.Contains(strings.ToLower(line), "chacha_const") ||
			strings.Contains(trimmed, "equ ") ||
			strings.HasPrefix(trimmed, "db ") ||
			strings.HasPrefix(trimmed, "dd ") ||
			strings.HasPrefix(trimmed, "dq ") ||
			strings.HasPrefix(trimmed, "dw ") {
			result = append(result, line)
			continue
		}

		newLine := constPattern.ReplaceAllStringFunc(line, func(match string) string {
			count++
			return fmt.Sprintf("(0x%s ^ 0x%s) ^ 0x%s", randomHex(8), randomHex(8), randomHex(8))
		})
		result = append(result, newLine)
	}

	if count > 0 {
		log.Printf("obfuscated %d constants", count)
	}
	return strings.Join(result, "\n")
}

func (c *Compiler) flattenControlFlow(source string) string {
	lines := strings.Split(source, "\n")

	// First pass: identify function boundaries and which functions are safe to flatten.
	// A function is "safe" if it contains no conditional jumps and no local labels.
	type funcRange struct {
		start int
		end   int
		safe  bool
	}
	var functions []funcRange
	inFunction := false
	currentStart := 0
	currentSafe := true

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}

		if strings.HasPrefix(trimmed, "section ") {
			if inFunction {
				functions = append(functions, funcRange{start: currentStart, end: i, safe: currentSafe})
				inFunction = false
			}
			continue
		}

		if strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, ".") {
			if inFunction {
				functions = append(functions, funcRange{start: currentStart, end: i, safe: currentSafe})
			}
			currentStart = i
			currentSafe = true
			inFunction = true
			continue
		}

		if inFunction {
			// Conditional jumps make flattening unsafe unless we also rewrite targets
			if strings.HasPrefix(trimmed, "j") && !strings.HasPrefix(trimmed, "jmp") {
				currentSafe = false
			}
			// Local labels are jump targets; flattening would break them
			if strings.HasSuffix(trimmed, ":") && strings.HasPrefix(trimmed, ".") {
				currentSafe = false
			}
		}
	}
	if inFunction {
		functions = append(functions, funcRange{start: currentStart, end: len(lines), safe: currentSafe})
	}

	if len(functions) == 0 {
		return source
	}

	// Second pass: flatten only safe functions
	unsafeFuncs := make(map[int]bool)
	for _, fr := range functions {
		if !fr.safe {
			for i := fr.start; i < fr.end; i++ {
				unsafeFuncs[i] = true
			}
		}
	}

	var result []string
	blockCount := 0
	stateVar := "fl_state_" + randomSuffix()
	flattenedAny := false

	flushBlock := func(currentBlock *[]string, blockCount *int) {
		if len(*currentBlock) == 0 {
			return
		}
		blockID := *blockCount
		*blockCount++

		result = append(result, fmt.Sprintf(".fl_block_%d:", blockID))
		result = append(result, *currentBlock...)
		*currentBlock = nil
	}

	inFunction = false
	functionDepth := 0
	var currentBlock []string

	for i, line := range lines {
		if unsafeFuncs[i] {
			flushBlock(&currentBlock, &blockCount)
			result = append(result, line)
			inFunction = true
			functionDepth = 0
			continue
		}

		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, ";") || trimmed == "" {
			result = append(result, line)
			continue
		}

		if strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, ".") {
			flushBlock(&currentBlock, &blockCount)
			result = append(result, line)
			inFunction = true
			functionDepth = 0
			continue
		}

		if strings.HasPrefix(trimmed, "section ") {
			flushBlock(&currentBlock, &blockCount)
			result = append(result, line)
			inFunction = false
			continue
		}

		if inFunction {
			if strings.HasPrefix(trimmed, "call ") || strings.HasPrefix(trimmed, "ret") {
				currentBlock = append(currentBlock, line)
				flushBlock(&currentBlock, &blockCount)

				nextBlock := blockCount
				if strings.HasPrefix(trimmed, "ret") {
					result = append(result, fmt.Sprintf("    mov dword [%s], 0xFFFFFFFF", stateVar))
				} else {
					result = append(result, fmt.Sprintf("    mov dword [%s], %d", stateVar, nextBlock))
					result = append(result, fmt.Sprintf("    jmp .fl_dispatch_%s", stateVar))
				}
				flattenedAny = true
				continue
			}

			currentBlock = append(currentBlock, line)
			functionDepth++

			if functionDepth >= 10 {
				flushBlock(&currentBlock, &blockCount)
				nextBlock := blockCount
				result = append(result, fmt.Sprintf("    mov dword [%s], %d", stateVar, nextBlock))
				result = append(result, fmt.Sprintf("    jmp .fl_dispatch_%s", stateVar))
				functionDepth = 0
				flattenedAny = true
			}
			continue
		}

		result = append(result, line)
	}

	flushBlock(&currentBlock, &blockCount)

	if flattenedAny && blockCount > 0 {
		dispatcher := fmt.Sprintf(`
; Control flow flattening dispatcher
section .bss
%s:    resd 1

section .text
.fl_dispatch_%s:
    mov eax, [%s]
`, stateVar, stateVar, stateVar)

		for i := 0; i < blockCount; i++ {
			dispatcher += fmt.Sprintf("    cmp eax, %d\n    je .fl_block_%d\n", i, i)
		}

		result = append(result, dispatcher)
		log.Printf("flattened control flow: %d blocks", blockCount)
	}

	return strings.Join(result, "\n")
}

func (c *Compiler) extractRawBinary(objFile, outputFile string) error {
	ldPath := "ld"
	if _, err := exec.LookPath(ldPath); err != nil {
		return fmt.Errorf("linker 'ld' not found in PATH; cannot extract raw binary from object file")
	}

	cmd := exec.Command(ldPath, "--oformat", "binary", "-o", outputFile, objFile)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ld raw binary extraction failed: %w", err)
	}
	return nil
}

func isReservedLabel(name string) bool {
	reserved := []string{"_start", "main", "WinMain", "DllMain"}
	return slices.Contains(reserved, name)
}

func randomSuffix() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randomHex(n int) string {
	b := make([]byte, n/2)
	rand.Read(b)
	return hex.EncodeToString(b)
}

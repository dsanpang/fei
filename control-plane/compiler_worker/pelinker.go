package main



// Minimal COFF(x86-64) -> PE64 EXE linker, purpose-built for the agent

// object NASM produces: sections .text/.data/.bss, ADDR64/REL32/REL32_*

// relocations, and every undefined symbol an import from kernel32.dll.

//

// Layout produced:

//   PE headers | .text (code + import thunks) | .rdata (imports + IAT) |

//   .data | .reloc

//

// Each imported function F gets:

//   - an IAT slot (__imp_F) in .rdata

//   - a 6-byte thunk "jmp qword [rip+2]" (FF 25 00 00 00 00) in .text

// REL32 relocations against F resolve to the thunk; ADDR64 resolve to the

// IAT slot. This is exactly how MSVC handles `extern` + `call F` in NASM.



import (

	"bytes"

	"encoding/binary"

	"fmt"

	"os"

	"sort"

)



const (

	pageSize  = 0x1000

	fileAlign = 0x200

)



type coffSection struct {

	name         string

	virtualSize  uint32

	rawSize      uint32

	rawData      []byte

	relocsPtr    uint32

	numRelocs    uint16

	flags        uint32

	outputOffset uint32 // filled during layout: RVA when >0

	fileOffset   uint32

}



type coffSymbol struct {

	name    string

	value   uint32

	secNum  int16 // 1-based; 0 = undefined (external), -1/-2 = absolute

	storage uint8 // 2 = external

	auxCount int

}



type coffReloc struct {

	vaddr  uint32

	symIdx uint32

	typ    uint16

}



// linkCOFFtoPE reads a NASM win64 object and writes a standalone PE64 exe.

func linkCOFFtoPE(objPath, outPath, entryName string) error {

	raw, err := os.ReadFile(objPath)

	if err != nil {

		return err

	}

	le := binary.LittleEndian



	if len(raw) < 20 || le.Uint16(raw[0:]) != 0x8664 {

		return fmt.Errorf("not an x86-64 COFF object")

	}

	nSections := int(le.Uint16(raw[2:]))

	symPtr := le.Uint32(raw[8:])

	nSyms := le.Uint32(raw[12:])

	optHeaderSize := int(le.Uint16(raw[16:]))

	if optHeaderSize != 0 {

		return fmt.Errorf("unexpected optional header in object")

	}

	if symPtr == 0 || symPtr > uint32(len(raw)) {

		return fmt.Errorf("bad symbol table pointer")

	}



	// --- sections ---

	sections := make([]*coffSection, 0, nSections)

	secOff := uint32(20)

	for i := 0; i < nSections; i++ {

		sh := raw[secOff+uint32(i*40) : secOff+uint32((i+1)*40)]

		var name string

		if sh[0] == '/' {

			// long name: offset into string table

			off := parseDec(sh[1:8])

			strTabBase := symPtr + nSyms*18

			name = cstr(raw[strTabBase+off:])

		} else {

			name = cstr(sh[0:8])

		}

		s := &coffSection{

			name:        name,

			virtualSize: le.Uint32(sh[8:]),

			rawSize:     le.Uint32(sh[16:]),

			relocsPtr:   le.Uint32(sh[24:]),

			numRelocs:   le.Uint16(sh[32:]),

			flags:       le.Uint32(sh[36:]),

		}

		if sh[20] != 0 && s.rawSize > 0 && le.Uint32(sh[20:]) < uint32(len(raw)) {

			s.rawData = raw[le.Uint32(sh[20:]) : le.Uint32(sh[20:])+s.rawSize]

		}

		if s.virtualSize == 0 {

			s.virtualSize = s.rawSize

		}

		sections = append(sections, s)

	}



	// --- symbols ---

	strTabBase := symPtr + nSyms*18

	// dense table INCLUDING aux entries: relocation symbol indices address

	// the raw table, so positions must match 1:1

	symbols := make([]coffSymbol, 0, nSyms)

	for i := uint32(0); i < nSyms; i++ {

		sy := raw[symPtr+i*18 : symPtr+(i+1)*18]

		var name string

		if sy[0] == 0 && sy[1] == 0 && sy[2] == 0 && sy[3] == 0 {

			name = cstr(raw[strTabBase+le.Uint32(sy[4:]):])

		} else {

			name = cstr(sy[0:8])

		}

		symbols = append(symbols, coffSymbol{

			name:    name,

			value:   le.Uint32(sy[8:]),

			secNum:  int16(le.Uint16(sy[12:])),

			storage: sy[16],

		})

	}



	// --- collect imports (undefined externals) ---

	importNames := []string{}

	importIndex := map[string]int{}

	for _, s := range symbols {

		if s.storage == 2 && s.secNum == 0 && s.name != "" {

			if _, ok := importIndex[s.name]; !ok {

				importIndex[s.name] = len(importNames)

				importNames = append(importNames, s.name)

			}

		}

	}

	sort.Strings(importNames)

	for i, n := range importNames {

		importIndex[n] = i

	}



	// --- layout ---

	// headers


	// .text (existing sections first, thunks appended after)

	var text *coffSection

	for _, s := range sections {

		if s.name == ".text" {

			text = s

		}

	}

	if text == nil {

		return fmt.Errorf("no .text section")

	}

	thunkCount := len(importNames)

	thunkSize := uint32(thunkCount) * 6

	textPlus := thunkSize + 16 // + align padding

	textVA := uint32(pageSize)

	textSize := alignUp(text.virtualSize+textPlus, pageSize)



	// thunk RVAs (6 bytes each, appended at original .text end)

	thunkBase := textVA + text.virtualSize



	// .rdata: import descriptors + hint/name table + IAT

	rdataVA := textVA + textSize

	iatBase := rdataVA + 40 // descriptors first

	hintNameBase := iatBase + uint32(thunkCount+1)*8

	rdataSizeRaw := uint32(40) + (uint32(thunkCount)+1)*8

	hn := make([]byte, 0, thunkCount*32)

	hintOffsets := make([]uint32, thunkCount)

	for i, n := range importNames {

		hintOffsets[i] = hintNameBase + uint32(len(hn))

		hn = append(hn, 0, 0) // hint

		hn = append(hn, n...)

		hn = append(hn, 0)

		if len(hn)%2 == 1 {

			hn = append(hn, 0)

		}

	}

	hn = append(hn, 0, 0) // null terminator entry

	rdataSizeRaw += uint32(len(hn)) + 16 // + dll name string

	rdataSize := alignUp(rdataSizeRaw, pageSize)



	// remaining sections (.data, .bss, ...) after rdata

	nextVA := rdataVA + rdataSize

	for _, s := range sections {

		if s.name == ".text" {

			s.outputOffset = textVA

			continue

		}

		s.outputOffset = nextVA

		size := s.virtualSize

		if s.name == ".bss" {

			size = alignUp(size, 16)

		}

		nextVA += alignUp(size, pageSize)

	}

	relocVA := nextVA

	_ = relocVA



	// --- apply relocations ---

	// symbol address resolution

	symAddr := func(name string) (uint32, bool) {

		if idx, ok := importIndex[name]; ok {

			return iatBase + uint32(idx)*8, true // ADDR64 target = IAT slot

		}

		for _, s := range symbols {

			if s.name == name && s.secNum >= 1 {

				sec := sections[s.secNum-1]

				return sec.outputOffset + s.value, true

			}

		}

		if sym, ok := lookupLocal(symbols, name); ok {

			sec := sections[sym.secNum-1]

			return sec.outputOffset + sym.value, true

		}

		return 0, false

	}

	thunkAddr := func(name string) (uint32, bool) {

		if idx, ok := importIndex[name]; ok {

			return thunkBase + uint32(idx)*6, true

		}

		return 0, false

	}



	relocByPage := map[uint32][][2]uint32{} // page -> []{rva, type}



	for si, sec := range sections {

		if sec.numRelocs == 0 {

			continue

		}

		for ri := 0; ri < int(sec.numRelocs); ri++ {

			rp := sec.relocsPtr + uint32(ri*10) // IMAGE_RELOCATION: VA(4)+Index(4)+Type(2), packed

			if rp+10 > uint32(len(raw)) {

				return fmt.Errorf("reloc out of range")

			}

			rel := coffReloc{

				vaddr:  le.Uint32(raw[rp:]),

				symIdx: le.Uint32(raw[rp+4:]),

				typ:    le.Uint16(raw[rp+8:]),

			}

			if int(rel.symIdx) >= len(symbols) {

				return fmt.Errorf("reloc symbol index %d out of range (nsyms=%d)", rel.symIdx, nSyms)

			}

			sym := symbols[rel.symIdx]

			loc := sec.outputOffset + rel.vaddr

			dataOff := int(rel.vaddr)

			if dataOff+4 > len(sec.rawData) {

				return fmt.Errorf("reloc location out of section data")

			}

			switch rel.typ {

			case 1: // ADDR64

				addr, ok := symAddr(sym.name)

				if !ok {

					return fmt.Errorf("unresolved symbol %s (ADDR64)", sym.name)

				}

				le.PutUint64(sec.rawData[dataOff:], uint64(addr))

				relocByPage[loc&^0xFFF] = append(relocByPage[loc&^0xFFF], [2]uint32{loc, 1})

			case 3: // ADDR32NB (rare)

				addr, ok := symAddr(sym.name)

				if !ok {

					return fmt.Errorf("unresolved symbol %s (ADDR32NB)", sym.name)

				}

				le.PutUint32(sec.rawData[dataOff:], addr)

			case 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14: // REL32 family

				var target uint32

				addend := int32(int8(0))

				// stored disp already includes NASM's addend; read it

				disp := int32(le.Uint32(sec.rawData[dataOff:]))

				addend = disp

				if _, ok := importIndex[sym.name]; ok {

					// calls/jmps to imports go through the thunk

					target, _ = thunkAddr(sym.name)

				} else {

					a, ok := symAddr(sym.name)

					if !ok {

						return fmt.Errorf("unresolved symbol %s (REL32)", sym.name)

					}

					target = a

				}

				// variants 5..14 pre-adjust the addend; base case: disp = target - (loc+4) + addend

				final := int64(target) - int64(loc+4) + int64(addend)

				le.PutUint32(sec.rawData[dataOff:], uint32(int32(final)))

				_ = addend

			case 0: // absolute, ignore

			default:

				return fmt.Errorf("unsupported reloc type %d for %s", rel.typ, sym.name)

			}

		}

		_ = si

	}



	// entry point

	entrySym, ok := lookupLocal(symbols, entryName)

	if !ok {

		return fmt.Errorf("entry symbol %s not found", entryName)

	}

	entryRVA := sections[entrySym.secNum-1].outputOffset + entrySym.value



	// --- build .reloc data ---

	pages := make([]uint32, 0, len(relocByPage))

	for p := range relocByPage {

		pages = append(pages, p)

	}

	sort.Slice(pages, func(i, j int) bool { return pages[i] < pages[j] })

	var relocBuf bytes.Buffer

	for _, p := range pages {

		ents := relocByPage[p]

		sort.Slice(ents, func(i, j int) bool { return ents[i][0] < ents[j][0] })

		blockSize := uint32(8 + len(ents)*2)

		writeLE(&relocBuf, p)

		writeLE(&relocBuf, blockSize)

		for _, e := range ents {

			writeLE(&relocBuf, uint16(e[1]<<12|(e[0]&0xFFF)))

		}

	}

	relocData := relocBuf.Bytes()



	// --- assemble file ---

	imageBase := uint64(0x140000000)

	secAlign := uint32(pageSize)



	type outSec struct {

		name string

		va   uint32

		vsz  uint32

		raw  uint32

		data []byte

		char uint32

	}

	var out []outSec



	// .text with thunks appended

	textData := make([]byte, textSize)

	copy(textData, text.rawData)

	for i, n := range importNames {

		off := text.virtualSize + uint32(i)*6

		copy(textData[off:], []byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00})

		// jmp [rip+0]: the IAT slot address goes into the disp

		disp := int64(iatBase+uint32(i)*8) - int64(thunkBase+uint32(i)*6+6)

		le.PutUint32(textData[off+2:], uint32(int32(disp)))

		_ = n

	}

	out = append(out, outSec{".text", textVA, textSize, uint32(len(textData)), textData, 0x60000020})



	// .rdata

	rdata := make([]byte, rdataSizeRaw)

	// import descriptor: kernel32.dll, first thunk = iatBase

	// IMAGE_IMPORT_DESCRIPTOR: +0 OriginalFirstThunk, +12 TimeDateStamp,
	// +16 ForwarderChain, +20 Name, +24 FirstThunk
	le.PutUint32(rdata[0:], iatBase)  // +0 OriginalFirstThunk
	le.PutUint32(rdata[16:], iatBase) // +16 FirstThunk (loader fills IAT here)

	dllNameOff := rdataSizeRaw - 16
	copy(rdata[dllNameOff:], "kernel32.dll\x00")
	le.PutUint32(rdata[12:], rdataVA+dllNameOff) // +12 Name RVA

	for i := range importNames {

		le.PutUint32(rdata[iatBase-rdataVA+uint32(i)*8:], hintOffsets[i])

	}

	copy(rdata[hintNameBase-rdataVA:], hn)

	out = append(out, outSec{".rdata", rdataVA, rdataSizeRaw, rdataSizeRaw, rdata, 0x40000040})



	// other sections in order

	for _, s := range sections {

		if s.name == ".text" {

			continue

		}

		sz := s.virtualSize

		if s.name == ".bss" {

			sz = alignUp(sz, 16)

		}

		data := make([]byte, alignUp(sz, fileAlign))

		copy(data, s.rawData)

		char := uint32(0xC0000040)

		if s.name == ".bss" {

			char = 0xC0000080

			data = nil

			out = append(out, outSec{s.name, s.outputOffset, sz, 0, nil, char})

			continue

		}

		out = append(out, outSec{s.name, s.outputOffset, sz, uint32(len(data)), data, char})

	}



	// .reloc

	if len(relocData) > 0 {

		rv := out[len(out)-1]

		rva := rv.va + alignUp(rv.vsz, secAlign)

		out = append(out, outSec{".reloc", rva, uint32(len(relocData)), uint32(len(relocData)), relocData, 0x42000040})

	}



	sizeOfImage := uint32(0)

	for _, s := range out {

		sizeOfImage = s.va + alignUp(max(s.vsz, s.raw), secAlign)

	}



	// headers — offset-addressed writes (no ordering bugs)

	nOut := len(out)

	headersSize := alignUp(uint32(0x98+240+nOut*40), fileAlign)

	hdr := make([]byte, headersSize)

	copy(hdr, "MZ")

	put32(hdr, 0x3C, 0x80)

	copy(hdr[0x80:], "PE\x00\x00")

	fh := uint32(0x84)

	put16(hdr, fh+0, 0x8664)      // machine

	put16(hdr, fh+2, uint16(nOut)) // sections

	put32(hdr, fh+4, 0)           // timestamp

	put32(hdr, fh+8, 0)           // symtab

	put32(hdr, fh+12, 0)          // nsyms

	put16(hdr, fh+16, 240)        // opt header size

	put16(hdr, fh+18, 0x0022)     // EXECUTABLE|LARGEADDRESSAWARE



	oh := fh + 20

	put16(hdr, oh+0, 0x20B)       // PE32+

	hdr[oh+2] = 14                // linker ver

	put32(hdr, oh+4, 0)           // size of code

	put32(hdr, oh+8, 0)           // size of init data

	put32(hdr, oh+12, 0)          // size of uninit data

	put32(hdr, oh+16, entryRVA)   // entry point

	put32(hdr, oh+20, textVA)     // base of code

	put64(hdr, oh+24, imageBase) // image base

	put32(hdr, oh+32, pageSize)   // section alignment

	put32(hdr, oh+36, fileAlign)  // file alignment

	put16(hdr, oh+40, 6)          // OS major

	put16(hdr, oh+42, 0)

	put16(hdr, oh+44, 0)          // image major

	put16(hdr, oh+46, 0)

	put16(hdr, oh+48, 6)          // subsystem major

	put16(hdr, oh+50, 0)

	put32(hdr, oh+52, 0)          // win32 ver

	put32(hdr, oh+56, sizeOfImage)

	put32(hdr, oh+60, headersSize)

	put32(hdr, oh+64, 0)          // checksum

	put16(hdr, oh+68, 3)          // subsystem: console

	put16(hdr, oh+70, 0x8160)     // dll chars

	put64(hdr, oh+72, 0x100000)   // stack reserve

	put64(hdr, oh+80, 0x1000)     // stack commit

	put64(hdr, oh+88, 0x100000)   // heap reserve

	put64(hdr, oh+96, 0x1000)     // heap commit

	put32(hdr, oh+104, 0)         // loader flags

	put32(hdr, oh+108, 16)        // num dirs

	// dir[1] = import

	put32(hdr, oh+112+8, rdataVA)

	put32(hdr, oh+112+12, 40)

	// dir[5] = reloc

	if len(relocData) > 0 {

		last := out[len(out)-1]

		put32(hdr, oh+112+5*8, last.va)

		put32(hdr, oh+112+5*8+4, uint32(len(relocData)))

	}



	// section table at oh+240

	st := oh + 240

	fileCursor := headersSize

	for i, s := range out {

		sh := st + uint32(i*40)

		copy(hdr[sh:], s.name)

		if len(s.name) > 8 {

			copy(hdr[sh:], s.name[:8])

		}

		put32(hdr, sh+8, s.vsz)

		put32(hdr, sh+12, s.va)

		if len(s.data) > 0 {

			put32(hdr, sh+16, alignUp(uint32(len(s.data)), fileAlign))

			put32(hdr, sh+20, fileCursor)

			fileCursor += alignUp(uint32(len(s.data)), fileAlign)

		} else {

			put32(hdr, sh+16, 0)

			put32(hdr, sh+20, 0)

		}

		put32(hdr, sh+36, s.char)

	}



	// file body: headers + section data (file-aligned)

	var exe bytes.Buffer

	exe.Write(hdr)

	for _, s := range out {

		if len(s.data) == 0 {

			continue

		}

		exe.Write(s.data)

		for exe.Len()%int(fileAlign) != 0 {

			exe.WriteByte(0)

		}

	}



	return os.WriteFile(outPath, exe.Bytes(), 0644)

}



func lookupLocal(symbols []coffSymbol, name string) (coffSymbol, bool) {

	for _, s := range symbols {

		if s.name == name && s.secNum >= 1 {

			return s, true

		}

	}

	return coffSymbol{}, false

}



func cstr(b []byte) string {

	for i, c := range b {

		if c == 0 {

			return string(b[:i])

		}

	}

	return string(b)

}



func parseDec(b []byte) uint32 {

	var v uint32

	for _, c := range b {

		if c < '0' || c > '9' {

			break

		}

		v = v*10 + uint32(c-'0')

	}

	return v

}



func alignUp(v, a uint32) uint32 {

	if a == 0 {

		return v

	}

	return (v + a - 1) & ^(a - 1)

}



func max(a, b uint32) uint32 {

	if a > b {

		return a

	}

	return b

}



func writeLE(buf *bytes.Buffer, v interface{}) {

	switch x := v.(type) {

	case uint16:

		var b [2]byte

		binary.LittleEndian.PutUint16(b[:], x)

		buf.Write(b[:])

	case uint32:

		var b [4]byte

		binary.LittleEndian.PutUint32(b[:], x)

		buf.Write(b[:])

	case uint64:

		var b [8]byte

		binary.LittleEndian.PutUint64(b[:], x)

		buf.Write(b[:])

	}

}



func put16(b []byte, off uint32, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }

func put32(b []byte, off uint32, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

func put64(b []byte, off uint32, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }


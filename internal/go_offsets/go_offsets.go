package go_offsets

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Masterminds/semver"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

type GoAbi int

const (
	ABI0 GoAbi = iota
	ABIInternal
)

const PtrSize int = 8

type GoOffsets struct {
	GoWriteOffset *GoExtendedOffset
	GoReadOffset  *GoExtendedOffset
	GoVersion     string
	Abi           GoAbi
	SysFdOffset   uint64
}

type GoExtendedOffset struct {
	Enter uint64
	Exits []uint64
}

const (
	minimumABIInternalGoVersion = "1.17.0"
	goVersionSymbol             = "runtime.buildVersion.str" // symbol does not exist in Go (<=1.16)
	goWriteSymbol               = "crypto/tls.(*Conn).Write"
	goReadSymbol                = "crypto/tls.(*Conn).Read"
)

func checkGoVersion(fpath string, versionOffset uint64) (bool, string, error) {
	fd, err := os.Open(fpath)
	if err != nil {
		return false, "", err
	}
	defer fd.Close()

	reader := bufio.NewReader(fd)

	_, err = reader.Discard(int(versionOffset))
	if err != nil {
		return false, "", err
	}

	line, err := reader.ReadString(0)
	if err != nil {
		return false, "", err
	}

	if len(line) < 3 {
		return false, "", fmt.Errorf("ELF data segment read error (corrupted result)")
	}

	goVersionStr := line[2 : len(line)-1]

	goVersion, err := semver.NewVersion(goVersionStr)
	if err != nil {
		return false, goVersionStr, err
	}

	goVersionConstraint, err := semver.NewConstraint(fmt.Sprintf(">= %s", minimumABIInternalGoVersion))
	if err != nil {
		return false, goVersionStr, err
	}

	return goVersionConstraint.Check(goVersion), goVersionStr, nil
}

func GetSymbolOffset(filePath string, symbolName string) (*GoExtendedOffset, error) {
	fmt.Println("GetSymbolOffset()", filePath, "/", symbolName)
	elfFile, err := elf.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("elf.Open() for %v, err: %v", elfFile, err)
	}

	textSection := elfFile.Section(".text")
	if textSection == nil {
		return nil, fmt.Errorf("No text section")
	}

	// extract the raw bytes from the .text section
	var textSectionData []byte
	textSectionData, err = textSection.Data()
	if err != nil {
		return nil, fmt.Errorf("error textSection.Data(): %v", err)
	}
	textSectionLen := uint64(len(textSectionData) - 1)

	symbols, err := elfFile.Symbols()
	if err != nil {
		if errors.Is(err, elf.ErrNoSymbols) {
			return nil, fmt.Errorf("ERROR no symbols section of bin for: %v", filePath)
		}
		return nil, fmt.Errorf("elfFile.Symbols() for %v, error: %v", filePath, err)
	}

	extendedOffset := GoExtendedOffset{Enter: uint64(0), Exits: []uint64{}}
	for _, symbol := range symbols {
		if symbol.Name == symbolName {
			// Get the enter offset
			for _, prog := range elfFile.Progs {
				if prog.Vaddr <= symbol.Value && symbol.Value < (prog.Vaddr+prog.Memsz) {
					offset := symbol.Value - prog.Vaddr + prog.Off
					extendedOffset.Enter = offset
					break
				}
			}

			// Get the exit offsets
			symStart := symbol.Value - textSection.Addr
			symEnd := symStart + symbol.Size
			if symEnd > textSectionLen {
				continue
			}
			symBytes := textSectionData[symStart:symEnd]
			returnOffsets := getExitOffsets(elfFile.Machine, symBytes)

			for _, exitOffset := range returnOffsets {
				extendedOffset.Exits = append(extendedOffset.Exits, exitOffset+extendedOffset.Enter)
			}
		}
	}
	fmt.Println("GetSymbolOffset() done")
	return &extendedOffset, nil
}

func GetStructMemberOffset(filePath string, structName string, memberName string) (uint64, error) {
	elfFile, err := elf.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("elf.Open() failed for %s, err: %v", filePath, err)
	}

	dwarfData, err := elfFile.DWARF()
	if err != nil {
		return 0, fmt.Errorf("elfFile.DWARF() failed for %s, err: %v", filePath, err)
	}

	entryReader := dwarfData.Reader()
	onChildren := false
	memberOffset := uint64(0)

	// var memberOffset
	for {
		// Read all entries in sequence
		entry, err := entryReader.Next()
		if err == io.EOF {
			// We've reached the end of DWARF entries
			break
		}
		if entry == nil {
			continue
		}

		// TODO: This line can panic
		if entry.Tag == dwarf.TagStructType && entry.AttrField(dwarf.AttrName) != nil {
			typeName, _ := entry.Val(dwarf.AttrName).(string)
			if typeName == structName {
				// Now, find the member's offset
				onChildren = true
			}
		} else if onChildren {
			if entry.Tag == 0 {
				onChildren = false
				break
			}

			typeName, _ := entry.Val(dwarf.AttrName).(string)

			// fmt.Print("		", typeName, " offset: ")
			if typeName != memberName {
				continue
			}

			for _, field := range entry.Field {
				if field.Attr == dwarf.AttrDataMemberLoc {
					memberOffset = uint64(field.Val.(int64))
					// fmt.Print(memberOffset, "\n")
				}
			}
		}
	}

	return memberOffset, nil
}

func getExitOffsets(machine elf.Machine, instructions []byte) []uint64 {
	var res []uint64
	switch machine {
	case elf.EM_X86_64:
		for i := 0; i < len(instructions); {
			ins, err := x86asm.Decode(instructions[i:], 64)
			if err == nil && ins.Op == x86asm.RET {
				res = append(res, uint64(i))
			}
			i += ins.Len
		}
	case elf.EM_AARCH64:
		for i := 0; i < len(instructions); {
			ins, err := arm64asm.Decode(instructions[i:])
			if err == nil && ins.Op == arm64asm.RET {
				res = append(res, uint64(i))
			}
			i += 4
		}
	}
	return res
}

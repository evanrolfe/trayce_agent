package sockets_test

import (
	"encoding/hex"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSockets(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sockets Suite")
}

func hexDumpToBytes(hexDump string) ([]byte, error) {
	lines := strings.Split(hexDump, "\n")
	var hexString string
	for _, line := range lines {
		// Find the hex portion of each line and concatenate it
		if i := strings.Index(line, "|"); i != -1 {
			hexString += strings.TrimSpace(line[10:i])
		}

	}

	// Remove spaces and split the concatenated hex string into bytes
	hexString = strings.ReplaceAll(hexString, " ", "")
	decoded, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func convertSliceToArray(slice []byte) [4096]byte {
	var arr [4096]byte
	copy(arr[:], slice)

	return arr
}

package utils

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func Test_hexDumpToBytes(t *testing.T) {
	hexDump := `00000000  fd d5 01 00 00 01 00 00  00 00 00 01 06 70 6e 74  |.............pnt|
00000010  65 73 74 02 69 6f 00 00  1c 00 01 00 00 29 04 d0  |est.io.......)..|
00000020  00 00 00 00 00 00                                 |......|`

	tests := []struct {
		name    string
		args    string
		want    []byte
		wantErr bool
	}{
		{
			name:    "1",
			args:    hexDump,
			want:    []byte{0xfd, 0xd5, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x70, 0x6e, 0x74, 0x65, 0x73, 0x74, 0x02, 0x69, 0x6f, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := hexDumpToBytes(tt.args)
			if !tt.wantErr {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.want, res)
		})
	}
}

package sockets

import (
	"fmt"
	"time"

	"github.com/vczyh/mysql-protocol/packet"
)

type MysqlColumn struct {
	Database string
	Table    string
	Name     string
	Type     byte
}

type MysqlResponse struct {
	Columns       []Column
	Rows          [][]string
	colEOF        bool // whether or not we have received an EOF packet for the columns
	rowEOF        bool // whether or not we have received an EOF packet for the rows
	colCount      int
	lastMsgSeq    *int // the sequence number of the last message received
	packetColumns []packet.Column
}

func NewMysqlResponse() MysqlResponse {
	return MysqlResponse{Columns: []Column{}, colEOF: false, rowEOF: false, lastMsgSeq: nil}
}

func (resp *MysqlResponse) AddPayload(data []byte) {
	// if msg.Type == TypeMysqlQuery { // this is a column being sent
	// 	socket.bufResp.AddColumnPayload(msg.Payload[1:])
	// } else if msg.Type == TypeMysqlRow {
	// 	socket.bufResp.AddRowPayload(msg.Payload[1:])
	// } else if msg.Type == TypeMysqlEOF {
	// 	socket.bufResp.AddEOF()
	// }
}

func (resp *MysqlResponse) AddMessage(msg MysqlMessage) {
	defer func() {
		resp.lastMsgSeq = &msg.SequenceNum
	}()

	if resp.lastMsgSeq == nil {
		colCount, err := packet.ParseColumnCount(msg.FullMessage)
		if err != nil {
			fmt.Println("[Error] packet.ParseColumnCount():", err)
			return
		}
		// First message received is the column count
		resp.colCount = int(colCount)

		return
	}

	if *resp.lastMsgSeq != msg.SequenceNum-1 && msg.SequenceNum != 0 {
		fmt.Printf("[WARN] MysqlResponse.AddMessage() received an out-of-order message, seq: %d, last seq: %d\n", msg.SequenceNum, *resp.lastMsgSeq)
		return
	}

	if msg.Type == TypeMysqlEOF {
		resp.AddEOF()
		return
	}

	if resp.colCount > len(resp.Columns) {
		// Assume this is still a column definition being received
		resp.AddColumnPayload(msg.FullMessage)
		return
	}

	resp.AddRowPayload(msg)
}

// AddColumnPayload decodes a single column payload and adds it to this response
func (resp *MysqlResponse) AddColumnPayload(data []byte) {
	packetCol, err := packet.ParseColumnDefinition(data)
	var col Column
	if err != nil {
		fmt.Println("Error - parsing mysql column:", err)
		col = Column{
			Name: "PARSE_ERROR",
			Type: 0xFC, // varchar
		}
	} else {
		col = Column{
			Name: packetCol.GetName(),
			Type: 0xFC,
		}
	}

	resp.packetColumns = append(resp.packetColumns, packetCol)
	resp.Columns = append(resp.Columns, col)
}

// AddRowPayload decodes a single row payload and adds it to this response
func (resp *MysqlResponse) AddRowPayload(msg MysqlMessage) {
	row := []string{}

	if msg.Payload[0] == 0x00 {
		packetRow, err := packet.ParseBinaryResultSetRow(msg.FullMessage, resp.packetColumns, time.Now().Location())
		if err != nil {
			fmt.Println("Error - parsing mysql binary row:", err)
		}
		for _, value := range packetRow {
			valueBytes, err := value.DumpText()
			if err != nil {
				row = append(row, "PARSE_ERROR")
				continue
			}
			row = append(row, string(trimNonASCII(valueBytes)))
		}
	} else {
		packetRow, err := packet.ParseTextResultSetRow(msg.FullMessage, resp.packetColumns, time.Now().Location())
		if err != nil {
			fmt.Println("Error - parsing mysql text row:", err)
		}
		for _, value := range packetRow {
			valueBytes, err := value.DumpText()
			if err != nil {
				row = append(row, "PARSE_ERROR")
				continue
			}
			row = append(row, string(trimNonASCII(valueBytes)))
		}
	}

	resp.Rows = append(resp.Rows, row)
}

func (resp *MysqlResponse) AddEOF() {
	// sometimes we dont get an EOF packet for the columns but we do get one for the rows, so we need this logic to handle that
	if len(resp.Columns) > 0 && len(resp.Rows) == 0 {
		resp.colEOF = true
	} else if len(resp.Columns) > 0 && len(resp.Rows) > 0 {
		resp.rowEOF = true
	}
}

// Complete returns true if all the column and row data for this response has been parsed
func (resp *MysqlResponse) Complete() bool {
	return resp.rowEOF
}

func (resp *MysqlResponse) String() string {
	out := ""
	for _, col := range resp.Columns {
		out += fmt.Sprintf("%s, ", col.Name)
	}
	for _, row := range resp.Rows {
		out += "\n"
		for _, value := range row {
			out += fmt.Sprintf("%s, ", value)
		}
	}
	return out
}

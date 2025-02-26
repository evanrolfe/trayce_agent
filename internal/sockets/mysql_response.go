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

func (q *MysqlResponse) AddPayload(data []byte) {
	// if msg.Type == TypeMysqlQuery { // this is a column being sent
	// 	socket.bufResp.AddColumnPayload(msg.Payload[1:])
	// } else if msg.Type == TypeMysqlRow {
	// 	socket.bufResp.AddRowPayload(msg.Payload[1:])
	// } else if msg.Type == TypeMysqlEOF {
	// 	socket.bufResp.AddEOF()
	// }
}

func (q *MysqlResponse) AddMessage(msg MysqlMessage) {
	defer func() {
		q.lastMsgSeq = &msg.SequenceNum
	}()

	if q.lastMsgSeq == nil {
		colCount, err := packet.ParseColumnCount(msg.FullMessage)
		if err != nil {
			fmt.Println("[Error] packet.ParseColumnCount():", err)
			return
		}
		// First message received is the column count
		q.colCount = int(colCount)

		return
	}

	if *q.lastMsgSeq != msg.SequenceNum-1 && msg.SequenceNum != 0 {
		fmt.Printf("[WARN] MysqlResponse.AddMessage() received an out-of-order message, seq: %d, last seq: %d\n", msg.SequenceNum, *q.lastMsgSeq)
		return
	}

	if msg.Type == TypeMysqlEOF {
		q.AddEOF()
		return
	}

	if q.colCount > len(q.Columns) {
		// Assume this is still a column definition being received
		q.AddColumnPayload(msg.FullMessage)
		return
	}

	q.AddRowPayload(msg)
}

// AddColumnPayload decodes a single column payload and adds it to this response
func (q *MysqlResponse) AddColumnPayload(data []byte) {
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

	q.packetColumns = append(q.packetColumns, packetCol)
	q.Columns = append(q.Columns, col)
}

// AddRowPayload decodes a single row payload and adds it to this response
func (q *MysqlResponse) AddRowPayload(msg MysqlMessage) {
	row := []string{}

	if msg.Payload[0] == 0x00 {
		packetRow, err := packet.ParseBinaryResultSetRow(msg.FullMessage, q.packetColumns, time.Now().Location())
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
		packetRow, err := packet.ParseTextResultSetRow(msg.FullMessage, q.packetColumns, time.Now().Location())
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

	q.Rows = append(q.Rows, row)
}

func (q *MysqlResponse) AddEOF() {
	// sometimes we dont get an EOF packet for the columns but we do get one for the rows, so we need this logic to handle that
	if len(q.Columns) > 0 && len(q.Rows) == 0 {
		q.colEOF = true
	} else if len(q.Columns) > 0 && len(q.Rows) > 0 {
		q.rowEOF = true
	}
}

// Complete returns true if all the column and row data for this response has been parsed
func (q *MysqlResponse) Complete() bool {
	return q.rowEOF
}

func (q *MysqlResponse) String() string {
	out := ""
	for _, col := range q.Columns {
		out += fmt.Sprintf("%s, ", col.Name)
	}
	for _, row := range q.Rows {
		out += "\n"
		for _, value := range row {
			out += fmt.Sprintf("%s, ", value)
		}
	}
	return out
}

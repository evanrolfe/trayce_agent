package sockets

import (
	"fmt"
)

type MysqlColumn struct {
	Database string
	Table    string
	Name     string
	Type     byte
}

type MysqlResponse struct {
	Columns    []Column
	Rows       [][]string
	colEOF     bool // whether or not we have received an EOF packet for the columns
	rowEOF     bool // whether or not we have received an EOF packet for the rows
	colCount   int
	lastMsgSeq *int // the sequence number of the last message received
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
		// First message received is the column count
		q.colCount = int(msg.Payload[0]) // NOTE this will fail if there are > 255 columns
		fmt.Println("----------> q.colCount:", q.colCount)
		return
	}

	if *q.lastMsgSeq != msg.SequenceNum-1 {
		fmt.Printf("[WARN] MysqlResponse.AddMessage() received an out-of-order message, seq: %d, last seq: %d\n", msg.SequenceNum, *q.lastMsgSeq)
		return
	}

	if msg.Type == TypeMysqlEOF {
		q.AddEOF()
		return
	}

	if q.colCount > len(q.Columns) {
		// Assume this is still a column definition being received
		q.AddColumnPayload(msg.Payload[1:])
		return
	}

	q.AddRowPayload(msg.Payload)
}

// AddColumnPayload decodes a single column payload and adds it to this response
func (q *MysqlResponse) AddColumnPayload(data []byte) {
	col, err := parseColumn(data)
	if err != nil {
		fmt.Println("Error - parsing mysql column:", err)
		col = &Column{
			Name: "PARSE_ERROR",
			Type: 0xFC, // varchar
		}
	}
	fmt.Println("----------> added col:", col.Name)

	q.Columns = append(q.Columns, *col)
}

// AddRowPayload decodes a single row payload and adds it to this response
func (q *MysqlResponse) AddRowPayload(data []byte) {
	row, err := parseRow(data)
	if err != nil {
		fmt.Println("Error - parsing mysql row:", err)
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

func parseColumn(data []byte) (*Column, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("packet too short")
	}

	// The format follows the MySQL Column Definition Packet structure:
	// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_column_definition.html

	offset := 0

	// Skip catalog (always "def")
	if offset+3 > len(data) {
		return nil, fmt.Errorf("catalog field exceeds packet length at offset %d", offset)
	}
	offset += 3

	// Read database name length
	if offset >= len(data) {
		return nil, fmt.Errorf("database name length field exceeds packet length at offset %d", offset)
	}
	dbNameLen := int(data[offset])
	offset++

	// Skip database name
	if offset+dbNameLen > len(data) {
		return nil, fmt.Errorf("database name field exceeds packet length at offset %d", offset)
	}
	offset += dbNameLen

	// Read table name length
	if offset >= len(data) {
		return nil, fmt.Errorf("table name length field exceeds packet length at offset %d", offset)
	}
	tableNameLen := int(data[offset])
	offset++

	// Skip table name
	if offset+tableNameLen > len(data) {
		return nil, fmt.Errorf("table name field exceeds packet length at offset %d", offset)
	}
	offset += tableNameLen

	// Read original table name length
	if offset >= len(data) {
		return nil, fmt.Errorf("original table name length field exceeds packet length at offset %d", offset)
	}
	orgTableNameLen := int(data[offset])
	offset++

	// Skip original table name
	if offset+orgTableNameLen > len(data) {
		return nil, fmt.Errorf("original table name field exceeds packet length at offset %d", offset)
	}
	offset += orgTableNameLen

	// Read column name length
	if offset >= len(data) {
		return nil, fmt.Errorf("column name length field exceeds packet length at offset %d", offset)
	}
	columnNameLen := int(data[offset])
	offset++

	// Extract column name
	if offset+columnNameLen > len(data) {
		return nil, fmt.Errorf("column name field exceeds packet length at offset %d", offset)
	}
	columnName := string(data[offset : offset+columnNameLen])
	offset += columnNameLen

	// Read original column name length
	if offset >= len(data) {
		return nil, fmt.Errorf("original column name length field exceeds packet length at offset %d", offset)
	}
	orgColumnNameLen := int(data[offset])
	offset++

	// Skip original column name
	if offset+orgColumnNameLen > len(data) {
		return nil, fmt.Errorf("original column name field exceeds packet length at offset %d", offset)
	}
	offset += orgColumnNameLen

	// Check fixed-length fields
	if offset+6 > len(data) { // 2 bytes charset + 4 bytes column length
		return nil, fmt.Errorf("fixed length fields exceed packet length at offset %d", offset)
	}
	offset += 2 // Character set (2 bytes)
	offset += 4 // Column length (4 bytes)

	// Extract column type
	if offset >= len(data) {
		return nil, fmt.Errorf("column type field exceeds packet length at offset %d", offset)
	}
	columnType := data[offset]

	return &Column{Name: columnName, Type: columnType}, nil
}

func parseRow(data []byte) ([]string, error) {
	var fields []string
	pos := 0

	// // First field is special - it's just a single byte value
	// if pos >= len(data) {
	// 	return nil, fmt.Errorf("empty data")
	// }
	// fields = append(fields, string([]byte{data[pos]}))
	// pos++

	// Parse remaining fields
	for pos < len(data) {
		// Check if we have at least 1 byte for the length
		if pos >= len(data) {
			return nil, fmt.Errorf("unexpected end of data at position %d", pos)
		}

		// Get length byte
		length := int(data[pos])
		pos++

		// Check if we have enough bytes for the field
		if pos+length > len(data) {
			return nil, fmt.Errorf("field length %d exceeds remaining data at position %d", length, pos)
		}

		// Extract the field value
		field := string(data[pos : pos+length])
		fields = append(fields, field)

		// Move position to next field
		pos += length
	}

	return fields, nil
}

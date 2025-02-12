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
	Columns []Column
	Rows    [][]string
	colEOF  bool // whether or not we have received an EOF packet for the columns
	rowEOF  bool // whether or not we have received an EOF packet for the rows
}

func NewMysqlResponse() MysqlResponse {
	return MysqlResponse{Columns: []Column{}, colEOF: false, rowEOF: false}
}

func (q *MysqlResponse) AddPayload(data []byte) {
	// rowValues, err := q.extractRowValues(data)
	// if err != nil {
	// 	fmt.Println("[Error] [SocketPsql] extractRowValues():", err)
	// 	return
	// }
	// q.Rows = append(q.Rows, rowValues)
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
	offset += 3

	// Read database name length
	dbNameLen := int(data[offset])
	offset++

	// Skip database name
	offset += dbNameLen

	// Read table name length
	tableNameLen := int(data[offset])
	offset++

	// Skip table name
	offset += tableNameLen

	// Read original table name length
	orgTableNameLen := int(data[offset])
	offset++

	// Skip original table name
	offset += orgTableNameLen

	// Read column name length
	columnNameLen := int(data[offset])
	offset++

	// Extract column name
	if offset+columnNameLen > len(data) {
		return nil, fmt.Errorf("column name exceeds packet length")
	}
	columnName := string(data[offset : offset+columnNameLen])
	offset += columnNameLen

	// Skip original column name length and actual original column name
	orgColumnNameLen := int(data[offset])
	offset++
	offset += orgColumnNameLen

	// Skip fixed-length fields (charset, column length, type)
	offset += 2 // Character set (2 bytes)
	offset += 4 // Column length (4 bytes)

	// Extract column type
	if offset >= len(data) {
		return nil, fmt.Errorf("column type exceeds packet length")
	}
	columnType := data[offset]

	return &Column{Name: columnName, Type: columnType}, nil
}

func parseRow(data []byte) ([]string, error) {
	var fields []string
	pos := 0

	// First field is special - it's just a single byte value
	if pos >= len(data) {
		return nil, fmt.Errorf("empty data")
	}
	fields = append(fields, string([]byte{data[pos]}))
	pos++

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

package sockets

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
)

type Column struct {
	Name string
	Type byte
}

var oidToTypeByte = map[int32]byte{
	23:   'i', // INT4 integer
	25:   't', // TEXT
	700:  'f', // FLOAT4
	701:  'f', // FLOAT8
	1043: 't', // VARCHAR
	1700: 'f', // NUMERIC
	1184: 'd', // TIMESTAMPTZ
}

type PSQLResponse struct {
	Columns []Column
	Rows    [][]string
}

func NewPSQLResponse(columns []Column) PSQLResponse {
	return PSQLResponse{Columns: columns}
}

// PSQLResponseFromRowDescription takes a row description payload, parses it into columns and returns a PSQLResponse struct
func PSQLResponseFromRowDescription(payload []byte) (PSQLResponse, error) {
	cols, err := extractColumns(payload)
	if err != nil {
		return PSQLResponse{}, err
	}

	return PSQLResponse{Columns: cols}, nil
}

func (q *PSQLResponse) AddPayload(data []byte) {
	rowValues, err := q.extractRowValues(data)
	if err != nil {
		fmt.Println("[Error] [SocketPsql] extractRowValues():", err)
		return
	}
	q.Rows = append(q.Rows, rowValues)
}

func (q *PSQLResponse) String() string {
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

// extractRowValues parses a PostgreSQL DataRow message payload and returns the column values as strings.
// payload is the DataRow contents excluding the initial message type byte and length bytes.
func (q *PSQLResponse) extractRowValues(payload []byte) ([]string, error) {
	buf := bytes.NewReader(payload)
	// Read the number of columns (int16)
	var colCount int16
	if err := binary.Read(buf, binary.BigEndian, &colCount); err != nil {
		return nil, fmt.Errorf("failed to read column count: %w", err)
	}

	if int(colCount) != len(q.Columns) {
		return nil, fmt.Errorf("column count in data (%d) does not match known columns (%d)", colCount, len(q.Columns))
	}

	values := make([]string, 0, colCount)

	for i := 0; i < int(colCount); i++ {
		// Read the length of the column value (int32)
		var length int32
		if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
			return nil, fmt.Errorf("failed to read column length: %w", err)
		}

		if length == -1 {
			// NULL column
			values = append(values, "")
			continue
		}

		if int(length) > buf.Len() {
			return nil, fmt.Errorf("not enough data for column value %d", i+1)
		}

		valBytes := make([]byte, length)
		if _, err := buf.Read(valBytes); err != nil {
			return nil, fmt.Errorf("failed to read column value: %w", err)
		}

		colType := q.Columns[i].Type
		valStr := string(valBytes)

		switch string(colType) {
		case "i":
			// Integer type
			// Already text-based, just ensure it's a valid integer
			if len(valBytes) == 4 {
				// TODO: This should differentiate between binary based  and text based columns
				valInt := binary.BigEndian.Uint32(valBytes)
				valStr = fmt.Sprintf("%d", valInt)
			}

		case "f":
			// Float type
			// Try parsing as float
			if f, err := strconv.ParseFloat(valStr, 64); err == nil {
				valStr = fmt.Sprintf("%g", f) // convert float64 back to a clean string
			} else {
				fmt.Println("[ERROR] parsing float value from postgres:", err)
			}

		case "t":
			// Text type, no change needed

		case "d":
			// Datetime/timestamp type
			// We could attempt to parse to time.Time if desired:
			// t, err := time.Parse("2006-01-02 15:04:05.999999", valStr)
			// if err == nil {
			//   valStr = t.String()
			// }
			// For simplicity, just leave it as the original string
		default:
			// 'u' or unknown type, just leave as-is
		}

		values = append(values, valStr)
	}

	return values, nil
}

// extractColumns parses a RowDescription payload and returns a slice of Column structs.
// Each Column has a Name string and a Type byte, representing the category of the column type.
func extractColumns(payload []byte) ([]Column, error) {
	buf := bytes.NewBuffer(payload)

	// Read number of fields (int16)
	var fieldCount int16
	if err := binary.Read(buf, binary.BigEndian, &fieldCount); err != nil {
		return nil, fmt.Errorf("failed to read field count: %w", err)
	}

	columns := make([]Column, 0, fieldCount)

	for i := 0; i < int(fieldCount); i++ {
		name, err := readNullTerminatedString(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to read field name: %w", err)
		}

		// Read the 18 bytes of metadata
		metadata := make([]byte, 18)
		if n, err := buf.Read(metadata); err != nil || n < 18 {
			return nil, fmt.Errorf("not enough data to read field metadata")
		}

		// Extract the type OID from the metadata
		typeOID := int32(binary.BigEndian.Uint32(metadata[6:10]))

		typeByte := oidToTypeByte[typeOID]
		if typeByte == 0 {
			typeByte = 'u' // unknown
		}

		columns = append(columns, Column{Name: name, Type: typeByte})
	}

	return columns, nil
}

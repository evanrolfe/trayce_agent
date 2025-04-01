package sockets

import "fmt"

type MysqlQuery struct {
	Query  string
	Params []string
}

func NewMysqlQuery(query []byte) MysqlQuery {
	return MysqlQuery{
		Query: string(trimNonASCII(query)),
	}
}

func (qry *MysqlQuery) AddPayload(data []byte) {
	// // Do nothing, this isn't used for sql queries
	// params, err := extractBindArgsFromPayload(data)
	// if err != nil {
	// 	fmt.Println("[Error] extractBindArgsFromPayload():", err)
	// 	return
	// }
	// q.Params = params
}

func (qry *MysqlQuery) String() string {
	out := qry.Query
	if len(qry.Params) > 0 {
		out += "\n"
		for _, param := range qry.Params {
			out += fmt.Sprintf("%s\n", param)
		}
	}
	return out
}

// trimNonASCII removes non-ASCII characters from the beginning and end of a string
func trimNonASCII(s []byte) []byte {
	if len(s) == 0 {
		return s
	}

	start := 0
	end := len(s)

	// Trim from start
	for start < end && (s[start] < 32 || s[start] > 126) {
		start++
	}

	// Trim from end
	for end > start && (s[end-1] < 32 || s[end-1] > 126) {
		end--
	}

	return s[start:end]
}

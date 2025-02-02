package sockets

import "fmt"

type MysqlQuery struct {
	Query  string
	Params []string
}

func NewMysqlQuery(query string) MysqlQuery {
	return MysqlQuery{
		Query: query,
	}
}

func (q *MysqlQuery) AddPayload(data []byte) {
	// // Do nothing, this isn't used for sql queries
	// params, err := extractBindArgsFromPayload(data)
	// if err != nil {
	// 	fmt.Println("[Error] extractBindArgsFromPayload():", err)
	// 	return
	// }
	// q.Params = params
}

func (q *MysqlQuery) String() string {
	out := q.Query
	if len(q.Params) > 0 {
		out += "\n"
		for _, param := range q.Params {
			out += fmt.Sprintf("%s\n", param)
		}
	}
	return out
}

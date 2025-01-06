package sockets

import "fmt"

type PSQLQuery struct {
	Query  string
	Params []string
}

func NewPSQLQuery(query string) PSQLQuery {
	return PSQLQuery{
		Query: query,
	}
}

func (q *PSQLQuery) AddPayload(data []byte) {
	// Do nothing, this isn't used for sql queries
	params, err := extractBindArgsFromPayload(data)
	if err != nil {
		fmt.Println("[Error] extractBindArgsFromPayload():", err)
		return
	}
	q.Params = params
}

func (q *PSQLQuery) String() string {
	out := q.Query
	if len(q.Params) > 0 {
		out += "\n"
		for _, param := range q.Params {
			out += fmt.Sprintf("%s\n", param)
		}
	}
	return out
}

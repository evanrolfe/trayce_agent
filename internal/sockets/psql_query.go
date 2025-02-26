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

func (qry *PSQLQuery) AddPayload(data []byte) {
	// Do nothing, this isn't used for sql queries
	params, err := extractBindArgsFromPayload(data)
	if err != nil {
		fmt.Println("[Error] extractBindArgsFromPayload():", err)
		return
	}
	qry.Params = params
}

func (qry *PSQLQuery) String() string {
	out := qry.Query
	if len(qry.Params) > 0 {
		out += "\n"
		for _, param := range qry.Params {
			out += fmt.Sprintf("%s\n", param)
		}
	}
	return out
}

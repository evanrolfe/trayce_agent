package api

import (
	"fmt"

	"github.com/evanrolfe/trayce_agent/internal/sockets"
)

func convertToAPIFlow(socketFlow sockets.Flow) *Flow {
	apiFlow := Flow{
		Uuid:       socketFlow.UUID,
		SourceAddr: socketFlow.SourceAddr,
		DestAddr:   socketFlow.DestAddr,
		L4Protocol: socketFlow.L4Protocol,
		L7Protocol: socketFlow.L7Protocol,
	}

	// Convert request
	if socketFlow.Request != nil {
		switch req := socketFlow.Request.(type) {
		case *sockets.HTTPRequest:
			apiFlow.Request = &Flow_HttpRequest{
				HttpRequest: &HTTPRequest{
					Method:      req.Method,
					Path:        req.Path,
					Host:        req.Host,
					HttpVersion: req.HttpVersion,
					Headers:     convertToAPIHeaders(req.Headers),
					Payload:     req.Payload,
				},
			}
		case *sockets.GRPCRequest:
			payload := req.Payload[5:] // strip off the first 5 bytes as that is the http2 message length
			if payload[0] != 0x00 {
				fmt.Println("WARNING: Compressed GRPC payload received") // TODO: need to figure out how to handle this
			}
			apiFlow.Request = &Flow_GrpcRequest{
				GrpcRequest: &GRPCRequest{
					Path:    req.Path,
					Headers: convertToAPIHeaders(req.Headers),
					Payload: payload,
				},
			}
		case *sockets.PSQLQuery:
			apiFlow.Request = &Flow_SqlQuery{
				SqlQuery: &SQLQuery{
					Query:  req.Query,
					Params: &StringList{Values: req.Params},
				},
			}
		default:
			fmt.Println("ERROR: convertToAPIFlow() wrong type for request")
		}
	}

	// Convert response
	if socketFlow.Response != nil {
		switch resp := socketFlow.Response.(type) {
		case *sockets.HTTPResponse:
			apiFlow.Response = &Flow_HttpResponse{
				HttpResponse: &HTTPResponse{
					Status:      int32(resp.Status),
					StatusMsg:   resp.StatusMsg,
					HttpVersion: resp.HttpVersion,
					Headers:     convertToAPIHeaders(resp.Headers),
					Payload:     resp.Payload,
				},
			}
		case *sockets.GRPCResponse:
			payload := resp.Payload[5:]
			if payload[0] != 0x00 {
				fmt.Println("WARNING: Compressed GRPC payload received")
			}
			apiFlow.Response = &Flow_GrpcResponse{
				GrpcResponse: &GRPCResponse{
					Headers: convertToAPIHeaders(resp.Headers),
					Payload: payload,
				},
			}
		case *sockets.PSQLResponse:
			apiFlow.Response = &Flow_SqlResponse{
				SqlResponse: &SQLResponse{
					Columns: convertToAPIColumns(resp.Columns),
					Rows:    convertToAPIRows(resp.Rows),
				},
			}
		default:
			fmt.Println("ERROR: convertToAPIFlow() wrong type for response")
		}
	}

	return &apiFlow
}

func convertToAPIColumns(columns []sockets.Column) *StringList {
	apiCols := &StringList{}

	for _, col := range columns {
		apiCols.Values = append(apiCols.Values, col.Name)
	}

	return apiCols
}

func convertToAPIHeaders(headers map[string][]string) map[string]*StringList {
	apiHeaders := map[string]*StringList{}

	for key, values := range headers {
		apiHeaders[key] = &StringList{Values: values}
	}

	return apiHeaders
}

func convertToAPIRows(rows [][]string) []*StringList {
	apiRows := []*StringList{}

	for _, row := range rows {
		apiRow := &StringList{Values: row}
		apiRows = append(apiRows, apiRow)
	}

	return apiRows
}

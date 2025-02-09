package test

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/evanrolfe/trayce_agent/api"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	reqRegex               = `^GET /\w* HTTP/1\.1`
	reqRegexHttp2          = `^GET /\d* HTTP/2`
	reqChunkRegex          = `^GET /chunked HTTP/1\.1`
	numRequestsLoad        = 100
	mega_server_image_name = "mega_server"
)

func AssertFlows(t *testing.T, flows []*api.Flow) {
	assert.Greater(t, len(flows), 0)
	// assert.Greater(t, len(flows[0].Request), 0)

	for _, flow := range flows {
		assert.Greater(t, len(flow.SourceAddr), 0)
		assert.Greater(t, len(flow.DestAddr), 0)
		assert.NotEqual(t, flow.SourceAddr, "0.0.0.0:0")
		assert.NotEqual(t, flow.DestAddr, "0.0.0.0:0")

		if flow.Request != nil {
			// TODO:
			// assert.Regexp(t, regexp.MustCompile(reqRegex), string(flow.RequestRaw))
			assert.Equal(t, "tcp", flow.L4Protocol)
			assert.Equal(t, "http", flow.L7Protocol)
		}
	}
}

func AssertFlowsHttp2(t *testing.T, flows []*api.Flow) {
	for _, flow := range flows {
		assert.Greater(t, len(flow.SourceAddr), 0)
		assert.Greater(t, len(flow.DestAddr), 0)
		assert.NotEqual(t, flow.SourceAddr, "0.0.0.0:0")
		assert.NotEqual(t, flow.DestAddr, "0.0.0.0:0")

		if flow.Request != nil {
			// TODO:
			// assert.Regexp(t, regexp.MustCompile(reqRegexHttp2), string(flow.RequestRaw))
			assert.Equal(t, "tcp", flow.L4Protocol)
			assert.Equal(t, "http2", flow.L7Protocol)
		}
	}
}

func getMegaServer(t *testing.T) (string, string) {
	// Find the mega_server container
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}

	megaserverId := ""
	megaserverIp := ""
	containers, err := dockerClient.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		panic(err)
	}

	for _, container := range containers {
		if strings.Contains(container.Image, mega_server_image_name) {
			megaserverId = container.ID
			for _, network := range container.NetworkSettings.Networks {
				megaserverIp = network.IPAddress
			}

			fmt.Println("Found mega_server:", megaserverIp, "ID:", megaserverId)
		}
	}

	// Check we have a mega server
	if megaserverId == "" {
		t.Errorf("\n\nFAIL: No mega server found! See README.md to start it.")
		assert.NotEmpty(t, megaserverId)
		return "", ""
	}

	return megaserverId, megaserverIp
}

func getTestConfig() (int, int, time.Duration) {
	// Load test or single test?
	var numRequests int
	var timeout time.Duration
	if testing.Short() {
		numRequests = 1
		timeout = 3 * time.Second
	} else {
		numRequests = numRequestsLoad
		timeout = 20 * time.Second
	}

	return numRequests, numRequests * 2, timeout
}

func makeRequests(url string, ishttp2 bool, num int) {
	var wg sync.WaitGroup
	for i := 0; i < num; i++ {
		wg.Add(1)
		go makeRequest(i, url, ishttp2, &wg)
		time.Sleep(50 * time.Millisecond)
	}
	wg.Wait()
}

func makeRequest(i int, url string, ishttp2 bool, wg *sync.WaitGroup) {
	defer wg.Done()

	if url[0:4] == "grpc" {
		makeGrpcRequest(url[7:])
	} else if url[0:4] == "psql" {
		makePostgresRequestPrepared(url[7:])
	} else if url[0:5] == "mysql" {
		makeMysqlRequest(url[8:])
	} else if url[0:4] == "http" {
		var client *http.Client
		if ishttp2 {
			// Setup HTTP/2 transport
			client = &http.Client{
				Transport: &http2.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		} else {
			// Setup HTTP/1.1 transport
			client = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					// This line forces http1.1:
					TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
				},
			}
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Printf("error constructing http request: %s\n", err)
			os.Exit(1)
		}
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("X-Request-ID", uuid.NewString())
		res, err := client.Do(req)
		if err != nil {
			fmt.Printf("error sending http request: %s\n", err)
			os.Exit(1)
		}

		io.ReadAll(res.Body)
	}
}

func makeGrpcRequest(addr string) {
	client, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		fmt.Printf("error constructing grpc client: %s\n", err)
		os.Exit(1)
	}

	trayceClient := api.NewTrayceAgentClient(client)

	// reply, err := trayceClient.SendAgentStarted(context.Background(), &api.AgentStarted{Version: "1.2.3"})
	reply, err := trayceClient.SendContainersObserved(context.Background(), &api.Containers{
		Containers: []*api.Container{
			{
				Id:     "1234",
				Image:  "ubuntu",
				Ip:     "172.0.1.19",
				Name:   "evan",
				Status: "running",
			},
		},
	})
	if err != nil {
		fmt.Printf("error sending agent started over grpc: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("grpc reply:", reply.Status)
}

func makePostgresRequest(addr string) {
	connStr := fmt.Sprintf("postgres://postgres:postgres@%s/postgres?sslmode=disable", addr)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Println("Error failed: to connect to database:", err)
	}
	defer db.Close()

	// Verify connection
	err = db.Ping()
	if err != nil {
		fmt.Println("Error: failed to connect to database:", err)
	}

	rows, err := db.Query("SELECT id, name, quantity, price, created_at FROM things")
	if err != nil {
		fmt.Println("Error: Failed to run query:", err)
	}
	defer rows.Close()
}

func makePostgresRequestPrepared(addr string) {
	connStr := fmt.Sprintf("postgres://postgres:postgres@%s/postgres?sslmode=disable", addr)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Println("Error failed: to connect to database:", err)
	}
	defer db.Close()

	// Verify connection
	err = db.Ping()
	if err != nil {
		fmt.Println("Error: failed to connect to database:", err)
	}

	stmt, err := db.Prepare("SELECT id, name, quantity, price, created_at FROM things WHERE id <> $1 AND name <> $2")
	if err != nil {
		fmt.Printf("Failed to prepare statement: %v\n", err)
	}
	defer stmt.Close()

	rows, err := stmt.Query(123, "hello world")
	if err != nil {
		fmt.Println("Error: Failed to run query:", err)
	}
	defer rows.Close()
}

func makeMysqlRequest(addr string) {
	// MySQL connection details
	dsn := fmt.Sprintf("root:root@tcp(%s)/my_database", addr)

	// Connect to the database
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}
	defer db.Close()

	// Test the connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Error pinging the database: %v", err)
	}

	fmt.Println("\n\n\n\nSuccessfully connected to the database!")

	// Query the database
	query := "SELECT id, name, quantity, price, created_at FROM things"
	rows, err := db.Query(query)
	if err != nil {
		log.Fatalf("Error executing query: %v", err)
	}
	defer rows.Close()

	// Count rows
	rowCount := 0
	for rows.Next() {
		rowCount++
	}

	// Check for errors during iteration
	if err = rows.Err(); err != nil {
		log.Fatalf("Error iterating over rows: %v", err)
	}

	fmt.Printf("Number of rows returned: %d\n", rowCount)
}

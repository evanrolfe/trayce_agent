package test

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/evanrolfe/trayce_agent/api"
	"github.com/stretchr/testify/assert"
)

const (
	reqRegex               = `^GET /\w* HTTP/1\.1`
	reqRegexHttp2          = `^GET /\d* HTTP/2`
	reqChunkRegex          = `^GET /chunked HTTP/1\.1`
	numRequestsLoad        = 100
	mega_server_image_name = "mega_server"
)

func AssertFlows(t *testing.T, flows []*api.Flow) {
	assert.Greater(t, len(flows[0].Request), 0)
	if len(flows) > 1 {
		assert.Greater(t, len(flows[1].Response), 0)
	}

	for _, flow := range flows {
		assert.Greater(t, len(flow.LocalAddr), 0)
		assert.Greater(t, len(flow.RemoteAddr), 0)

		if len(flow.Request) > 0 {
			assert.Regexp(t, regexp.MustCompile(reqRegex), string(flow.Request))
			assert.Equal(t, "tcp", flow.L4Protocol)
			assert.Equal(t, "http", flow.L7Protocol)
			fmt.Println("Request:\n", string(flow.Request))

		} else if len(flow.Response) > 0 {
			assert.GreaterOrEqual(t, len(flow.Response), 15)
			if len(flow.Response) >= 15 {
				assert.Equal(t, "HTTP/1.1 200 OK", string(flow.Response[0:15]))
				assert.Equal(t, "tcp", flow.L4Protocol)
				assert.Equal(t, "http", flow.L7Protocol)

				fmt.Println("RESPONSE:\n", string(flow.Response))
			}
		}
	}
}

func AssertFlowsHttp2(t *testing.T, flows []*api.Flow) {
	for _, flow := range flows {
		assert.Greater(t, len(flow.LocalAddr), 0)
		assert.Greater(t, len(flow.RemoteAddr), 0)

		if len(flow.Request) > 0 {
			assert.Regexp(t, regexp.MustCompile(reqRegexHttp2), string(flow.Request))
			assert.Equal(t, "tcp", flow.L4Protocol)
			assert.Equal(t, "http2", flow.L7Protocol)
		} else if len(flow.Response) > 0 {
			assert.Equal(t, "HTTP/2 200", string(flow.Response[0:10]))
			assert.Equal(t, "tcp", flow.L4Protocol)
			assert.Equal(t, "http2", flow.L7Protocol)
		}
	}
}

func AssertFlowsChunked(t *testing.T, flows []*api.Flow) {
	for _, flow := range flows {
		assert.Greater(t, len(flow.LocalAddr), 0)
		assert.Greater(t, len(flow.RemoteAddr), 0)

		if len(flow.Request) > 0 {
			assert.Regexp(t, regexp.MustCompile(reqChunkRegex), string(flow.Request))
			assert.Equal(t, "tcp", flow.L4Protocol)
			assert.Equal(t, "http", flow.L7Protocol)
		} else if len(flow.Response) > 0 {
			assert.Equal(t, "HTTP/1.1 200 OK", string(flow.Response[0:15]))
			assert.Equal(t, "tcp", flow.L4Protocol)
			assert.Equal(t, "http", flow.L7Protocol)
		}
	}
}

func AssertFlows2(t *testing.T, flows []*api.Flow) {
	assert.Equal(t, len(flows), 4)
}

func getMegaServer(t *testing.T) (string, string) {
	// Find the mega_server container
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}

	megaserverId := ""
	megaserverIp := ""
	containers, err := dockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		panic(err)
	}

	for _, container := range containers {
		if container.Image == mega_server_image_name {
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
		timeout = 5 * time.Second
	} else {
		numRequests = numRequestsLoad
		timeout = 30 * time.Second
	}

	return numRequests, numRequests * 2, timeout
}

// TODO: Make this verify that it has all the correct requests
// func hasAllFlows(flows []*api.Flow) {
// 	collectedMatches := []int{}

// 	for _, f := range flows {
// 		if f.Request == nil {
// 			continue
// 		}

// 		req := string(f.Request[0:8])
// 		pattern := `GET /(\d+)`
// 		re := regexp.MustCompile(pattern)
// 		matches := re.FindStringSubmatch(req)

// 		if len(matches) >= 2 {
// 			// The number is in the first capture group (index 1)
// 			number := matches[1]
// 			n, _ := strconv.Atoi(number)
// 			collectedMatches = append(collectedMatches, n)
// 		}
// 	}

// 	fmt.Println(collectedMatches)
// }

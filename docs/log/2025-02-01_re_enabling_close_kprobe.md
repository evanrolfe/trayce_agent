**Problem:** The load tests in CI were always failing with this same failure:
```
=== RUN   Test_agent_server
Found mega_server: 172.17.0.3 ID: f0bb83c2d91a3db8b66763749fe675336ee113ae6e9845f9dd6fbb8623fcd730
=== RUN   Test_agent_server/[Python]_Server_an_HTTP/1.1_request
Received 200
================================================
Completed 0/22
================================================
=== RUN   Test_agent_server/[Python]_Server_an_HTTP/1.1_request_to_/second_http
Received 400
================================================
Completed 5/22
================================================
=== RUN   Test_agent_server/[Ruby]_Server_an_HTTPS/1.1_request_to_/second_https
Received 400
================================================
Completed 9/22
================================================
=== RUN   Test_agent_server/[Go]_Server_an_HTTP/1.1_request_to_/second_http
    agent_server_test.go:316:
                Error Trace:    /home/circleci/project/test/agent_server_test.go:316
                Error:          Not equal:
                                expected: 400
                                actual  : 392
                Test:           Test_agent_server/[Go]_Server_an_HTTP/1.1_request_to_/second_http
================================================
Completed 14/22
================================================
=== RUN   Test_agent_server/[Go]_Server_an_HTTPS/2_request
Received 200
================================================
Completed 18/22
================================================
=== RUN   Test_agent_server/[Go]_Server_an_HTTPS/2_request_to_/second_http
Received 400
================================================
Completed 19/22
================================================
--- FAIL: Test_agent_server (102.82s)
    --- PASS: Test_agent_server/[Python]_Server_an_HTTP/1.1_request (7.35s)
    --- PASS: Test_agent_server/[Python]_Server_an_HTTP/1.1_request_to_/second_http (7.37s)
    --- PASS: Test_agent_server/[Ruby]_Server_an_HTTPS/1.1_request_to_/second_https (7.37s)
    --- FAIL: Test_agent_server/[Go]_Server_an_HTTP/1.1_request_to_/second_http (62.00s)
    --- PASS: Test_agent_server/[Go]_Server_an_HTTPS/2_request (7.35s)
    --- PASS: Test_agent_server/[Go]_Server_an_HTTPS/2_request_to_/second_http (7.37s)
FAIL
FAIL    github.com/evanrolfe/trayce_agent/test  102.834s
FAIL
```

They passed locally but I'm not sure why. The solution was to re-enable the close kprobe.

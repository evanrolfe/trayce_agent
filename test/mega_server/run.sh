rm -f /app/ror/tmp/pids/server.pid
cd /app/ror/ && ./run.sh &
cd /app/flask/ && ./run.sh &
cd /app/node && ./run.sh &
cd /app/go && ./mock_server

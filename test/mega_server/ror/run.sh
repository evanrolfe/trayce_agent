rm -f /app/ror/tmp/pids/server_3003.pid
rm -f /app/ror/tmp/pids/server_3004.pid

bin/rails s -b 'ssl://0.0.0.0:3004?key=./config/ssl/localhost.key&cert=./config/ssl/localhost.crt' --pid tmp/pids/server_3004.pid &
bin/rails s -b 0.0.0.0 -p 3003 --pid tmp/pids/server_3003.pid

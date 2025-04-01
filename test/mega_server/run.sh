cat banner.txt
current_ip=$(hostname -I | awk '{print $1}')

echo "*---------------------------------------------------------------------------*"
echo "| Go Server (http):           http://$current_ip:4122/                       |"
echo "| Go Server (https):          https://$current_ip:4123/                      |"
echo "| Go Server (grpc):           $current_ip:50051/                             |"
echo "| Python server (http):       http://$current_ip:3001/                       |"
echo "| Python server (https):      http://$current_ip:3002/                       |"
echo "| Ruby server (http):         http://$current_ip:3003/                       |"
echo "| Ruby server (https):        http://$current_ip:3004/                       |"
echo "| Postgres:                   $current_ip:5432                               |"
echo "| MySQL:                      $current_ip:3306                               |"
echo "*---------------------------------------------------------------------------*\n\n"

service postgresql start &
service mysql start &
cd /app/ror/ && ./run.sh &
cd /app/flask/ && ./run.sh &
cd /app/node && ./run.sh &
cd /app/go && ./http_server &
cd /app/go && ./grpc_server

cat banner.txt
current_ip=$(hostname -I | awk '{print $1}')

echo "*---------------------------------------------------------------------------*"
echo "| Go Server (http):           http://$current_ip:4122/                       |"
echo "| Go Server (https):          https://$current_ip:4123/                      |"
echo "| Python server (http):       http://$current_ip:3001/                       |"
echo "| Python server (https):      http://$current_ip:3002/                       |"
echo "| Ruby server (http):         http://$current_ip:3003/                       |"
echo "| Ruby server (https):        http://$current_ip:3004/                       |"
echo "*---------------------------------------------------------------------------*\n\n"

cd /app/ror/ && ./run.sh &
cd /app/flask/ && ./run.sh &
cd /app/node && ./run.sh &
cd /app/go && ./mock_server

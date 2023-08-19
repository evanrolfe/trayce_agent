import requests

resp1 = requests.get('https://api.github.com')
print(f"status1 : {resp1.status_code}")

# resp2 = requests.get('https://pntest.io')
# print(f"status2 : {resp2.status_code}")
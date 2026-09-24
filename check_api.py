import urllib.request, json
req = urllib.request.Request('http://127.0.0.1:8000/auth/login', data=b'{"userid": "10", "password": "123"}', headers={'Content-Type': 'application/json'})
token = json.loads(urllib.request.urlopen(req).read().decode())['token']
req2 = urllib.request.Request('http://127.0.0.1:8000/auth/employees', headers={'Authorization': 'Bearer ' + token})
print([u['id'] for u in json.loads(urllib.request.urlopen(req2).read().decode())])

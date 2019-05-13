import requests
payload = {'flag': '2d00c696765ee44e54225a43b18126160b278ba99a45a58681444a02d01933881cb35ea63cd64837fa70dc3b77bef33181289de11317f3a5d8350b2c150c14f8'}
r = requests.post("http://165.22.71.82:8083/getflag", data=payload)
print(r.status_code)
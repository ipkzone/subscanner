# (c) Ferry Kirdan Austin
# Subdomain Scanner / Team Pencari Proxy TPP
# Regard's New Phreaker Ababil

import requests

url = "https://api.securitytrails.com/v1/domain/telkomsel.com/subdomains"
querystring = {"apikey":"fZtaC7q0R95KyqKBhfpC7MVb6hGT4sUm"}
response = requests.request("GET", url, params=querystring)
print(response.text)

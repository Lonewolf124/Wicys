import requests

jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
response = requests.get(jwks_uri)

if response.status_code == 200:
    print("JWKS fetched successfully:", response.json())
else:
    print("Failed to fetch JWKS, status code:", response.status_code)

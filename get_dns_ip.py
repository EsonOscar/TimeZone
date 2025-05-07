import requests
import time

#Dumbass godaddy fucked the API access, switching to cloudflare

#PROD
api_key = 'h1oro6M9e2EK_MFtgDJrofW48RYfhSEChzd'
api_secret = "Bz4qqX9auXNKhiRt1ea3gv"

#OTE
#pi_key = '3mM44Ywf1DXPmr_PoFR81oC4w7ayhyt4iGTYR'
#api_secret = "RnRLudn8VynnA1wykJaJUq"

domain = 'hvalfangerne.com'
record_type = 'A'
record_name = '@'

headers = {
    "Authorization": f"sso-key {api_key}:{api_secret}",
    "Content-Type": "application/json"
}

def get_current_dns_ip():
    url = f"https://api.godaddy.com/v1/domains/{domain}/records/{record_type}/{record_name}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        records = response.json()
        if records:
            return records[0]['data']
    print(response.status_code, response.text)
    return None

print(get_current_dns_ip())
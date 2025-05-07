import requests
import time

def get_public_ip():
    # List of services to get the public IP address. Add or remove services as needed.
    services = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip"
    ]
    for service in services:
        try:
            response = requests.get(service, timeout=5)  # Added a timeout for the request
            if response.status_code == 200:
                return response.text.strip()
            else:
                print(f"Error: Received status code {response.status_code} from {service}")
        except requests.RequestException as e:
            print(f"Error fetching public IP address from {service}: {e}")
    return None

print(get_public_ip())
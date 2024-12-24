import requests
from colorama import init, Fore, Back, Style
from tabulate import tabulate
import json

# Initialize colorama
init(autoreset=True)

# ASCII Logo
logo = """


       _                        _                                   
    ___FJ     ___ _    _ ___   FJ __      ____    _    _     ____   
   F __  L   F __` L  J '__ ",J |/ /L    F __ J  J |  | L   F __ J  
  | |--| |  | |--| |  | |__|-J|    \    | _____J | |  | |  | _____J 
  F L__J J  F L__J J  F L  `-'F L:\ J   F L___--.F L__J J  F L___--.
 J\____,__LJ\____,__LJ__L    J__L \_J.J\______/F)-____  LJ\______/F
  J____,__F J____,__F|__L    |__L  \L_| J______FJ\______/F J______F 
                                                 J______F           Code by Vecert / Threat Intelligence / vecert.io
                                                 
                                                 
|  Threat Intelligence  |  |     Passwords Leaks     |  |      Computers         |  |      Mentions          |                                                 

"""

print(Fore.GREEN + Back.BLACK + logo)

def get_asset_id(url):
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "Cookie": '__jsluid_s=b1ab69c55f648ec8067416c032051898; _ga=GA1.1.589433742.1735065866; ASSETS="gASVQAAAAAAAAAB9lIwEdXVpZJSMBFVVSUSUk5QpgZR9lIwDaW50lIoQT+6tIzu0UbmwSQVbq/nFfXNijApjbmUuZ29iLnZllHMu"; _ga_4W9GPBYZ2H=GS1.1.1735065866.1.1.1735066247.0.0.0',
        "Origin": "https://darkeye.org",
        "Pragma": "no-cache",
        "Referer": "https://darkeye.org/search",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Linux; Android) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.109 Safari/537.36 CrKey/1.54.248666",
        "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Android"'
    }

    data = [{"value": url}]

    response = requests.post("https://darkeye.org/api/assets/assets/", headers=headers, json=data)
    if response.status_code in [200, 201]:
        response_data = response.json()
        return response_data[0]['id'] if response_data else None
    else:
        print(f"{Fore.RED}Error: {response.status_code}")
        return None

def query_endpoints(asset_id):
    base_url = "https://darkeye.org/api"
    endpoints = [
        f"/i/employee_credential_leak/?asset_id={asset_id}",
        f"/i/controlled_system/?asset_id={asset_id}",
        f"/assets/assets/{asset_id}/",
        f"/i/darkweb_mention/?asset_id={asset_id}",
        f"/i/attack_surface_exposure/?asset_id={asset_id}",
        f"/i/user_credential_leak/?asset_id={asset_id}"
    ]

    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0"
    }

    for endpoint in endpoints:
        url = f"{base_url}{endpoint}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            print(Style.BRIGHT + Fore.GREEN + Back.BLACK + f"Response from {endpoint}:")
            if "darkweb_mention" in endpoint or "employee_credential_leak" in endpoint:
                # Directly print the response for these endpoints without organizing
                print(json.dumps(data, indent=2))
            elif isinstance(data, dict) and 'list' in data:
                if data['list']:
                    render_table(data['list'], endpoint)
                else:
                    print(Fore.YELLOW + "No data available for this endpoint.")
            elif isinstance(data, dict):
                render_single(data, endpoint)
            else:
                print(data)
        else:
            print(f"{Fore.RED}Error fetching {endpoint}: {response.status_code}")

def render_table(data, endpoint):
    if not data:
        print(Fore.YELLOW + "No data available")
        return

    # Define headers and keys based on the endpoint
    if "controlled_system" in endpoint:
        headers = ["ID", "User", "IP", "Leak Time"]
        keys = ["id", "computer_user", "victim_ip", "leak_time"]
    elif "attack_surface_exposure" in endpoint:
        headers = ["ID", "IP", "Service", "Site", "Timestamp"]
        keys = ["id", "ip", "service", "site", "timestamp"]
    else:
        headers = data[0].keys()
        keys = headers

    # Convert data to list of lists
    table_data = [[item.get(key, "N/A") for key in keys] for item in data]
    
    # Create and print table with colors
    colored_table = Fore.GREEN + Back.BLACK + tabulate(table_data, headers, tablefmt="grid", stralign="center", numalign="center")
    print(colored_table)

def render_single(data, endpoint):
    if "assets/assets" in endpoint:
        # For single asset data
        headers = ["Field", "Value"]
        table_data = []
        for key, value in data.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    table_data.append([f"{key}.{sub_key}", sub_value])
            else:
                table_data.append([key, value])
        colored_table = Fore.GREEN + Back.BLACK + tabulate(table_data, headers, tablefmt="grid", stralign="center", numalign="center")
        print(colored_table)

def main():
    url = input("Enter a URL (e.g., nasa.gov): ")
    asset_id = get_asset_id(url)
    if asset_id:
        print(Fore.YELLOW + "Asset ID obtained: " + asset_id)
        query_endpoints(asset_id)
    else:
        print(Fore.RED + "Could not obtain the Asset ID.")

if __name__ == "__main__":
    main()

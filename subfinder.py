import requests
import sys

API_KEY = "e7855c8a4ffa13c9cbf5218506897995eb3544e90a29825d2a9b7714cf26f350"   # अपना VirusTotal API key यहाँ डालो

def find_subdomains_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "data" in data:
                return [item["id"] for item in data["data"]]
            else:
                print("No subdomains found (or API limit reached).")
                return []
        else:
            print("VirusTotal API error:", response.status_code, response.text[:200])
            return []
    except Exception as e:
        print("Connection error:", e)
        return []

def is_url_live(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return 200 <= response.status_code < 400
    except:
        return False

def main():
    print("✅ VirusTotal Subdomain Finder + Live Checker\n")

    while True:
        domain = input("Enter domain (without https://): ").strip().lower()
        if not domain:
            print("Exiting...")
            break
        if "." not in domain or "http" in domain:
            print("Invalid format. Enter like 'example.com'.\n")
            continue

        print(f"\n🔍 Fetching subdomains from VirusTotal for {domain} ...\n")
        subdomains = find_subdomains_virustotal(domain)

        if not subdomains:
            print("No subdomains to check.\n")
            print("-" * 60)
            continue

        print(f"\n📋 Checking live status of {len(subdomains)} subdomains:\n")
        for sub in subdomains:
            full_url = f"https://{sub}"
            if is_url_live(full_url):
                print(f"\033[92m✅ LIVE:\033[0m {full_url}")
            else:
                print(f"\033[91m❌ OFFLINE:\033[0m {full_url}")

        print("\n" + "-" * 60)

if __name__ == "__main__":
    main()


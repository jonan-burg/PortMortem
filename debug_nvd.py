import requests

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# try broader search first — just the product name, no version
params = {
    "keywordSearch": "dnsmasq",
    "resultsPerPage": 3,
}

response = requests.get(url, params=params, timeout=10)
print("Status code:", response.status_code)
data = response.json()
print("Total results:", data.get("totalResults"))
print("Vulnerabilities returned:", len(data.get("vulnerabilities", [])))

# print first CVE id if any
for v in data.get("vulnerabilities", []):
    print(" -", v["cve"]["id"])
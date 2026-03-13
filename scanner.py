import nmap
import json

def run_scan(target: str) -> list[dict]:
    """
    Runs an Nmap scan on the target and returns
    a list of services with port/name/version info.
    """
    print(f"[*] Starting Nmap scan on: {target}")

    nm = nmap.PortScanner()

    # -sV = version detection, -T4 = faster scan, --open = only open ports
    nm.scan(hosts=target, arguments="-sV -T4 --open")

    results = []

    for host in nm.all_hosts():
        print(f"[+] Host found: {host} ({nm[host].hostname()})")

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()

            for port in ports:
                service_info = nm[host][proto][port]

                entry = {
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "state": service_info["state"],
                    "service": service_info["name"],
                    "product": service_info.get("product", ""),
                    "version": service_info.get("version", ""),
                    "extrainfo": service_info.get("extrainfo", ""),
                }
                results.append(entry)
                print(f"    Port {port}/{proto}: {entry['service']} "
                      f"{entry['product']} {entry['version']}")

    return results


if __name__ == "__main__":
    # Quick test — scan your own machine
    data = run_scan("10.22.95.247")
    print("\n--- Raw Results ---")
    print(json.dumps(data, indent=2))
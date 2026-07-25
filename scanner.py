"""
Basic Nmap Scanner Module
Scans a target for open ports and service versions.
"""
import nmap

def scan_target(target, ports="1-1024"):
    """
    Scans the given target for open ports and service/version info.
    
    Args:
        target (str): IP address, domain, or range (e.g. 192.168.1.10)
        ports (str): Port range to scan (default: 1-1024)
    
    Returns:
        dict: scan results per host
    """
    nm = nmap.PortScanner()
    print(f"[*] Scanning {target} on ports {ports} ...")
    
    # -sV = service/version detection
    nm.scan(hosts=target, ports=ports, arguments="-sV")
    
    results = {}
    
    for host in nm.all_hosts():
        results[host] = {
            "state": nm[host].state(),
            "services": []
        }
        for proto in nm[host].all_protocols():
            ports_list = nm[host][proto].keys()
            for port in ports_list:
                service_info = nm[host][proto][port]
                results[host]["services"].append({
                    "port": port,
                    "protocol": proto,
                    "service": service_info.get("name", ""),
                    "product": service_info.get("product", ""),
                    "version": service_info.get("version", ""),
                    "state": service_info.get("state", "")
                })
    
    return results


if __name__ == "__main__":
    target = input("Enter target IP/domain: ")
    data = scan_target(target)
    
    for host, info in data.items():
        print(f"\nHost: {host} ({info['state']})")
        for svc in info["services"]:
            print(f"  Port {svc['port']}/{svc['protocol']} - {svc['service']} "
                  f"{svc['product']} {svc['version']} [{svc['state']}]")

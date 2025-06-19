import socket
import requests
import concurrent.futures
import ipaddress
import whois
import dns.resolver
from datetime import datetime

def get_ip_info(ip):
    """Get information about an IP address"""
    try:
        # Basic IP information
        ip_obj = ipaddress.ip_address(ip)
        is_private = ip_obj.is_private
        
        # Reverse DNS lookup
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
        except socket.herror:
            hostname = "Not found"
        
        # WHOIS information
        whois_info = {}
        if not is_private:
            try:
                w = whois.whois(ip)
                whois_info = {
                    'registrar': w.registrar,
                    'creation_date': w.creation_date,
                    'updated_date': w.updated_date,
                    'expiration_date': w.expiration_date,
                    'country': w.country,
                    'org': w.org
                }
            except Exception as e:
                whois_info = {'error': str(e)}
        
        # DNS records (if hostname exists)
        dns_records = {}
        if hostname != "Not found" and not is_private:
            try:
                resolver = dns.resolver.Resolver()
                # Query common DNS records
                for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']:
                    try:
                        answers = resolver.resolve(hostname, record_type)
                        dns_records[record_type] = [str(r) for r in answers]
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        pass
            except Exception as e:
                dns_records = {'error': str(e)}
        
        # GeoIP information (using free API)
        geo_info = {}
        if not is_private:
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
                geo_info = response.json()
            except Exception as e:
                geo_info = {'error': str(e)}
        
        return {
            'ip': ip,
            'hostname': hostname,
            'is_private': is_private,
            'whois': whois_info,
            'dns': dns_records,
            'geo': geo_info
        }
    except Exception as e:
        return {'ip': ip, 'error': str(e)}

def scan_port(ip, port, timeout=1):
    """Check if a port is open on the given IP"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return port if result == 0 else None
    except Exception:
        return None

def scan_ports(ip, ports=None, max_workers=100):
    """Scan multiple ports on an IP address"""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            result = future.result()
            if result is not None:
                open_ports.append(result)
    
    return sorted(open_ports)

def scan_ip_range(ip_range, port_scan=False):
    """Scan a range of IP addresses"""
    results = []
    
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        print(f"Scanning {network.num_addresses} IP addresses...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(get_ip_info, str(ip)): ip for ip in network.hosts()}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    
                    if port_scan and not result.get('is_private', True):
                        open_ports = scan_ports(result['ip'])
                        if open_ports:
                            result['open_ports'] = open_ports
                    
                    results.append(result)
                    print(f"Scanned {result['ip']} - Hostname: {result.get('hostname', 'N/A')}")
                except Exception as e:
                    print(f"Error processing {ip}: {str(e)}")
    
    except ValueError as e:
        print(f"Invalid IP range: {str(e)}")
    
    return results

def save_results(results, filename=None):
    """Save scan results to a file"""
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        for result in results:
            f.write(f"\nIP: {result['ip']}\n")
            f.write(f"Hostname: {result.get('hostname', 'N/A')}\n")
            f.write(f"Private: {'Yes' if result.get('is_private', False) else 'No'}\n")
            
            if 'open_ports' in result:
                f.write(f"Open Ports: {', '.join(map(str, result['open_ports']))}\n")
            
            if 'whois' in result:
                f.write("\nWHOIS Information:\n")
                for key, value in result['whois'].items():
                    f.write(f"  {key}: {value}\n")
            
            if 'geo' in result:
                f.write("\nGeolocation Information:\n")
                for key, value in result['geo'].items():
                    f.write(f"  {key}: {value}\n")
            
            if 'dns' in result:
                f.write("\nDNS Records:\n")
                for record_type, records in result['dns'].items():
                    f.write(f"  {record_type}: {', '.join(records)}\n")
            
            f.write("\n" + "="*50 + "\n")
    
    print(f"\nResults saved to {filename}")

def main():
    print("IP Scanner and Information Gathering Tool")
    print("="*50 + "\n")
    
    target = input("Enter IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24): ").strip()
    port_scan = input("Perform port scanning? (y/n): ").lower() == 'y'
    
    print("\nStarting scan...\n")
    
    # Check if input is a single IP or a range
    if '/' in target:
        results = scan_ip_range(target, port_scan)
    else:
        results = [get_ip_info(target)]
        if port_scan and not results[0].get('is_private', True):
            open_ports = scan_ports(results[0]['ip'])
            if open_ports:
                results[0]['open_ports'] = open_ports
    
    save_results(results)

if __name__ == "__main__":
    main()
import nmap

scanner = nmap.PortScanner()

print("\n\n************************")
print("Nmap AUTOMATION TOOL")
print("************************\n")

ip_address = input("Enter IP address to scan: ")

respond = input("""\nEnter a number for the type of scan you want to run->
                    1. SYN ACK Scan
                    2. UDP Scan
                    3. Comprehensive Scan\n""")
print("The option you picked:", respond)

try:
    if respond == '1':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_address, '1-1024', '-v -sS')
    
    elif respond == '2':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_address, '1-1024', '-v -sU')
    
    elif respond == '3':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_address, '1-1024', '-sS -sV -sC -A -O')
    
    else:
        print("Invalid Option")
        exit()

    print(scanner.scaninfo())
    print("Status: ", scanner[ip_address].state())
    all_protocols = scanner[ip_address].all_protocols()
    print("Protocols: ", all_protocols)

    if 'tcp' in all_protocols:
        print("Open TCP Ports: ", scanner[ip_address]['tcp'].keys())
    
    if 'udp' in all_protocols:
        print("Open UDP Ports: ", scanner[ip_address]['udp'].keys())
        
except Exception as e:
    print(f"An error occurred: {e}")
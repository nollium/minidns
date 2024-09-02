from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, CNAME, dns
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR

def dns_server(hostname_mapping: dict[str, str], port: int = 53) -> None:
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))

    # Normalize keys in the hostname_mapping dictionary to lowercase
    normalized_mapping = {k.lower(): v for k, v in hostname_mapping.items()}

    resolved_value = None
    n = 0
    try:
        while True:
            data, addr = server_socket.recvfrom(512)
            request = DNSRecord.parse(data)

            response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

            qname = str(request.q.qname)
            qtype = request.q.qtype

            if qname.endswith('.'):
                qname = qname[:-1]

            # Convert the queried name to lowercase for case-insensitive comparison
            qname_lower = qname.lower()

            if qname_lower in normalized_mapping:
                resolved_value = normalized_mapping[qname_lower]

                if qtype == QTYPE.A:
                    # Check if resolved_value is an IP, otherwise it's an error in mapping
                    if is_valid_ip(resolved_value):
                        response.add_answer(RR(qname, QTYPE.A, rdata=A(resolved_value), ttl=60))
                elif qtype == QTYPE.CNAME or (not is_valid_ip(resolved_value)):
                    # Add a CNAME record if the query type is CNAME or if it's not a valid IP (assuming it's a CNAME by default)
                    response.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(resolved_value), ttl=60))

            print("Request from", addr , ":", qname, "->", resolved_value)
            server_socket.sendto(response.pack(), addr)

    except KeyboardInterrupt:
        server_socket.close()

def is_valid_ip(ip: str) -> bool:
    """Check if the string is a valid IPv4 address."""
    try:
        return tuple(map(int, ip.split("."))) and len(ip.split(".")) == 4
    except ValueError:
        return False

if __name__ == "__main__":
    # Example hostname to IP/CNAME mapping
    mapping = {
        "example.com": "169.254.169.254",  # A record
        "www.example.com": "example.com",  # CNAME record
    }

    dns_server(mapping)


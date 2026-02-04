#!/usr/bin/env python3
"""
List all clients connected to a Qumulo cluster.

Usage:
    python list_clients.py -c cluster.example.com                # Basic usage
    python list_clients.py -c cluster.example.com -j             # JSON output
    python list_clients.py -c cluster.example.com -d 10.0.0.1    # With DNS lookup
    python list_clients.py -c cluster.example.com -f /path/creds # Custom credentials
    python list_clients.py -c cluster.example.com --show-next-best-nodes  # Show least loaded nodes
    python list_clients.py -c cluster.example.com --show-next-best-nodes --exclude-list exclude.txt
"""

import argparse
import json
import socket
import ssl
import struct
import urllib.request
from pathlib import Path


# Configuration
PORT = 8000


def load_token(cred_file):
    """Load bearer token from credentials file."""
    with open(cred_file) as f:
        return json.load(f)['bearer_token']


def make_request(cluster, endpoint, cred_file):
    """Make API request to Qumulo cluster."""
    url = f"https://{cluster}:{PORT}{endpoint}"
    headers = {
        'Authorization': f'Bearer {load_token(cred_file)}',
        'accept': 'application/json'
    }

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers=headers)

    with urllib.request.urlopen(req, context=ssl_context) as response:
        return json.loads(response.read())


def reverse_dns_lookup(ip, dns_server, timeout=2):
    """
    Perform reverse DNS lookup using a specific DNS server.

    Args:
        ip: IP address to look up
        dns_server: DNS server to query
        timeout: Query timeout in seconds

    Returns:
        Hostname if found, None otherwise
    """
    try:
        # Build reverse DNS query (PTR record)
        # Convert IP to reverse format (e.g., 1.2.3.4 -> 4.3.2.1.in-addr.arpa)
        reversed_ip = '.'.join(reversed(ip.split('.')))
        query_name = f"{reversed_ip}.in-addr.arpa"

        # Build DNS query packet
        # Transaction ID (2 bytes) + Flags (2 bytes) + Questions (2 bytes) +
        # Answer RRs (2 bytes) + Authority RRs (2 bytes) + Additional RRs (2 bytes)
        transaction_id = 0x1234
        flags = 0x0100  # Standard query with recursion desired
        questions = 1

        header = struct.pack('>HHHHHH', transaction_id, flags, questions, 0, 0, 0)

        # Build question section
        question = b''
        for label in query_name.split('.'):
            question += bytes([len(label)]) + label.encode()
        question += b'\x00'  # Null terminator
        question += struct.pack('>HH', 12, 1)  # Type PTR (12), Class IN (1)

        query = header + question

        # Send UDP query to DNS server
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (dns_server, 53))

        # Receive response
        response, _ = sock.recvfrom(512)
        sock.close()

        # Parse response - skip header (12 bytes) and question section
        # Find the answer section
        pos = 12
        # Skip question section
        while response[pos] != 0:
            pos += response[pos] + 1
        pos += 5  # Skip null byte + QTYPE (2) + QCLASS (2)

        # Check if we have answers
        answer_count = struct.unpack('>H', response[6:8])[0]
        if answer_count == 0:
            return None

        # Parse answer - skip name pointer (2 bytes), type (2), class (2), TTL (4), rdlength (2)
        pos += 2 + 2 + 2 + 4
        rdlength = struct.unpack('>H', response[pos:pos+2])[0]
        pos += 2

        # Parse PTR record (domain name)
        hostname = []
        end_pos = pos + rdlength
        while pos < end_pos and response[pos] != 0:
            if response[pos] >= 192:  # Compression pointer
                ptr_offset = struct.unpack('>H', response[pos:pos+2])[0] & 0x3FFF
                # Follow pointer and read name
                while response[ptr_offset] != 0:
                    label_len = response[ptr_offset]
                    hostname.append(response[ptr_offset+1:ptr_offset+1+label_len].decode())
                    ptr_offset += label_len + 1
                break
            else:
                label_len = response[pos]
                hostname.append(response[pos+1:pos+1+label_len].decode())
                pos += label_len + 1

        return '.'.join(hostname) if hostname else None

    except Exception:
        return None


def load_exclude_list(exclude_file):
    """
    Load list of IPs to exclude from a file.

    Args:
        exclude_file: Path to file containing one IP per line

    Returns:
        Set of IP addresses to exclude
    """
    if not exclude_file:
        return set()

    exclude_ips = set()
    with open(exclude_file) as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                exclude_ips.add(line)

    return exclude_ips


def get_node_connections(cluster, cred_file, exclude_ips=None):
    """
    Get connection data organized by node.

    Args:
        cluster: Qumulo cluster hostname
        cred_file: Path to credentials file
        exclude_ips: Set of IPs to exclude from counts

    Returns:
        Dictionary of nodes with their connection info
    """
    if exclude_ips is None:
        exclude_ips = set()

    data = make_request(cluster, '/v2/network/connections/', cred_file)

    nodes = {}
    for node in data:
        node_id = node.get('id')
        nodes[node_id] = {
            'total_connections': 0,
            'filtered_connections': 0,
            'clients': set(),
            'filtered_clients': set(),
            'protocols': set()
        }

        for conn in node.get('connections', []):
            ip = conn.get('network_address', 'unknown')
            conn_type = conn.get('type', 'unknown')

            # Skip localhost connections (internal)
            if ip == '127.0.0.1':
                continue

            protocol = conn_type.replace('CONNECTION_TYPE_', '')

            nodes[node_id]['total_connections'] += 1
            nodes[node_id]['clients'].add(ip)
            nodes[node_id]['protocols'].add(protocol)

            # Count connections not in exclude list
            if ip not in exclude_ips:
                nodes[node_id]['filtered_connections'] += 1
                nodes[node_id]['filtered_clients'].add(ip)

    return nodes


def get_connected_clients(cluster, cred_file, dns_server=None):
    """
    Get all connected clients.

    Args:
        cluster: Qumulo cluster hostname
        cred_file: Path to credentials file
        dns_server: Optional DNS server for reverse lookups

    Returns:
        Dictionary of clients with their connection info
    """
    data = make_request(cluster, '/v2/network/connections/', cred_file)

    # Collect unique clients
    clients = {}
    for node in data:
        node_id = node.get('id')
        for conn in node.get('connections', []):
            ip = conn.get('network_address', 'unknown')
            conn_type = conn.get('type', 'unknown')

            # Skip localhost connections (internal)
            if ip == '127.0.0.1':
                continue

            # Normalize connection type for display
            protocol = conn_type.replace('CONNECTION_TYPE_', '')

            if ip not in clients:
                clients[ip] = {
                    'protocols': set(),
                    'nodes': set(),
                    'connection_count': 0,
                    'hostname': None
                }

            clients[ip]['protocols'].add(protocol)
            clients[ip]['nodes'].add(node_id)
            clients[ip]['connection_count'] += 1

    # Perform reverse DNS lookups if requested
    if dns_server:
        for ip in clients:
            hostname = reverse_dns_lookup(ip, dns_server)
            clients[ip]['hostname'] = hostname

    return clients


def output_json(cluster, clients):
    """Output clients as JSON."""
    # Convert sets to lists for JSON serialization
    output = []
    for ip, info in sorted(clients.items()):
        output.append({
            'ip': ip,
            'hostname': info['hostname'],
            'protocols': sorted(info['protocols']),
            'connection_count': info['connection_count'],
            'nodes': sorted(info['nodes'])
        })

    print(json.dumps({
        'cluster': cluster,
        'total_clients': len(clients),
        'total_connections': sum(c['connection_count'] for c in clients.values()),
        'clients': output
    }, indent=2))


def output_next_best_nodes(cluster, nodes, exclude_ips, as_json=False):
    """
    Output nodes sorted by connection count, excluding nodes with clients in exclude list.

    Args:
        cluster: Qumulo cluster hostname
        nodes: Dictionary of node connection data
        exclude_ips: Set of excluded IPs
        as_json: Output as JSON if True
    """
    # Filter out nodes that have ANY client in the exclude list
    # Then sort remaining nodes by total connection count (ascending)
    available_nodes = [
        (node_id, info) for node_id, info in nodes.items()
        if not (info['clients'] & exclude_ips)  # No overlap with exclude list
    ]
    available_nodes.sort(key=lambda x: x[1]['total_connections'])

    if as_json:
        output = [
            {'node_id': node_id, 'connections': info['total_connections']}
            for node_id, info in available_nodes
        ]
        print(json.dumps({
            'cluster': cluster,
            'next_best_nodes': output
        }, indent=2))
    else:
        if available_nodes:
            print(f"{'Node':<8} {'Connections'}")
            print("-" * 20)
            for node_id, info in available_nodes:
                print(f"{node_id:<8} {info['total_connections']}")
        else:
            print("No available nodes (all nodes have clients in exclude list)")


def output_table(cluster, clients):
    """Output clients as a formatted table."""
    has_hostnames = any(c['hostname'] for c in clients.values())

    if has_hostnames:
        print(f"Connected Clients to {cluster}")
        print("=" * 100)
        print(f"{'Client IP':<18} {'Hostname':<30} {'Protocols':<15} {'Conns':<6} {'Nodes'}")
        print("-" * 100)

        for ip, info in sorted(clients.items()):
            protocols = ', '.join(sorted(info['protocols']))
            nodes = ', '.join(str(n) for n in sorted(info['nodes']))
            hostname = info['hostname'] or '-'
            if len(hostname) > 28:
                hostname = hostname[:25] + '...'
            print(f"{ip:<18} {hostname:<30} {protocols:<15} {info['connection_count']:<6} {nodes}")
    else:
        print(f"Connected Clients to {cluster}")
        print("=" * 70)
        print(f"{'Client IP':<20} {'Protocols':<20} {'Connections':<12} {'Nodes'}")
        print("-" * 70)

        for ip, info in sorted(clients.items()):
            protocols = ', '.join(sorted(info['protocols']))
            nodes = ', '.join(str(n) for n in sorted(info['nodes']))
            print(f"{ip:<20} {protocols:<20} {info['connection_count']:<12} {nodes}")

    print("-" * (100 if has_hostnames else 70))
    print(f"Total unique clients: {len(clients)}")
    print(f"Total connections: {sum(c['connection_count'] for c in clients.values())}")


def main():
    default_creds = Path.home() / '.qfsd_cred'

    parser = argparse.ArgumentParser(
        description='List all clients connected to a Qumulo cluster.'
    )
    parser.add_argument(
        '-c', '--cluster',
        metavar='HOSTNAME',
        required=True,
        help='Qumulo cluster hostname or IP'
    )
    parser.add_argument(
        '-f', '--credentials',
        metavar='FILE',
        default=default_creds,
        type=Path,
        help=f'Path to credentials file (default: {default_creds})'
    )
    parser.add_argument(
        '-j', '--json',
        action='store_true',
        help='Output in JSON format'
    )
    parser.add_argument(
        '-d', '--dns-server',
        metavar='SERVER',
        help='DNS server to use for reverse lookups'
    )
    parser.add_argument(
        '--show-next-best-nodes',
        action='store_true',
        help='Show nodes sorted by connection count (least loaded first)'
    )
    parser.add_argument(
        '--exclude-list',
        metavar='FILE',
        type=Path,
        help='File containing IPs to exclude from connection counts (one per line)'
    )

    args = parser.parse_args()

    if args.show_next_best_nodes:
        exclude_ips = load_exclude_list(args.exclude_list)
        nodes = get_node_connections(args.cluster, args.credentials, exclude_ips)
        output_next_best_nodes(args.cluster, nodes, exclude_ips, as_json=args.json)
    else:
        clients = get_connected_clients(args.cluster, args.credentials, dns_server=args.dns_server)
        if args.json:
            output_json(args.cluster, clients)
        else:
            output_table(args.cluster, clients)


if __name__ == "__main__":
    main()

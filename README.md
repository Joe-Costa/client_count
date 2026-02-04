# Qumulo Client List

List clients connected to a Qumulo cluster and find optimal nodes for new connections.

## Requirements

- Python 3.6+
- Qumulo cluster credentials (default: `~/.qfsd_cred`)

## Usage

```bash
# List all connected clients
python list_clients.py -c <cluster>

# JSON output
python list_clients.py -c <cluster> --json

# With reverse DNS lookup
python list_clients.py -c <cluster> -d <dns-server>

# Find best nodes for new connections (least loaded first)
python list_clients.py -c <cluster> --show-next-best-nodes

# Find best nodes, excluding nodes with specific clients
python list_clients.py -c <cluster> --show-next-best-nodes --exclude-list <file>
```

## Options

| Option | Description |
|--------|-------------|
| `-c, --cluster` | Qumulo cluster hostname (required) |
| `-f, --credentials` | Path to credentials file (default: `~/.qfsd_cred`) |
| `-j, --json` | Output in JSON format |
| `-d, --dns-server` | DNS server for reverse lookups |
| `--show-next-best-nodes` | Show nodes sorted by connection count |
| `--exclude-list` | File with IPs to exclude (one per line) |

## Examples

### List connected clients
```bash
$ python list_clients.py -c music.eng.qumulo.com

Client IP            Protocols            Connections  Nodes
----------------------------------------------------------------------
10.102.0.46          REST                 1            6
10.102.0.72          NFS                  2            6
10.220.1.60          SMB                  1            6
----------------------------------------------------------------------
Total unique clients: 20
Total connections: 30
```

### Find best nodes for new connections
```bash
$ python list_clients.py -c music.eng.qumulo.com --show-next-best-nodes

Node     Connections
--------------------
3        4
4        4
5        5
6        8
```

### Exclude nodes with specific clients
```bash
$ cat exclude_list.txt
10.220.150.148

$ python list_clients.py -c music.eng.qumulo.com --show-next-best-nodes --exclude-list exclude_list.txt

Node     Connections
--------------------
4        4
5        5
6        8
```

Node 3 is excluded because it has a client (10.220.150.148) in the exclude list.

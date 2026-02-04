# Qumulo Client Connection List Tool

List clients connected to a Qumulo cluster and find optimal nodes for new connections.

## Requirements

- Python 3.6+
- Qumulo cluster credentials (default: `~/.qfsd_cred`)

## Credential file format

The format is the same as the `.qfsd_cred` format created by `qq --host cluster login -u user`

`{"bearer_token": "session-v1:foo_bar_baz_boop_bap_bop", "version": 1}`

## RBAC privileges required 

The only privilege required is `PRIVILEGE_NETWORK_READ`

## Helpful Qumulo Care Articles:

[How to get an Access Token](https://docs.qumulo.com/administrator-guide/connecting-to-external-services/creating-using-access-tokens-to-authenticate-external-services-qumulo-core.html) 

[Qumulo Role Based Access Control](https://care.qumulo.com/hc/en-us/articles/360036591633-Role-Based-Access-Control-RBAC-with-Qumulo-Core#managing-roles-by-using-the-web-ui-0-7)

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
## Exclude List

The exclude list is a new line separated list of IPs, any nodes that have a conenction from one of those IPs will be excluded from the output of the tool 
when the option `--exclude-list` is used.<br>
One possible use of this function would be to help automate connections of demanding, high performance clients that should not share a node with other high performance clients.
<br>
Review the file `exclude_list.txt` for a sample

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

### List connected clients ( Add `-j` for JSON output )
```bash
$ python list_clients.py -c myqumulo.company.com

Client IP            Protocols            Connections  Nodes
----------------------------------------------------------------------
10.102.0.46          REST                 1            6
10.102.0.72          NFS                  2            6
10.220.1.60          SMB                  1            6
----------------------------------------------------------------------
Total unique clients: 20
Total connections: 30
```

### Find best nodes for new connections ( Add `-j` for JSON output )
```bash
$ python list_clients.py -c myqumulo.company.com --show-next-best-nodes

Node     Connections
--------------------
3        4
4        4
5        5
6        8
```

### Exclude nodes with specific clients ( Add `-j` for JSON output )
```bash
$ cat exclude_list.txt
10.220.150.148

$ python list_clients.py -c myqumulo.company.com --show-next-best-nodes --exclude-list exclude_list.txt

Node     Connections
--------------------
4        4
5        5
6        8
```

Node 3 is excluded because it has a client (10.220.150.148) in the exclude list.

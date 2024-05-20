# dhcpd leases viewer

**WIP.**  
A simple HTTP server that serves up HTML pages containing the current leases of
the `isc-dhcpd` DHCP server.


## Configuration

The following environment variables can be defined to overwrite default
behaviour:
```bash
BIND_ADDR="0.0.0.0:80" # The socket address that the HTTP server binds to
LEASES_FILE="/var/db/dhcpd/dhcpd.leases" # The dhcpd.leases file location
```

# OpenThread CLI - SRP Server

## Quick Start

See [README_SRP_CLIENT.md](README_SRP_CLIENT.md).

## Command List

- [help](#help)
- [disable](#disable)
- [enable](#enable)
- [host](#host)
- [lease](#lease)
- [service](#service)

## Command Details

### help

Usage: `srpserver help`

Print SRP server help menu.

```bash
> srpserver help
disable
enable
help
host
lease
service
Done
```

### disable

Usage: `srpserver disable`

Disable the SRP server.

```bash
> srpserver disable
Done
```

### enable

Usage: `srpserver enable`

Enable the SRP server.

```bash
> srpserver enable
Done
```

### host

Usage: `srpserver host`

Print information of all registered hosts.

```bash
> srpserver host
srp-api-test-1.default.service.arpa.
    addresses: fdde:ad00:beef:0:0:ff:fe00:fc10
srp-api-test-0.default.service.arpa.
    addresses: fdde:ad00:beef:0:0:ff:fe00:fc10
Done
```

### srpserver service

Usage: `srpserver service`

Print information of all registered services.

```bash
> srpserver service
srp-api-test-1._ipps._tcp.default.service.arpa.
    host: srp-api-test-1.default.service.arpa.
    port: 49152
    addresses: fdde:ad00:beef:0:0:ff:fe00:fc10
    txt: 0130
srp-api-test-0._ipps._tcp.default.service.arpa.
    host: srp-api-test-0.default.service.arpa.
    port: 49152
    addresses: fdde:ad00:beef:0:0:ff:fe00:fc10
    txt: 0130
Done
```

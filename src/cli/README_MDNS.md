# OpenThread CLI - mDNS

The OpenThread mDNS APIs may be invoked via the OpenThread CLI. mDNS enables service discovery on the local network.

## Quick Start

### Form a Network

Form a network with at least two devices.

### Node 1 (mDNS Server/Publisher)

On node 1, enable the mDNS service and register a service instance.

```bash
> mdns enable
Done
> mdns register service my-instance _ot-test._udp.local my-host.local 1234
Service my-instance._ot-test._udp.local for _ot-test._udp.local
  host: my-host.local
  port: 1234
  priority: 0
  weight: 0
  ttl: 0
  txt-data: (empty)
Done
```

### Node 2 (mDNS Client/Querier)

On node 2, enable the mDNS service and start a browser to discover the service registered by Node 1.

```bash
> mdns enable
Done
> mdns browser start _ot-test._udp.local
Done
```

### Result

After a few moments, Node 2 should discover the service and print the browse result:

```bash
mDNS browse result for _ot-test._udp.local
  instance: my-instance
  ttl: 120
  if-index: 0
```

## Command List

- [help](#help)
- [auto](#auto)
- [browser](#browser)
- [browsers](#browsers)
- [disable](#disable)
- [enable](#enable)
- [hosts](#hosts)
- [ip4resolver](#ip4resolver)
- [ip4resolvers](#ip4resolvers)
- [ip6resolver](#ip6resolver)
- [ip6resolvers](#ip6resolvers)
- [keys](#keys)
- [localhostaddrs](#localhostaddrs)
- [localhostname](#localhostname)
- [recordquerier](#recordquerier)
- [recordqueriers](#recordqueriers)
- [register](#register)
- [services](#services)
- [srvresolver](#srvresolver)
- [srvresolvers](#srvresolvers)
- [state](#state)
- [txtresolver](#txtresolver)
- [txtresolvers](#txtresolvers)
- [unicastquestion](#unicastquestion)
- [unregister](#unregister)

## Command Details

### help

List the mDNS CLI commands.

```bash
> mdns help
help
auto
browser
browsers
disable
enable
hosts
ip4resolver
...
Done
```

### auto

Requires `OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE`.

Enables or disables the automatic start of the mDNS service by the Border Routing manager.

Usage: `mdns auto [enable|disable]`

```bash
> mdns auto enable
Done
```

### browser \<start|stop\> \<service-type\> \[\<sub-type\>]

Starts or stops Browse for service instances on the network. The callback reports discovered, changed, or removed service instances.

- `start|stop`: Start or stop the browser.
- `service-type`: The service type to browse for (e.g., `_http._tcp`).
- `sub-type`: An optional service sub-type to filter results.

```bash
> mdns browser start _http._tcp
Done
```

### browsers

Requires `OPENTHREAD_CONFIG_MULTICAST_DNS_ENTRY_ITERATION_API_ENABLE`.

Lists all currently active service browsers.

```bash
> mdns browsers
Browser _http._tcp
  active: yes
  cached-results: no
Done
```

### disable

Disables the mDNS service.

```bash
> mdns disable
Done
```

### enable \[\<infra-if-index\>]

Enables the mDNS service.

- `infra-if-index`: (Optional) The network interface index for mDNS to operate on. If not provided and Border Routing is enabled, it defaults to the infrastructure interface.

```bash
> mdns enable 1
Done
```

### hosts

Requires `OPENTHREAD_CONFIG_MULTICAST_DNS_ENTRY_ITERATION_API_ENABLE`.

Lists all hosts registered by the local mDNS module.

```bash
> mdns hosts
Host my-host.local
  1 address:
    fdde:ad00:beef:0:1234:5678:9abc:def0
  ttl: 120
  state: registered
Done
```

### ip4resolver \<start|stop\> \<host-name\>

Starts or stops resolving IPv4 addresses (A records) for a given host name. The callback reports the discovered addresses.

```bash
> mdns ip4resolver start my-host.local
Done
```

### ip4resolvers

Requires `OPENTHREAD_CONFIG_MULTICAST_DNS_ENTRY_ITERATION_API_ENABLE`.

Lists all currently active IPv4 address resolvers.

```bash
> mdns ip4resolvers
IPv4 address resolver my-host.local
  active: yes
  cached-results: yes
Done
```

### ip6resolver \<start|stop\> \<host-name\>

Starts or stops resolving IPv6 addresses (AAAA records) for a given host name. The callback reports the discovered addresses.

```bash
> mdns ip6resolver start my-host.local
Done
```

### ip6resolvers

Requires `OPENTHREAD_CONFIG_MULTICAST_DNS_ENTRY_ITERATION_API_ENABLE`.

Lists all currently active IPv6 address resolvers.

```bash
> mdns ip6resolvers
IPv6 address resolver my-host.local
  active: yes
  cached-results: yes
Done
```

### keys

Requires `OPENTHREAD_CONFIG_MULTICAST_DNS_ENTRY_ITERATION_API_ENABLE`.

Lists all keys registered by the local mDNS module.

```bash
> mdns keys
Key mykey for _my-service._tcp.local (service)
  key-data: 0102030405
  ttl: 3600
  state: registered
Done
```

### localhostaddrs

Requires `OPENTHREAD_CONFIG_MULTICAST_DNS_ENTRY_ITERATION_API_ENABLE`.

Lists all IP addresses of the local host that mDNS is aware of.

```bash
> mdns localhostaddrs
fdde:ad00:beef:0:1234:5678:9abc:def0
192.168.1.10
Done
```

### localhostname \[\<name\>]

Gets or sets the local host name used by mDNS.

```bash
> mdns localhostname my-device
Done
> mdns localhostname
my-device
Done
```

### recordquerier \<start|stop\> \<record-type\> \<first-label\> \[\<next-labels\>]

Starts or stops a generic DNS record querier.

- `record-type`: The numerical value of the DNS record type (e.g., 16 for TXT).
- `first-label`: The first label of the domain name.
- `next-labels`: The remaining labels of the domain name.

```bash
> mdns recordquerier start 16 my-instance _ot-test._udp.local
Done
```

### recordqueriers

Requires `OPENTHREAD_CONFIG_MULTICAST_DNS_ENTRY_ITERATION_API_ENABLE`.

Lists all currently active generic record queriers.

```bash
> mdns recordqueriers
Record querier for type 16 and name my-instance _ot-test._udp.local
  active: yes
  cached-results: no
Done
```

### register \[\<async\>\] \<host|service|key\> \<args...\>

Registers a host, service, or key with the mDNS module. The registration can be synchronous (default) or asynchronous.

- `async`: (Optional) Perform the operation asynchronously. A request ID will be printed.
- `host <name> [<address>...] [<ttl>]`: Registers a host with its name, optional addresses, and TTL.
- `service <instance> <type,sub_types> <host> <port> [<prio>] [<weight>] [<ttl>] [<txt>]`: Registers a service. `txt` data is a hex string.
- `key <name> [_<service-type>] <key-data> [<ttl>]`: Registers a KEY record for a host or service. `key-data` is a hex string.

```bash
> mdns register host my-host.local fdde:ad00:beef:0::1
Host my-host.local
  1 address:
    fdde:ad00:beef:0:0:0:0:1
  ttl: 0
Done

> mdns register service my-inst _test._udp my-host.local 1234 0 0 120 010203
Service my-inst for _test._udp
  host: my-host.local
  port: 1234
  priority: 0
  weight: 0
  ttl: 120
  txt-data: 010203
Done
```

### services

Requires `OPENTHREAD_CONFIG_MULTICAST_DNS_ENTRY_ITERATION_API_ENABLE`.

Lists all services registered by the local mDNS module.

```bash
> mdns services
Service my-instance for _ot-test._udp.local
  host: my-host.local
  port: 1234
  priority: 0
  weight: 0
  ttl: 120
  txt-data: (empty)
  state: registered
Done
```

### srvresolver \<start|stop\> \<service-instance\> \<service-type\>

Starts or stops resolving the SRV record for a specific service instance. The callback reports the host name, port, and other SRV data.

```bash
> mdns srvresolver start my-instance _ot-test._udp.local
Done
```

### srvresolvers

Requires `OPENTHREAD_CONFIG_MULTICAST_DNS_ENTRY_ITERATION_API_ENABLE`.

Lists all currently active SRV resolvers.

```bash
> mdns srvresolvers
SRV resolver my-instance for _ot-test._udp.local
  active: yes
  cached-results: yes
Done
```

### state

Shows the current operational state of the mDNS module.

```bash
> mdns state
Enabled
Done
```

### txtresolver \<start|stop\> \<service-instance\> \<service-type\>

Starts or stops resolving the TXT record for a specific service instance. The callback reports the TXT data.

```bash
> mdns txtresolver start my-instance _ot-test._udp.local
Done
```

### txtresolvers

Requires `OPENTHREAD_CONFIG_MULTICAST_DNS_ENTRY_ITERATION_API_ENABLE`.

Lists all currently active TXT resolvers.

```bash
> mdns txtresolvers
TXT resolver my-instance for _ot-test._udp.local
  active: yes
  cached-results: no
Done
```

### unicastquestion \[\<enable|disable\>\]

Gets or sets whether unicast mDNS questions are allowed.

```bash
> mdns unicastquestion enable
Done
> mdns unicastquestion
Enabled
Done
```

### unregister \<host|service|key\> \<args...\>

Unregisters a previously registered host, service, or key.

- `host <name>`: Unregisters a host by name.
- `service <instance> <type>`: Unregisters a service by instance and type.
- `key <name> [_<service-type>]`: Unregisters a key by name and optional service type.

```bash
> mdns unregister host my-host.local
Done
> mdns unregister service my-instance _ot-test._udp.local
Done
```

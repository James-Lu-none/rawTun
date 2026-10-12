# rawTun

IPv4-over-UDP tunnel: Windows Wintun client and Linux TUN server.
The wire format remains compatible with the original version: eight-byte secret
prefix followed by an IPv4 packet, or an eight-byte keepalive timestamp.

## Build and update

```sh
make
sudo ./setup_server.sh
journalctl -u gateway-server -f
```

Stop the old Windows client before replacing `client.exe`; keep `wintun.dll` and
`tunnel.conf` beside it and run as Administrator. The full IPv4 routes, MTU default
of 1400, and 4 MiB Wintun ring remain unchanged. Existing EC2 forwarding, firewall,
NAT, and source/destination-check settings must remain in place; setup does not
change these settings.

## Forwarding and shutdown

* Server validates the header and IPv4 length before updating the active peer.
* Server uses nonblocking I/O and drains at most 32 packets per direction per poll cycle; it sends each packet immediately, without waiting to form a batch.
* Server reads directly behind the secret prefix. Windows uses scatter/gather WSASend to avoid copying outgoing packet payloads into an intermediate buffer.
* Windows waits on the Wintun read event while idle. It connects its UDP socket to the configured server, filtering other source addresses/ports.
* Windows UDP receive/send timeouts are 100 ms; these bound blocking operations, rather than adding a 100 ms delay to available packets.
* Enter/Ctrl+C stops and joins workers before ending the Wintun session. Closing the console gives cleanup a bounded window; forced termination cannot guarantee route restoration. Cleanup removes only routes successfully added by this run.
* Startup checks numeric/IP/interface-name configuration and required DLL exports; interface/route failures abort and roll back routes already added.

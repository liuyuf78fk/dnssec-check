# dnssec-check

This is a lightweight tool for testing DNSSEC support on Linux systems.
It uses `dig` to query two reference domains and evaluates the DNS resolver's DNSSEC validation capabilities.

## Features

- Compatible with both Debian and OpenWrt 
- Uses `inih` to read configuration from `/etc/dnssec-check/dnssec-check.conf`
- Performs DNS queries via `dig`
- Evaluates DNSSEC support level: secure, medium, or insecure
- Minimal dependencies: `bind9-dnsutils` on Debian, `bind-dig` on OpenWrt

## INI Configuration

File: `/etc/dnssec-check/dnssec-check.conf`

```
[domains]
secure_domain = nic.cz
broken_domain = dnssec-failed.org

[query]
dig_time = 3
dig_tries = 2

[output]
debug = 0
```

## Logic Summary

- `secure_domain`: should pass DNSSEC validation (e.g. nic.cz)
- `broken_domain`: deliberately broken for DNSSEC (e.g. dnssec-failed.org)
- Tool inspects `dig` output (AD bit + status code) to determine support level

## Severity Levels

- **secure**: local DNS resolver performs full DNSSEC validation for both reference domains
- **medium**: upstream resolver blocks invalid domains, but local does not validate
- **insecure**: no DNSSEC validation at any level

## Functional Test Report

### Case 1: Secure (Local resolver validates DNSSEC)

/etc/resolv.conf:

```
nameserver 1.1.1.1
nameserver 2606:4700:4700::1111
```

Command:

```
$ dnssec-check
[INFO] Loaded configuration from UCI.
[*] Querying nic.cz ...
[*] Querying dnssec-failed.org ...
Parsed nic.cz: AD=true, Status=NOERROR
Parsed dnssec-failed.org: AD=false, Status=SERVFAIL
-> Severity level: secure
```

Explanation: The local resolver successfully performs full DNSSEC validation.

### Case 2: Medium (Upstream validates, local does not)

/etc/resolv.conf:

```
nameserver 127.0.0.1 #(DNSSEC not enabled)
```

If the upstream DNS server is:

```
1.1.1.1
```

Command:

```
$ dnssec-check
[INFO] Loaded configuration from UCI.
[*] Querying nic.cz ...
[*] Querying dnssec-failed.org ...
Parsed nic.cz: AD=false, Status=NOERROR
Parsed dnssec-failed.org: AD=false, Status=SERVFAIL
-> Severity level: medium
```

Explanation: The local resolver does not validate DNSSEC, but the upstream resolver blocks failing domains.

### Case 3: Insecure (Neither local nor upstream validates DNSSEC)

/etc/resolv.conf:

```
nameserver 127.0.0.1 #(DNSSEC not enabled)
```

If the upstream DNS server is:

```
192.168.137.1 #(DNSSEC not enabled)
```

Command:

```
$ dnssec-check
[INFO] Loaded configuration from UCI.
[*] Querying nic.cz ...
[*] Querying dnssec-failed.org ...
Parsed nic.cz: AD=false, Status=NOERROR
Parsed dnssec-failed.org: AD=false, Status=NOERROR
-> Severity level: insecure
```

Explanation: Both the local and upstream resolvers return unsigned responses without blocking invalid domains.

## Summary

The tool accurately detects DNSSEC capabilities across three levels:

- secure: local DNSSEC validation is active
- medium: upstream DNSSEC validation is active, but local is not
- insecure: no DNSSEC validation at all

## Third-party components

This project includes the [inih](https://github.com/benhoyt/inih) library by Ben Hoyt,
which is licensed under the New BSD License. See [inih-LICENSE.txt](src/inih/inih-LICENSE.txt) for details.

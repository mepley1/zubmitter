# AbuseIPDB report submission tool

Another CLI tool for submitting abuse reports to AbuseIPDB API, written in Zig.

Supports the REPORT and CLEAR-ADDRESS endpoints.

## Usage

`zreport <action: submit|delete> <ip_addr> <categories> <comment>`

Configure API key in `app.conf` (rename `app.conf.default` to `app.conf`), and a default comment if preferred (default will be used if a comment arg isn't passed).

Examples:
- Submit a report (REPORT endpoint): `zreport submit "127.0.0.1" "15,23"  "Malicious activity"`
- Clear reports for an address (CLEAR-ADDRESS endpoint): `zreport delete "127.0.0.1"`

## Build

Build like any other (simple) Zig project:

`zig build -Doptimize=ReleaseSafe`

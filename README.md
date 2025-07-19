# AbuseIPDB report submission tool

Another CLI tool for submitting abuse reports to AbuseIPDB API, written in Zig (0.14.0).

Supports the REPORT and CLEAR-ADDRESS api endpoints.

~~Linux only, for now.~~ Compatible with both Linux/Windows.

Written while learning Zig, so there are some code smells / bad architecture to be found.

## Usage

`zreport <action: submit|delete> <ip_addr> <categories> <comment>`

Configure API key in `.conf` (copy/rename `.conf.default` to `.conf`), and a default comment if preferred (default will be used if a comment arg isn't passed).

Examples:
- Submit a report (REPORT endpoint): `zreport submit 127.0.0.1 "16,23"  "Attempted SQL injection"`
- Clear reports for an address (CLEAR-ADDRESS endpoint): `zreport delete 127.0.0.1`

Note: Please be detailed in your reports, i.e. include log lines, HTTP request method/uris, etc wherever practical.

## Build

Build like any other (simple) Zig project.

On Linux, for Linux (native): `zig build -Doptimize=ReleaseSafe -Dcpu=znver5`

On Linux, for Windows: `zig build-exe ./src/main.zig -O ReleaseSafe -target x86_64-windows -femit-bin=./BUILD/WIN/zreport.exe`

# TCP Port Scanner

A Python-based TCP Port Scanner developed as part of a Cybersecurity Internship Project.

## Features

* TCP port scanning
* Single host scanning
* Custom port range scanning
* Concurrent scanning using threads
* Banner grabbing
* Logging support
* Open, closed, timeout, and error reporting

## Requirements

Python 3.x

## Usage

Scan common ports:

python port_scanner.py -t scanme.nmap.org -p common

Scan a range of ports:

python port_scanner.py -t 192.168.1.1 -p 1-1024

Verbose mode:

python port_scanner.py -t localhost -p 1-65535 -v

## Author

Junaid

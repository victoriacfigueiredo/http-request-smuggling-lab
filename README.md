# HTTP Request Smuggling Lab

> Experimental HTTP/1.1 infrastructure for studying request desynchronization vulnerabilities and proxy parsing discrepancies.

## Overview

This repository is an educational and experimental lab focused on understanding how HTTP Request Smuggling vulnerabilities emerge when HTTP intermediaries interpret requests differently.

The project was inspired by:

- RFC 9112
- RFC 9931
- James Kettle's research: *HTTP/1.1 Must Die: The Desync Endgame*

Instead of only reproducing known payloads, the goal of this project is to understand how desynchronization happens internally between proxies, load balancers, caches, and backend servers.

The lab contains custom implementations of:

- HTTP client
- Reverse proxy
- Security proxy
- Caching proxy
- Load balancer
- Backend server

All components were built for experimentation and RFC-oriented behavior analysis.

---

# Project Structure

```text
http-request-smuggling-lab/
│
├── HTTPServer_CPython/
│   ├── client.py
│   └── server.py
│
├── WEBrick/
│   ├── proxy.rb
│   └── server.rb
│
├── caching_proxy.py        # Simple caching proxy
├── client.py               # HTTP client used for experiments
├── forward_proxy.py        # Forward proxy implementation
├── load_balancer.py        # Round-robin load balancer
├── reverse_proxy.py        # Reverse proxy implementation
├── security_proxy.py       # Security filtering proxy
├── server.py               # Main backend server
├── server2.py              # Secondary backend server
├── server3.py              # Third backend server
└── README.md
```

---

# Components

## Client

Responsible for crafting and sending HTTP requests, including malformed and ambiguous payloads used during desynchronization experiments.

## Backend Server

RFC-inspired HTTP/1.1 server implementation responsible for:

- Request parsing
- Persistent connections
- Chunked transfer decoding
- Response generation

## Reverse Proxy

Base intermediary component responsible for forwarding requests upstream while applying RFC-inspired header handling.

## Security Proxy

Experimental proxy that performs lightweight filtering for suspicious patterns such as:

- Path traversal
- SQL injection attempts
- Cross-site scripting payloads

## Caching Proxy

Stores previously received responses and serves cached content whenever possible.

## Load Balancer

Distributes requests between backend servers using simple round-robin logic.

---

# Features

- RFC-inspired HTTP/1.1 parsing
- Persistent connections (keep-alive)
- Chunked transfer parsing
- Experimental CL.TE desynchronization testing
- Hop-by-hop header removal
- `Connection` header sanitization
- Basic reverse proxying
- Experimental security filtering
- Simple caching behavior
- Round-robin load balancing

---

# Example Architecture

```text
Client
   ↓
Security Proxy
   ↓
Caching Proxy
   ↓
Load Balancer
   ↓
Backend Server
```

---

# Running the Project

## Clone the repository

```bash
git clone https://github.com/victoriacfigueiredo/http-request-smuggling-lab.git
cd http-request-smuggling-lab
```

---

## Start the backend server

```bash
python server.py
```
```bash
python server2.py
```
```bash
python server3.py
```

---

## Start the proxies

### Security Proxy

```bash
python security_proxy.py
```

### Caching Proxy

```bash
python caching_proxy.py
```

### Load Balancer

```bash
python load_balancer.py
```

---

## Run the client

```bash
python client.py
```

---

# Experimental Desynchronization Testing

The repository includes experimental configurations for reproducing CL.TE desynchronization scenarios.

In these experiments:

- Some components prioritize `Content-Length`
- Others prioritize `Transfer-Encoding`

This intentionally creates disagreement about request boundaries between intermediaries.

These behaviors exist exclusively for educational and research purposes.

## Enabling Desync Mode

To reproduce desynchronization scenarios, you must enable the following flag in both the caching proxy and the security proxy:

```python
LAB_DESYNC_MODE = True
```

Files:

```text
caching-proxy/caching_proxy.py
security-proxy/security_proxy.py
```

When enabled, the proxies intentionally propagate conflicting `Content-Length` and `Transfer-Encoding` headers upstream, allowing controlled CL.TE desynchronization experiments.

---

# Educational Goals

This project was built for:

- Learning
- Research
- Experimentation
- Understanding HTTP ambiguities
- Studying proxy behavior
- Exploring desynchronization vulnerabilities

---

# Disclaimer

This repository was created strictly for educational and research purposes.

Several components intentionally implement unsafe behavior in order to reproduce controlled desynchronization scenarios.

---

# Future Work

Possible future improvements include:

- HTTP/2 experiments
- TE.CL and TE.TE variants
- More realistic caching behavior

---

# Final Note

One of the main ideas behind this project is simple:

> HTTP/1.1 works very well until two components start disagreeing about where a request ends.

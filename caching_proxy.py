import socket
import threading
import hashlib
import time
from urllib.parse import urlsplit

HOST = "127.0.0.1"
PORT = 8081

NEXT_HOST = "127.0.0.1"
NEXT_PORT = 8082

SERVER_NAME = "Caching Proxy"

CACHE = {}
CACHE_LOCK = threading.Lock()

MAX_HEADER_SIZE = 64 * 1024
MAX_OBJECT_SIZE = 5 * 1024 * 1024

CACHEABLE_METHODS = {"GET", "HEAD"}

HOP_BY_HOP_DEFAULT = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
}

LAB_DESYNC_MODE = False
FRONTEND_FRAMING_MODE = "CL" 

def recv_until(sock: socket.socket, marker: bytes):
    data = b""

    while marker not in data:
        chunk = sock.recv(4096)

        if not chunk:
            break

        data += chunk

        if len(data) > MAX_HEADER_SIZE:
            raise ValueError("Header muito grande")

    return data

def parse_headers(header_bytes: bytes):
    text = header_bytes.decode("iso-8859-1")
    lines = text.split("\r\n")

    start_line = lines[0]
    headers = []

    for line in lines[1:]:
        if not line:
            continue

        if line.startswith((" ", "\t")):
            raise ValueError("obs-fold rejeitado")

        if ":" not in line:
            raise ValueError(f"Header inválido: {line!r}")

        name, value = line.split(":", 1)

        headers.append((name.strip(), value.strip()))

    return start_line, headers


def get_all(headers, name):
    lname = name.lower()
    return [v for k, v in headers if k.lower() == lname]


def parse_connection_options(headers):
    options = set()

    for value in get_all(headers, "connection"):
        for item in value.split(","):
            item = item.strip().lower()

            if item:
                options.add(item)

    return options


def remove_hop_by_hop_headers(headers):
    forbidden = HOP_BY_HOP_DEFAULT | parse_connection_options(headers)

    clean = []

    for name, value in headers:
        if name.lower() in forbidden:
            continue

        clean.append((name, value))

    return clean

def validate_request_line(line: str):
    parts = line.split(" ")

    if len(parts) != 3:
        raise ValueError("Request-Line inválida")

    method, target, version = parts

    if version != "HTTP/1.1":
        raise ValueError("Apenas HTTP/1.1 suportado")

    return method.upper(), target, version


def normalize_target(method, target):
    if target == "*":
        return target

    parsed = urlsplit(target)

    if parsed.scheme or parsed.netloc:
        path = parsed.path or "/"

        if parsed.query:
            path += "?" + parsed.query

        return path

    return target


def validate_host(headers):
    hosts = get_all(headers, "host")

    if len(hosts) != 1:
        raise ValueError("HTTP/1.1 exige exatamente um Host")


def validate_framing(headers):
    cls = get_all(headers, "content-length")
    tes = get_all(headers, "transfer-encoding")

    if cls and tes and not LAB_DESYNC_MODE:
        raise ValueError("TE + CL bloqueado")

    if len(cls) > 1:
        raise ValueError("Múltiplos Content-Length")

    if tes:
        codings = [x.strip().lower() for x in tes[0].split(",")]

        if codings[-1] != "chunked":
            raise ValueError("Transfer-Encoding inválido")


def read_chunked_body(sock, initial_rest):
    data = initial_rest
    body = b""

    while True:
        while b"\r\n" not in data:
            chunk = sock.recv(4096)

            if not chunk:
                raise ConnectionError("Chunk incompleto")

            data += chunk

        line, data = data.split(b"\r\n", 1)

        line = line.split(b";", 1)[0].strip()

        chunk_size = int(line.decode("ascii"), 16)

        if chunk_size == 0:
            while b"\r\n" not in data:
                chunk = sock.recv(4096)

                if not chunk:
                    raise ConnectionError("Trailer incompleto")

                data += chunk

            _, data = data.split(b"\r\n", 1)

            break

        while len(data) < chunk_size + 2:
            chunk = sock.recv(4096)

            if not chunk:
                raise ConnectionError("Chunk incompleto")

            data += chunk

        body += data[:chunk_size]

        if data[chunk_size:chunk_size + 2] != b"\r\n":
            raise ValueError("Chunk sem CRLF")

        data = data[chunk_size + 2:]

    return body


def read_http_request(conn):
    raw = recv_until(conn, b"\r\n\r\n")

    if not raw:
        return None

    if b"\r\n\r\n" not in raw:
        raise ValueError("Header incompleto")

    header_part, rest = raw.split(b"\r\n\r\n", 1)

    request_line, headers = parse_headers(header_part)

    method, target, version = validate_request_line(request_line)

    target = normalize_target(method, target)

    validate_host(headers)
    validate_framing(headers)

    cls = get_all(headers, "content-length")
    tes = get_all(headers, "transfer-encoding")

    body = b""

    if LAB_DESYNC_MODE and cls and tes and FRONTEND_FRAMING_MODE == "CL":
        length = int(cls[0])

        body = rest

        while len(body) < length:
            chunk = conn.recv(4096)

            if not chunk:
                raise ConnectionError("Body incompleto")

            body += chunk

        body = body[:length]

    elif tes:
        body = read_chunked_body(conn, rest)

    elif cls:
        length = int(cls[0])

        body = rest

        while len(body) < length:
            chunk = conn.recv(4096)

            if not chunk:
                raise ConnectionError("Body incompleto")

            body += chunk

        body = body[:length]

    return method, target, version, headers, body

def build_cache_key(method, target, headers):
    host = get_all(headers, "host")[0]

    key = f"{method}:{host}:{target}"

    return hashlib.sha256(key.encode()).hexdigest()


def parse_cache_control(headers):
    directives = {}

    for value in get_all(headers, "cache-control"):
        parts = value.split(",")

        for part in parts:
            part = part.strip()

            if "=" in part:
                k, v = part.split("=", 1)
                directives[k.strip().lower()] = v.strip()
            else:
                directives[part.lower()] = True

    return directives


def is_request_cacheable(method, headers):
    if method not in CACHEABLE_METHODS:
        return False

    directives = parse_cache_control(headers)

    if "no-store" in directives:
        return False

    return True


def is_response_cacheable(headers):
    directives = parse_cache_control(headers)

    if "no-store" in directives:
        return False

    return True

def process_esi(body: bytes):
    text = body.decode("utf-8", errors="ignore")
    import re

    pattern = re.compile(
        r'<esi:include\s+src="([^"]+)"\s*/?>',
        re.IGNORECASE
    )

    def replacer(match):
        src = match.group(1)

        try:
            fragment = fetch_fragment(src)

            return fragment.decode("utf-8", errors="ignore")

        except Exception as exc:
            return f"[ESI ERROR: {exc}]"

    return pattern.sub(replacer, text).encode("utf-8")


def fetch_fragment(path):
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {NEXT_HOST}:{NEXT_PORT}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((NEXT_HOST, NEXT_PORT))

        s.sendall(request)

        response = b""

        while True:
            chunk = s.recv(4096)

            if not chunk:
                break

            response += chunk

    if b"\r\n\r\n" not in response:
        return b""

    _, body = response.split(b"\r\n\r\n", 1)

    return body

def merge_via_headers(headers, server_name):
    existing = []

    for name, value in headers:
        if name.lower() == "via":
            existing.append(value)

    existing.append(f"1.1 {server_name}")

    return ", ".join(existing)

def build_forwarded_request(method, target, version, headers, body):
    if LAB_DESYNC_MODE:
        clean_headers = []

        for name, value in headers:
            lname = name.lower()

            if lname in {
                "connection",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "te",
                "trailer",
                "upgrade",
                "proxy-connection",
            }:
                continue

            clean_headers.append((name, value))
    else:
        clean_headers = remove_hop_by_hop_headers(headers)

    final_headers = []
    saw_host = False

    via_value = merge_via_headers(clean_headers, SERVER_NAME)

    for name, value in clean_headers:
        lname = name.lower()

        if lname == "via":
            continue

        if lname == "host":
            final_headers.append(("Host", f"{NEXT_HOST}:{NEXT_PORT}"))
            saw_host = True
            continue

        if lname == "content-length" and not LAB_DESYNC_MODE:
            continue

        final_headers.append((name, value))

    if not saw_host:
        final_headers.append(("Host", f"{NEXT_HOST}:{NEXT_PORT}"))

    final_headers.append(("Via", via_value))

    if not LAB_DESYNC_MODE:
        final_headers.append(("Content-Length", str(len(body))))
        final_headers.append(("Connection", "close"))
    else:
        final_headers.append(("Connection", "keep-alive"))

    request_line = f"{method} {target} {version}\r\n"

    header_block = "".join(
        f"{k}: {v}\r\n"
        for k, v in final_headers
    )

    return (
        request_line +
        header_block +
        "\r\n"
    ).encode("iso-8859-1") + body

def forward_request(request_bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
        upstream.connect((NEXT_HOST, NEXT_PORT))

        upstream.sendall(request_bytes)

        response = b""

        while True:
            chunk = upstream.recv(4096)

            if not chunk:
                break

            response += chunk

        return response

def parse_response(response: bytes):
    if b"\r\n\r\n" not in response:
        raise ValueError("Response inválida")

    header_part, body = response.split(b"\r\n\r\n", 1)

    status_line, headers = parse_headers(header_part)

    return status_line, headers, body

def handle_client(conn, addr):
    try:
        request = read_http_request(conn)

        if request is None:
            return

        method, target, version, headers, body = request

        print(f"\nCache {method} {target}")

        cache_key = build_cache_key(method, target, headers)

        if is_request_cacheable(method, headers):

            with CACHE_LOCK:
                entry = CACHE.get(cache_key)

            if entry:
                expires, response = entry

                if time.time() < expires:
                    print("Cache hit")

                    conn.sendall(response)
                    return

                else:
                    print("Cache stale")

                    with CACHE_LOCK:
                        CACHE.pop(cache_key, None)

        print("Cache miss")

        forwarded = build_forwarded_request(
            method,
            target,
            version,
            headers,
            body,
        )

        response = forward_request(forwarded)

        status_line, response_headers, response_body = parse_response(response)

        content_type = get_all(response_headers, "content-type")

        if content_type:
            if "text/html" in content_type[0].lower():

                if b"<esi:include" in response_body:
                    print("Cache - Processando ESI")

                    response_body = process_esi(response_body)

                    response_headers = [
                        h for h in response_headers
                        if h[0].lower() != "content-length"
                    ]

                    response_headers.append(
                        ("Content-Length", str(len(response_body)))
                    )

                    header_block = "".join(
                        f"{k}: {v}\r\n"
                        for k, v in response_headers
                    )

                    response = (
                        status_line + "\r\n" +
                        header_block + "\r\n"
                    ).encode("iso-8859-1") + response_body

        if (
            is_request_cacheable(method, headers)
            and
            is_response_cacheable(response_headers)
            and
            len(response) <= MAX_OBJECT_SIZE
        ):

            ttl = 30

            cc = parse_cache_control(response_headers)

            if "max-age" in cc:
                try:
                    ttl = int(cc["max-age"])
                except:
                    pass

            with CACHE_LOCK:
                CACHE[cache_key] = (
                    time.time() + ttl,
                    response
                )

            print(f"Cache stored ({ttl}s)")

        conn.sendall(response)

    except Exception as exc:
        error = build_error_response(
            400,
            "Bad Request",
            f"Erro no cache proxy: {exc}"
        )

        conn.sendall(error)

    finally:
        conn.close()

def build_error_response(status_code, reason, body):
    body_bytes = body.encode("utf-8")

    return (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Type: text/plain\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("iso-8859-1") + body_bytes

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        proxy.bind((HOST, PORT))
        proxy.listen(50)

        print(f"[Cache] ouvindo em {HOST}:{PORT}")

        while True:
            conn, addr = proxy.accept()

            threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True,
            ).start()


if __name__ == "__main__":
    main()
import socket
import threading
import re
from urllib.parse import urlsplit, unquote_plus

HOST = "127.0.0.1"
PORT = 8080

NEXT_HOST = "127.0.0.1"
NEXT_PORT = 8081

SERVER_NAME = "Security Proxy"

MAX_HEADER_SIZE = 64 * 1024
MAX_BODY_SIZE = 2 * 1024 * 1024

ALLOWED_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"}

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

WAF_PATTERNS = [
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"onload\s*=", re.IGNORECASE),
    re.compile(r"<\s*iframe", re.IGNORECASE),
    re.compile(r"\bunion\s+select\b", re.IGNORECASE),
    re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"\band\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"'\s*or\s*'", re.IGNORECASE),
    re.compile(r"--", re.IGNORECASE),
    re.compile(r"/\*", re.IGNORECASE),
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"cmd\.exe", re.IGNORECASE),
    re.compile(r"powershell", re.IGNORECASE),
]


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


def build_error_response(status_code: int, reason: str, body: str):
    body_bytes = body.encode("utf-8")

    return (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("iso-8859-1") + body_bytes


def parse_headers(header_bytes: bytes):
    text = header_bytes.decode("iso-8859-1")
    lines = text.split("\r\n")

    request_line = lines[0]
    headers = []

    for line in lines[1:]:
        if line == "":
            continue
        if line.startswith((" ", "\t")):
            raise ValueError("Header com obs-fold rejeitado")

        if ":" not in line:
            raise ValueError(f"Header inválido: {line!r}")

        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()

        if not name:
            raise ValueError("Header sem nome")

        if any(c in name for c in " \t\r\n"):
            raise ValueError(f"Nome de header inválido: {name!r}")

        headers.append((name, value))

    return request_line, headers


def get_all(headers, name: str):
    lname = name.lower()
    return [v for k, v in headers if k.lower() == lname]


def validate_request_line(request_line: str):
    parts = request_line.split(" ")

    if len(parts) != 3:
        raise ValueError("Request-Line inválida")

    method, target, version = parts

    if version != "HTTP/1.1":
        raise ValueError("Apenas HTTP/1.1 é aceito")

    if method.upper() not in ALLOWED_METHODS:
        raise ValueError(f"Método bloqueado: {method}")

    if "\r" in target or "\n" in target:
        raise ValueError("Request-target inválido")

    return method.upper(), target, version


def normalize_target(method: str, target: str):
    if method == "CONNECT":
        raise ValueError("CONNECT não é suportado")

    if target == "*":
        return target

    parsed = urlsplit(target)

    if parsed.scheme or parsed.netloc:
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return path

    if not target.startswith("/"):
        raise ValueError("Request-target precisa estar em origin-form ou absolute-form")

    return target


def validate_host(headers):
    hosts = get_all(headers, "host")

    if len(hosts) != 1:
        raise ValueError("HTTP/1.1 exige exatamente um Host")

    if hosts[0] == "":
        raise ValueError("Host vazio")


def validate_message_framing(headers):
    cls = get_all(headers, "content-length")
    tes = get_all(headers, "transfer-encoding")

    if len(cls) > 1:
        values = [v.strip() for v in cls]

        if len(set(values)) != 1:
            raise ValueError("Múltiplos Content-Length divergentes")

        raise ValueError("Múltiplos Content-Length rejeitados")

    if cls:
        try:
            cl = int(cls[0])
        except ValueError:
            raise ValueError("Content-Length inválido")

        if cl < 0:
            raise ValueError("Content-Length negativo")

        if cl > MAX_BODY_SIZE:
            raise ValueError("Body muito grande")

    if tes and cls and not LAB_DESYNC_MODE:
        raise ValueError("Ambiguidade TE + CL bloqueada")

    if len(tes) > 1:
        raise ValueError("Múltiplos Transfer-Encoding rejeitados")

    if tes:
        codings = [x.strip().lower() for x in tes[0].split(",")]

        if codings[-1] != "chunked":
            raise ValueError("Transfer-Encoding final precisa ser chunked")

        for coding in codings:
            if coding != "chunked":
                raise ValueError(f"Transfer-Encoding não suportado: {coding}")


def read_chunked_body(sock: socket.socket, initial_rest: bytes):
    data = initial_rest
    body = b""

    while True:
        while b"\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão encerrada durante chunk-size")
            data += chunk

        line, data = data.split(b"\r\n", 1)
        line = line.split(b";", 1)[0].strip()

        try:
            chunk_size = int(line.decode("ascii"), 16)
        except ValueError:
            raise ValueError("Chunk-size inválido")

        if chunk_size == 0:
            while b"\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("Conexão encerrada antes dos trailers")
                data += chunk

            trailer_block, data = data.split(b"\r\n", 1)

            if trailer_block:
                raise ValueError("Trailers rejeitados por segurança")

            break

        while len(data) < chunk_size + 2:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão encerrada durante chunk-data")
            data += chunk

        body += data[:chunk_size]

        if len(body) > MAX_BODY_SIZE:
            raise ValueError("Body muito grande")

        if data[chunk_size:chunk_size + 2] != b"\r\n":
            raise ValueError("Chunk sem CRLF final")

        data = data[chunk_size + 2:]

    return body


def read_http_request(conn: socket.socket):
    raw = recv_until(conn, b"\r\n\r\n")

    if not raw:
        return None

    if b"\r\n\r\n" not in raw:
        raise ValueError("Cabeçalho HTTP incompleto")

    header_part, rest = raw.split(b"\r\n\r\n", 1)

    request_line, headers = parse_headers(header_part)

    method, target, version = validate_request_line(request_line)
    target = normalize_target(method, target)

    validate_host(headers)
    validate_message_framing(headers)

    cls = get_all(headers, "content-length")
    tes = get_all(headers, "transfer-encoding")

    body = b""

    if LAB_DESYNC_MODE and cls and tes:
        length = int(cls[0])
        body = rest

        while len(body) < length:
            chunk = conn.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão encerrada antes do body completo")
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
                raise ConnectionError("Conexão encerrada antes do body completo")
            body += chunk

        body = body[:length]

    return method, target, version, headers, body


def parse_connection_options(headers):
    options = set()

    for value in get_all(headers, "connection"):
        for item in value.split(","):
            item = item.strip().lower()
            if item:
                options.add(item)

    return options


def remove_hop_by_hop_headers(headers):
    connection_options = parse_connection_options(headers)
    forbidden = HOP_BY_HOP_DEFAULT | connection_options

    clean = []

    for name, value in headers:
        if name.lower() in forbidden:
            continue

        clean.append((name, value))

    return clean


def inspect_with_waf(method: str, target: str, headers, body: bytes):
    decoded_target = unquote_plus(target)
    decoded_body = body.decode("utf-8", errors="ignore")
    decoded_headers = "\n".join(f"{k}: {v}" for k, v in headers)

    inspection_area = "\n".join([
        method,
        decoded_target,
        decoded_headers,
        decoded_body,
    ])

    for pattern in WAF_PATTERNS:
        if pattern.search(inspection_area):
            raise ValueError(f"Payload suspeito bloqueado: {pattern.pattern}")

def merge_via_headers(headers, server_name):
    existing = []

    for name, value in headers:
        if name.lower() == "via":
            existing.append(value)

    existing.append(f"1.1 {server_name}")

    return ", ".join(existing)

def build_forwarded_request(method, target, version, headers, body, client_ip):
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
    saw_xff = False

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

        if lname == "x-forwarded-for":
            final_headers.append(("X-Forwarded-For", f"{value}, {client_ip}"))
            saw_xff = True
            continue

        final_headers.append((name, value))

    if not saw_host:
        final_headers.append(("Host", f"{NEXT_HOST}:{NEXT_PORT}"))

    final_headers.append(("Via", via_value))

    if not saw_xff:
        final_headers.append(("X-Forwarded-For", client_ip))

    if not LAB_DESYNC_MODE:
        final_headers.append(("Content-Length", str(len(body))))
        final_headers.append(("Connection", "close"))
    else:
        final_headers.append(("Connection", "keep-alive"))

    request_line = f"{method} {target} {version}\r\n"
    header_block = "".join(f"{k}: {v}\r\n" for k, v in final_headers)

    return (request_line + header_block + "\r\n").encode("iso-8859-1") + body

def forward_to_next(request_bytes: bytes) -> bytes:
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


def handle_client(conn: socket.socket, addr):
    try:
        request = read_http_request(conn)

        if request is None:
            return

        method, target, version, headers, body = request

        inspect_with_waf(method, target, headers, body)

        print("\nSecurity Proxy Recebeu:")
        print(f"Cliente: {addr[0]}:{addr[1]}")
        print(f"Request-Line: {method} {target} {version}")
        print("Headers:")
        for h in headers:
            print(h)
        print(f"Body: {len(body)} bytes\n")

        forwarded_request = build_forwarded_request(
            method,
            target,
            version,
            headers,
            body,
            addr[0],
        )

        print("\nSecurity Proxy Enviando:")
        print(f"Destino: {NEXT_HOST}:{NEXT_PORT}")
        print(forwarded_request.decode("iso-8859-1", errors="replace"))
        print("\n")

        response = forward_to_next(forwarded_request)
        conn.sendall(response)

    except Exception as exc:
        conn.sendall(
            build_error_response(
                400,
                "Bad Request",
                f"Requisição bloqueada pelo security proxy: {exc}",
            )
        )

    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy.bind((HOST, PORT))
        proxy.listen(50)

        print(f"[Security Proxy] ouvindo em {HOST}:{PORT}")

        while True:
            conn, addr = proxy.accept()
            threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True,
            ).start()


if __name__ == "__main__":
    main()
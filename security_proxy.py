import socket
import threading
from urllib.parse import urlsplit


HOST = "127.0.0.1"
PORT = 8092

MAX_HEADER_BYTES = 16 * 1024
MAX_BODY_BYTES = 64 * 1024
MAX_PATH_LEN = 2048

BLOCKED_HEADER_NAMES = {
    "x-original-url",
    "x-rewrite-url",
}

SUSPICIOUS_PATTERNS = [
    "../",
    "..\\",
    "<script",
    "' or 1=1",
    "\" or 1=1",
    "union select",
    "sleep(",
    "benchmark(",
]


def recv_until(sock: socket.socket, marker: bytes, max_bytes: int | None = None):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if max_bytes is not None and len(data) > max_bytes:
            raise ValueError("Cabeçalho maior que o permitido")
    return data


def parse_header_lines(header_bytes: bytes):
    text = header_bytes.decode("iso-8859-1")
    lines = text.split("\r\n")
    start_line = lines[0]

    headers = []
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))

    return start_line, headers


def headers_to_dict(headers):
    return {k.lower(): v for k, v in headers}


def read_chunked_body(sock: socket.socket, initial_rest: bytes):
    data = initial_rest
    body = b""

    while True:
        while b"\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão encerrada durante leitura do chunk size")
            data += chunk

        line, data = data.split(b"\r\n", 1)
        chunk_size = int(line.decode("ascii").strip(), 16)

        if chunk_size == 0:
            while len(data) < 2:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("Conexão encerrada antes do fim do chunked body")
                data += chunk

            if data[:2] != b"\r\n":
                raise ValueError("Formato chunked inválido")
            data = data[2:]
            break

        if len(body) + chunk_size > MAX_BODY_BYTES:
            raise ValueError("Body maior que o permitido")

        while len(data) < chunk_size + 2:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão encerrada durante leitura do chunk")
            data += chunk

        body += data[:chunk_size]

        if data[chunk_size:chunk_size + 2] != b"\r\n":
            raise ValueError("Chunk sem CRLF final")

        data = data[chunk_size + 2:]

    return body


def read_http_request(conn: socket.socket):
    raw = recv_until(conn, b"\r\n\r\n", max_bytes=MAX_HEADER_BYTES)
    if not raw:
        return None

    if b"\r\n\r\n" not in raw:
        raise ValueError("Cabeçalho HTTP incompleto")

    header_part, rest = raw.split(b"\r\n\r\n", 1)
    request_line, headers = parse_header_lines(header_part)
    header_dict = headers_to_dict(headers)

    content_length = header_dict.get("content-length")
    transfer_encoding = header_dict.get("transfer-encoding", "").lower()

    if content_length and "chunked" in transfer_encoding:
        raise ValueError("Content-Length e Transfer-Encoding juntos")

    if "chunked" in transfer_encoding:
        body = read_chunked_body(conn, rest)
    elif content_length is not None:
        length = int(content_length)
        if length > MAX_BODY_BYTES:
            raise ValueError("Body maior que o permitido")
        body = rest
        while len(body) < length:
            chunk = conn.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão encerrada antes do body completo")
            body += chunk
        body = body[:length]
    else:
        body = b""

    return request_line, headers, body


def read_http_response(sock: socket.socket):
    raw = recv_until(sock, b"\r\n\r\n", max_bytes=MAX_HEADER_BYTES)
    if not raw:
        return None

    if b"\r\n\r\n" not in raw:
        raise ValueError("Cabeçalho HTTP incompleto")

    header_part, rest = raw.split(b"\r\n\r\n", 1)
    status_line, headers = parse_header_lines(header_part)
    header_dict = headers_to_dict(headers)

    content_length = header_dict.get("content-length")
    transfer_encoding = header_dict.get("transfer-encoding", "").lower()

    if content_length and "chunked" in transfer_encoding:
        raise ValueError("Content-Length e Transfer-Encoding juntos")

    if "chunked" in transfer_encoding:
        body = read_chunked_body(sock, rest)
    elif content_length is not None:
        length = int(content_length)
        body = rest
        while len(body) < length:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão encerrada antes do body completo")
            body += chunk
        body = body[:length]
    else:
        body = rest

    return status_line, headers, body


def rebuild_http_message(start_line: str, headers, body: bytes):
    data = start_line + "\r\n"
    for name, value in headers:
        data += f"{name}: {value}\r\n"
    data += "\r\n"
    return data.encode("iso-8859-1") + body


def build_error_response(status_code: int, reason: str, body: str, keep_alive: bool = False):
    body_bytes = body.encode("utf-8")
    connection_value = "keep-alive" if keep_alive else "close"
    return (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: {connection_value}\r\n"
        f"\r\n"
    ).encode("iso-8859-1") + body_bytes


def inspect_request(request_line: str, headers, body: bytes):
    parts = request_line.split(" ")
    if len(parts) != 3:
        return 400, "Bad Request", "Request-Line inválida"

    method, target, version = parts

    if version != "HTTP/1.1":
        return 400, "Bad Request", "Somente HTTP/1.1 é aceito neste lab"

    if method.upper() not in {"GET", "POST", "HEAD", "OPTIONS"}:
        return 405, "Method Not Allowed", f"Método não permitido: {method}"

    parsed = urlsplit(target)

    if not parsed.scheme or not parsed.hostname:
        return 400, "Bad Request", "O alvo deve estar em absolute-form"

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if len(path) > MAX_PATH_LEN:
        return 414, "URI Too Long", "Path maior que o permitido"

    header_dict = headers_to_dict(headers)

    for header_name in header_dict:
        if header_name in BLOCKED_HEADER_NAMES:
            return 403, "Forbidden", f"Header bloqueado: {header_name}"

    content_type = header_dict.get("content-type", "").lower()
    inspected_text = (path + "\n" + body.decode("utf-8", errors="replace")).lower()

    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in inspected_text:
            return 403, "Forbidden", f"Padrão suspeito detectado: {pattern}"

    if "application/x-www-form-urlencoded" in content_type and len(body) > MAX_BODY_BYTES:
        return 413, "Payload Too Large", "Body maior que o permitido"

    return None


def build_forwarded_request(request_line: str, headers, body: bytes, client_ip: str):
    parts = request_line.split(" ")
    method, target, version = parts
    parsed = urlsplit(target)

    upstream_host = parsed.hostname
    upstream_port = parsed.port or 80

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    new_request_line = f"{method} {path} {version}"

    filtered_headers = []
    saw_host = False
    saw_xff = False

    for name, value in headers:
        lname = name.lower()

        if lname == "proxy-connection":
            continue

        if lname == "host":
            filtered_headers.append(("Host", f"{upstream_host}:{upstream_port}"))
            saw_host = True
            continue

        if lname == "x-forwarded-for":
            saw_xff = True
            filtered_headers.append((name, value))
            continue

        filtered_headers.append((name, value))

    if not saw_host:
        filtered_headers.append(("Host", f"{upstream_host}:{upstream_port}"))

    filtered_headers.append(("Via", "1.1 python-security-proxy"))
    filtered_headers.append(("X-Security-Proxy", "python-lab"))

    if not saw_xff:
        filtered_headers.append(("X-Forwarded-For", client_ip))

    return upstream_host, upstream_port, rebuild_http_message(new_request_line, filtered_headers, body)


def forward_request_to_upstream(host: str, port: int, request_bytes: bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
        upstream.connect((host, port))
        upstream.sendall(request_bytes)

        response = read_http_response(upstream)
        if response is None:
            raise ConnectionError("Upstream fechou sem responder")

        status_line, headers, body = response
        return rebuild_http_message(status_line, headers, body)


def handle_client(conn: socket.socket, addr):
    try:
        while True:
            request = read_http_request(conn)
            if request is None:
                break

            request_line, headers, body = request
            header_dict = headers_to_dict(headers)

            inspection_result = inspect_request(request_line, headers, body)
            if inspection_result is not None:
                status_code, reason, message = inspection_result
                print(f"[Security block] {addr[0]}:{addr[1]} | {request_line} | {message}")
                keep_alive = header_dict.get("connection", "").lower() != "close"
                conn.sendall(build_error_response(status_code, reason, message, keep_alive=keep_alive))
                if not keep_alive:
                    break
                continue

            upstream_host, upstream_port, forwarded_request = build_forwarded_request(
                request_line, headers, body, addr[0]
            )

            print(f"[Security allow] {addr[0]}:{addr[1]} -> {upstream_host}:{upstream_port} | {request_line}")

            upstream_response = forward_request_to_upstream(
                upstream_host, upstream_port, forwarded_request
            )

            conn.sendall(upstream_response)

            if header_dict.get("connection", "").lower() == "close":
                break

    except Exception as exc:
        conn.sendall(build_error_response(400, "Bad Request", f"Erro no security proxy: {exc}", keep_alive=False))
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy.bind((HOST, PORT))
        proxy.listen(50)
        print(f"[Security proxy] ouvindo em {HOST}:{PORT}")

        while True:
            conn, addr = proxy.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
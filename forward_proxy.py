import socket
import threading
from urllib.parse import urlsplit

HOST = "127.0.0.1"
PORT = 8080


def recv_until(sock: socket.socket, marker: bytes):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break 
        data += chunk
    return data


def parse_headers(header_bytes: bytes):
    text = header_bytes.decode("iso-8859-1")
    lines = text.split("\r\n")
    request_line = lines[0]

    headers = []
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))

    return request_line, headers


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
    raw = recv_until(conn, b"\r\n\r\n")
    if not raw:
        return None

    if b"\r\n\r\n" not in raw:
        raise ValueError("Cabeçalho HTTP incompleto")

    header_part, rest = raw.split(b"\r\n\r\n", 1)
    request_line, headers = parse_headers(header_part)
    header_dict = headers_to_dict(headers)

    content_length = header_dict.get("content-length")
    transfer_encoding = header_dict.get("transfer-encoding", "").lower()

    if content_length and "chunked" in transfer_encoding:
        raise ValueError("Content-Length e Transfer-Encoding juntos")

    body = b""

    if "chunked" in transfer_encoding:
        body = read_chunked_body(conn, rest)
    elif content_length is not None:
        length = int(content_length)
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


def build_error_response(status_code: int, reason: str, body: str):
    body_bytes = body.encode("utf-8")
    return (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("iso-8859-1") + body_bytes


def forward_request_to_backend(host: str, port: int, request_bytes: bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
        upstream.connect((host, port))
        upstream.sendall(request_bytes)

        response = b""
        while True:
            chunk = upstream.recv(4096)
            if not chunk:
                break
            response += chunk
        return response


def build_forwarded_request(request_line: str, headers, body: bytes, client_ip: str):
    parts = request_line.split(" ")
    if len(parts) != 3:
        raise ValueError("Request-Line inválida")

    method, target, version = parts

    parsed = urlsplit(target)

    if not parsed.scheme or not parsed.hostname:
        raise ValueError("O alvo deve estar em absolute-form")

    backend_host = parsed.hostname
    backend_port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    new_request_line = f"{method} {path} {version}\r\n"

    filtered_headers = []
    saw_host = False

    for name, value in headers:
        lname = name.lower()

        if lname in ("proxy-connection",):
            continue

        if lname == "host":
            saw_host = True
            filtered_headers.append((name, value))
            continue

        if lname == "connection":
            filtered_headers.append(("Connection", "close"))
            continue

        filtered_headers.append((name, value))

    if not saw_host:
        host_value = backend_host if backend_port == 80 else f"{backend_host}:{backend_port}"
        filtered_headers.append(("Host", host_value))

    filtered_headers.append(("Via", "1.1 python-forward-proxy"))
    filtered_headers.append(("X-Forwarded-For", client_ip))

    header_block = "".join(f"{k}: {v}\r\n" for k, v in filtered_headers)
    full_request = (new_request_line + header_block + "\r\n").encode("iso-8859-1") + body

    return backend_host, backend_port, full_request


def handle_client(conn: socket.socket, addr):
    try:
        request = read_http_request(conn)
        if request is None:
            return

        request_line, headers, body = request
        backend_host, backend_port, forwarded_request = build_forwarded_request(
            request_line, headers, body, addr[0]
        )
        response = forward_request_to_backend(backend_host, backend_port, forwarded_request)
        conn.sendall(response)

    except Exception as exc:
        conn.sendall(build_error_response(400, "Bad Request", f"Erro no forward proxy: {exc}"))
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy.bind((HOST, PORT))
        proxy.listen(50)
        print(f"[Forward Proxy] ouvindo em {HOST}:{PORT}")

        while True:
            conn, addr = proxy.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
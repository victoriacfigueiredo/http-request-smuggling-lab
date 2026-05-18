import socket
import threading

HOST = "127.0.0.1"
PORT = 8091

SERVIDORES = [
    ("127.0.0.1", 8081),
    ("127.0.0.1", 8082),
    ("127.0.0.1", 8083),
]

server_index = 0
server_lock = threading.Lock()


def get_next_server():
    global server_index
    with server_lock:
        server = SERVIDORES[server_index]
        server_index = (server_index + 1) % len(SERVIDORES)
        return server


def recv_until(sock: socket.socket, marker: bytes):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
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
    raw = recv_until(sock, b"\r\n\r\n")
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


def build_forwarded_request(request_line, headers, body, backend_host, backend_port):
    method, path, version = request_line.split(" ")

    filtered_headers = []
    saw_host = False

    for name, value in headers:
        lname = name.lower()

        if lname == "proxy-connection":
            continue

        if lname == "host":
            filtered_headers.append((name, value))  
            saw_host = True
            continue

        filtered_headers.append((name, value))

    if not saw_host:
        filtered_headers.append(("Host", f"{backend_host}:{backend_port}"))

    filtered_headers.append(("X-Load-Balancer", "python-reverse-lb"))

    new_request_line = f"{method} {path} {version}"

    return rebuild_http_message(new_request_line, filtered_headers, body)

def forward_request(host: str, port: int, request_bytes: bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(request_bytes)

        response = read_http_response(s)
        if response is None:
            raise ConnectionError("Servidor fechou sem responder")

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

            backend_host, backend_port = get_next_server()
            print(f"[LB] {addr} -> {backend_host}:{backend_port}")

            forwarded = build_forwarded_request(
                request_line, headers, body, backend_host, backend_port
            )

            response_bytes = forward_request(backend_host, backend_port, forwarded)
            conn.sendall(response_bytes)

            if header_dict.get("connection", "").lower() == "close":
                break

    except Exception as e:
        body = f"Erro no load balancer: {e}".encode("utf-8")
        error_response = (
            f"HTTP/1.1 400 Bad Request\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("iso-8859-1") + body
        conn.sendall(error_response)
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(50)

        print(f"[LOAD BALANCER] {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
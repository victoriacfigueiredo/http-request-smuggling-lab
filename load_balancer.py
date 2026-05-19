import socket
import threading
from urllib.parse import urlsplit

HOST = "127.0.0.1"
PORT = 8082

SERVERS = [
    ("127.0.0.1", 9001),
    ("127.0.0.1", 9002),
    ("127.0.0.1", 9003),
]

SERVER_NAME = "Load Balancer"

MAX_HEADER_SIZE = 64 * 1024
MAX_BODY_SIZE = 5 * 1024 * 1024

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

server_index = 0
server_lock = threading.Lock()

class BufferedSocket:
    def __init__(self, sock: socket.socket, initial_buffer=b""):
        self.sock = sock
        self.buffer = initial_buffer

    def recv(self, n: int):
        if self.buffer:
            data = self.buffer[:n]
            self.buffer = self.buffer[n:]
            return data

        return self.sock.recv(n)

    def sendall(self, data: bytes):
        self.sock.sendall(data)

    def close(self):
        self.sock.close()


def pick_server():
    global server_index

    with server_lock:
        server = SERVERS[server_index]
        server_index = (server_index + 1) % len(SERVERS)

    return server


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

    start_line = lines[0]
    headers = []

    for line in lines[1:]:
        if line == "":
            continue

        if line.startswith((" ", "\t")):
            raise ValueError("obs-fold rejeitado")

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

    return start_line, headers


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

    if not method:
        raise ValueError("Método vazio")

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


def validate_framing(headers):
    cls = get_all(headers, "content-length")
    tes = get_all(headers, "transfer-encoding")

    if cls and tes and not LAB_DESYNC_MODE:
        raise ValueError("TE + CL bloqueado")

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

            return body, data

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
    validate_framing(headers)

    cls = get_all(headers, "content-length")
    tes = get_all(headers, "transfer-encoding")

    body = b""

    leftover = b""

    if tes:
        body, leftover = read_chunked_body(conn, rest)

    elif cls:
        length = int(cls[0])
        body = rest

        while len(body) < length:
            chunk = conn.recv(4096)

            if not chunk:
                raise ConnectionError("Conexão encerrada antes do body completo")

            body += chunk
        leftover = body[length:]
        body = body[:length]
    
    else: 
        leftover = rest
        body = b""

    return method, target, version, headers, body, leftover


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

def merge_via_headers(headers, server_name):
    existing = []

    for name, value in headers:
        if name.lower() == "via":
            existing.append(value)

    existing.append(f"1.1 {server_name}")

    return ", ".join(existing)

def build_forwarded_request(
    method,
    target,
    version,
    headers,
    body,
    backend_host,
    backend_port,
    client_ip,
):
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
            final_headers.append(("Host", f"{backend_host}:{backend_port}"))
            saw_host = True
            continue

        if lname == "content-length":
            continue

        if lname == "x-forwarded-for":
            final_headers.append(("X-Forwarded-For", f"{value}, {client_ip}"))
            saw_xff = True
            continue

        final_headers.append((name, value))

    if not saw_host:
        final_headers.append(("Host", f"{backend_host}:{backend_port}"))

    final_headers.append(("Via", via_value))

    if not saw_xff:
        final_headers.append(("X-Forwarded-For", client_ip))

    final_headers.append(("Content-Length", str(len(body))))
    final_headers.append(("Connection", "close"))

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

def forward_to_backend(host: str, port: int, request_bytes: bytes):
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


def handle_client(conn: socket.socket, addr):
    conn = BufferedSocket(conn)
    try:
        while True:
            request = read_http_request(conn)

            if request is None:
                return

            method, target, version, headers, body, leftover = request

            backend_host, backend_port = pick_server()

            print("\nLoad Balancer Recebeu:")
            print(f"Cliente: {addr[0]}:{addr[1]}")
            print(f"Request-Line: {method} {target} {version}")
            print(f"Servidor escolhido: {backend_host}:{backend_port}")
            print(f"Body: {len(body)} bytes\n")

            forwarded_request = build_forwarded_request(
                method,
                target,
                version,
                headers,
                body,
                backend_host,
                backend_port,
                addr[0],
            )

            print("\nLoad Balancer Enviando:")
            print(forwarded_request.decode("iso-8859-1", errors="replace"))
            print("\n")

            response = forward_to_backend(
                backend_host,
                backend_port,
                forwarded_request,
            )

            conn.sendall(response)
            if leftover:
                conn.buffer = leftover + conn.buffer

            connection_values = get_all(headers, "connection")
            connection_tokens = []

            for value in connection_values:
                for item in value.split(","):
                    connection_tokens.append(item.strip().lower())

            if "close" in connection_tokens:
                break

    except Exception as exc:
        conn.sendall(
            build_error_response(
                400,
                "Bad Request",
                f"Erro no load balancer: {exc}",
            )
        )

    finally:
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as lb:
        lb.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lb.bind((HOST, PORT))
        lb.listen(50)

        print(f"[Load Balancer] ouvindo em {HOST}:{PORT}")
        while True:
            conn, addr = lb.accept()

            threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True,
            ).start()


if __name__ == "__main__":
    main()
import socket
import threading
import time


HOST = "127.0.0.1"
PORT = 8090

CACHE = {}
CACHE_LOCK = threading.Lock()


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

def rebuild_http_response(status_line: str, headers, body: bytes):
    header_block = status_line + "\r\n"
    for name, value in headers:
        header_block += f"{name}: {value}\r\n"
    header_block += "\r\n"
    return header_block.encode("iso-8859-1") + body

def should_cache_request(method: str, request_headers_dict: dict):
    if method.upper() != "GET":
        return False

    cache_control = request_headers_dict.get("cache-control", "").lower()
    pragma = request_headers_dict.get("pragma", "").lower()

    if "no-store" in cache_control or "no-cache" in cache_control:
        return False

    if "no-cache" in pragma:
        return False

    return True


def extract_response_headers(response_bytes: bytes):
    if b"\r\n\r\n" not in response_bytes:
        raise ValueError("Resposta HTTP incompleta")

    header_part, body = response_bytes.split(b"\r\n\r\n", 1)
    status_line, headers = parse_header_lines(header_part)
    return status_line, headers, body


def get_status_code(status_line: str):
    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        raise ValueError("Status-Line invalida")
    return int(parts[1])


def parse_max_age(cache_control_value: str):
    directives = [x.strip() for x in cache_control_value.split(",")]
    for directive in directives:
        if directive.startswith("max-age="):
            raw = directive.split("=", 1)[1].strip()
            if raw.isdigit():
                return int(raw)
    return None


def should_cache_response(status_code: int, response_headers_dict: dict):
    if status_code != 200:
        return False

    cache_control = response_headers_dict.get("cache-control", "").lower()

    if "no-store" in cache_control or "private" in cache_control:
        return False

    return True


def compute_expiry(response_headers_dict: dict):
    cache_control = response_headers_dict.get("cache-control", "").lower()
    max_age = parse_max_age(cache_control)

    if max_age is not None:
        return time.time() + max_age

    return time.time() + 300


def build_cache_key(method: str, target: str):
    return f"{method.upper()} {target.strip()}"


def add_or_replace_header(response_bytes: bytes, header_name: str, header_value: str):
    if b"\r\n\r\n" not in response_bytes:
        return response_bytes

    header_part, body = response_bytes.split(b"\r\n\r\n", 1)
    status_line, headers = parse_header_lines(header_part)

    new_headers = []
    replaced = False

    for name, value in headers:
        if name.lower() == header_name.lower():
            new_headers.append((header_name, header_value))
            replaced = True
        else:
            new_headers.append((name, value))

    if not replaced:
        new_headers.append((header_name, header_value))

    rebuilt = status_line + "\r\n"
    for name, value in new_headers:
        rebuilt += f"{name}: {value}\r\n"
    rebuilt += "\r\n"

    return rebuilt.encode("iso-8859-1") + body

def build_forwarded_request(request_line, headers, body, client_ip):
    method, path, version = request_line.split(" ")
    upstream_host = "127.0.0.1"
    upstream_port = 8081

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
        filtered_headers.append(("Host", f"{upstream_host}:{upstream_port}"))

    filtered_headers.append(("Via", "1.1 python-reverse-cache"))
    filtered_headers.append(("X-Forwarded-For", client_ip))

    new_request_line = f"{method} {path} {version}\r\n"
    header_block = "".join(f"{k}: {v}\r\n" for k, v in filtered_headers)

    return method, path, upstream_host, upstream_port, (new_request_line + header_block + "\r\n").encode("iso-8859-1") + body

def forward_request_to_upstream(host: str, port: int, request_bytes: bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
        upstream.connect((host, port))
        upstream.sendall(request_bytes)

        response = read_http_response(upstream)
        if response is None:
            raise ConnectionError("Upstream fechou sem responder")

        status_line, headers, body = response
        return rebuild_http_response(status_line, headers, body)


def get_cached_response(cache_key: str):
    with CACHE_LOCK:
        entry = CACHE.get(cache_key)

        if entry is None:
            print(f"[Cache lookup] key={cache_key!r} -> nao encontrou")
            return None

        now = time.time()
        print(f"[Cache lookup] key={cache_key!r} -> encontrou expires_at={entry['expires_at']}, now={now}")

        if now >= entry["expires_at"]:
            print(f"[Cache lookup] key={cache_key!r} -> expirado")
            del CACHE[cache_key]
            return None

        print(f"[Cache lookup] key={cache_key!r} -> hit")
        return entry["response"]

def save_cached_response(cache_key: str, response_bytes: bytes, expires_at: float):
    with CACHE_LOCK:
        CACHE[cache_key] = {
            "response": response_bytes,
            "expires_at": expires_at,
        }
        print(f"[Cache save] key={cache_key!r} salvo. expires_at={expires_at}. total_keys={list(CACHE.keys())}")


def handle_client(conn: socket.socket, addr):
    try:
        while True:
            request = read_http_request(conn)
            if request is None:
                print(f"Client: conexão encerrada por {addr[0]}:{addr[1]}")
                break

            request_line, headers, body = request
            request_headers_dict = headers_to_dict(headers)

            method, path, upstream_host, upstream_port, forwarded_request = build_forwarded_request(
                request_line, headers, body, addr[0]
            )

            key = build_cache_key(method, path.strip())
            print(f"Request: key addr={addr[0]}:{addr[1]} key={key!r}")

            cached_response = None
            if should_cache_request(method, request_headers_dict):
                cached_response = get_cached_response(key)
            else:
                print(f"[Cache decision] request nao cacheavel | method={method!r}")

            if cached_response is not None:
                print(f"[Cache hit] {addr[0]}:{addr[1]} | {key}")
                response_to_client = add_or_replace_header(cached_response, "X-Cache", "HIT")
                conn.sendall(response_to_client)

                if request_headers_dict.get("connection", "").lower() == "close":
                    break
                continue

            print(f"[Cache miss] {addr[0]}:{addr[1]} | {key}")

            upstream_response = forward_request_to_upstream(
                upstream_host, upstream_port, forwarded_request
            )

            response_to_client = add_or_replace_header(upstream_response, "X-Cache", "MISS")

            if should_cache_request(method, request_headers_dict):
                status_line, response_headers, _ = extract_response_headers(upstream_response)
                response_headers_dict = headers_to_dict(response_headers)
                status_code = get_status_code(status_line)

                response_cacheable = should_cache_response(status_code, response_headers_dict)
                print(f"[Cache decision] status_code={status_code} cacheavel={response_cacheable}")

                if response_cacheable:
                    expires_at = compute_expiry(response_headers_dict)
                    save_cached_response(key, upstream_response, expires_at)
                else:
                    print(f"[Cache decision] resposta nao cacheavel | headers={response_headers_dict}")

            conn.sendall(response_to_client)

            if request_headers_dict.get("connection", "").lower() == "close":
                break

    except Exception as exc:
        print(f"[Erro] {exc}")
        conn.sendall(build_error_response(400, "Bad Request", f"Erro no caching proxy: {exc}"))
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy.bind((HOST, PORT))
        proxy.listen(50)
        print(f"[Cache] ouvindo em {HOST}:{PORT}")

        while True:
            conn, addr = proxy.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
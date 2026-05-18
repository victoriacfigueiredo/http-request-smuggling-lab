import socket
import threading
from urllib.parse import urlsplit

HOST = "127.0.0.1"
PORT = 8082


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

    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    return request_line, headers


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

    content_length = headers.get("content-length")
    transfer_encoding = headers.get("transfer-encoding", "").lower()

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


def build_response(status_code: int, reason: str, body: str, keep_alive=True):
    body_bytes = body.encode("utf-8")
    connection_value = "keep-alive" if keep_alive else "close"

    response = (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: {connection_value}\r\n"
        f"\r\n"
    ).encode("iso-8859-1") + body_bytes

    return response


def handle_client(conn: socket.socket, addr):
    try:
        while True:
            request = read_http_request(conn)
            if request is None:
                break

            request_line, headers, body = request

            parts = request_line.split(" ")
            if len(parts) != 3:
                conn.sendall(build_response(400, "Bad Request", "Request-Line inválida"))
                break

            method, target, version = parts

            parsed = urlsplit(target)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            response_body = (
                "Servidor Recebeu:\n"
                f"Cliente TCP: {addr[0]}:{addr[1]}\n"
                f"Método: {method}\n"
                f"Target: {target}\n"
                f"Path: {path}\n\n"
            )

            for k, v in headers.items():
                response_body += f"{k}: {v}\n"

            response_body += f"\nBody:\n{body.decode(errors='replace')}"
            connection_header = headers.get("connection", "").lower()
            keep_alive = connection_header != "close"

            response = build_response(
                200,
                "OK",
                response_body,
                keep_alive=keep_alive
            )

            conn.sendall(response)

            if not keep_alive:
                break

    except Exception as exc:
        conn.sendall(build_response(400, "Bad Request", str(exc), keep_alive=False))
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(50)
        print(f"[Servidor 2] ouvindo em {HOST}:{PORT}")

        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
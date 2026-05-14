import socket

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8090


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
    start_line = lines[0]

    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    return start_line, headers


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
                raise ValueError("Formato chunked inválido no fim da resposta")
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


def read_http_response(sock: socket.socket):
    raw = recv_until(sock, b"\r\n\r\n")
    if not raw:
        return None

    if b"\r\n\r\n" not in raw:
        raise ValueError("Cabeçalho HTTP incompleto")

    header_part, rest = raw.split(b"\r\n\r\n", 1)
    status_line, headers = parse_headers(header_part)

    content_length = headers.get("content-length")
    transfer_encoding = headers.get("transfer-encoding", "").lower()

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


def format_response(status_line: str, headers: dict, body: bytes) -> str:
    lines = [status_line]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(body.decode("utf-8", errors="replace"))
    return "\n".join(lines)


def main():
    print("Digite EXIT para encerrar o cliente.\n")
    print("Insira uma requisição HTTP/1.1 seguindo esse modelo:")
    print("GET /?x=1 HTTP/1.1")
    print("Host: 127.0.0.1:8082")
    print("Connection: keep-alive")
    print()
    print("END")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((PROXY_HOST, PROXY_PORT))

        while True:
            lines = []
            while True:
                line = input()
                if line == "EXIT":
                    return
                if line == "END":
                    break
                lines.append(line)

            if not lines:
                continue

            raw_request = "\r\n".join(lines) + "\r\n\r\n"
            client.sendall(raw_request.encode("iso-8859-1"))

            response = read_http_response(client)
            if response is None:
                print("\n[Servidor fechou a conexão]")
                break

            status_line, headers, body = response

            print("\nResposta do Servidor:")
            print(format_response(status_line, headers, body))

            if headers.get("connection", "").lower() == "close":
                print("\n[Servidor pediu fechamento da conexão]")
                break


if __name__ == "__main__":
    main()
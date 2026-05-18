import socket

HOST = "127.0.0.1"
PORT = 8000


def recv_until(sock, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def read_http_response(sock):
    raw = recv_until(sock, b"\r\n\r\n")

    if not raw:
        return None

    header_part, rest = raw.split(b"\r\n\r\n", 1)
    header_text = header_part.decode("iso-8859-1", errors="replace")

    lines = header_text.split("\r\n")
    status_line = lines[0]

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

    content_length = headers.get("content-length")

    body = rest
    if content_length is not None:
        length = int(content_length)
        while len(body) < length:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body += chunk
        body = body[:length]

    return status_line, headers, body


def read_request_from_terminal():
    print("\nDigite a requisição HTTP linha por linha.")
    print("Finalize com uma linha contendo apenas: END")
    print("Digite EXIT para sair.\n")

    lines = []
    while True:
        line = input()
        if line == "EXIT":
            return None
        if line == "END":
            break
        lines.append(line)

    return "\r\n".join(lines) + "\r\n\r\n"


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))

    while True:
        request = read_request_from_terminal()
        if request is None:
            break

        sock.sendall(request.encode("iso-8859-1"))

        response = read_http_response(sock)
        if response is None:
            print("Servidor fechou a conexão.")
            break

        status_line, headers, body = response

        print("\n=== RESPOSTA ===\n")
        print(status_line)
        for k, v in headers.items():
            print(f"{k}: {v}")
        print()
        print(body.decode("iso-8859-1", errors="replace"))

        if headers.get("connection", "").lower() == "close":
            print("\nConexão fechada pelo servidor.")
            break
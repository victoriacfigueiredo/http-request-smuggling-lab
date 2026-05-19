import socket
import threading
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, parse_qs, unquote_plus

CRLF = b"\r\n"
HEADER_END = b"\r\n\r\n"

MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 10 * 1024 * 1024
MAX_START_LINE_LEN = 8192
MAX_HEADER_LINE_LEN = 8192
MAX_CHUNK_LINE_LEN = 1024

SERVER_NAME = "server A"

TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
HTTP_VERSION_RE = re.compile(r"^HTTP/(1\.0|1\.1)$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")


class HTTPError(Exception):
    def __init__(self, code: int, reason: str, message: str):
        self.code = code
        self.reason = reason
        self.message = message
        super().__init__(message)


@dataclass
class RequestLine:
    method: str
    target: str
    version: str


@dataclass
class Request:
    line: RequestLine
    headers: list[tuple[str, str]]
    body: bytes
    trailers: list[tuple[str, str]]
    target_form: str


class HTTPReader:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = b""

    def read_until(self, marker: bytes, limit: int):
        while marker not in self.buffer:
            if len(self.buffer) > limit:
                raise HTTPError(431, "Request Header Fields Too Large", "Limite excedido")

            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão fechada")

            self.buffer += chunk

        data, self.buffer = self.buffer.split(marker, 1)
        data += marker

        if len(data) > limit:
            raise HTTPError(431, "Request Header Fields Too Large", "Limite excedido")

        return data

    def read_exactly(self, n: int):
        if n > MAX_BODY_BYTES:
            raise HTTPError(413, "Content Too Large", "Body grande demais")

        while len(self.buffer) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Body incompleto")
            self.buffer += chunk

        data = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return data

    def read_line(self, limit: int):
        return self.read_until(CRLF, limit)


def get_values(headers: list[tuple[str, str]], name: str):
    lname = name.lower()
    return [v for k, v in headers if k.lower() == lname]


def has_header(headers: list[tuple[str, str]], name: str):
    return bool(get_values(headers, name))


def parse_comma(values: list[str]):
    result = []

    for value in values:
        for item in value.split(","):
            item = item.strip()
            if item:
                result.append(item)

    return result


def contains_bad_header_value_chars(value: str):
    for ch in value:
        o = ord(ch)

        if ch == "\t":
            continue

        if o < 0x20 or o == 0x7F:
            return True

    return False


def parse_header_section(raw: bytes):
    if not raw.endswith(HEADER_END):
        raise HTTPError(400, "Bad Request", "Header section não termina com CRLF CRLF")

    if b"\n" in raw.replace(b"\r\n", b""):
        raise HTTPError(400, "Bad Request", "LF isolado detectado")

    text = raw.decode("iso-8859-1")
    text = text[:-4]
    lines = text.split("\r\n")

    if not lines or lines[0] == "":
        raise HTTPError(400, "Bad Request", "Start-line vazia")

    start_line = lines[0]

    if len(start_line) > MAX_START_LINE_LEN:
        raise HTTPError(414, "URI Too Long", "Start-line grande demais")

    headers: list[tuple[str, str]] = []

    for line in lines[1:]:
        if line == "":
            raise HTTPError(400, "Bad Request", "Linha vazia dentro dos headers")

        if len(line) > MAX_HEADER_LINE_LEN:
            raise HTTPError(431, "Request Header Fields Too Large", "Linha de header grande demais")

        if line.startswith(" ") or line.startswith("\t"):
            raise HTTPError(400, "Bad Request", "obs-fold rejeitado")

        if ":" not in line:
            raise HTTPError(400, "Bad Request", f"Header malformado: {line!r}")

        name, value = line.split(":", 1)

        if not name:
            raise HTTPError(400, "Bad Request", "Header sem nome")

        if name != name.strip():
            raise HTTPError(400, "Bad Request", f"Whitespace inválido no nome do header: {name!r}")

        if not TOKEN_RE.match(name):
            raise HTTPError(400, "Bad Request", f"Nome de header inválido: {name!r}")

        value = value.strip(" \t")

        if contains_bad_header_value_chars(value):
            raise HTTPError(400, "Bad Request", f"Valor de header inválido: {name!r}")

        headers.append((name.lower(), value))

    return start_line, headers


def parse_request_line(start_line: str):
    parts = start_line.split(" ")

    if len(parts) != 3 or any(p == "" for p in parts):
        raise HTTPError(400, "Bad Request", f"Request-line inválida: {start_line!r}")

    method, target, version = parts

    if not TOKEN_RE.match(method):
        raise HTTPError(400, "Bad Request", f"Método inválido: {method!r}")

    if not HTTP_VERSION_RE.match(version):
        raise HTTPError(505, "HTTP Version Not Supported", f"Versão não suportada: {version!r}")

    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in target):
        raise HTTPError(400, "Bad Request", "Request-target contém caractere inválido")

    return RequestLine(method.upper(), target, version)


def validate_port(port: int):
    if not (1 <= port <= 65535):
        raise HTTPError(400, "Bad Request", "Porta fora do intervalo válido")


def parse_authority(authority: str, default_port: int = 80):
    if not authority:
        raise HTTPError(400, "Bad Request", "Authority/Host vazio")

    if "@" in authority:
        raise HTTPError(400, "Bad Request", "Userinfo não aceito")

    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise HTTPError(400, "Bad Request", "IPv6 malformado")

        host = authority[1:end]
        rest = authority[end + 1:]

        if not host:
            raise HTTPError(400, "Bad Request", "Host IPv6 vazio")

        if rest.startswith(":"):
            port_text = rest[1:]
            if not port_text.isdigit():
                raise HTTPError(400, "Bad Request", "Porta inválida")
            port = int(port_text)
        elif rest == "":
            port = default_port
        else:
            raise HTTPError(400, "Bad Request", "Authority IPv6 inválida")

        validate_port(port)
        return host, port

    if ":" in authority:
        host, port_text = authority.rsplit(":", 1)

        if not host:
            raise HTTPError(400, "Bad Request", "Host vazio")

        if not port_text.isdigit():
            raise HTTPError(400, "Bad Request", "Porta inválida")

        port = int(port_text)
    else:
        host = authority
        port = default_port

    if not host:
        raise HTTPError(400, "Bad Request", "Host vazio")

    if any(ord(c) <= 0x20 or ord(c) == 0x7F for c in host):
        raise HTTPError(400, "Bad Request", "Host contém caractere inválido")

    validate_port(port)
    return host, port


def validate_host(headers: list[tuple[str, str]], version: str):
    host_values = get_values(headers, "host")

    if version == "HTTP/1.1":
        if len(host_values) == 0:
            raise HTTPError(400, "Bad Request", "HTTP/1.1 exige Host")

        if len(host_values) > 1:
            raise HTTPError(400, "Bad Request", "Host duplicado")

        parse_authority(host_values[0], default_port=80)

    elif version == "HTTP/1.0":
        if len(host_values) > 1:
            raise HTTPError(400, "Bad Request", "Host duplicado")


def classify_request_target(req_line: RequestLine):
    target = req_line.target

    if target == "*":
        if req_line.method != "OPTIONS":
            raise HTTPError(400, "Bad Request", "asterisk-form só é válido com OPTIONS")
        return "asterisk-form"

    if req_line.method == "CONNECT":
        parse_authority(target, default_port=443)
        return "authority-form"

    if target.startswith("http://"):
        parsed = urlsplit(target)

        if parsed.scheme != "http":
            raise HTTPError(400, "Bad Request", "Somente http:// suportado")

        if not parsed.hostname:
            raise HTTPError(400, "Bad Request", "absolute-form sem host")

        if parsed.username or parsed.password:
            raise HTTPError(400, "Bad Request", "userinfo em URI não aceito")

        if parsed.port:
            validate_port(parsed.port)

        path = parsed.path or "/"

        if not path.startswith("/"):
            raise HTTPError(400, "Bad Request", "absolute-form com path inválido")

        return "absolute-form"

    if target.startswith("/"):
        return "origin-form"

    raise HTTPError(400, "Bad Request", f"Request-target inválido: {target!r}")


def validate_content_length(values: list[str]):
    if not values:
        return

    normalized = []

    for value in values:
        stripped = value.strip()

        if not stripped.isdigit():
            raise HTTPError(400, "Bad Request", f"Content-Length inválido: {value!r}")

        n = int(stripped)

        if n > MAX_BODY_BYTES:
            raise HTTPError(413, "Content Too Large", "Content-Length grande demais")

        normalized.append(str(n))

    if len(set(normalized)) != 1:
        raise HTTPError(400, "Bad Request", "Múltiplos Content-Length conflitantes")


def validate_transfer_encoding(values: list[str], is_request: bool = True):
    if not values:
        return

    codings = [c.lower() for c in parse_comma(values)]

    if not codings:
        raise HTTPError(400, "Bad Request", "Transfer-Encoding vazio")

    for coding in codings:
        if coding != "chunked":
            raise HTTPError(501, "Not Implemented", f"Transfer-Encoding não suportado: {coding!r}")

    if is_request and codings[-1] != "chunked":
        raise HTTPError(400, "Bad Request", "Transfer-Encoding final precisa ser chunked")

    if codings.count("chunked") > 1:
        raise HTTPError(400, "Bad Request", "Transfer-Encoding chunked duplicado")


HOP_BY_HOP_BASE = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
}


def get_connection_tokens(headers: list[tuple[str, str]]):
    tokens = set()

    for value in get_values(headers, "connection"):
        for token in value.split(","):
            token = token.strip().lower()
            if token:
                tokens.add(token)

    return tokens


def validate_hop_by_hop_policy(headers: list[tuple[str, str]]):
    connection_tokens = get_connection_tokens(headers)

    for token in connection_tokens:
        if not TOKEN_RE.match(token):
            raise HTTPError(400, "Bad Request", f"Token inválido em Connection: {token!r}")

    if has_header(headers, "upgrade"):
        raise HTTPError(426, "Upgrade Required", "Upgrade não implementado")


def should_close_after_response(req_line: RequestLine, headers: list[tuple[str, str]]):
    tokens = get_connection_tokens(headers)

    if "close" in tokens:
        return True

    if req_line.version == "HTTP/1.0" and "keep-alive" not in tokens:
        return True

    return False

def method_is_known(method: str):
    return method in {
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "TRACE",
        "CONNECT",
    }


def read_chunked_body(reader: HTTPReader):
    body = bytearray()
    trailers: list[tuple[str, str]] = []

    while True:
        size_line = reader.read_line(MAX_CHUNK_LINE_LEN)

        try:
            size_text = size_line[:-2].decode("ascii")
        except UnicodeDecodeError:
            raise HTTPError(400, "Bad Request", "Chunk-size não ASCII")

        size_part = size_text.split(";", 1)[0].strip()

        if not size_part:
            raise HTTPError(400, "Bad Request", "Chunk-size vazio")

        try:
            chunk_size = int(size_part, 16)
        except ValueError:
            raise HTTPError(400, "Bad Request", f"Chunk-size inválido: {size_part!r}")

        if len(body) + chunk_size > MAX_BODY_BYTES:
            raise HTTPError(413, "Content Too Large", "Body chunked grande demais")

        if chunk_size == 0:
            trailer_raw = bytearray()

            while True:
                line = reader.read_line(MAX_HEADER_LINE_LEN)

                if line == CRLF:
                    break

                trailer_raw += line

                if len(trailer_raw) > MAX_HEADER_BYTES:
                    raise HTTPError(431, "Request Header Fields Too Large", "Trailers grandes demais")
            if trailer_raw:
                fake = b"HTTP/1.1 200 OK\r\n" + bytes(trailer_raw) + b"\r\n"
                _, trailers = parse_header_section(fake)
                forbidden = {
                    "transfer-encoding",
                    "content-length",
                    "host",
                    "connection",
                    "keep-alive",
                    "upgrade",
                    "proxy-connection",
                    "te",
                    "trailer",
                }
                for name, _ in trailers:
                    if name.lower() in forbidden:
                        raise HTTPError(400, "Bad Request", f"Trailer proibido: {name}")
            return bytes(body), trailers
        chunk = reader.read_exactly(chunk_size)
        ending = reader.read_exactly(2)
        if ending != CRLF:
            raise HTTPError(400, "Bad Request", "Chunk sem CRLF final")
        body.extend(chunk)

def read_body(reader: HTTPReader, headers: list[tuple[str, str]]):
    cl = get_values(headers, "content-length")
    te = get_values(headers, "transfer-encoding")
    validate_content_length(cl)
    validate_transfer_encoding(te, is_request=True)
    if te:
        return read_chunked_body(reader)
    if cl:
        return reader.read_exactly(int(cl[0])), []
    return b"", []


def maybe_send_100_continue(conn: socket.socket, headers: list[tuple[str, str]]):
    expects = [v.lower() for v in get_values(headers, "expect")]
    for value in expects:
        if value == "100-continue":
            conn.sendall(
                b"HTTP/1.1 100 Continue\r\n"
                b"\r\n"
            )
        else:
            raise HTTPError(417, "Expectation Failed", f"Expect não suportado: {value}")


def read_request(reader: HTTPReader, conn: socket.socket):
    raw_headers = reader.read_until(HEADER_END, MAX_HEADER_BYTES)
    start_line, headers = parse_header_section(raw_headers)
    req_line = parse_request_line(start_line)
    validate_host(headers, req_line.version)
    target_form = classify_request_target(req_line)
    validate_hop_by_hop_policy(headers)
    if not method_is_known(req_line.method):
        raise HTTPError(501, "Not Implemented", f"Método não implementado: {req_line.method}")
    if req_line.method == "CONNECT":
        raise HTTPError(405, "Method Not Allowed", "CONNECT não implementado neste servidor")
    maybe_send_100_continue(conn, headers)
    body, trailers = read_body(reader, headers)
    return Request(
        line=req_line,
        headers=headers,
        body=body,
        trailers=trailers,
        target_form=target_form,
    )


def serialize_response(
    status_code: int,
    reason: str,
    body: bytes,
    request_method: str = "GET",
    extra_headers: list[tuple[str, str]] | None = None,
    close: bool = True,
    content_type: str = "text/plain; charset=utf-8",
) -> bytes:
    extra_headers = extra_headers or []
    no_body = (
        request_method.upper() == "HEAD"
        or 100 <= status_code < 200
        or status_code in (204, 304)
    )
    raw = f"HTTP/1.1 {status_code} {reason}\r\n".encode("iso-8859-1")
    headers = [
        ("server", SERVER_NAME),
        ("date", "Mon, 04 May 2026 00:00:00 GMT"),
    ]
    headers.extend(extra_headers)
    if close:
        headers.append(("connection", "close"))
    else:
        headers.append(("connection", "keep-alive"))
    if not no_body:
        headers.append(("content-length", str(len(body))))
        headers.append(("content-type", content_type))
    for name, value in headers:
        raw += f"{name}: {value}\r\n".encode("iso-8859-1")
    raw += CRLF
    if not no_body:
        raw += body
    return raw

def response_for_request(req: Request, close: bool):
    method = req.line.method
    target = req.line.target
    parsed = urlsplit(target)
    path = parsed.path or "/"
    query = parse_qs(parsed.query)
    if method == "OPTIONS" and target == "*":
        body = (
            "OK OPTIONS *\n"
            "Allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE\n"
        ).encode("utf-8")
        return serialize_response(
            200,
            "OK",
            body,
            request_method=method,
            extra_headers=[
                ("allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE")
            ],
            close=close,
        )
    if method == "TRACE":
        reconstructed = (
            f"{req.line.method} "
            f"{req.line.target} "
            f"{req.line.version}\r\n"
        ).encode("iso-8859-1")

        for k, v in req.headers:
            reconstructed += f"{k}: {v}\r\n".encode("iso-8859-1")

        reconstructed += CRLF + req.body

        return serialize_response(
            200,
            "OK",
            reconstructed,
            request_method=method,
            extra_headers=[("content-type", "message/http")],
            close=close,
        )
    if path == "/no-content":
        return serialize_response(
            204,
            "No Content",
            b"",
            request_method=method,
            close=close,
        )
    if path == "/secret-fragment":
        body = b"""
<div>
    SECRET INTERNAL DATA FROM BACKEND
</div>
"""
        return serialize_response(
            200,
            "OK",
            body,
            request_method=method,
            close=close,
            content_type="text/html; charset=utf-8",
        )
    if path == "/reflect":
        q = query.get("q", [""])[0]
        q = unquote_plus(q)
        body = f"""
<html>
    <body>
        <h1>Reflect page</h1>

        <p>Conteudo refletido:</p>

        {q}
    </body>
</html>
""".encode("utf-8")
        return serialize_response(
            200,
            "OK",
            body,
            request_method=method,
            close=close,
            content_type="text/html; charset=utf-8",
        )

    if path == "/page-with-esi":
        body = b"""
<html>
    <body>
        <h1>Pagina com ESI legitimo</h1>

        <esi:include src="/secret-fragment" />
    </body>
</html>
"""
        return serialize_response(
            200,
            "OK",
            body,
            request_method=method,
            close=close,
            content_type="text/html; charset=utf-8",
        )
    body = (
        f"OK\n"
        f"method={req.line.method}\n"
        f"target={req.line.target}\n"
        f"target_form={req.target_form}\n"
        f"version={req.line.version}\n"
        f"body_len={len(req.body)}\n"
        f"body={req.body!r}\n"
        f"trailers={req.trailers!r}\n"
    ).encode("utf-8")
    return serialize_response(
        200,
        "OK",
        body,
        request_method=method,
        close=close,
    )

def build_error_response(code: int, reason: str, message: str):
    body = message.encode("utf-8", errors="replace")
    return serialize_response(
        code,
        reason,
        body,
        request_method="GET",
        close=True,
    )


def handle_client(conn: socket.socket, addr):
    conn.settimeout(10)
    reader = HTTPReader(conn)
    try:
        while True:
            req = read_request(reader, conn)

            close = should_close_after_response(req.line, req.headers)

            print("\nServidor Recebeu:")
            print(f"{req.line.method} {req.line.target} {req.line.version}")
            print(f"target_form: {req.target_form}")
            for k, v in req.headers:
                print(f"{k}: {v}")
            print(f"body_len={len(req.body)} body={req.body!r}")
            print(f"trailers={req.trailers!r}")

            resp = response_for_request(req, close=close)
            conn.sendall(resp)

            if close:
                break
    except socket.timeout:
        try:
            conn.sendall(build_error_response(408, "Request Timeout", "Timeout lendo requisição"))
        except Exception:
            pass
    except HTTPError as e:
        try:
            conn.sendall(build_error_response(e.code, e.reason, e.message))
        except Exception:
            pass
    except ConnectionError:
        pass

    except Exception as e:
        try:
            conn.sendall(build_error_response(500, "Internal Server Error", str(e)))
        except Exception:
            pass
    finally:
        conn.close()

def main():
    host = "127.0.0.1"
    port = 9001
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(50)
        print(f"[Server A] ouvindo em {host}:{port}")
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
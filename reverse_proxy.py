import socket
import threading
import select
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

CRLF = b"\r\n"
HEADER_END = b"\r\n\r\n"
MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 10 * 1024 * 1024
MAX_START_LINE_LEN = 8192
MAX_HEADER_LINE_LEN = 8192
MAX_CHUNK_SIZE_LINE_LEN = 1024

DEFAULT_UPSTREAM_HOST = "127.0.0.1"
DEFAULT_UPSTREAM_PORT = 8081
PROXY_NAME = "Reverse Proxy"

TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
HTTP_VERSION_RE = re.compile(r"^HTTP/(1\.0|1\.1)$")
STATUS_CODE_RE = re.compile(r"^[0-9]{3}$")

def contains_bad_header_value_chars(value: str) -> bool:
    for ch in value:
        o = ord(ch)
        if ch == "\t":
            continue
        if o < 0x20 or o == 0x7F:
            return True
    return False


@dataclass
class BodyInfo:
    mode: str
    length: int = 0


@dataclass
class RequestLine:
    method: str
    target: str
    version: str


@dataclass
class HTTPResponse:
    status_line: str
    headers: list[tuple[str, str]]
    body: bytes
    status_code: int


@dataclass
class UpstreamTarget:
    host: str
    port: int
    path: str
    host_header: str
    is_tunnel: bool = False


class HTTPError(Exception):
    def __init__(self, status_code: int, reason: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.reason = reason
        self.message = message


class HTTPReader:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = b""

    def read_until(self, marker: bytes, limit: int):
        while marker not in self.buffer:
            if len(self.buffer) > limit:
                raise HTTPError(431, "Request Header Fields Too Large", "Headers excederam o limite permitido")

            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão encerrada antes de encontrar o marcador")
            self.buffer += chunk

        data, self.buffer = self.buffer.split(marker, 1)
        data += marker

        if len(data) > limit:
            raise HTTPError(431, "Request Header Fields Too Large", "Headers excederam o limite permitido")

        return data

    def read_exactly(self, n: int):
        if n > MAX_BODY_BYTES:
            raise HTTPError(413, "Content Too Large", "Body maior que o limite permitido")

        while len(self.buffer) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Conexão encerrada antes de ler o body completo")
            self.buffer += chunk

            if len(self.buffer) > MAX_BODY_BYTES:
                raise HTTPError(413, "Content Too Large", "Body maior que o limite permitido")

        data = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return data

    def read_line(self, limit: int):
        return self.read_until(CRLF, limit)

def get_header_values(headers: list[tuple[str, str]], name: str):
    lname = name.lower()
    return [value for hname, value in headers if hname.lower() == lname]


def has_header(headers: list[tuple[str, str]], name: str):
    return bool(get_header_values(headers, name))


def parse_comma_list(values: list[str]):
    tokens: list[str] = []
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if item:
                tokens.append(item)
    return tokens


def parse_header_section(header_bytes: bytes):
    if not header_bytes.endswith(HEADER_END):
        raise HTTPError(400, "Bad Request", "Seção de headers não termina com CRLF CRLF")

    if b"\n" in header_bytes.replace(b"\r\n", b""):
        raise HTTPError(400, "Bad Request", "LF isolado nos headers")

    try:
        text = header_bytes.decode("iso-8859-1")
    except UnicodeDecodeError:
        raise HTTPError(400, "Bad Request", "Headers não estão em ISO-8859-1")

    text = text[:-4]
    lines = text.split("\r\n")

    if not lines or lines[0] == "":
        raise HTTPError(400, "Bad Request", "Start-line vazia")

    start_line = lines[0]

    if len(start_line) > MAX_START_LINE_LEN:
        raise HTTPError(414, "URI Too Long", "Start-line excedeu o limite")

    headers: list[tuple[str, str]] = []

    for line in lines[1:]:
        if line == "":
            raise HTTPError(400, "Bad Request", "Linha vazia dentro da seção de headers")

        if len(line) > MAX_HEADER_LINE_LEN:
            raise HTTPError(431, "Request Header Fields Too Large", "Linha de header grande demais")

        if line.startswith(" ") or line.startswith("\t"):
            raise HTTPError(400, "Bad Request", "obs-fold/linha dobrada não suportada")

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
            raise HTTPError(400, "Bad Request", f"Valor de header contém caractere de controle: {name!r}")

        headers.append((name.lower(), value))

    return start_line, headers

def parse_request_line(start_line: str):
    parts = start_line.split(" ")

    if len(parts) != 3 or any(p == "" for p in parts):
        raise HTTPError(400, "Bad Request", f"Request-line inválida: {start_line!r}")

    method, target, version = parts

    if not TOKEN_RE.match(method):
        raise HTTPError(400, "Bad Request", f"Método HTTP inválido: {method!r}")

    if not HTTP_VERSION_RE.match(version):
        raise HTTPError(505, "HTTP Version Not Supported", f"Versão HTTP não suportada: {version!r}")

    if not target:
        raise HTTPError(400, "Bad Request", "Request-target vazio")

    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in target):
        raise HTTPError(400, "Bad Request", "Request-target contém caractere inválido")

    return RequestLine(method=method.upper(), target=target, version=version)


def parse_host_port(authority: str, default_port: int):
    if not authority:
        raise HTTPError(400, "Bad Request", "Authority/Host vazio")

    if "@" in authority:
        raise HTTPError(400, "Bad Request", "Userinfo em authority não é aceito")

    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise HTTPError(400, "Bad Request", "IPv6 authority inválida")

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


def validate_port(port: int):
    if not (1 <= port <= 65535):
        raise HTTPError(400, "Bad Request", "Porta fora do intervalo 1-65535")


def normalize_absolute_path(path: str, query: str):
    result = path or "/"
    if not result.startswith("/"):
        raise HTTPError(400, "Bad Request", "absolute-form com path inválido")
    if query:
        result += "?" + query
    return result


def resolve_upstream_target(request_line: RequestLine, headers: list[tuple[str, str]]):
    target = request_line.target

    if request_line.method == "CONNECT":
        host, port = parse_host_port(target, default_port=443)
        return UpstreamTarget(
            host=host,
            port=port,
            path="",
            host_header=target,
            is_tunnel=True,
        )

    if target == "*":
        if request_line.method != "OPTIONS":
            raise HTTPError(400, "Bad Request", "asterisk-form só é válido com OPTIONS")

        host_values = get_header_values(headers, "host")
        host_header = host_values[0]

        return UpstreamTarget(
            host=DEFAULT_UPSTREAM_HOST,
            port=DEFAULT_UPSTREAM_PORT,
            path="*",
            host_header=host_header,
        )

    if target.startswith("http://"):
        parsed = urlsplit(target)

        if parsed.scheme != "http":
            raise HTTPError(400, "Bad Request", "Somente http:// suportado")

        if not parsed.hostname:
            raise HTTPError(400, "Bad Request", "absolute-form sem host")

        host_values = get_header_values(headers, "host")
        if not host_values:
            raise HTTPError(400, "Bad Request", "Host obrigatório")

        if parsed.netloc != host_values[0]:
            raise HTTPError(400, "Bad Request", "absolute-form inconsistente com Host")

        port = parsed.port or 80
        validate_port(port)

        path = normalize_absolute_path(parsed.path, parsed.query)

        return UpstreamTarget(
            host=DEFAULT_UPSTREAM_HOST,  
            port=DEFAULT_UPSTREAM_PORT,
            path=path,
            host_header=host_values[0],
        )

    if target.startswith("/"):
        host_values = get_header_values(headers, "host")
        host_header = host_values[0]
        parse_host_port(host_header, default_port=80)  

        return UpstreamTarget(
            host=DEFAULT_UPSTREAM_HOST,
            port=DEFAULT_UPSTREAM_PORT,
            path=target,
            host_header=host_header,
        )

    raise HTTPError(400, "Bad Request", f"Request-target inválido: {target!r}")

def validate_request_headers(request_line: RequestLine, headers: list[tuple[str, str]]):
    host_values = get_header_values(headers, "host")

    if request_line.version == "HTTP/1.1":
        if len(host_values) == 0:
            raise HTTPError(400, "Bad Request", "HTTP/1.1 exige header Host")
        if len(host_values) > 1:
            raise HTTPError(400, "Bad Request", "Header Host duplicado")
        if host_values[0].strip() == "":
            raise HTTPError(400, "Bad Request", "Header Host vazio")
        parse_host_port(host_values[0], default_port=80)

    content_length_values = get_header_values(headers, "content-length")
    transfer_encoding_values = get_header_values(headers, "transfer-encoding")

    validate_content_length_values(content_length_values)
    validate_transfer_encoding_values(transfer_encoding_values, is_request=True)

    if request_line.version == "HTTP/1.0" and transfer_encoding_values:
        raise HTTPError(400, "Bad Request", "Transfer-Encoding não aceito em HTTP/1.0")

    if request_line.method == "CONNECT" and (content_length_values or transfer_encoding_values):
        raise HTTPError(400, "Bad Request", "CONNECT com body não é suportado")

    if has_header(headers, "upgrade"):
        raise HTTPError(426, "Upgrade Required", "Upgrade explícito não é suportado; use CONNECT para túnel")


def validate_content_length_values(values: list[str]):
    if not values:
        return

    normalized = []
    for value in values:
        stripped = value.strip()
        if not stripped or not stripped.isdigit():
            raise HTTPError(400, "Bad Request", f"Content-Length inválido: {value!r}")
        length = int(stripped)
        if length < 0 or length > MAX_BODY_BYTES:
            raise HTTPError(413, "Content Too Large", "Content-Length fora do limite permitido")
        normalized.append(str(length))

    if len(set(normalized)) != 1:
        raise HTTPError(400, "Bad Request", "Múltiplos Content-Length conflitantes")


def validate_transfer_encoding_values(values: list[str], is_request: bool):
    if not values:
        return

    codings = [c.lower() for c in parse_comma_list(values)]

    if not codings:
        raise HTTPError(400, "Bad Request", "Transfer-Encoding vazio")

    for coding in codings:
        if coding != "chunked":
            raise HTTPError(501, "Not Implemented", f"Transfer-Encoding não suportado: {coding!r}")

    if is_request and codings[-1] != "chunked":
        raise HTTPError(400, "Bad Request", "Transfer-Encoding final precisa ser chunked")

    if codings.count("chunked") > 1:
        raise HTTPError(400, "Bad Request", "Transfer-Encoding chunked duplicado")


def determine_request_body_length(headers: list[tuple[str, str]]):
    transfer_encoding_values = get_header_values(headers, "transfer-encoding")
    content_length_values = get_header_values(headers, "content-length")

    if transfer_encoding_values:
        return BodyInfo(mode="chunked")

    if content_length_values:
        return BodyInfo(mode="content-length", length=int(content_length_values[0].strip()))

    return BodyInfo(mode="none")


def read_chunked_body(reader: HTTPReader):
    body = bytearray()
    trailers: list[tuple[str, str]] = []

    while True:
        size_line = reader.read_line(MAX_CHUNK_SIZE_LINE_LEN)
        if not size_line.endswith(CRLF):
            raise HTTPError(400, "Bad Request", "Linha de chunk inválida")

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

        if chunk_size < 0:
            raise HTTPError(400, "Bad Request", "Chunk-size negativo")

        if len(body) + chunk_size > MAX_BODY_BYTES:
            raise HTTPError(413, "Content Too Large", "Body chunked maior que o limite")

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
                    "transfer-encoding", "content-length", "host", "connection",
                    "keep-alive", "upgrade", "proxy-connection", "te", "trailer",
                }
                for name, _ in trailers:
                    if name.lower() in forbidden:
                        raise HTTPError(400, "Bad Request", f"Trailer proibido: {name}")
            break

        chunk = reader.read_exactly(chunk_size)
        ending = reader.read_exactly(2)
        if ending != CRLF:
            raise HTTPError(400, "Bad Request", "Chunk sem CRLF final")

        body.extend(chunk)

    return bytes(body), trailers


def read_request_body(reader: HTTPReader, body_info: BodyInfo):
    if body_info.mode == "none":
        return b"", []

    if body_info.mode == "content-length":
        return reader.read_exactly(body_info.length), []

    if body_info.mode == "chunked":
        return read_chunked_body(reader)

    raise HTTPError(500, "Internal Server Error", f"Modo de body desconhecido: {body_info.mode!r}")

BASE_HOP_BY_HOP_HEADERS = {
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


def remove_hop_by_hop_headers(headers: list[tuple[str, str]]):
    connection_tokens = set()

    for name, value in headers:
        if name.lower() == "connection":
            for token in value.split(","):
                token = token.strip().lower()
                if token:
                    connection_tokens.add(token)

    blocked = BASE_HOP_BY_HOP_HEADERS | connection_tokens

    return [(name, value) for name, value in headers if name.lower() not in blocked]

def build_normalized_upstream_request(
    request_line: RequestLine,
    headers: list[tuple[str, str]],
    body: bytes,
    trailers: list[tuple[str, str]],
    client_ip: str,
    upstream_target: UpstreamTarget,
):
    filtered = remove_hop_by_hop_headers(headers)
    new_headers: list[tuple[str, str]] = []

    for name, value in filtered:
        lname = name.lower()
        if lname in {"host", "content-length", "transfer-encoding", "expect"}:
            continue
        new_headers.append((name, value))

    new_headers.append(("host", upstream_target.host_header))
    new_headers.append(("via", f"1.1 {PROXY_NAME}"))
    new_headers.append(("x-forwarded-for", client_ip))
    new_headers.append(("connection", "close"))

    if body:
        new_headers.append(("content-length", str(len(body))))
    else:
        if has_header(headers, "content-length"):
            new_headers.append(("content-length", "0"))

    for name, value in trailers:
        new_headers.append((f"x-forwarded-trailer-{name}", value))

    start_line = f"{request_line.method} {upstream_target.path} {request_line.version}\r\n"
    raw = bytearray(start_line.encode("iso-8859-1"))

    for name, value in new_headers:
        raw += f"{name}: {value}\r\n".encode("iso-8859-1")

    raw += CRLF
    raw += body
    return bytes(raw)

def parse_status_line(status_line: str):
    if len(status_line) > MAX_START_LINE_LEN:
        raise HTTPError(502, "Bad Gateway", "Status-line grande demais")

    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        raise HTTPError(502, "Bad Gateway", f"Status-line inválida: {status_line!r}")

    version, code = parts[0], parts[1]

    if not HTTP_VERSION_RE.match(version):
        raise HTTPError(502, "Bad Gateway", f"Versão de resposta não suportada: {version!r}")

    if not STATUS_CODE_RE.match(code):
        raise HTTPError(502, "Bad Gateway", f"Status code inválido: {code!r}")

    return int(code)


def validate_response_headers(status_code: int, headers: list[tuple[str, str]]):
    content_length_values = get_header_values(headers, "content-length")
    transfer_encoding_values = get_header_values(headers, "transfer-encoding")

    validate_content_length_values(content_length_values)

    if transfer_encoding_values:
        validate_transfer_encoding_values(transfer_encoding_values, is_request=False)

    if transfer_encoding_values and content_length_values:
        raise HTTPError(502, "Bad Gateway", "Resposta com Transfer-Encoding e Content-Length juntos")

    if 100 <= status_code < 200 or status_code in (204, 304):
        if transfer_encoding_values:
            raise HTTPError(502, "Bad Gateway", "Resposta sem body não deve usar Transfer-Encoding")


def determine_response_body_length(status_code: int, headers: list[tuple[str, str]], request_method: str):
    if request_method.upper() == "HEAD":
        return BodyInfo(mode="none")

    if 100 <= status_code < 200 or status_code in (204, 304):
        return BodyInfo(mode="none")

    transfer_encoding_values = get_header_values(headers, "transfer-encoding")
    if transfer_encoding_values:
        return BodyInfo(mode="chunked")

    content_length_values = get_header_values(headers, "content-length")
    if content_length_values:
        return BodyInfo(mode="content-length", length=int(content_length_values[0].strip()))

    return BodyInfo(mode="until-close")


def read_response_body(reader: HTTPReader, body_info: BodyInfo):
    if body_info.mode == "none":
        return b"", []

    if body_info.mode == "content-length":
        return reader.read_exactly(body_info.length), []

    if body_info.mode == "chunked":
        return read_chunked_body(reader)

    if body_info.mode == "until-close":
        chunks: list[bytes] = []
        total = 0

        if reader.buffer:
            chunks.append(reader.buffer)
            total += len(reader.buffer)
            reader.buffer = b""

        while True:
            chunk = reader.sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                raise HTTPError(502, "Bad Gateway", "Resposta maior que o limite permitido")

        return b"".join(chunks), []

    raise HTTPError(500, "Internal Server Error", f"Modo de body desconhecido: {body_info.mode!r}")


def serialize_response(response: HTTPResponse, trailers: list[tuple[str, str]] | None = None, force_close: bool = True):
    trailers = trailers or []
    filtered = remove_hop_by_hop_headers(response.headers)
    new_headers: list[tuple[str, str]] = []

    for name, value in filtered:
        lname = name.lower()
        if lname in {"content-length", "transfer-encoding", "connection"}:
            continue
        new_headers.append((name, value))

    new_headers.append(("via", f"1.1 {PROXY_NAME}"))

    if force_close:
        new_headers.append(("connection", "close"))

    if not (100 <= response.status_code < 200 or response.status_code in (204, 304)):
        new_headers.append(("content-length", str(len(response.body))))

    for name, value in trailers:
        new_headers.append((f"x-forwarded-trailer-{name}", value))

    raw = bytearray(response.status_line.encode("iso-8859-1") + CRLF)
    for name, value in new_headers:
        raw += f"{name}: {value}\r\n".encode("iso-8859-1")
    raw += CRLF
    raw += response.body
    return bytes(raw)

def forward_to_backend(
    request_bytes: bytes,
    request_method: str,
    upstream_target: UpstreamTarget,
    client_conn: socket.socket,
):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
        upstream.settimeout(10)
        upstream.connect((upstream_target.host, upstream_target.port))
        upstream.sendall(request_bytes)
        upstream.shutdown(socket.SHUT_WR)

        reader = HTTPReader(upstream)

        while True:
            header_bytes = reader.read_until(HEADER_END, MAX_HEADER_BYTES)
            status_line, headers = parse_header_section(header_bytes)
            status_code = parse_status_line(status_line)
            validate_response_headers(status_code, headers)

            body_info = determine_response_body_length(status_code, headers, request_method)
            body, trailers = read_response_body(reader, body_info)

            response = HTTPResponse(
                status_line=status_line,
                headers=headers,
                body=body,
                status_code=status_code,
            )

            client_conn.sendall(serialize_response(response, trailers=trailers, force_close=True))

            if not (100 <= status_code < 200):
                break


def tunnel_bidirectional(client: socket.socket, upstream: socket.socket):
    sockets = [client, upstream]

    while True:
        readable, _, errored = select.select(sockets, [], sockets, 60)

        if errored:
            break

        if not readable:
            break

        for s in readable:
            other = upstream if s is client else client
            data = s.recv(4096)
            if not data:
                return
            other.sendall(data)


def is_connect_allowed(host: str, port: int):
    allowed_ports = {443, 8443, 8081}
    return port in allowed_ports


def should_close_connection(request_line: RequestLine, headers: list[tuple[str, str]]):
    connection_tokens = [t.lower() for t in parse_comma_list(get_header_values(headers, "connection"))]

    if "close" in connection_tokens:
        return True

    if request_line.version == "HTTP/1.0" and "keep-alive" not in connection_tokens:
        return True

    return False


def build_error_response(status_code: int, reason: str, body: str):
    body_bytes = body.encode("utf-8", errors="replace")
    return (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"content-type: text/plain; charset=utf-8\r\n"
        f"content-length: {len(body_bytes)}\r\n"
        f"connection: close\r\n"
        f"\r\n"
    ).encode("iso-8859-1") + body_bytes


def handle_client(conn: socket.socket, addr):
    conn.settimeout(10)
    reader = HTTPReader(conn)

    try:
        while True:
            header_bytes = reader.read_until(HEADER_END, MAX_HEADER_BYTES)
            start_line, headers = parse_header_section(header_bytes)
            request_line = parse_request_line(start_line)

            if request_line.method == "CONNECT":
                raise HTTPError(405, "Method Not Allowed", "CONNECT não é permitido em reverse proxy")

            validate_request_headers(request_line, headers)
            handle_expect_100_continue(conn, headers)
            upstream_target = resolve_upstream_target(request_line, headers)
            body_info = determine_request_body_length(headers)
            body, trailers = read_request_body(reader, body_info)

            upstream_request = build_normalized_upstream_request(
                request_line=request_line,
                headers=headers,
                body=body,
                trailers=trailers,
                client_ip=addr[0],
                upstream_target=upstream_target,
            )

            forward_to_backend(
                request_bytes=upstream_request,
                request_method=request_line.method,
                upstream_target=upstream_target,
                client_conn=conn,
            )

            if should_close_connection(request_line, headers):
                break
            break

    except socket.timeout:
        try:
            conn.sendall(build_error_response(408, "Request Timeout", "Tempo limite excedido lendo a requisição."))
        except Exception:
            pass

    except HTTPError as exc:
        try:
            conn.sendall(build_error_response(exc.status_code, exc.reason, exc.message))
        except Exception:
            pass

    except ConnectionError as exc:
        try:
            conn.sendall(build_error_response(502, "Bad Gateway", str(exc)))
        except Exception:
            pass

    except Exception as exc:
        try:
            conn.sendall(build_error_response(500, "Internal Server Error", str(exc)))
        except Exception:
            pass

    finally:
        conn.close()

def handle_expect_100_continue(conn: socket.socket, headers: list[tuple[str, str]]):
    expect_values = get_header_values(headers, "expect")

    if not expect_values:
        return

    tokens = [v.lower() for v in parse_comma_list(expect_values)]

    for token in tokens:
        if token != "100-continue":
            raise HTTPError(417, "Expectation Failed", f"Expect não suportado: {token}")

    conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

def main():
    host = "127.0.0.1"
    port = 8090

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy.bind((host, port))
        proxy.listen(50)

        print(f"[Reverse Proxy] ouvindo em {host}:{port}")

        while True:
            conn, addr = proxy.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()


if __name__ == "__main__":
    main()
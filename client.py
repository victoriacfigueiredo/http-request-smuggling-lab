import socket

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080


def main():
    print("Insira uma requisição HTTP/1.1 seguindo esse modelo:")
    print("GET http://127.0.0.1:8082/oi?x=1 HTTP/1.1")
    print("Host: 127.0.0.1:8082")
    print("Connection: close")
    print("END")

    lines = []
    while True:
        line = input()
        if line == "END":
            break
        lines.append(line)

    raw_request = "\r\n".join(lines) + "\r\n\r\n"
    request_bytes = raw_request.encode("iso-8859-1")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((PROXY_HOST, PROXY_PORT))
        client.sendall(request_bytes)

        response = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk

    print("\nResposta do servidor:\n")
    print(response.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
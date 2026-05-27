from __future__ import annotations

import argparse
import urllib.parse
import urllib.request
from pathlib import Path

from action_pill_tools import load_private_key


def sign_challenge(private_key_path: Path, challenge_hex: str) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    challenge = bytes.fromhex(challenge_hex.strip())
    private_key = load_private_key(private_key_path)
    signature = private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def http_get_text(url: str, timeout: float) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8").strip()


def http_post_form(url: str, fields: dict[str, str], timeout: float) -> str:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8").strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Assina o challenge do admin_server e faz unlock da pagina de manutencao."
    )
    parser.add_argument("--private-key", required=True, help="issuer_private_key.pem")
    parser.add_argument("--host", default="192.168.4.1", help="IP do Guardian no AP temporario")
    parser.add_argument("--challenge", help="challenge hex manual; se omitido, busca em /challenge")
    parser.add_argument("--no-post", action="store_true", help="so imprime a assinatura")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    base_url = f"http://{args.host}"
    challenge_hex = args.challenge
    if not challenge_hex:
        challenge_hex = http_get_text(f"{base_url}/challenge", args.timeout)
        print(f"challenge={challenge_hex}")

    signature_hex = sign_challenge(Path(args.private_key), challenge_hex)
    print(f"signature_hex={signature_hex}")

    if args.no_post:
        return 0

    response = http_post_form(
        f"{base_url}/unlock",
        {"signature_hex": signature_hex},
        args.timeout,
    )
    print(f"unlock_response={response}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

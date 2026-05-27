from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path

from action_pill_tools import issuer_key_id_from_public_pem


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Gera uma chave ECDSA P-256 para assinar Action Pills."
    )
    parser.add_argument("--out-dir", default="test_keys", help="pasta de saida")
    parser.add_argument("--force", action="store_true", help="sobrescreve arquivos existentes")
    args = parser.parse_args()

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_path = out_dir / "issuer_private_key.pem"
    public_path = out_dir / "issuer_public_key.pem"
    material_path = out_dir / "test_material.json"

    for path in (private_path, public_path, material_path):
        if path.exists() and not args.force:
            raise SystemExit(f"{path} ja existe; use --force para sobrescrever")

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    issuer_key_id = issuer_key_id_from_public_pem(public_pem)
    device_secret = secrets.token_bytes(32)

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    material_path.write_text(
        json.dumps(
            {
                "issuer_public_key_pem": str(public_path),
                "issuer_key_id_hex": issuer_key_id.hex(),
                "device_secret_hex": device_secret.hex(),
                "ribosome_epoch": 1,
                "note": "Cadastre device_secret_hex no ribosome do ESP com o mesmo mqtt_client_id usado no send_action_pill_ble.py.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"private_key={private_path}")
    print(f"public_key={public_path}")
    print(f"issuer_key_id={issuer_key_id.hex()}")
    print(f"device_secret={device_secret.hex()}")
    print(f"material={material_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

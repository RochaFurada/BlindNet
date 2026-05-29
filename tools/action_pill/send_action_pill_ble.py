from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from action_pill_tools import (
    ACTIVE_SUBSTANCE_CIPHER_AES_128_GCM,
    ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM,
    AMINOS,
    G2G_RX_UUID,
    G2G_SERVICE_UUID,
    build_action_pill,
    build_g2g_fragments,
    load_private_key,
    parse_hex_exact,
    send_fragments_ble,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monta e opcionalmente envia uma Action Pill para o ESP via G2G BLE."
    )
    parser.add_argument("--private-key", required=True, help="issuer_private_key.pem")
    parser.add_argument("--device-secret", help="hex de 32 bytes cadastrado no ribosome")
    parser.add_argument("--device-id", help="mqtt_client_id do ribosome/dispositivo")
    parser.add_argument("--topic", help="topico MQTT do comando")
    parser.add_argument("--amino", default="TOGGLE", choices=sorted(AMINOS.keys()))
    parser.add_argument("--value", type=int, help="valor para aminos INT/BOOL")
    parser.add_argument("--epoch", type=int, default=1, help="epoch do ribosome")
    parser.add_argument("--issued-ms", type=int, default=1)
    parser.add_argument("--expires-ms", type=int, default=0xFFFFFFFF)
    parser.add_argument(
        "--cipher",
        choices=("aes-128-gcm", "aes-256-gcm"),
        default="aes-256-gcm",
    )

    parser.add_argument("--out", default="action_pill.bin", help="arquivo binario gerado")
    parser.add_argument("--meta-out", default="action_pill.meta.json")
    parser.add_argument(
        "--empty-active",
        action="store_true",
        help="gera um active substance dummy sem device-secret, apenas para testar recepcao/stomach inicial",
    )
    parser.add_argument("--no-send", action="store_true", help="gera arquivos sem enviar BLE")
    parser.add_argument("--address", help="endereco BLE do ESP; se omitido, faz scan pelo service UUID")
    parser.add_argument("--name-contains", help="filtro opcional por nome BLE")
    parser.add_argument("--service-uuid", default=G2G_SERVICE_UUID)
    parser.add_argument("--char-uuid", default=G2G_RX_UUID)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument(
        "--no-response",
        action="store_true",
        help="usa write sem resposta na caracteristica BLE",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.empty_active:
        device_secret = None
    else:
        if not args.device_secret:
            raise SystemExit("--device-secret e obrigatorio sem --empty-active")
        if not args.device_id:
            raise SystemExit("--device-id e obrigatorio sem --empty-active")
        if not args.topic:
            raise SystemExit("--topic e obrigatorio sem --empty-active")
        device_secret = parse_hex_exact(args.device_secret, 32, "device-secret")

    network_id = b"\x00" * 16

    cipher = (
        ACTIVE_SUBSTANCE_CIPHER_AES_128_GCM
        if args.cipher == "aes-128-gcm"
        else ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM
    )

    private_key = load_private_key(Path(args.private_key))
    built = build_action_pill(
        private_key=private_key,
        device_secret=device_secret,
        network_id=network_id,
        device_id=args.device_id,
        topic=args.topic,
        amino=args.amino,
        value=args.value,
        epoch=args.epoch,
        issued_ms=args.issued_ms,
        expires_ms=args.expires_ms,
        cipher=cipher,
        empty_active=args.empty_active,
    )
    fragments = build_g2g_fragments(built.action_pill, built.message_id)

    Path(args.out).write_bytes(built.action_pill)
    Path(args.meta_out).write_text(
        json.dumps(
            {
                "action_pill": args.out,
                "action_pill_len": len(built.action_pill),
                "fragment_count": len(fragments),
                "message_id_hex": built.message_id.hex(),
                "issuer_key_id_hex": built.issuer_key_id.hex(),
                "active_hash_hex": built.active_hash.hex(),
                "empty_active": args.empty_active,
                "signature_len": len(built.signature),
                "service_uuid": args.service_uuid,
                "char_uuid": args.char_uuid,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"action_pill={args.out} len={len(built.action_pill)}")
    print(f"message_id={built.message_id.hex()}")
    print(f"issuer_key_id={built.issuer_key_id.hex()}")
    print(f"fragments={len(fragments)}")

    if args.no_send:
        print("send=skipped")
        return 0

    asyncio.run(
        send_fragments_ble(
            fragments,
            address=args.address,
            name_contains=args.name_contains,
            service_uuid=args.service_uuid,
            char_uuid=args.char_uuid,
            timeout=args.timeout,
            response=not args.no_response,
        )
    )
    print("send=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# Usage: python3 check_candidates.py --csv zden_lvl5_candidates_full.csv --target 1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7
import argparse, csv, hashlib, sys
try:
    import ecdsa, base58
except ImportError as e:
    print("Please install prerequisites:\n  pip install ecdsa base58", file=sys.stderr)
    raise

def priv_to_pub(priv_bytes):
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    x, y = vk.pubkey.point.x(), vk.pubkey.point.y()
    uncompressed = b"\x04" + x.to_bytes(32,"big") + y.to_bytes(32,"big")
    compressed = (b"\x02" if y % 2 == 0 else b"\x03") + x.to_bytes(32,"big")
    return uncompressed, compressed

def pub_to_addr(pub_bytes):
    sha = hashlib.sha256(pub_bytes).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    prefix = b"\x00" + ripe
    chk = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58.b58encode(prefix+chk).decode()

def to_wif(priv_bytes, compressed=True):
    # WIF mainnet (0x80 + priv [+ 0x01 if compressed] + 4-byte checksum), Base58Check
    payload = b"\x80" + priv_bytes + (b"\x01" if compressed else b"")
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    import base58
    return base58.b58encode(payload + chk).decode()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Path to CSV with candidate priv_hex")
    ap.add_argument("--target", required=True, help="Target P2PKH address")
    ap.add_argument("--limit", type=int, default=0, help="Stop after N candidates (0 = all)")
    args = ap.parse_args()

    target = args.target.strip()
    tested = 0
    with open(args.csv, newline='') as f:
        r = csv.DictReader(f)
        for row in r:
            priv_hex = row["priv_hex"].strip()
            priv = bytes.fromhex(priv_hex)
            # skip invalid ranges for secp256k1 (ecdsa lib handles, but we can short-circuit)
            if int.from_bytes(priv, "big") == 0:
                continue
            pub_u, pub_c = priv_to_pub(priv)
            addr_u = pub_to_addr(pub_u)
            addr_c = pub_to_addr(pub_c)
            tested += 1
            if addr_u == target or addr_c == target:
                wif_u = to_wif(priv, compressed=False)
                wif_c = to_wif(priv, compressed=True)
                print("FOUND!")
                print("priv_hex:", priv_hex)
                print("WIF (uncompressed):", wif_u)
                print("WIF (compressed):  ", wif_c)
                print("address_uncompressed:", addr_u)
                print("address_compressed:  ", addr_c)
                return
            if args.limit and tested >= args.limit:
                break
            if tested % 5000 == 0:
                print(f"Progress: tested {tested}...")
    print("Finished. No match found in provided candidates.")

if __name__ == "__main__":
    main()

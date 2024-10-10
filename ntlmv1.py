import argparse
import json
import hashlib
import pyDes
from typing import Dict, Tuple

def parse_ntlmv1(ntlmv1: str) -> Dict[str, str]:
    """Parse NTLMv1 hash and return components."""
    parts = ntlmv1.split(':')
    return {
        'user': parts[0],
        'domain': parts[2],
        'lmresp': parts[3],
        'ntresp': parts[4],
        'challenge': parts[5]
    }

def transform_netntlmv1_key(nthash: bytes) -> bytes:
    """Transform NT hash for DES key."""
    key = bytearray(8)
    key[0] = (nthash[0] >> 0) | 0x01
    key[1] = ((nthash[0] << 7) | (nthash[1] >> 1)) & 0xFF | 0x01
    key[2] = ((nthash[1] << 6) | (nthash[2] >> 2)) & 0xFF | 0x01
    key[3] = ((nthash[2] << 5) | (nthash[3] >> 3)) & 0xFF | 0x01
    key[4] = ((nthash[3] << 4) | (nthash[4] >> 4)) & 0xFF | 0x01
    key[5] = ((nthash[4] << 3) | (nthash[5] >> 5)) & 0xFF | 0x01
    key[6] = ((nthash[5] << 2) | (nthash[6] >> 6)) & 0xFF | 0x01
    key[7] = (nthash[6] << 1) & 0xFF | 0x01
    return bytes(key)

def crack_ct3(ct3: str, challenge: str) -> str:
    """Crack CT3 to get last two bytes of NT hash."""
    ct3_bytes = bytes.fromhex(ct3)
    challenge_bytes = bytes.fromhex(challenge)

    for i in range(0x10000):
        key_md4 = i.to_bytes(2, 'little') + b'\x00' * 6
        key_des = transform_netntlmv1_key(key_md4)

        des = pyDes.des(key_des, pyDes.ECB, padmode=pyDes.PAD_NORMAL)
        pt3 = des.encrypt(challenge_bytes)

        if pt3 == ct3_bytes:
            return f"{i:04x}"[2:] + f"{i:04x}"[:2]

    return "Key not found"

def process_ntlmv1(ntlmv1: str) -> Dict[str, str]:
    """Process NTLMv1 hash and return cracking information."""
    parts = parse_ntlmv1(ntlmv1)
    result = {**parts, 'ntlmv1': ntlmv1}

    ct1, ct2, ct3 = parts['ntresp'][:16], parts['ntresp'][16:32], parts['ntresp'][32:48]
    result['ct1'], result['ct2'], result['ct3'] = ct1, ct2, ct3

    if parts['lmresp'][20:48] != "0" * 28:
        # Non-ESS mode
        result['ct3_last_bytes'] = crack_ct3(ct3, parts['challenge'])
        result['hash1'] = f"{ct1}:{parts['challenge']}"
        result['hash2'] = f"{ct2}:{parts['challenge']}"
    else:
        # ESS mode
        client_challenge = parts['challenge']
        combined_challenge = client_challenge + parts['lmresp'][:16]
        srv_challenge = hashlib.md5(bytes.fromhex(combined_challenge)).hexdigest()[:16]
        
        result['client_challenge'] = client_challenge
        result['combined_challenge'] = combined_challenge
        result['srv_challenge'] = srv_challenge
        result['ct3_last_bytes'] = crack_ct3(ct3, client_challenge)
        result['hash1'] = f"{ct1}:{srv_challenge}"
        result['hash2'] = f"{ct2}:{srv_challenge}"

    return result

def main():
    parser = argparse.ArgumentParser(description="NTLMv1 Hash Parser and Cracker")
    parser.add_argument('--ntlmv1', help='NTLMv1 Hash in Responder format', required=True)
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    args = parser.parse_args()

    result = process_ntlmv1(args.ntlmv1)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("NTLMv1 Hash Information:")
        print(f"User: {result['user']}")
        print(f"Domain: {result['domain']}")
        print(f"Challenge: {result['challenge']}")
        print(f"LM Response: {result['lmresp']}")
        print(f"NT Response: {result['ntresp']}")
        print(f"CT1: {result['ct1']}")
        print(f"CT2: {result['ct2']}")
        print(f"CT3: {result['ct3']}")
        print(f"\nLast two bytes of NT hash: {result['ct3_last_bytes']}")
        print("\nTo crack with hashcat:")
        print(f"echo '{result['hash1']}' >> 14000.hash")
        print(f"echo '{result['hash2']}' >> 14000.hash")
        print("hashcat -m 14000 -a 3 -1 charsets/DES_full.hcchr --hex-charset 14000.hash ?1?1?1?1?1?1?1?1")
        print(f"\n\nNote: You'll need to update the path to the DES_full.hcchr charset file.")

if __name__ == "__main__":
    main()
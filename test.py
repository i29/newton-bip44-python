from crypto import HDPrivateKey, HDPublicKey, HDKey
import base58
import binascii

DEV_CHAIN_ID = 1002
TEST_CHAIN_ID = 1007
MAIN_CHAIN_ID = 1012
chainID = TEST_CHAIN_ID
PREFIX = 'NEW'


def address_encode(address_data):
    if address_data.startswith('0x'):
        address_data = address_data[2:]
    hex_chainID = hex(chainID)[2:][-8:]
    if (len(hex_chainID) % 2) == 1:
        hex_chainID = '0' + hex_chainID
    num_sum = hex_chainID + address_data
    data = base58.b58encode_check(b'\0' + binascii.a2b_hex(num_sum))
    new_address = PREFIX + data
    return new_address


def test_generate():
    master_key, mnemonic = HDPrivateKey.master_key_from_entropy()
    root_keys = HDKey.from_path(master_key, "m/44'/1642'/0'")
    acct_priv_key = root_keys[-1]
    for i in range(1):
        keys = HDKey.from_path(acct_priv_key, '{change}/{index}'.format(change=0, index=i))
        private_key = keys[-1]
        public_key = private_key.public_key
        print("Index %s:" % i)
        print("  Private key (hex, compressed): " + private_key._key.to_hex())
        print("  HexAddress: " + private_key.public_key.address())
        print("  NewAddress: " + address_encode(private_key.public_key.address()))


def test_from_mnemonic():
    mnemonic = "forget upset tray still clutch sweet sheriff rifle trick kid apart choose"
    master_key = HDPrivateKey.master_key_from_mnemonic(mnemonic)
    root_keys = HDKey.from_path(master_key, "m/44'/1642'/0'")
    acct_priv_key = root_keys[-1]
    keys = HDKey.from_path(acct_priv_key, '{change}/{index}'.format(change=0, index=0))
    private_key = keys[-1]
    print("  Private key (hex, compressed): " + private_key._key.to_hex())
    print("  HexAddress: " + private_key.public_key.address())
    print("  NewAddress: " + address_encode(private_key.public_key.address()))


if __name__ == '__main__':
    test_from_mnemonic()
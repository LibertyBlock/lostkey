import sys
from bitcoin import ecdsa_raw_sign, encode_privkey
from sha3 import keccak_256
from getpass import getpass

def is_canonical( sig ):
  return not (sig[1] & 0x80)\
     and not (sig[1] == 0 and not (sig[2] & 0x80))\
     and not (sig[33] & 0x80)\
     and not (sig[33] == 0 and not (sig[34] & 0x80))

priv = getpass("ETH private key: ")
msg = "I lost my EOS genesis key"
msghash = keccak_256(msg).digest()
  
v, r, s = ecdsa_raw_sign(msghash, encode_privkey(priv,'hex').decode('hex'))
signature = '00%02x%064x%064x' % (v,r,s)

print(signature)
sys.exit(0)
if is_canonical(bytearray(signature.decode('hex'))):
    print(signature)
    sys.exit(0)
else:
    print("Error: bad sig")
    sys.exit(1)


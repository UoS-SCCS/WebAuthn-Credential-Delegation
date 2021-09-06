import sys
sys.path.insert(1, 'psuw/')

from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from fido2 import cbor
import json
from psuw import encode_key, decode_key
from sys import argv

dev = next(CtapHidDevice.list_devices(), None)
assert dev is not None

ctap2_dev = Ctap2(dev)

if argv[1] == 'export-pkp':
    filename = argv[2] if len(argv) > 2 else 'proxy.publickey'
    with open(filename, 'wb') as f:
        f.write(ctap2_dev.send_cbor(64, None))

if argv[1] == 'import-pkp':
    with open(argv[2], 'rb') as f:
        pkp = f.read()
        
    ctap2_dev.send_cbor(65, {'pkp': encode_key(decode_key(pkp, public=True, from_bytes=True)), 
                             'name': argv[3]})
    
if argv[1] == 'list-proxies':
    print(ctap2_dev.send_cbor(66, None))

if argv[1] == 'export-warrant':
    ctap2_dev.send_cbor(67, {'rp': argv[2], 'username': argv[3], 'proxy': argv[4]})

#if argv[1] == 'import-warrant':
#    ctap2_dev.send_cbor(68, {'warr': argv[2], 'name': argv[3]})

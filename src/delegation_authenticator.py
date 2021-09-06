import sys

sys.path.insert(1, 'virtual_authenticator/src/')
sys.path.insert(1, 'arkg/')
sys.path.insert(1, 'psuw/')

import logging
from enum import Enum, unique
from binascii import hexlify
from authenticator.datatypes import DICEAuthenticatorException
from authenticator.storage import DICEAuthenticatorStorageException
from authenticator.json_storage import EncryptedJSONAuthenticatorStorage
from authenticator.ui import DICEAuthenticatorUI
from ctap.messages import CTAPHIDCBORResponse
from ctap.constants import CTAP_STATUS_CODE
from crypto.algs import PUBLIC_KEY_ALG
from ctap.attestation import AttestationObject
from dice_key import DICEKey
import psuw
from fido2 import cbor
import json
from psuw import encode_key, decode_key
import logging.config
import os
import tempfile

extension_data = os.path.join(tempfile.gettempdir(), 'webauthn-delegation-ext-data.json')

EXTENSION_NAME = 'webauthn-delegation'
logging.getLogger('debug').setLevel(logging.CRITICAL)
log = logging.getLogger(EXTENSION_NAME)


class DelegationStorage(EncryptedJSONAuthenticatorStorage):
    """ Storage class to support delegation. Provides key import, export, and list methods."""
    PROXY_PUBLIC = f'{EXTENSION_NAME}-pkp'
    PROXY_SIGNING = f'{EXTENSION_NAME}-skp'
    PROXY_WARRANT = f'{EXTENSION_NAME}-warrant'

    def __init__(self, *args, **kwargs):
        ''' Pass write_cleartext=False to disable writing to decrypted file for debugging. '''
        self._write_cleartext = kwargs.pop('write_cleartext', True)
        super().__init__(*args, **kwargs)

    def export_proxy_public_key(self):
        ''' Sample and record (skp,pkp) and return pkp, to give to a delegator. '''
        skp, pkp = psuw.pkgen(psuw.pp)
        self._data[self.PROXY_SIGNING][encode_key(pkp)] = encode_key(skp)
        assert self._write_to_json()
        return encode_key(pkp, as_bytes=True)

    def import_delegation_key(self, pkp, name, aaguid=None, overwrite=False, **kwargs):
        ''' Store proxy key pkp, a user-defined identifier, name, and optional AAGUID, to delegate
            to at a later time. '''
        if not name.isalnum():
            raise DICEAuthenticatorStorageException('Proxy name invalid')

        if name in self._data[self.PROXY_PUBLIC] and not overwrite:
            raise DICEAuthenticatorStorageException(
                'Proxy with same name already exists')

        self._data[self.PROXY_PUBLIC][name] = {'pkp': pkp, 'aaguid': aaguid}
        return self._write_to_json()

    def get_delegation_signing_key(self, pkp):
        ''' Retrieve skp to sign messages as a proxy. '''
        try:
            return self._data[self.PROXY_SIGNING][pkp]
        except KeyError as e:
            raise DICEAuthenticatorStorageException('Proxy public key unknown') from e

    def list_proxy_public_keys(self):
        ''' Return list of delegator-defined proxy identifiers for imported proxy keys pkp. '''
        return list(self._data[self.PROXY_PUBLIC].keys())

    def get_proxy_public_key(self, name):
        try:
            return self._data[self.PROXY_PUBLIC][name]['pkp']
        except KeyError:
            raise DICEAuthenticatorStorageException(
                'Proxy name unknown or key missing')

    def import_delegation_warr(self, warr, ddata, overwrite=False):
        ''' Store warr and ddata for later use. '''
        self._data[self.PROXY_WARRANT][ddata['cred_id']] = {'warr': warr, 'ddata': ddata}
        return self._write_to_json()

    def init_new(self):
        self._data[self.PROXY_PUBLIC] = {}
        self._data[self.PROXY_SIGNING] = {}
        self._data[self.PROXY_WARRANT] = {}
        super().init_new()

    def _write_to_json(self):
        self.debug()
        if self._write_cleartext:
            data = json.dumps(self._data)
            with open(f'{self._path}.json', 'w') as file:
                file.write(data)

        return super()._write_to_json()


@unique
class CTAPHIDDelegationCmd(Enum):
    CTAPHID_EXPORTDELKEY = b'\x40'
    CTAPHID_IMPORTDELKEY = b'\x41'
    CTAPHID_LISTDELKEYS = b'\x42'
    CTAPHID_EXPORTDELCRED = b'\x43'
    CTAPHID_IMPORTDELCRED = b'\x44'


@unique
class AuthenticatorDelegationCmd(Enum):
    AUTHN_MakeDelegatedCredential = b'\x44'


def _get_extension_data():
    try:
        with open(extension_data) as f:
            return json.load(f)
    except OSError:
        return {}

def _set_extension_data(data):
    with open(extension_data, 'w') as f:
        return json.dump(data, f)



class DelegationAuthenticator(DICEKey):
    def __init__(self):
        super().__init__(ui=DelegationDemoUI(), storage_cls=DelegationStorage)


    def authenticator_make_credential(self, params, keep_alive):
        # Would be in params.get_extensions() if client allowed this.
        ext_data = _get_extension_data()
        
        if EXTENSION_NAME not in ext_data:
            return super().authenticator_make_credential(params, keep_alive)

        keep_alive.start(DICEKey.KEEP_ALIVE_TIME_MS)

        if self._user_verification_capable and params.require_user_verification():
            _raise_for_user_verification()
        elif params.require_user_verification() or params.require_resident_key():
            raise DICEAuthenticatorException(CTAP_STATUS_CODE.CTAP2_ERR_UNSUPPORTED_OPTION,
                                             'Not supported')
        else:
            _raise_for_user_presence()

        try:
            pkp = self._storage.get_proxy_signing_key(ext_data['name'])
        except (DICEAuthenticatorStorageException, KeyError) as e:
            log.error(e.message)
            raise DICEAuthenticatorException(
                CTAP_STATUS_CODE.CTAP2_ERR_EXTENSION_FIRST, e.message) from e

        cred_source = PublicKeyCredentialSource()
        cred_source.init_new()
        # Would use extensions parameter here.
        authn_data = self._get_authenticator_data(credsource, up=True,
                                                  uv=params.require_user_verification())

        params.pop('name')
        # FIXME: Include extension data in signed data, but concat and verify on other end?

        #attest_object = AttestationObject.create_packed_self_attestation_object(
        #    credential_source, authn_data, params.get_hash())
        keep_alive.stop()
        return MakeCredentialResp(attest_object)

    # Online and remote variants.
    def authenticator_get_assertion(self, params, keep_alive):
        # if delegate not in params
        print('Authn get assert', params.__dict__)
        print('Params', params.__dict__)
        return super().authenticator_get_assertion(params, keep_alive)

    #def authenticator_get_next_assertion(self, params, idx, keep_alive):
    #    print('Authn get next assert', params.__dict__, idx)
    #    return super().authenticator_get_next_assertion(
    #        params, idx, keep_alive)

    def _raise_for_user_presence(self, msg='User cancelled'):
        if not self._ui.check_user_presence():
            raise DICEAuthenticatorException(CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED, msg)

    def _raise_for_user_verification(self, msg='User verification failed'):
        if not self._ui.check_user_presence():
            raise DICEAuthenticatorException(CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED, msg)

    def export_del_key(self):
        self._raise_for_user_presence()
        return cbor.encode(self._storage.export_proxy_public_key())

    def import_del_key(self, data):
        self._raise_for_user_presence()

        try:
            self._storage.import_delegation_key(**data)
        except (DICEAuthenticatorStorageException, KeyError) as e:
            log.error(e.message)
            raise DICEAuthenticatorException(
                CTAP_STATUS_CODE.CTAP2_ERR_EXTENSION_FIRST, e.message) from e

        return b''
    
    def export_del_cred(self, data):
        self._raise_for_user_presence()
        
        pkc = None
        for pkc_src in self._storage.get_credential_source_by_rp(data['rp']):
            if pkc_src._other_ui['name'] == data['username']:
                pkc = pkc_src
        
        if not pkc:
            raise DICEAuthenticatorException(
                CTAP_STATUS_CODE.CTAP2_ERR_EXTENSION_FIRST, 'Credential for username and RP pair not found')
        
        if pkc_src.get_alg() != PUBLIC_KEY_ALG.ES256.value:
            raise DICEAuthenticatorException(
                CTAP_STATUS_CODE.CTAP2_ERR_EXTENSION_FIRST, 'Credential algorithm not supported')
        
        pkp = self._storage.get_proxy_public_key(data['proxy'])
        pkp_decoded = decode_key(pkp, public=True)
        skd = None  # FIXME
        warr = psuw.delegate(psuw.pp, skd, pkp_decoded)
        return cbor.encode(warr)

    def process_cbor(self, cbor_data, keep_alive, cid=None):
        cmd = cbor_data[:1]

        if cmd == CTAPHIDDelegationCmd.CTAPHID_EXPORTDELKEY.value:
            #log.info('Export key operation requested')
            return self.export_del_key()

        elif cmd == CTAPHIDDelegationCmd.CTAPHID_IMPORTDELKEY.value:
            log.info('Import key operation requested')
            return self.import_del_key(cbor.decode(cbor_data[1:]))

        elif cmd == CTAPHIDDelegationCmd.CTAPHID_LISTDELKEYS.value:
            log.debug('List keys called')
            return cbor.encode(self._storage.list_proxy_public_keys())
        
        elif cmd == CTAPHIDDelegationCmd.CTAPHID_EXPORTDELCRED.value:
            log.info('Import delegation credential operation requested')
            return self.export_del_cred(cbor.decode(cbor_data[1:]))

        elif cmd == CTAPHIDDelegationCmd.CTAPHID_IMPORTDELCRED.value:
            #log.info('Import delegation credential operation requested')
            return #self.import_del_key(cbor.decode(cbor_data[1:]))

        else:
            return super().process_cbor(cbor_data, keep_alive, cid)

    def _create_debug_logs(self):
       pass


''' Simple command line UI for demo. '''


class DelegationDemoUI(DICEAuthenticatorUI):
    def start(self):
        self.fire_post_ui_loaded()
        while True:
            pass

    def check_user_presence(self, msg=None):
        return input('Presence check. Continue? [y/N]: ').lower() == 'y'

    def get_user_password(self, msg=None):
        return input(f'User password required. Password: ')

    def check_user_verification(self, msg=None):
        return input(
            f'User verification required. Enter password to continue: ')

    def choose_proxy(self):
        return None

    def create(self):
        pass

    def shutdown(self):
        pass


def main():
    logging.basicConfig()
    logging.root.setLevel(logging.INFO)
    key = DelegationAuthenticator()
    key.start()


if __name__ == '__main__':
    main()

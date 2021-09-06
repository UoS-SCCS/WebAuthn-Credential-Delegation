# WebAuthn Delegation Demo
Please note that this demo is not suitable for use in production and is currently under development, with some functionality WIP.

## CTAP implementation
We implement our CTAP methods using [Chris Culnane et al.'s virtual authenticator](https://github.com/UoS-SCCS/VirtualWebAuthn).

The following CTAP commands are added as [vendor-specific commands](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#usb-vendor-specific-commands): 
1. CTAPHID_EXPORTDELKEY to export a public key `pkp` for a proxy user
2. CTAPHID_IMPORTDELKEY to import a proxy's public key `pkp`, along with a delegator-defined name to identify this key later
3. CTAPHID_LISTDELKEYS to list known proxies
4. CTAPHID_EXPORTDELCRED to export warrants
5. CTAPHID_IMPORTDELCRED to import warrants to present to RPs at a later time

We also create our own storage class `DelegationStorage` to handle the storage of proxy keys and warrants, and to support the required CTAP commands (such as LISTDELKEYS). This extends the functionality of the existing storage backend.

We override the `process_cbor` method which handles incoming CBOR messages. If the message is one of our CTAP commands above, it will be handled here. Otherwise the message is passed on to be handled as normal.

## RP
Duo Lab's `py_webauthn` is used in `rp/app.py` to handle WebAuthn credential registration and authentication. Their demo app is used as the basis of ours. We replace the credential management with an SQLite3 schema to handle multiple credentials per user (ORM planned) with a new credential assertion request to be used for each failed credential (WIP).

### WebAuthn registration
Standard WebAuthn registration is used for the delegator's credentials at the RP, these credentials are also unlinkable due to them being created through WebAuthn.

![Starting the RP and virtual authenticator, then registering.](img/login.gif)

As the demo is running locally without TLS/SSL certificates, Chromium will issue a warning about the security of the site. 

## Export proxy key
To export a proxy key pkp, run the script `authenticator_util.py export-pkp [filename]` with the virtual authenticator running. You can inspect the output with `cat`.

![Exporting a proxy public key.](img/export-pkp.gif)

The user must perform a presence check before the authenticator will export a public key.

## Import proxy key and list known proxies
Proxy public keys are imported with a name so they can be managed by the delegator. These names can be listed with `CTAPHID_LISTDELKEYS`. In practice, these delegator-defined names should never be seen by the RP, instead only used locally by client extensions and within the authenticator itself.

To import a proxy key, the filepath and name must be specified.

![Import a proxy public key.](img/import-list.gif)

A list of valid proxy keys can be obtained with `list-proxies`. Now that these public keys have been imported, setup is complete. The delegator can now delegate to the proxy. Because these delegations are unlinkable, the delegator may delegate to the same proxy multiple times without undermining unlinkability.

## Export warrant
Exporting a warrant for direct delegation requires as input the RP (i.e. the site the login is for), the username (as the delegator may hold multiple accounts at the same RP), and the delegator-defined proxy name to delegate to.

![Export a warrant.](img/warrant.gif)

# Passing data with the WebAuthn extension field
WebAuthn clients (browsers) will often not pass extension data between the RP and authenticator. _For demonstration purposes_, this would either require patching a browser to handle the extension data, as would be the case if the extension were recognised by vendors, or passing the data in a separate channel. We use a temporary file shared between the RP and authenticator to simulate the extension data being passed as though it were recognised by vendors. You can watch the extension data being sent with `watch -n 0.5 cat [TEMPDIR]/webauthn-delegation-ext-data.json`.

# WIP
Please note that the RP implementation and WebAuthn handling is currently under development. The storage backend, CTAP handling, and companion client are implemented. The RP's credential management is updated with new functionality.

''' Simple delegation demo RP. Simplified... Do not use in production. Absolutely no warranty. '''
#FIXME: Move to SQL to ORM.

import os
import sys

from flask import Flask
from flask import flash
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask_login import LoginManager
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user
from flask_login import UserMixin

import tempfile

import util
import webauthn

app = Flask(__name__)

import sqlite3

tempdir = os.path.join(tempfile.gettempdir(), 'delegation-demo')
os.makedirs(tempdir, exist_ok=True)

app.secret_key = os.urandom(40)
login_manager = LoginManager()
login_manager.init_app(app)

RP_ID = 'localhost'
RP_NAME = 'webauthn demo localhost'
ICON_URL = 'https://example.com'
ORIGIN = 'https://localhost:5000'
TRUST_ANCHOR_DIR = 'trusted_attestation_roots'

new_user_sql = 'INSERT INTO user VALUES (?,?,?,?,?)'
get_user_sql = 'SELECT * FROM user WHERE username=?'
new_cred_sql = 'INSERT INTO credential VALUES (?,?,?,?,?,?)'
get_creds_sql = 'SELECT * FROM credential WHERE username=?'
get_cred_sql = 'SELECT * FROM credential WHERE cred_id=?'


class User(UserMixin):
    def set_id(self, username):
        self.username = username
        
    def get_id(self):
        return self.username

def execute_sql(sql, values, fetchone=False, fetchall=False):
    try:
        con = sqlite3.connect('file:accounts.db?mode=rw', uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
    except sqlite3.OperationalError:
        con = sqlite3.connect('accounts.db')
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        
        with open('schema.sql') as schema:
            cur.executescript(schema.read())
    
    
    print(sql, values)
    cur.execute(sql, values)
    
    res = None
    if fetchone:
        res = cur.fetchone()
    if fetchall:
        res = cur.fetchall()
    
    con.commit()
    con.close()
    print(res)
    return res


@login_manager.user_loader
def load_user(username):
    u = User()
    u.set_id(username)
    return u


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/webauthn_begin_activate', methods=['POST'])
def webauthn_begin_activate():
    username = request.form.get('register_username')
    display_name = request.form.get('register_display_name')

    session.pop('register_ukey', None)
    session.pop('register_username', None)
    session.pop('register_display_name', None)
    session.pop('challenge', None)
    session.pop('cred_idx', None)

    session['register_username'] = username
    session['register_display_name'] = display_name
    
    challenge = util.generate_challenge(32)
    ukey = util.generate_ukey()
    
    session['challenge'] = challenge.rstrip('=')
    session['register_ukey'] = ukey

    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge, RP_NAME, RP_ID, ukey, username, display_name,
        'https://example.com')

    return jsonify(make_credential_options.registration_dict)

#@app.route('/webauthn_continue_assertion', methods=['POST'])
#def webauthn_begin_assertion():

@app.route('/webauthn_begin_assertion', methods=['POST'])
def webauthn_begin_assertion():
    username = request.form.get('login_username')
    session['cred_idx'] = 0 #session.get('cred_idx', -1) + 1

    session.pop('challenge', None)

    challenge = util.generate_challenge(32)
    session['challenge'] = challenge.rstrip('=')

    user = execute_sql(get_user_sql, (username,), fetchone=True)
    cred = execute_sql(get_creds_sql, (username,), fetchall=True)[session['cred_idx']]

    webauthn_user = webauthn.WebAuthnUser(
        user['ukey'], user['username'], user['display_name'], user['icon_url'],
        cred['cred_id'], cred['pub_key'], cred['sign_count'], user['rp_id'])
    
    print(cred['cred_id'], cred['username'])

    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
        webauthn_user, challenge)
    
    print(webauthn_assertion_options)
    print(webauthn_assertion_options.assertion_dict)

    return jsonify(webauthn_assertion_options.assertion_dict)


@app.route('/verify_credential_info', methods=['POST'])
def verify_credential_info():
    challenge = session['challenge']
    username = session['register_username']
    display_name = session['register_display_name']
    ukey = session['register_ukey']

    registration_response = request.form.to_dict()
    registration_response.pop('registrationClientExtensions')
    trust_anchor_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
    trusted_attestation_cert_required = True
    self_attestation_permitted = True
    none_attestation_permitted = True

    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        RP_ID,
        ORIGIN,
        registration_response,
        challenge,
        trust_anchor_dir,
        trusted_attestation_cert_required,
        self_attestation_permitted,
        none_attestation_permitted,
        uv_required=False)
    
    try:
        webauthn_credential = webauthn_registration_response.verify()
    except Exception as e:
        return jsonify({'fail': 'Registration failed. Error: {}'.format(e)})
    print(webauthn_credential.credential_id)
    
    execute_sql(new_user_sql, (username, ukey, display_name, RP_ID, ICON_URL))
    execute_sql(new_cred_sql, (webauthn_credential.credential_id.decode("ascii"), username, webauthn_credential.public_key.decode("ascii"), webauthn_credential.sign_count, True, True))

    flash('Successfully registered as {}.'.format(username))

    return jsonify({'success': 'User successfully registered.'})


@app.route('/verify_assertion', methods=['POST'])
def verify_assertion():
    challenge = session.get('challenge')
    assertion_response = request.form
    cred_id = assertion_response.get('id')
    
    cred = execute_sql(get_cred_sql, (cred_id,), fetchone=True)
    user = execute_sql(get_user_sql, (cred['username'],), fetchone=True)

    webauthn_user = webauthn.WebAuthnUser(
        user['ukey'], user['username'], user['display_name'], user['icon_url'],
        cred['cred_id'], cred['pub_key'], cred['sign_count'], user['rp_id'])

    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user,
        assertion_response,
        challenge,
        ORIGIN,
        uv_required=False)  # User Verification

    try:
        sign_count = webauthn_assertion_response.verify()
    except Exception as e:
        return jsonify({'fail': 'Assertion failed. Error: {}'.format(e)})

    # Update counter.
    #user.sign_count = sign_count
    #db.session.add(user)
    #db.session.commit()

    u = User()
    u.set_id(cred['username'])
    login_user(u)

    return jsonify({
        'success':
        'Successfully authenticated as {}'.format(u.username)
    })


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', ssl_context='adhoc', debug=True)

#!/usr/bin/env python3
#
# Simple wrapper to test pam_script_pysaml.py
#
import sys
import os

sys.path.append('..')
import pam_script_pysaml as pam

data_dir = pam.__data_test_dir__

sys.argv = [
    '',
    'grace = 600',
    'check_timeframe=True',
    f'idp="{data_dir}/idp_not_exist.xml,'
    f'{data_dir}/idp_metadata_multi_signing_certs.xml,'
    f'{data_dir}/idp_zcu_metadata.xml, '
    f'{data_dir}/idp_signed_metadata_demo1.xml "',
    'log_level=DEBUG',
    'only_from=127.0.0.1,::1,localhost',
    'trusted_sp=https://fake-sp/metadata.php, '
    'https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php',
    'user_id=uid'
]

os.environ['PAM_AUTHTOK'] = ''
os.environ['PAM_RHOST'] = 'localhost'
os.environ['PAM_RUSER'] = 'test'
os.environ['PAM_SERVICE'] = 'dovecot'
os.environ['PAM_TTY'] = '/dev/null'
os.environ['PAM_USER'] = 'test'
os.environ['PAM_TYPE'] = 'auth'

with open(f"{data_dir}/signed_assertion_response.xml.base64", "r") as fh:
    os.environ['PAM_AUTHTOK'] = fh.read()

pam.main()

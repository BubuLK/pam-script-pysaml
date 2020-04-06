import os
from os.path import join
import sys
import pytest

import pam_script_pysaml as pam

data_dir = pam.data_test_dir

sys.argv = [
    '',
    'grace = 600',
    'check_timeframe=True',
    f'idp={data_dir}/idp_signed_metadata_demo1.xml, ',
    'log_level=ERROR',
    'only_from=127.0.0.1,::1,localhost',
    'trusted_sp=https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php',
    'user_id=uid'
]

os.environ['PAM_AUTHTOK'] = ''
os.environ['PAM_RHOST'] = 'localhost'
os.environ['PAM_RUSER'] = 'test'
os.environ['PAM_SERVICE'] = 'dovecot'
os.environ['PAM_TTY'] = '/dev/null'
os.environ['PAM_USER'] = 'test'
os.environ['PAM_TYPE'] = 'auth'

with open(join(data_dir, "signed_assertion_response.xml.base64"), "r") as fh:
    os.environ['PAM_AUTHTOK'] = fh.read()


@pytest.mark.skip(reason="ToDo")
def test_get_pam_params():
    # ToDo
    # pam_params = pam.get_pam_params(os.environ, sys.argv[1:])
    assert True


def test_main():
    with pytest.raises(SystemExit) as exit_err:
        pam.main()
    assert exit_err.value.code == pam.PAM_SUCCESS

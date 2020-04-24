import pytest
from contextlib import nullcontext as does_not_raise

import os
import sys
import pickle
import typing

import time

from signxml import (XMLSigner, XMLVerifier,
                     InvalidInput, InvalidSignature,
                     InvalidCertificate, InvalidDigest)
from lxml import etree

import pam_script_pysaml as pam

data_dir = pam.__data_test_dir__
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

with open(os.path.join(data_dir,
                       "signed_assertion_response.xml.base64"), "r") as fh:
    os.environ['PAM_AUTHTOK'] = fh.read()

with open(os.path.join(data_dir,
                       "signed_assertion_response.xml"), "rb") as fh:
    root = etree.parse(fh).getroot()

test_data_xml = b"<Test></Test>"

test_data_dict = [
    ({1: 1, 2: 2, 3: 3}, [1, 3], {1: 1, 3: 3}),
    ({1: 1, 2: 2, 3: 3}, [1, 4], {1: 1}),
    ({1: 1, 2: 2, 3: 3}, [], {}),
]


@pytest.mark.parametrize(
    "dictionary, keys, expected",
    test_data_dict,
    ids=["Select Keys", "Missing Keys", "Empty Keys"]
)
def test_select_dict_keys(dictionary, keys, expected):
    result = pam.select_dict_keys(dictionary, keys)
    assert result == expected


@pytest.mark.parametrize(
    "env, argv, pam_params_expected",
    [
        (
            {
                'PAM_AUTHTOK': 'password',
                'PAM_NOT_USED': 'not used'
            },
            [
                'grace = 600',
                'check_timeframe=True',
                'idp="metadata.xml"',
                'not_used = None'
            ],
            {
                'PAM_AUTHTOK': 'password',
                'grace': 600,
                'check_timeframe': 1,
                'idp': 'metadata.xml',
                'log_level': 'WARNING',
                'only_from': '127.0.0.1,::1',
                'trusted_sp': '',
                'user_id': 'uid'
            }
        )
    ]
)
def test_get_pam_params(env, argv, pam_params_expected):
    pam_params = pam.get_pam_params(env, argv)
    assert pam_params == pam_params_expected


@pytest.mark.parametrize(
    "rhost, only_from, ret_expected",
    [
        ('localhost', '127.0.0.1,::1,localhost', True),
        ('147.228.1.1', '127.0.0.1,::1,localhost', False)
    ],
    ids=["RHOST OK", "RHOST Bad"]
)
def test_verify_only_from(rhost, only_from, ret_expected):
    assert pam.verify_only_from(rhost, only_from) == ret_expected


@pytest.mark.parametrize(
    "tree, trusted_sp, ret_expected",
    [
        (
            root,
            'https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php',
            True
        ),
        (root, 'https://wrong.ip.org', False),
        (root, '', True)
    ],
    ids=["Trusted SP", "Untrusted SP", "Trusted SP Missing"]
)
def test_verify_trusted_sp(tree, trusted_sp, ret_expected):
    assert pam.verify_trusted_sp(tree, trusted_sp) == ret_expected


@pytest.mark.parametrize(
    "data, data_expected",
    [
        (b'PFRlc3Q+PC9UZXN0Pg==', test_data_xml),
        (b'eJyzCUktLrGz0QdTAB5XBGQ=', test_data_xml)
    ],
    ids=["Base64", "Compress+Base64"]
)
def test_decode_assertion(data, data_expected):
    data_decoded = pam.decode_assertion(data)
    assert data_decoded == data_expected


@pytest.mark.parametrize(
    "uid, uid_expected",
    [
        ("uid", "test"),
        ("uid_not_present", None)
    ],
    ids=["uid", "uid Not Present"]
)
def test_get_uid_attribute(uid, uid_expected):
    user = pam.get_uid_attribute(root, uid)
    if user is not None:
        user = user.text
    assert user == uid_expected


def test_parse_idp_metadata():
    with open(
            os.path.join(data_dir, "idp_metadata_multi_signing_certs.pickle"),
            "rb") as f:
        data_expected = pickle.load(f)

    data = pam.parse_idp_metadata(
        os.path.join(data_dir, "idp_metadata_multi_signing_certs.xml"))
    assert data == data_expected


@pytest.mark.parametrize(
    "data, data_expected",
    [
        (
                [{'entityID': 'e1', 'x509cert': ['c1']}],
                [('e1', 'c1')]
        ),
        (
                [{'entityID': 'e1', 'x509cert': ['c11', 'c12', 'c13']}],
                [('e1', 'c11'), ('e1', 'c12'), ('e1', 'c13')]
        ),
        (
                [{'entityID': 'e3', 'x509cert': ''}],
                []
        )
    ],
    ids=["Standard", "Multi Certs", "No Certs"]
)
def test_iterate_certs(data, data_expected):
    data_iter = []
    [data_iter.append((e, c)) for e, c in pam.iterate_certs(data)]
    assert data_iter == data_expected


@pytest.mark.parametrize(
    "ts, nb_expected, nooa_expected, raise_expected",
    [
        (
            'NotBefore="2014-03-31T00:36:46Z" '
            'NotOnOrAfter="2023-10-02T05:57:16Z"',
            1396226206,
            1696226236,
            does_not_raise()
        ),
        (
            'NotBefore="2014-03-31T00:36:46Z" '
            'NotOnOrAfter="2023-10-02T05:57:16Z"',
            1396226206,
            1696226236,
            does_not_raise()
        ),
        (
            'NotBefore="2014-03-31T00:36:46Z" '
            'NotOnOrAfter="2023-10-02T05:57:16Z"',
            1396226206,
            1696226236,
            does_not_raise()
        ),
        (
            '', 0, 0, does_not_raise()
        ),
        (
            'NotBefore="2014-03-31T00:36:46X"',
            None, None, pytest.raises((ValueError, SystemExit))
        )
    ],
    ids=[
        "Standard",
        "NotBefore Only",
        "NotOnOrAfter Only",
        "No Conditions",
        "Bad Time Format"
    ]
)
def test_get_timestamps(ts, nb_expected, nooa_expected, raise_expected):
    ts_conditions_xml = f"""
        <Response xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'> 
        <saml:Conditions {ts}></saml:Conditions></Response>
    """

    ts_root = etree.fromstring(ts_conditions_xml)
    nb = nooa = None

    with raise_expected:
        nb, nooa = pam.get_timestamps(ts_root)

    assert nb == nb_expected
    assert nooa == nooa_expected


@pytest.mark.parametrize(
    "nb_diff, nooa_diff, grace, ret_expected",
    [
        (60, 60, 0, True),
        (0, 60, 0, True),
        (60, 0, 0, True),
        (0, 0, 0, True),
        (60, -60, 0, False),
        (-60, 60, 0, False)
    ],
    ids=[
        "Standard",
        "NotBefore Only",
        "NotOnOrAfter Only",
        "No Conditions",
        "NotBefore Out",
        "NotOnOrAfter Out"
    ]
)
def test_verify_timestamps(nb_diff, nooa_diff, grace, ret_expected):
    now = int(time.time())

    nb = (0 if nb_diff == 0 else now - nb_diff)
    nooa = (0 if nooa_diff == 0 else now + nooa_diff)

    assert pam.verify_timestamps(nb, nooa, grace) == ret_expected


def test_xml_verifier():
    with open(os.path.join(data_dir, "example.pem"), "r") as f:
        cert = f.read()
    with open(os.path.join(data_dir, "example.key"), "r") as f:
        key = f.read()

    tree = etree.fromstring(test_data_xml)

    signed_root = XMLSigner().sign(tree, key=key, cert=cert)
    verified_data = XMLVerifier().verify(signed_root,
                                         x509_cert=cert).signed_data
    assert verified_data == test_data_xml


with open(
        os.path.join(data_dir, "signed_assertion_response.xml.base64"),
        "rb") as fh:
    auth_data = fh.read()


@pytest.mark.parametrize(
    "idp_metadata, assertion_expected, raise_expected",
    [
        (
            os.path.join(data_dir, "idp_signed_metadata_demo1.xml"),
            os.path.join(data_dir, "verified_assertion_response.xml"),
            does_not_raise()
        ),
        (
            os.path.join(data_dir, "idp_metadata_multi_signing_certs.xml"),
            "",
            pytest.raises(SystemExit)
        ),
        (
            os.path.join(data_dir, "idp_not_exist.xml"),
            "",
            pytest.raises((InvalidSignature, InvalidDigest, InvalidCertificate,
                           InvalidInput, SystemExit))
        )
    ],
    ids=[
            "Signature OK",
            "Signature BAD",
            "Signature Not Found"
        ]
)
def test_verify_assertion_signature(idp_metadata,
                                    assertion_expected,
                                    raise_expected):
    try:
        with open(assertion_expected, "rb") as f:
            assertion_expected = f.read()
    except IOError:
        pass

    with raise_expected:
        verified_assertion = pam.verify_assertion_signature(auth_data,
                                                            idp_metadata)
        assert etree.tostring(verified_assertion) == assertion_expected

    assert True


def test_main():
    with pytest.raises(SystemExit) as exit_err:
        pam.main()
    assert exit_err.value.code == pam.PAM_SUCCESS

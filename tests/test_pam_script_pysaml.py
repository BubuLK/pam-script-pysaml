import pytest

from os.path import join
import pickle

from signxml import XMLSigner, XMLVerifier
from lxml import etree

import pam_script_pysaml as pam

data_dir = pam.data_test_dir

with open(join(data_dir, "signed_assertion_response.xml"), "rb") as fh:
    root = etree.parse(fh).getroot()

test_dict_data = [
    ({1: 1, 2: 2, 3: 3}, [1, 3], {1: 1, 3: 3}),
    ({1: 1, 2: 2, 3: 3}, [1, 4], {1: 1}),
    ({1: 1, 2: 2, 3: 3}, [], {}),
]


@pytest.mark.parametrize(
    "dictionary, keys, expected",
    test_dict_data,
    ids=["Select_keys", "Missing_keys", "Empty_keys"]
)
def test_select_dict_keys(dictionary, keys, expected):
    result = pam.select_dict_keys(dictionary, keys)
    assert result == expected


def test_parse_saml_to_time():
    time = "2020-03-06T16:43:49.942Z"
    time_unix_expected = 1583513029
    time_wrong_fmt = "2020-03-06T16:43:49.Z"

    time_unix = pam.parse_saml_to_time(time)
    assert time_unix_expected == time_unix

    with pytest.raises((ValueError, SystemExit)) as exit_err:
        pam.parse_saml_to_time(time_wrong_fmt)
    assert exit_err


@pytest.mark.parametrize(
    "data, data_expected",
    [
        (b'cGFtX3NjcmlwdF9weXNhbWwgdGVzdGluZyBkYXRhIHN0cmluZy4=',
         b'pam_script_pysaml testing data string.'),
        (b'eJwrSMyNL04uyiwoiS+oLE7MzVEoSS0uycxLV0hJLElUKC4pArL1ACtdDuU=',
         b'pam_script_pysaml testing data string.')
    ],
    ids=["Base64", "Compress-Base64"]
)
def test_decode_assertion(data, data_expected):
    data_decoded = pam.decode_assertion(data)
    assert data_expected == data_decoded


@pytest.mark.parametrize(
    "uid, uid_expected",
    [
        ("uid", "test"),
        ("uid_not_present", None)
    ],
    ids=["uid", "uid_not_present"]
)
def test_get_uid_attribute(uid, uid_expected):
    user = pam.get_uid_attribute(root, uid)
    if user is not None:
        user = user.text
    assert user == uid_expected


def test_parse_idp_metadata():
    with open(join(data_dir, "idp_metadata_multi_signing_certs.pickle"),
              "rb") as f:
        data_expected = pickle.load(f)

    data = pam.parse_idp_metadata(
        join(data_dir, "idp_metadata_multi_signing_certs.xml"))
    assert data_expected == data


@pytest.mark.parametrize(
    "nb_expected, nooa_expected",
    [("2014-03-31T00:36:46Z", "2023-10-02T05:57:16Z")],
    ids=["Standard"]
)
def test_get_timestamps(nb_expected, nooa_expected):
    nb, nooa = pam.get_timestamps(root)

    assert nb == nb_expected
    assert nooa == nooa_expected


@pytest.mark.parametrize(
    "nb, nooa, grace, ret_expected",
    [
        ("2014-07-17T01:01:18Z", "2024-01-18T06:21:48Z", 0, True),
        ("2014-07-17T01:01:18Z", "", 0, True),
        ("", "2024-01-18T06:21:48Z", 0, True)
    ],
    ids=["Standard", "NotBefore Only", "NotOnOrAfter Only"]
)
def test_verify_timestamps(nb, nooa, grace, ret_expected):
    assert ret_expected == pam.verify_timestamps(nb, nooa, grace)


def test_xml_verifier():
    data = b"<Test></Test>"

    with open(join(data_dir, "example.pem"), "r") as f:
        cert = f.read()
    with open(join(data_dir, "example.key"), "r") as f:
        key = f.read()

    tree = etree.fromstring(data)

    signed_root = XMLSigner().sign(tree, key=key, cert=cert)
    verified_data = XMLVerifier().verify(signed_root,
                                         x509_cert=cert).signed_data
    assert data == verified_data

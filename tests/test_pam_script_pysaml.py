import pytest

from os.path import join
import pickle

from signxml import XMLSigner, XMLVerifier
from lxml import etree

import pam_script_pysaml as pam

data_dir = pam.__data_test_dir__

with open(join(data_dir, "signed_assertion_response.xml"), "rb") as fh:
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
    with open(join(data_dir, "idp_metadata_multi_signing_certs.pickle"),
              "rb") as f:
        data_expected = pickle.load(f)

    data = pam.parse_idp_metadata(
        join(data_dir, "idp_metadata_multi_signing_certs.xml"))
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
    "ts, nb_expected, nooa_expected",
    [
        (
                'NotBefore="2014-03-31T00:36:46Z" '
                'NotOnOrAfter="2023-10-02T05:57:16Z"',
                1396226206,
                1696226236
        ),
        (
                'NotBefore="2014-03-31T00:36:46Z" '
                'NotOnOrAfter="2023-10-02T05:57:16Z"',
                1396226206,
                1696226236
        ),
        (
                'NotBefore="2014-03-31T00:36:46Z" '
                'NotOnOrAfter="2023-10-02T05:57:16Z"',
                1396226206,
                1696226236
        ),
        (
                '', 0, 0
        )
    ],
    ids=["Standard", "NotBefore Only", "NotOnOrAfter Only", "No Conditions"]
)
def test_get_timestamps(ts, nb_expected, nooa_expected):
    test_conditions_xml = \
        '<Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"> ' \
        f'<saml:Conditions {ts}></saml:Conditions></Response>'

    ts_root = etree.fromstring(test_conditions_xml)
    nb, nooa = pam.get_timestamps(ts_root)

    assert nb == nb_expected
    assert nooa == nooa_expected


@pytest.mark.parametrize(
    "nb, nooa, grace, ret_expected",
    [
        (1396226206, 1696226236, 0, True),
        (0, 1696226236, 0, True),
        (1396226206, 0, 0, True),
        (0, 0, 0, True)
    ],
    ids=["Standard", "NotBefore Only", "NotOnOrAfter Only", "No Conditions"]
)
def test_verify_timestamps(nb, nooa, grace, ret_expected):
    assert pam.verify_timestamps(nb, nooa, grace) == ret_expected


def test_xml_verifier():
    with open(join(data_dir, "example.pem"), "r") as f:
        cert = f.read()
    with open(join(data_dir, "example.key"), "r") as f:
        key = f.read()

    tree = etree.fromstring(test_data_xml)

    signed_root = XMLSigner().sign(tree, key=key, cert=cert)
    verified_data = XMLVerifier().verify(signed_root,
                                         x509_cert=cert).signed_data
    assert verified_data == test_data_xml


def test_verify_assertion_signature():
    with open(join(data_dir,
                   "signed_assertion_response.xml.base64"), "rb") as f:
        auth_data = f.read()
    with open(join(data_dir,
                   "verified_assertion_response.xml"), "rb") as f:
        verified_assertion_expected = f.read()

    idp_metadata = join(data_dir, "idp_signed_metadata_demo1.xml")
    verified_assertion = pam.verify_assertion_signature(auth_data,
                                                        idp_metadata)

    assert etree.tostring(verified_assertion) == verified_assertion_expected

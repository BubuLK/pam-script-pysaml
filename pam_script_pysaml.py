#!/usr/bin/env python3
"""Implements 'pam_script_auth' module for pam-script subsystem.

The environment variables passed by pam-script onto the script
(all will exist but some may be null if not applicable):

PAM_SERVICE	 - the application that's invoking the PAM stack
PAM_TYPE       - the module-type (e.g. auth_data,account,session,password)
PAM_USER	     - the user being authenticated into
PAM_RUSER	     - the remote user, the user invoking the application
PAM_RHOST	     - remote host
PAM_TTY		 - the controlling tty
PAM_AUTHTOK	 - password in readable text
PAM_OLDAUTHTOK - old password in readable text

Id addition the pam_script.so arguments in the pam.conf will be passed
on the command line, which can be used to modify the script behavior.

dir               - installation dir
grace             - time 'skew' allowing the validation (in seconds)
check_timeframe   - validates the SAML assertion if expired (True/False)
idp               - trusted IdPs metadata file (CSV multi-value)
log_level         - logging severity
only_from         - trusted IdPs host names (CSV multi-value)
trusted_sp        - entityID of trusted SP
user_id           - Attribute element representing validated username
"""

import os
import sys
import logging
from distutils.util import strtobool

import time
import calendar

import zlib
from base64 import b64decode

import ciso8601

from lxml import etree
from signxml import (XMLVerifier, Namespace,
                     InvalidInput, InvalidSignature,
                     InvalidCertificate, InvalidDigest)

#
# PAM subsystem compatible exit codes
#
PAM_SUCCESS = 0
PAM_SYSTEM_ERR = 4
PAM_PERM_DENIED = 7
PAM_AUTH_ERR = 9
PAM_CRED_INSUFFICIENT = 11
PAM_AUTHINFO_UNAVAIL = 12
PAM_USER_UNKNOWN = 13
PAM_CRED_UNAVAIL = 14
PAM_CRED_EXPIRED = 15
PAM_CRED_ERR = 16
PAM_AUTHTOK_EXPIRED = 18
PAM_AUTHTOK_ERR = 20
PAM_AUTHTOK_DISABLE_AGING = 23
PAM_NO_MODULE_DATA = 24
PAM_IGNORE = 25
PAM_ABORT = 26
PAM_MODULE_UNKNOWN = 28
#
__pam_module_name__ = "pam-script-pysaml"
__data_test_dir__ = os.path.join(os.path.dirname(__file__), "tests", "data")
#
ns = Namespace(
    ds="http://www.w3.org/2000/09/xmldsig#",
    md="urn:oasis:names:tc:SAML:2.0:metadata",
    shibmd="urn:mace:shibboleth:metadata:1.0",
    saml="urn:oasis:names:tc:SAML:2.0:assertion",
    samlp="urn:oasis:names:tc:SAML:2.0:protocol"
)


def config_logging(severity):
    """Setup basic logging configuration.

    :param severity: logging severity
    :return: logging handler
    """

    log = logging.getLogger(__pam_module_name__)

    log_level = getattr(logging, severity.upper(), logging.WARNING)
    log.setLevel(log_level)

    log_formatter = logging.Formatter(
        '%(asctime)s %(name)s (%(levelname)s): %(message)s',
        '%b %d %H:%M:%S')

    # Main stream handler
    log_stream_handler = logging.StreamHandler(stream=sys.stdout)
    log_stream_handler.setLevel(log_level)
    log_stream_handler.setFormatter(log_formatter)
    log.addHandler(log_stream_handler)

    # Temporary file handler
    log_file_handler = logging.FileHandler(
        os.path.join(os.path.dirname(__file__),
                     "log", f"{__pam_module_name__}.log"))
    log_file_handler.setLevel(log_level)
    log_file_handler.setFormatter(log_formatter)
    log.addHandler(log_file_handler)

    return log


def select_dict_keys(dictionary, keys):
    """Filters a dict by only including certain keys.

    :param dictionary: dictionary
    :param keys: keys to be selected
    :return: dictionary with selected keys
    """

    key_set = set(keys) & set(dictionary.keys())
    return {key: dictionary[key] for key in key_set}


def get_pam_params(env, argv):
    """Get module parameters and set default values.

    :param env: environment variables
    :param argv: command line arguments
    :return: dictionary of selected parameters
    """

    pam_env = [
        'PAM_AUTHTOK',
        'PAM_OLDAUTHTOK',
        'PAM_RHOST',
        'PAM_RUSER',
        'PAM_SERVICE',
        'PAM_TTY',
        'PAM_TYPE',
        'PAM_USER'
    ]
    pam_argv = [
        'grace',
        'check_timeframe',
        'idp',
        'log_level',
        'only_from',
        'trusted_sp',
        'user_id'
    ]

    env = select_dict_keys(env, pam_env)

    argv = {k: v.replace('"', '').strip() for k, v in
            dict(map(lambda arg: arg.split('=', 1), argv)).items()}
    argv = select_dict_keys(dict(argv), pam_argv)

    # Setup default values
    argv.setdefault('grace', 600)
    argv['grace'] = int(argv['grace'])

    argv.setdefault('check_timeframe', 'True')
    argv['check_timeframe'] = strtobool(argv['check_timeframe'])

    argv.setdefault('idp', '')
    argv.setdefault('log_level', 'WARNING')
    argv.setdefault('only_from', '127.0.0.1,::1')
    argv.setdefault('trusted_sp', '')
    argv.setdefault('user_id', 'uid')

    return {**env, **argv}


def verify_only_from(pam_rhost, only_from):
    """Verify 'only_from' response conditions."""

    return only_from and pam_rhost and \
        pam_rhost in [host.strip() for host in only_from.split(',')]


def verify_trusted_sp(tree, trusted_sp=False):
    """Verify trusted SP."""

    logger = logging.getLogger(__pam_module_name__)

    if not trusted_sp:
        logger.warning(
            "Unsecured configuration: no trusted_sp argument defined.")
        return True

    node = tree.find(
        ".//saml:AudienceRestriction/saml:Audience", namespaces=ns)
    return node is not None and node.text and node.text == trusted_sp


def decode_assertion(data):
    """Base64 decodes and then inflates SAML assertion data.

    :param data: base64 encoded and deflated SAML assertion data (as
                 received from IdP)
    :return: decoded and inflated SAML assertion string
    """

    data_decoded = b64decode(data)
    try:
        return zlib.decompress(data_decoded)
    except zlib.error:
        pass
    return data_decoded


def get_uid_attribute(etree_xml, uid):
    """Get SAML assertion Attribute element representing uid.

    :param etree_xml: etree element object
    :param uid: name of Attribute element representing uid
    :return: uid value
    """

    return etree_xml.find(
        f".//saml:AttributeStatement/saml:Attribute[@Name='{uid}']"
        f"/saml:AttributeValue",
        namespaces=ns)


def parse_idp_metadata(idp_metadata_file):
    """Parse entityID and X509Certificate elements from metadata file.

    :param idp_metadata_file: IdP metadata file name
    :return: dictionary of element values
    """

    logger = logging.getLogger(__pam_module_name__)
    data = {'entityID': '', 'x509cert': ''}

    try:
        with open(idp_metadata_file, "rb") as fh:
            md_tree = etree.parse(fh).getroot()
    except (OSError, IOError) as err:
        logger.warning(
            f"IdP metadata file is missing or corrupted: {err}.")
        return data

    data['entityID'] = dict(md_tree.items()).get('entityID')
    signing_nodes = md_tree.findall(".//md:KeyDescriptor[@use='signing']",
                                    namespaces=ns)

    if len(signing_nodes) > 0:
        certs = []
        for cert_node in signing_nodes:
            certs.append(''.join(cert_node.find(
                ".//ds:KeyInfo/ds:X509Data/ds:X509Certificate",
                namespaces=ns).text.split()))
        data['x509cert'] = certs

    return data


def iterate_certs(data):
    """Iterate over all (entityID, x509cert) pairs.

    :param data: parsed IdP data
    :return: entityID, cert
    """

    for idp in data:
        eid = idp['entityID']
        for crt in idp['x509cert']:
            yield eid, crt


def get_timestamps(etree_xml):
    """Parse SAML assertion validity timestamps

    Timestamps are parsed from Conditions element and converted to Unix
    timestamps.

    :param etree_xml: etree element object
    :return: NotBefore, NotOnOrAfter
    """

    logger = logging.getLogger(__pam_module_name__)
    time_attr = {'NotBefore': 0, 'NotOnOrAfter': 0}

    conditions_node = etree_xml.find(".//saml:Conditions", namespaces=ns)

    if conditions_node is not None:
        time_attr['NotBefore'] = conditions_node.get('NotBefore')
        time_attr['NotOnOrAfter'] = conditions_node.get('NotOnOrAfter')

        for key, timestamp in time_attr.items():
            if timestamp is not None:
                try:
                    dtime = ciso8601.parse_datetime(timestamp)
                    time_attr[key] = calendar.timegm(dtime.utctimetuple())
                except ValueError as err:
                    logger.error(
                        f"Time string {key}={timestamp} does not match "
                        f"expected format: {err}.")
                    sys.exit(PAM_CRED_ERR)

    return [(0 if v is None else v) for v in time_attr.values()]


def verify_timestamps(nb, nooa, grace):
    """Verify if given timeframe (including grace) is valid.

    :param nb:
    :param nooa:
    :param grace: grace/skew time period in seconds
    :return: True/False
    """

    logger = logging.getLogger(__pam_module_name__)

    now = int(time.time())

    logger.info(
        f"SAML assertion validity: NB={time.ctime(nb)} "
        f"NOOA={time.ctime(nooa)} (grace={grace}).")

    if nb and nb > (now + grace):
        logger.error("SAML assertion timestamps verification "
                     "failed: timestamps not yet valid.")
        return False
    if nooa and (nooa + grace) <= now:
        logger.error("SAML assertion timestamps verification "
                     "failed: timestamps expired.")
        return False
    return True


def verify_assertion_signature(auth_data, idp_metadata):
    """Verify SAML assertion signature

    :param auth_data: encoded SAML assertion
    :param idp_metadata: IdP metadata
    :return: verified assertion tree element
    """

    logger = logging.getLogger(__pam_module_name__)

    assertion = decode_assertion(auth_data)
    verified_assertion = b''

    # Extract IdPs signing certificates
    idp_data = []
    for file in [file.strip() for file in idp_metadata.split(',')]:
        idp_data.append(parse_idp_metadata(file))

    for entity, cert in iterate_certs(idp_data):
        try:
            verified_assertion = XMLVerifier().verify(
                assertion,
                x509_cert=cert,
                validate_schema=True)
            logger.debug(f"SAML assertion signature verified for "
                         f"IdP entityID={entity}.")
            break
        except (InvalidSignature,
                InvalidDigest,
                InvalidCertificate,
                InvalidInput) as assertion_verify_err:
            logger.warning(
                f"SAML assertion signature verification error for IdP "
                f"entityID={entity}: {assertion_verify_err}.")

    if verified_assertion:
        verified_assertion = verified_assertion.signed_xml
    else:
        logger.error(
            "SAML assertion signatures can not be verified: "
            "no valid signature found.")
        sys.exit(PAM_AUTH_ERR)
    return verified_assertion


def main():
    """Implements 'pam_script_auth' module for pam-script subsystem.

    :return: PAM compatible exit code
    """

    pam_params = get_pam_params(os.environ, sys.argv[1:])
    logger = config_logging(pam_params.get('log_level'))

    # Verify PAM_TYPE request
    pam_type = pam_params.get('PAM_TYPE')
    if pam_type != 'auth_data':
        logger.error(f"Unsupported PAM_TYPE={pam_type} requested.")
        sys.exit(PAM_MODULE_UNKNOWN)

    # Verify 'only_from' response conditions
    if not verify_only_from(pam_params['PAM_RHOST'], pam_params['only_from']):
        logger.error(
            f"Requesting remote host PAM_RHOST={pam_params['PAM_RHOST']} is "
            f"not allowed to authenticate.")
        sys.exit(PAM_CRED_INSUFFICIENT)

    # Verify SAML assertion signature
    tree_verified = verify_assertion_signature(pam_params.get('PAM_AUTHTOK'),
                                               pam_params.get('idp'))

    # Verify trusted SP
    if verify_trusted_sp(tree_verified, pam_params['trusted_sp']):
        logger.debug(
            f"SAML assertion element Audience "
            f"match trusted_sp={pam_params['trusted_sp']}.")
    else:
        logger.error(
            f"SAML assertion element Audience "
            f"do not match trusted_sp={pam_params['trusted_sp']}.")
        sys.exit(PAM_CRED_INSUFFICIENT)

    # Verify uid matching
    user_id = pam_params.get('user_id')
    user = get_uid_attribute(tree_verified, user_id)
    if user is not None:
        user = user.text
        logger.debug("SAML assertion attribute element with user_id "
                     "value extracted.")
    else:
        logger.error(
            f"SAML assertion did not contain attribute element with "
            f"user_id={user_id} value.")
        sys.exit(PAM_AUTH_ERR)

    pam_user = pam_params.get('PAM_USER')

    if user and (user == pam_user):
        logger.debug(
            f"SAML assertion attribute element user_id={user_id} value match "
            f"to PAM_USER={pam_user}.")
    else:
        logger.error(
            f"SAML assertion attribute element user_id={user_id} value do "
            f"not match to PAM_USER={pam_user}.")
        sys.exit(PAM_AUTH_ERR)

    # Verify timestamps
    if pam_params['check_timeframe']:
        nb, nooa = get_timestamps(tree_verified)
        if verify_timestamps(nb, nooa, pam_params['grace']):
            logger.debug("SAML assertion timestamps verified.")
        else:
            logger.error("SAML assertion timestamps verification failed.")
            sys.exit(PAM_CRED_EXPIRED)
    else:
        logger.warning(
            "SAML assertion time validity not checked: disabled by "
            "check_timeframe=False parameter.")

    logger.info(f"SAML assertion verified: user={user} allowed to login.")
    sys.exit(PAM_SUCCESS)


if __name__ == "__main__":
    main()

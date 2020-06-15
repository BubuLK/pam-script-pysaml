# pam-script-pysaml
This package implements `pam_auth_script` for 
[`pam-script`](https://manpages.debian.org/testing/libpam-script/pam-script.7.en.html) module. Module
validates SAML response assertion given as user password.


### Prerequisites
Ensure you have met the following basic requirements:

* any recent Unix-based system running,
* PAM subsystem installed and configured,
* python 3.6+ installed.

### Installation
(These instructions may vary depending on OS version and your configuration.)

* clone this repository to any appropriate place (e.g. `/usr/share/libpam-script`):
    ```commandline
    git clone https://github.com/BubuLK/pam-script-pysaml
    ```
* install OS dependencies, e.g. for Debian install `zlib` library:
    ```commandline
  apt install zlib1g-dev
    ```
* install Python dependencies:
    ```commandline
    pip3 install -r requirements.txt
    ```
* run a simple tests suite and ensure all tests passed:
    ```commandline
    pytest -v tests/
    ```
* configure PAM system (see bellow).

### Configuration
#### Environment variables
Passed by `pam-script` module as shell environment. All variables are defined,
but some may be empty depending on context:

* `PAM_AUTHTOK`:    password (i.e. encoded SAML response assertion)
* `PAM_RHOST`:      remote host
* `PAM_RUSER`:      the remote user, the user invoking the application
* `PAM_SERVICE`:    the application that's invoking the PAM stack
* `PAM_TYPE`:       the module-type (e.g. auth,account,session,password)
* `PAM_USER`:       the user (login) being authenticated into

#### Configuration options
These options are passed in PAM configuration in `key=value` format (key order
is not significant):

* `dir`: installation dir,
* `grace`: time frame (in seconds) allowing the validation of the assertion
    deviating from the given time frame in the assertion 
    (for clock skew or longer authentication validity). Default: `600`,
* `check_timeframe`: if `False`, validation of the assertion timeframe 
    is disabled (not recommended). Default: `True`,
* `idp`: path(s) to IdP metadata file(s) which signing certificates for assertion
    signature verification are extracted from (multiple CSV values allowed).
    Required to validate assertion signature,
* `log_level`: logging `<severity>`. Default: `WARNING`.
* `only_from`: list of IP/host names which can authenticate
    (multiple CSV values allowed),
* `trusted_sp`: entityID of SP which should be trusted (multiple CSV values allowed).
    If none is given (not recommended) any SP is allowed,
* `userid`: name of SAML attribute which contains the username (login). Value
   of this attribute will be matched against the username passed. Default: `uid`,

#### PAM system configuration
* Copy the metadata.xml file from your IdP somewhere into installation
  (see `idp` parameter above),
* configure PAM module for selected service in `/etc/pam.d/` (or `/etc/pam.conf`)
  like this:

    ```
    auth	required	pam_script.so dir=<dir> user_id=uid grace=900 [...]
    ```

#### Logging
This module use `stdout` stream to logging all information. You can use standard
`systemd` configuration (or simple helper script) to redirect output to
destination of your choice.

## Compatibility
This work is primary focused (and tested) on SSO environment configured with
[Shibboleth](https://www.shibboleth.net/) IdP, [SOGo Groupware](https://sogo.nu/)
as SP and the [Dovecot MDA](http://dovecot.org/)
configured to use PAM authentication (with SAML assertion given as password).

However everything should work fine for any other similar setup.


## References
* [Linux PAM](https://en.wikipedia.org/wiki/Linux_PAM)
* [SAML 2.0](https://en.wikipedia.org/wiki/SAML_2.0)
* [SignXML](https://github.com/XML-Security/signxml)

## Contributing
* reporting bug/issues: https://github.com/BubuLK/pam-script-pysaml/issues,
* contributing code: fork this repository, make proposed changes and use
  PR (Pull Request),
* with any other questions contact author: [L. Kejzlar](mailto:kejzlar@gmail.com) 


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE)
file for details.

## Acknowledgments
* Inspired by [pam-script-saml](https://github.com/ck-ws/pam-script-saml)

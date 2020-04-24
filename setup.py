import os
from setuptools import setup

srcdir = os.path.dirname(__file__)
readme_filename = os.path.join(srcdir, 'README.md')

setup(
    name='pam-script-pysaml',
    version=0.1,
    description='Implements pam_script_auth module for Unix pam-script.',
    long_description=open(readme_filename, encoding="utf-8").read(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
    keywords='SAML Assertion PAM',
    url='https://github.com/BubuLK/pam-script-pysaml',
    author='Lubos Kejzlar',
    author_email='kejzlar@civ.zcu.cz',
    license='MIT',
    packages=['pam_script_pysaml'],
    python_requires='>=3.5',
    install_requires=[
        'signxml',
        'lxml',
        'ciso8601',
    ],
)

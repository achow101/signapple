# -*- coding: utf-8 -*-
from setuptools import setup

packages = ["signapple"]

package_data = {"": ["*"], "signapple": ["certs/*"]}

install_requires = [
    "asn1crypto>=1.4.0,<2.0.0",
    "certvalidator @ "
    "git+https://github.com/achow101/certvalidator.git@allow-more-criticals",
    "elf-esteem @ "
    "git+https://github.com/LRGH/elfesteem.git@87bbd79ab7e361004c98cc8601d4e5f029fd8bd5",
    "macholib>=1.14,<2.0",
    "oscrypto>=1.2.1,<2.0.0",
    "requests>=2.25.1,<3.0.0",
]

entry_points = {"console_scripts": ["signapple = signapple:main"]}

setup_kwargs = {
    "name": "signapple",
    "version": "0.1.0",
    "description": "Signing and verification tool for MacOS code signatures",
    "long_description": None,
    "author": "Andrew Chow",
    "author_email": "achow101-github@achow101.com",
    "maintainer": None,
    "maintainer_email": None,
    "url": None,
    "packages": packages,
    "package_data": package_data,
    "install_requires": install_requires,
    "entry_points": entry_points,
    "python_requires": ">=3.6,<4.0",
}


setup(**setup_kwargs)

from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='ldap-attributes-selector',
    version='0.2.1',
    description='Get a CSV formatted list from an LDAP database based on given attributes.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/tuxedoar/ldap-attributes-selector',
    author='tuxedoar',
    author_email='tuxedoar@gmail.com',
    packages=['ldap_attributes_selector'],
    python_requires='>=3.4',
    scripts=["ldap_attributes_selector/_version.py"],
    entry_points={
        "console_scripts": [
        "ldap-attributes-selector = ldap_attributes_selector.ldap_attributes_selector:main",
        ],
    },
    install_requires=[
    'python-ldap'
    ],

    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.4",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Intended Audience :: System Administrators",
        "Environment :: Console",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
        ],
)

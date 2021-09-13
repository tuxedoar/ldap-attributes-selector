# Copyright 2021 by tuxedoar@gmail.com .

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# ACKNOWLEDGMENT

# The pieces of code that implement LDAP queries with paged controls in this
# program, are based on this Python snippet:

# https://gist.github.com/mattfahrner/c228ead9c516fc322d3a#file-python-paged-ldap-snippet-2-4-py

import csv
import argparse
from sys import exit
import logging
import getpass
import ldapurl
from ldap import SERVER_DOWN
from ldap import UNWILLING_TO_PERFORM
from ldap import INVALID_CREDENTIALS
from ldap import SIZELIMIT_EXCEEDED
from distutils.version import LooseVersion
from _version import __version__
from ldap_attributes_selector.ldap_paging import start_session
from ldap_attributes_selector.ldap_paging import ldap_paging


def main():
    """ LDAP session and logging setup """
    try:
        # Setup logging
        logging.basicConfig(format='%(message)s', level=logging.INFO)
        # Setup arguments for LDAP session
        menu = menu_handler()
        BASEDN = menu.BASEDN
        PAGE_SIZE = menu.sizelimit
        SEARCH_FILTER = menu.filter
        ATTRS_LIST = menu.ATTRIBUTES.split(',')
        ldap_user = menu.userdn

        # Validate LDAP server URL
        if not ldapurl.isLDAPUrl(menu.SERVER):
            logging.critical("\nERROR: %s has an invalid URL format!\n", menu.SERVER)
            exit(1)

        # Pass ldap_auth=True argument when LDAP authentication is needed!.
        if menu.userdn:
            LDAP_SESSION = start_session(menu.SERVER, ldap_user, ldap_auth=True)
            ldap_paging(PAGE_SIZE, BASEDN, SEARCH_FILTER, ATTRS_LIST, LDAP_SESSION)
        else:
            # Anonymous query is performed!.
            LDAP_SESSION = start_session(menu.SERVER, ldap_user, ldap_auth=False)
            ldap_paging(PAGE_SIZE, BASEDN, SEARCH_FILTER, ATTRS_LIST, LDAP_SESSION)

    except (KeyboardInterrupt, SERVER_DOWN, UNWILLING_TO_PERFORM, \
            INVALID_CREDENTIALS, SIZELIMIT_EXCEEDED) as e:
        exit(e)


def menu_handler():
    """ Setup available arguments """
    parser = argparse.ArgumentParser(
        description='Get a CSV formatted list, based on a custom set '
                    'of LDAP attributes')
    parser.add_argument('SERVER', help='URI formatted address (IP or domain name) of the LDAP server')
    parser.add_argument('BASEDN', help='Specify the searchbase or base DN of the LDAP server')
    parser.add_argument('ATTRIBUTES', help='A set of comma separated LDAP attributes to list')
    parser.add_argument('-u', '--userdn', required=False, action='store',
                        help='Distinguished Name (DN) of the user to bind to the LDAP directory')
    parser.add_argument('-S', '--sizelimit', nargs='?', type=int, default=500,
                        help='The amount of per-page entries to retrieve (Default: 500)')
    parser.add_argument('-f', '--filter', nargs='?', type=str,
                        default="objectClass=*", \
                        help="Specify an LDAP filter (Default: 'objectClass=*')")
    parser.add_argument('-w', '--writetocsv', required=False, action='store',
                        help="Write results to a CSV file!.")
    parser.add_argument('-v', '--version', action='version',
                        version="%(prog)s {version}".format(version=__version__),
                        help='Show current version')

    args = parser.parse_args()
    return args


def write_to_csv(csv_file, fmode, attrs, append_csv_headers=False):
    """ Write retrieved results to a CSV file """

    if append_csv_headers:
        with open(csv_file, 'r') as original:
            data = original.read()
        with open(csv_file, 'w') as modified:
            modified.write(attrs + data)
    else:
        with open(csv_file, fmode) as f:
            writer = csv.writer(f)
            writer.writerow(attrs)


if __name__ == "__main__":
    main()

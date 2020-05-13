# Copyright 2020 by tuxedoar@gmail.com .

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
from distutils.version import LooseVersion
from ldap.controls import SimplePagedResultsControl
import ldap
from _version import __version__


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

        # Pass ldap_auth=True argument when LDAP authentication is needed!.
        if menu.userdn:
            LDAP_SESSION = start_session(menu.SERVER, ldap_auth=True)
            ldap_paging(PAGE_SIZE, BASEDN, SEARCH_FILTER, ATTRS_LIST, LDAP_SESSION)
        else:
            # Anonymous query is performed!.
            LDAP_SESSION = start_session(menu.SERVER, ldap_auth=False)
            ldap_paging(PAGE_SIZE, BASEDN, SEARCH_FILTER, ATTRS_LIST, LDAP_SESSION)

    except (KeyboardInterrupt, ldap.SERVER_DOWN, ldap.UNWILLING_TO_PERFORM, \
            ldap.INVALID_CREDENTIALS, ldap.SIZELIMIT_EXCEEDED) as e:
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


def start_session(server, ldap_auth):
    """ Initiate the LDAP session """
    menu = menu_handler()
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    ldap.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
    l = ldap.initialize(server)
    l.set_option(ldap.OPT_REFERRALS, 0)

    if ldap_auth:
        user = menu.userdn
        creds = getpass.getpass('\nPlease, enter your LDAP credentials: ')
        lsession = l.simple_bind_s(user, creds)
        if lsession:
            logging.info("\nSuccessful LDAP authentication!\n")
    else:
        logging.warning("\nWARNING: No user specified. Performing an anonymous query!\n")
    return l


def create_controls(pagesize, LDAP_API_CHECK):
    """Create an LDAP control with a page size of "pagesize"."""
    # Initialize the LDAP controls for paging. Note that we pass ''
    # for the cookie because on first iteration, it starts out empty.
    if LDAP_API_CHECK:
        return SimplePagedResultsControl(True, size=pagesize, cookie='')
    return SimplePagedResultsControl(ldap.LDAP_CONTROL_PAGE_OID, True,
                                     (pagesize, ''))


def get_pctrls(serverctrls, LDAP_API_CHECK):
    """Lookup an LDAP paged control object from the returned controls."""
    # Look through the returned controls and find the page controls.
    # This will also have our returned cookie which we need to make
    # the next search request.
    if LDAP_API_CHECK:
        return [c for c in serverctrls
                if c.controlType == SimplePagedResultsControl.controlType]
    return [c for c in serverctrls
            if c.controlType == ldap.LDAP_CONTROL_PAGE_OID]


def set_cookie(lc_object, pctrls, pagesize, LDAP_API_CHECK):
    """Push latest cookie back into the page control."""
    if LDAP_API_CHECK:
        cookie = pctrls[0].cookie
        lc_object.cookie = cookie
        return cookie
    est, cookie = pctrls[0].controlValue
    lc_object.controlValue = (pagesize, cookie)
    return cookie


def process_retrieved_data(retrieved_data):
    """ Show retrieved data or export to CSV """
    menu = menu_handler()
    # Get the order in which attributes were requested!
    attrs_order = menu.ATTRIBUTES.split(',')

    # Go through the retrieved attributes and find those selected by the user.
    # Replace with 'None' whenever an attribute is not found!.
    user_attrs = [retrieved_data.get(i, 'None') for i in attrs_order]
    # Decode bytes type objects only and leave out those that are not ('None')!.
    decoded_user_attrs = [i[0].decode() if isinstance(i[0], bytes) else i \
                    for i in user_attrs]

    # If '-w' argument was given, call function to write results to CSV!.
    if menu.writetocsv:
        write_to_csv(menu.writetocsv, 'a', decoded_user_attrs, \
                        append_csv_headers=False)
    else:
        # Print selected attributes!.
        print(','.join(decoded_user_attrs))


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


def ldap_paging(PAGE_SIZE, BASEDN, SEARCH_FILTER, ATTRS_LIST, LDAP_SESSION):
    """ Try to pull the search results using paged controls """
    # Check if we're using the Python "ldap" 2.4 or greater API
    LDAP_API_CHECK = LooseVersion(ldap.__version__) >= LooseVersion('2.4')
    lconn = LDAP_SESSION
    # Create the page control to work from
    lc = create_controls(PAGE_SIZE, LDAP_API_CHECK)

    # Do searches until we run out of "pages" to get from
    # the LDAP server.
    while True:
        # Send search request
        try:
            msgid = lconn.search_ext(BASEDN, ldap.SCOPE_SUBTREE, SEARCH_FILTER,
                                     ATTRS_LIST, serverctrls=[lc])
        except ldap.LDAPError as e:
            exit('LDAP search failed: %s' % e)

        # Pull the results from the search request
        try:
            rtype, rdata, rmsgid, serverctrls = lconn.result3(msgid)
        except ldap.LDAPError as e:
            exit('Could not pull LDAP results: %s' % e)

        # Each "rdata" is a tuple of the form (dn, attrs), where dn is
        # a string containing the DN (distinguished name) of the entry,
        # and attrs is a dictionary containing the attributes associated
        # with the entry. The keys of attrs are strings, and the associated
        # values are lists of strings.
        for dn, attrs in rdata:
            if isinstance(attrs, dict) and attrs:
                process_retrieved_data(attrs)

        # Get cookie for next request
        pctrls = get_pctrls(serverctrls, LDAP_API_CHECK)
        if not pctrls:
            logging.warning("Warning: Server ignores RFC 2696 control.")
            break

        # Ok, we did find the page control, yank the cookie from it and
        # insert it into the control for our next search. If however there
        # is no cookie, we are done!
        cookie = set_cookie(lc, pctrls, PAGE_SIZE, LDAP_API_CHECK)
        if not cookie:
            break

    # Add CSV headers
    menu = menu_handler()
    if menu.writetocsv:
        attrs = menu.ATTRIBUTES+'\n'
        write_to_csv(menu.writetocsv, 'r+', attrs, \
        append_csv_headers=True)

    # Clean up and exit
    lconn.unbind()
    exit(0)

if __name__ == "__main__":
    main()

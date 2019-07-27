# Copyright 2019 by tuxedoar@gmail.com .

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

# DESCRIPTION

# This script allows you to query an LDAP server, based on a custom set of
# provided attributes. The results are given in CSV format, though they
# are not written to a CSV file unless explicitly specified.

# ACKNOWLEDGMENT

# The pieces of code that implement LDAP queries with paged controls in this
# script, are based on this Python snippet:

# https://gist.github.com/mattfahrner/c228ead9c516fc322d3a#file-python-paged-ldap-snippet-2-4-py

import csv
import argparse
import sys
import getpass
from distutils.version import LooseVersion
from ldap.controls import SimplePagedResultsControl
from _version import __version__
import ldap

# Check if we're using the Python "ldap" 2.4 or greater API
LDAP24API = LooseVersion(ldap.__version__) >= LooseVersion('2.4')

def start_session(server, ldap_auth=None):
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
            print("\nSuccessful LDAP authentication!\n")
            return l
    else:
        print("\nWARNING: No user specified. Performing an anonymous query!\n")
        return l


def menu_handler():
    """ Setup available arguments """
    parser = argparse.ArgumentParser(
        description='Get a CSV formatted list from an LDAP database,'
                    ' given a custom set of provided attributes.')
    parser.add_argument('SERVER', help='URI formatted address (IP or domain name) of the LDAP server')
    parser.add_argument('BASEDN', help='Specify the searchbase or base DN of the LDAP server')
    parser.add_argument('USER_ATTRS', help='A set of comma separated LDAP attributes to list')
    parser.add_argument('-u', '--userdn', required=False, action='store',
                        help='Distinguished Name (DN) of the user to bind to the LDAP directory')
    parser.add_argument('-S', '--sizelimit', required=False, action='store',
                        help='The amount of per-page entries to retrieve (Default: 500)')
    parser.add_argument('-f', '--filter', required=False, action='store',
                        help="Specify an LDAP filter (Default: 'objectClass=*')")
    parser.add_argument('-w', '--writetocsv', required=False, action='store',
                        help="Write results to a CSV file!.")
    parser.add_argument('-v', '--version', action='version',
                       version="%(prog)s {version}".format(version=__version__),
                        help='Show current version')

    args = parser.parse_args()
    return args


def create_controls(pagesize):
    """Create an LDAP control with a page size of "pagesize"."""
    # Initialize the LDAP controls for paging. Note that we pass ''
    # for the cookie because on first iteration, it starts out empty.
    if LDAP24API:
        return SimplePagedResultsControl(True, size=pagesize, cookie='')
    return SimplePagedResultsControl(ldap.LDAP_CONTROL_PAGE_OID, True,
                                     (pagesize, ''))


def get_pctrls(serverctrls):
    """Lookup an LDAP paged control object from the returned controls."""
    # Look through the returned controls and find the page controls.
    # This will also have our returned cookie which we need to make
    # the next search request.
    if LDAP24API:
        return [c for c in serverctrls
                if c.controlType == SimplePagedResultsControl.controlType]
    return [c for c in serverctrls
            if c.controlType == ldap.LDAP_CONTROL_PAGE_OID]


def set_cookie(lc_object, pctrls, pagesize):
    """Push latest cookie back into the page control."""
    if LDAP24API:
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
    attrs_order = menu.USER_ATTRS.split(',')

    # Go through the retrieved attributes and find those selected by the user.
    # Replace with 'None' whenever an attribute is not found!. 
    user_attrs = [retrieved_data.get(i,'None') for i in attrs_order]
    # Decode bytes type objects only and leave out those that are not ('None')!. 
    decoded_user_attrs = [i[0].decode() if isinstance(i[0], bytes) else i \
                    for i in user_attrs]

    # If '-w' argument was given, call function to write results to CSV!.
    if menu.writetocsv:
        write_to_csv(menu.writetocsv, decoded_user_attrs)
    else:
        # Print selected attributes!.
        print(','.join(decoded_user_attrs))


def write_to_csv(csv_file, attrs):
    """ Write retrieved results to a CSV file """

    with open(csv_file, 'a') as file:
        writer = csv.writer(file)
        writer.writerow(attrs)


def ldap_paging(PAGE_SIZE, BASEDN, SEARCH_FILTER, ATTRS_LIST, LDAP_SESSION):
    """ Try to pull the search results using paged controls """

    lconn = LDAP_SESSION
    # Create the page control to work from
    lc = create_controls(PAGE_SIZE)

    # Do searches until we run out of "pages" to get from
    # the LDAP server.
    while True:
        # Send search request
        try:
            msgid = lconn.search_ext(BASEDN, ldap.SCOPE_SUBTREE, SEARCH_FILTER,
                                       ATTRS_LIST, serverctrls=[lc])
        except ldap.LDAPError as e:
            sys.exit('LDAP search failed: %s' % e)

        # Pull the results from the search request
        try:
            rtype, rdata, rmsgid, serverctrls = lconn.result3(msgid)
        except ldap.LDAPError as e:
            sys.exit('Could not pull LDAP results: %s' % e)

        # Each "rdata" is a tuple of the form (dn, attrs), where dn is
        # a string containing the DN (distinguished name) of the entry,
        # and attrs is a dictionary containing the attributes associated
        # with the entry. The keys of attrs are strings, and the associated
        # values are lists of strings.
        for dn, attrs in rdata:
            if isinstance(attrs, dict) and attrs:
                process_retrieved_data(attrs)

        # Get cookie for next request
        pctrls = get_pctrls(serverctrls)
        if not pctrls:
            print("Warning: Server ignores RFC 2696 control.")
            break

        # Ok, we did find the page control, yank the cookie from it and
        # insert it into the control for our next search. If however there
        # is no cookie, we are done!
        cookie = set_cookie(lc, pctrls, PAGE_SIZE)
        if not cookie:
            break

    # Clean up
    lconn.unbind()

    # Done!
    sys.exit(0)


def main():
    """ Putting all together """
    try:
        menu = menu_handler()
        BASEDN = menu.BASEDN
        PAGE_SIZE = 500
        SEARCH_FILTER = "objectClass=*"
        ATTRS_LIST = menu.USER_ATTRS.split(',')

        # Check if sizelimit, filter opts were given.   
        PAGE_SIZE = int(menu.sizelimit) if menu.sizelimit else PAGE_SIZE
        SEARCH_FILTER = menu.filter if menu.filter else SEARCH_FILTER
        # Pass ldap_auth=True argument when LDAP authentication is needed!.
        if menu.userdn:
            LDAP_SESSION = start_session(menu.SERVER, ldap_auth=True)
            ldap_paging(PAGE_SIZE, BASEDN, SEARCH_FILTER, ATTRS_LIST, LDAP_SESSION)
        else:
            # Anonymous query is performed!.
            LDAP_SESSION = start_session(menu.SERVER)
            ldap_paging(PAGE_SIZE, BASEDN, SEARCH_FILTER, ATTRS_LIST, LDAP_SESSION)

    except (KeyboardInterrupt, ldap.SERVER_DOWN, ldap.UNWILLING_TO_PERFORM, \
            ldap.INVALID_CREDENTIALS, ldap.SIZELIMIT_EXCEEDED) as e:
        sys.exit(e)


if __name__ == "__main__":
    main()

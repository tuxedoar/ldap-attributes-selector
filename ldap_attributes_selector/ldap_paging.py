# Copyright 2021 by Tuxedoar <tuxedoar@gmail.com>

# LICENSE

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

import ldap
from ldap.controls import SimplePagedResultsControl
from ldap_attributes_selector.ldap_attributes_selector import write_to_csv

""" Helper functions for LDAP paging """

def start_session(server, ldap_user, ldap_auth):
    """ Initiate the LDAP session """
    #menu = menu_handler()
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    ldap.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
    l = ldap.initialize(server)
    l.set_option(ldap.OPT_REFERRALS, 0)

    if ldap_auth:
        #user = menu.userdn
        creds = getpass.getpass('\nPlease, enter your LDAP credentials: ')
        lsession = l.simple_bind_s(ldap_user, creds)
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

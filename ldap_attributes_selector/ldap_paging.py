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

from ldap.controls import SimplePagedResultsControl

""" Helper functions for LDAP paging """

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

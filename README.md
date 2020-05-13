# LDAP Attributes Selector 

This command line program, allows you to query an LDAP server and retrieve a custom set of provided attributes. 

### Features
This program offers the following features:
 * Support for both *anonymous* and *authenticated LDAP queries*.
 * Encrypted queries with SSL.
 * Support for *LDAP filters* and *LDAP paging* (retrieve the total amount of
entries, regardless of limitations imposed by the server)!.
 * Export results to CSV.

### Requirements
Make sure you meet the following requirements:
 * [Python 3](https://www.python.org/downloads/)
 * [python-ldap](https://pypi.python.org/pypi/python-ldap/) library (tested
with *v3.2.0*).

### Installation
You can install it with `pip`:
```
pip install ldap-attributes-selector
```

### Usage 
First, some aspects of this tool to take into account:
 * Results are shown in CSV format, but they aren't written to a file by default!.
 * Note that whenever an *LDAP entry* doesn't have any of the provided *attributes*,
a `None` value is set, instead!.
 * When establishing an SSL connection, depending on the security settings on your
LDAP server, you might gonna need to perform some additional configuration on your LDAP client!.   
 * As a general rule, if you are able to make an LDAP query with the `ldapsearch` tool, this program should work as well!. 

Here's the complete help output:
```
usage: ldap-attributes-selector [-h] [-u USERDN] [-S SIZELIMIT] [-f FILTER]
                                [-w WRITETOCSV] [-v]
                                SERVER BASEDN ATTRIBUTES

Get a CSV formatted list, based on a custom set of LDAP attributes

positional arguments:
  SERVER                URI formatted address (IP or domain name) of the LDAP
                        server
  BASEDN                Specify the searchbase or base DN of the LDAP server
  ATTRIBUTES            A set of comma separated LDAP attributes to list

optional arguments:
  -h, --help            show this help message and exit
  -u USERDN, --userdn USERDN
                        Distinguished Name (DN) of the user to bind to the
                        LDAP directory
  -S SIZELIMIT, --sizelimit SIZELIMIT
                        The amount of per-page entries to retrieve (Default:
                        500)
  -f FILTER, --filter FILTER
                        Specify an LDAP filter (Default: 'objectClass=*')
  -w WRITETOCSV, --writetocsv WRITETOCSV
                        Write results to a CSV file!.
  -v, --version         Show current version
```

### Examples
In the following example, an encrypted LDAP query (note the `ldaps://` when specifying the LDAP server) is made, and the attributes `name`, `mail` and `ipPhone` are retrieved. Also, LDAP filter `objectClass=person` is set:
```
ldap-attributes-selector ldaps://somecorp.com "dc=somecorp,dc=com" -u "cn=Joe,ou=Users,dc=somecorp,dc=com" "name,mail,ipPhone" -f objectClass=person
```

Unlike the previous example, on the following one, the query isn't encrypted and a different LDAP filter is used: 
```
ldap-attributes-selector ldap://somecorp.com "dc=somecorp,dc=com" -u "uid=zimbra,cn=admins,cn=zimbra" "givenName,mail,zimbraAccountStatus" -f 'objectClass=inetOrgPerson'
```

This one is similar to the first one except that, this time, the retrieved results, are gonna be exported to a CSV file!: 
```
ldap-attributes-selector ldaps://somecorp.com "dc=somecorp,dc=com" -u "cn=joe,ou=Users,dc=somecorp,dc=com" "name,mail,ipPhone" -f objectClass=person -w users.csv
```

If no *user identity* (in DN format!) is specified (`-u` argument), an *anonymous* LDAP query is performed, as in the following example:
```
ldap-attributes-selector ldap://somecorp.com "dc=somecorp,dc=com" "sn,givenName,mail"
```

### License
This program is licensed under the GPLv3.

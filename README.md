# LDAP Attributes Selector 

This command line program, allows you to query an LDAP server, based on a custom set of provided attributes. The results are given in CSV format, though they are not written to a CSV file unless explicitly specified. 

### Requirements
Make sure you meet the following requirements:
 * [Python 3](https://www.python.org/downloads/)
 * [python-ldap](https://pypi.python.org/pypi/python-ldap/) library (tested with *v3.1.0*).

Also, note that when establishing an SSL connection, depending on the security settings in your LDAP server, you might gonna need to perform some additional configuration on your LDAP client!.   

As a general rule, if you are able to make an LDAP query with the `ldapsearch` tool, this script should work as well!. 

### Installation
You can install it with `pip`:
```
pip install ldap-attributes-selector
```

### Usage 
Help output:
```
usage: ldap-attributes-selector [-h] [-u USERDN] [-S SIZELIMIT] [-f FILTER]
                                   [-w WRITETOCSV] [-v]
                                   SERVER BASEDN USER_ATTRS

Get a CSV formatted list from an LDAP database, given a custom set of provided
attributes.

positional arguments:
  SERVER                URI formatted address (IP or domain name) of the LDAP
                        server
  BASEDN                Specify the searchbase or base DN of the LDAP server
  USER_ATTRS            A set of comma separated LDAP attributes to list

optional arguments:
  -h, --help            show this help message and exit
  -u USERDN, --userdn USERDN
                        Distinguished Name (DN) of the user to bind to the
                        LDAP directory
  -S SIZELIMIT, --sizelimit SIZELIMIT
                        Specify the maximum number of LDAP entries to display
                        (Default: 500)
  -f FILTER, --filter FILTER
                        Specify an LDAP filter (Default: 'objectClass=*')
  -w WRITETOCSV, --writetocsv WRITETOCSV
                        Write results to a CSV file!.
  -v, --version         Show current version
```
Note that whenever an entry doesn't have any of the provided LDAP attributes, nothing will be printed!.

### Examples
In the following example, an encrypted LDAP query (note the `ldaps://` when specifying the LDAP server) is made, and the attributes `name`, `mail` and `ipPhone` are retrieved. In addition, the search base used is `objectClass=person` and a maximum of 50 entries will be printed!:
```
ldap-attributes-selector ldaps://somecorp.com "dc=somecorp,dc=com" -u "cn=Joe,ou=Users,dc=somecorp,dc=com" "name,mail,ipPhone" -S 50 -f objectClass=person
```

Unlike the previous example, on the next one, the query won't be encrypted; a different LDAP filter is used and no limits on the number of results to display are given, other than the defults (500 entries): 
```
ldap-attributes-selector ldap://somecorp.com "dc=somecorp,dc=com" -u "uid=zimbra,cn=admins,cn=zimbra" "givenName,mail,zimbraAccountStatus" -f 'objectClass=inetOrgPerson'
```

This other example is similar to the first one, except that, this time, the retrieved results, are gonna be exported to a CSV file!: 
```
ldap-attributes-selector ldaps://somecorp.com "dc=somecorp,dc=com" -u "cn=joe,ou=Users,dc=somecorp,dc=com" "name,mail,ipPhone" -S 50 -f objectClass=person -w users.csv
```

If no *user identity* (in DN format!) is specified (`-u` argument), an *anonymous* LDAP query is performed, as in the following example:
```
ldap-attributes-selector ldap://somecorp.com "dc=somecorp,dc=com" "sn,givenName,mail"
```

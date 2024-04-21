References the following article: https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53



Simple bind usage:
------------------
```./target/debug/ldap_rust -i 172.16.0.6 -u "CN=bruhurb,CN=Users,DC=fed,DC=local" -p "MyPassword123!!!" -d "DC=fed,DC=local"```




Kerberos usage:
---------------
```KRB5CCNAME=bruhurb\@dc02.fed.local.ccache ./target/debug/ldap_rust -k -i dc02.fed.local -d "DC=fed,DC=local"```




Make sure to configure your /etc/krb5.conf file with the desired realm(s).

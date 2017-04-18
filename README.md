# Bouncy castle regression test

The BcPGP library behaves differently for bc 1.46 and 1.56 regarding PGP key validity with keys with multiple signatures.


This testcase contains a public keyring with a key with two signatures. One expires the key after five days, the other after 10 years.

```sh
$ GNUPGHOME=common/src/main/resources/gpg gpg2 --list-sigs DBB2C40D
pub   2048R/DBB2C40D 2017-04-18 [expires: 2017-04-23]
uid       [ultimate] double-signature-expired-first
sig 3        DBB2C40D 2017-04-18  double-signature-expired-first
sig 3        DBB2C40D 2017-04-18  double-signature-expired-first
sub   2048R/86025F04 2017-04-18 [expires: 2027-04-16]
sig          DBB2C40D 2017-04-18  double-signature-expired-first
```

Note the two signatures on the `DBB2C40D`.

Creating such a key:

```sh
gpg --gen-key (with 10 years validity)
gpg --export --armor <new-key-id> > original-expiration.key
gpg --edit-key <new-key-id>, change validity to five days
gpg --import < original-expiration.key
```

## Testing

```sh
$ mvn clean install
```

compiles and runs the same test cases against bc 1.46 and bc 1.56


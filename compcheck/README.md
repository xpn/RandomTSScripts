## Info

This is a quick and dirty script designed to be used over an implant SOCKS proxy to check Pre2K or computers with "Reset Password" done for default creds via a TGS.

The idea is to avoid having to spray authentication attempts across a domain.

If no SPN is provided (some newly created computer accounts don't have one set), the script will use the principal name to request the TGS (`userAccountControl` accounts with `WORKSTATION_TRUST_ACCOUNT` can be requested without an SPN). Using an SPN is preferred, as without may look a bit weird for opsec.

## Usage

To use this tool you'll need a TGT for a user.. just use `getTGT.py` or something.

Then set with `export KRB5CCNAME=myuser.ccache`.

```
# Using an SPN
python3 compcheck.py COMPUTER-NAME DOMAIN-NAME DC-IP SPN

# Without an SPN
python3 compcheck.py COMPUTER-NAME DOMAIN-NAME DC-IP
```

For example:

```
# Using an SPN
python3 compcheck.py PRE2KCOMPUTER LAB.LOCAL 192.168.130.2 HOST/PRE2KCOMPUTER

# Without an SPN
python3 compcheck.py PRE2KCOMPUTER LAB.LOCAL 192.168.130.2
```

## Further Info

Oddvar's original blog post - [Diving Info Pre-Created Computer Accounts](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/)
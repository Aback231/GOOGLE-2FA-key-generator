from datetime import datetime, timezone
import hmac, base64, struct, hashlib, time

GOOGLE_TOTP_TIME = 30
SECRETS = {}

def get_hotp_token(secret, intervals_no):
	"""This is where the magic happens."""
	key = base64.b32decode(normalize(secret), True) # True is to fold lower into uppercase
	msg = struct.pack(">Q", intervals_no)
	h = bytearray(hmac.new(key, msg, hashlib.sha1).digest())
	o = h[19] & 15
	h = str((struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000)
	return prefix0(h)

def get_totp_token(secret, totp_time):
	"""The TOTP token is just a HOTP token seeded with every 30 seconds."""
	return get_hotp_token(secret, intervals_no=int(time.time())//totp_time)

def normalize(key):
	"""Normalizes secret by removing spaces and padding with = to a multiple of 8"""
	k2 = key.strip().replace(' ','')
	# k2 = k2.upper()	# skipped b/c b32decode has a foldcase argument
	if len(k2)%8 != 0:
		k2 += '='*(8-len(k2)%8)
	return k2

def prefix0(h):
	"""Prefixes code with leading zeros if missing."""
	if len(h) < 6:
		h = '0'*(6-len(h)) + h
	return h

def get_totp_time(totp_time):
    unix_time = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
    time_counter = int(totp_time - ((unix_time / 1000) % totp_time))
    return str(time_counter)

def load_secrets():
    with open('secrets.txt') as f:
        global SECRETS
        try:
            lines = f.readlines()
            br = 0
            for i, line in enumerate(lines):
                SECRETS[lines[br].strip()] = lines[br+1].strip()
                br = br+2
        except Exception as e:
            pass


if __name__ == "__main__":
    load_secrets()
    for i, (k,v) in enumerate(SECRETS.items()):
        print("**************************** Email {} ***************************".format(i+1))
        print("Email: {}".format(k))
        print("2FA: {}".format(v))
        print("TOTP: {}".format(get_totp_token(v, GOOGLE_TOTP_TIME)))
        print("**************************** Email {} ***************************".format(i+1))

    print("\nTOTP time left: {}s".format(get_totp_time(GOOGLE_TOTP_TIME)))
    

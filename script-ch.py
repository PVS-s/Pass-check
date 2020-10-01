import requests
import hashlib
import sys


def request_api_data(querychar):
    url = 'https://api.pwnedpasswords.com/range/' + querychar  # request
    res = requests.get(url)  # response
    if res.status_code != 200:  # <Response [400]> = nope, 200 means ok
        raise RuntimeError('Error fetching: {}, check the api'.format(res.status_code))
    return res

# encoder just encodes to utf-8, unicode obj must be encoded before hashing
# hashlib creates hash object
# we need to convert hash obj to hex str
# hexdigest returns str object or double length, containing only hex digites


def get_passw_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1passw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, remains = sha1passw[:5], sha1passw[5:]
    response = request_api_data(first5_char)
    return get_passw_leak_count(response, remains)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print('{} was found {} times..you should change you password'.format(password, count))
        else:
            print('Your {} was not found. All good'.format(password))
    return 'done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

# hash passwords
# AAFDC23870ECBCD3D557B6423A8982134E17927E
# hash function generates a value of fixed length for each input that it gets
# types of hash function: md5(not cryptograph. secure), sha-1, sha-256(crypto+)
# idempotent means that an func. given the same input produces the same output
# hash func that we use for hash tables is gonna take input, generate gibberish
# and then convert it to index space(address) that it has based on generated O
# you only give a key to a hash table and it will know were it's in memory

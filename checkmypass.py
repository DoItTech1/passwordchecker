import requests
import hashlib
import sys

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code > 200:
        raise Exception(f'{res.status_code} too high. Needs to be 200 or under. Check API')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1 = hashlib.sha1()
    password_bytes = password.encode('utf-8')
    sha1.update(password_bytes)
    hashed_password = sha1.hexdigest().upper()

    first5_char, tail = hashed_password[:5], hashed_password[5:]
    api_response = request_api_data(first5_char)
    return get_password_leaks_count(api_response, tail)

def main(args):
    count = pwned_api_check(args)
    if count:
        print(f'{args} was found {count} times')
    else:
        print(f'{args} was found 0 times.')

if __name__ == '__main__':
    main(sys.argv[1])



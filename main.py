import requests
import hashlib
import sys

def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code !=200:
        raise RuntimeError(f"Error Fetching :{res.status_code},check the api")
    return res


def get_password_leaks_count(hashes,hash_to_check):
    hashes=(line.split(":") for line in hashes.text.splitlines())
    for h,count in hashes:
        if h==hash_to_check:
            return count
    return 0

def pawned_api_check(password):
    sha1password=hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    req_sha1password=sha1password[0:5]
    tail_sha1password=sha1password[5:]
    response=request_api_data(req_sha1password)
    return get_password_leaks_count(response,tail_sha1password)


def main(args):
    for passwod in args:
        count=pawned_api_check(passwod)
        if count:
            print(f"{passwod} was found {count} times.You should probably change it")
        else:
            print("Your password have never been hacked")

main(sys.argv[1:])
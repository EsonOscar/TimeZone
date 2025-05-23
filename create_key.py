from cryptography.fernet import Fernet
from pathlib import Path

def create_key():
    # Generate key
    key = Fernet.generate_key().decode()
    # write the command that sets the key as an environment variable
    # (once the terminal is restarted)
    command = f'export FERNET_KEY="{key}"\n'

    # Print key for copy-pasting, pls safeguard key
    print(command.strip())

    # define path to .bashrc
    # write the command to .bashrc
    rc = Path.home() / '.bashrc'
    with open(rc, 'a') as f:
        f.write("\n# Fernet key for TimeZone.db encryption\n")
        f.write(command)
        f.write("\n# End of Fernet key\n")
    
    print(f"Key saved to {rc}.\nPlease restart your terminal or run 'source {rc}' to use the key.")

create_key()

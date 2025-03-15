# Create a dummy key of 80 chars for testing

import secrets

def generate_random_hex(length) -> str:
    """Generate a random hex string of specified length."""
    return secrets.token_hex(length // 2)

if __name__ == "__main__":
    random_hex_string = generate_random_hex(80)
    print(random_hex_string)

import random
import string

def generate_password(length=12, use_uppercase=True, use_lowercase=True, 
                     use_digits=True, use_special_chars=True):
    """
    Generate a random password with specified characteristics.
    
    Parameters:
        length (int): Length of the password
        use_uppercase (bool): Include uppercase letters
        use_lowercase (bool): Include lowercase letters
        use_digits (bool): Include digits
        use_special_chars (bool): Include special characters
        
    Returns:
        str: Generated password
    """
    # Define character sets
    uppercase_chars = string.ascii_uppercase if use_uppercase else ""
    lowercase_chars = string.ascii_lowercase if use_lowercase else ""
    digit_chars = string.digits if use_digits else ""
    special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/" if use_special_chars else ""
    
    # Combine all chosen character sets
    all_chars = uppercase_chars + lowercase_chars + digit_chars + special_chars
    
    # Validate that at least one character set is selected
    if not all_chars:
        raise ValueError("At least one character set must be selected")
    
    # Ensure password meets minimum criteria (at least one character from each selected set)
    password = []
    
    if use_uppercase and uppercase_chars:
        password.append(random.choice(uppercase_chars))
    if use_lowercase and lowercase_chars:
        password.append(random.choice(lowercase_chars))
    if use_digits and digit_chars:
        password.append(random.choice(digit_chars))
    if use_special_chars and special_chars:
        password.append(random.choice(special_chars))
    
    # Fill the rest of the password with random characters
    remaining_length = length - len(password)
    password.extend(random.choices(all_chars, k=remaining_length))
    
    # Shuffle the password to make it more random
    random.shuffle(password)
    
    # Convert list to string and return
    return ''.join(password)
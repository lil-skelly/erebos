import random
import string

def random_string(n: int = 16, sample: str = string.ascii_lowercase + string.digits):
    """Returns a random string using the characters defined in sample"""
    return "".join(random.choices(sample, k=n))

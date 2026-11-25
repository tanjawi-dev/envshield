import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon entropy of a string.
    Higher entropy indicates higher randomness, typical of generated secrets and tokens.
    """
    if not data:
        return 0.0

    length = len(data)
    frequencies = Counter(data)
    entropy = 0.0

    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


def is_high_entropy(data: str, threshold: float = 4.3, min_length: int = 16) -> bool:
    """
    Determines if a candidate string looks like a high-entropy secret.
    Filters out common low-entropy patterns like repetitions or simple sequences.
    """
    if len(data) < min_length:
        return False

    # Skip strings with too many whitespace characters
    if any(c.isspace() for c in data):
        return False

    entropy = shannon_entropy(data)
    return entropy >= threshold

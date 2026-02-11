import numpy as np

from universal_rf import UniversalSignalAnalyzer


def test_bits_to_hex_byte_aligned():
    bits = np.array([1, 0, 1, 0, 1, 0, 1, 0], dtype=np.int8)
    assert UniversalSignalAnalyzer._bits_to_hex(bits) == "AA"


def test_bits_to_hex_padded():
    bits = np.array([1, 1, 1, 1], dtype=np.int8)
    assert UniversalSignalAnalyzer._bits_to_hex(bits) == "F0"

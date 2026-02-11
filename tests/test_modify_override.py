from universal_rf import DecodedSignal, DeviceType, SignalType, apply_field_override


def base_decoded():
    return DecodedSignal(
        raw_bits="101010101010101011110000",
        hex_data="",
        modulation="ASK/OOK",
        encoding="NRZ",
        baud_rate=1000,
        frequency=433920000,
        sample_rate=8000000,
        snr_db=20.0,
        estimated_center_hz=433920100.0,
        confidence=0.8,
        address="10101010101010101111",
        command="0000",
        device_type=DeviceType.REMOTE_CONTROL,
        signal_type=SignalType.FIXED_CODE,
    )


def test_apply_field_override_decimal():
    d = base_decoded()
    out = apply_field_override(d, "command", "3")
    assert out.command == "0011"
    assert out.raw_bits.endswith("0011")


def test_apply_field_override_binary():
    d = base_decoded()
    out = apply_field_override(d, "command", "1111")
    assert out.command == "1111"
    assert out.raw_bits.endswith("1111")

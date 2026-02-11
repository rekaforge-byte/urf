#!/usr/bin/env python3
"""
Universal RF Reverse Engineering Framework (Research/Educational)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np


class DeviceType(Enum):
    CAR_KEY_ROLLING = "car_key_rolling"
    CAR_KEY_FIXED = "car_key_fixed"
    GARAGE_DOOR = "garage_door"
    GATE_CONTROLLER = "gate_controller"
    ALARM_SYSTEM = "alarm_system"
    REMOTE_CONTROL = "remote_control"
    POWER_OUTLET = "power_outlet"
    DOORBELL = "doorbell"
    PAGER = "pager"
    SMART_HOME = "smart_home"
    UNKNOWN = "unknown"


class SignalType(Enum):
    FIXED_CODE = "fixed"
    ROLLING_CODE = "rolling"
    ENCRYPTED = "encrypted"
    TIMESTAMP = "timestamp"
    LEARNING_CODE = "learning"
    UNKNOWN = "unknown"


@dataclass
class DecodedSignal:
    raw_bits: str
    hex_data: str
    modulation: str
    encoding: str
    baud_rate: int
    frequency: int
    sample_rate: int
    snr_db: float
    estimated_center_hz: float
    confidence: float
    preamble: Optional[str] = None
    address: Optional[str] = None
    command: Optional[str] = None
    counter: Optional[str] = None
    checksum: Optional[str] = None
    device_type: DeviceType = DeviceType.UNKNOWN
    signal_type: SignalType = SignalType.UNKNOWN
    notes: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class ProtocolDatabase:
    KNOWN_PROTOCOLS: Dict[str, Dict] = {
        "ev1527_learning": {
            "device_type": DeviceType.REMOTE_CONTROL,
            "signal_type": SignalType.LEARNING_CODE,
            "pattern": {"total_bits": 24, "address_bits": 20, "data_bits": 4},
            "notes": "EV1527-like learning-code frame",
        },
        "pt2262_profile": {
            "device_type": DeviceType.REMOTE_CONTROL,
            "signal_type": SignalType.FIXED_CODE,
            "pattern": {"total_bits": 24},
            "notes": "PT2262-like fixed frame profile",
        },
        "keeloq_profile": {
            "device_type": DeviceType.CAR_KEY_ROLLING,
            "signal_type": SignalType.ROLLING_CODE,
            "pattern": {"total_bits": 66, "preamble": "10" * 6},
            "notes": "KeeLoq-family frame profile",
        },
    }

    @staticmethod
    def identify_protocol(bits: str) -> Optional[Dict]:
        if not bits:
            return None
        candidates: List[Dict] = []
        for name, info in ProtocolDatabase.KNOWN_PROTOCOLS.items():
            patt = info.get("pattern", {})
            score = 0.0
            total_bits = patt.get("total_bits")
            if total_bits is not None:
                delta = abs(len(bits) - total_bits)
                if delta <= 2:
                    score += 0.65
                elif delta <= 6:
                    score += 0.35
            preamble = patt.get("preamble")
            if preamble and bits.startswith(preamble):
                score += 0.3
            if score > 0:
                candidates.append({"name": name, "info": info, "confidence": min(score, 0.95)})
        return max(candidates, key=lambda c: c["confidence"]) if candidates else None


class UniversalSignalAnalyzer:
    def __init__(self) -> None:
        self.protocol_db = ProtocolDatabase()

    def analyze_iq_file(self, filename: str, sample_rate: int, frequency: int) -> DecodedSignal:
        iq = self._load_iq(filename)
        modulation = self._detect_modulation(iq)
        snr_db = self._calculate_snr(iq)
        center_offset_hz = self._estimate_center_offset(iq, sample_rate)

        best: Optional[Dict] = None
        for baud in self._estimate_baud_candidates(iq, sample_rate):
            raw = self._demodulate(iq, sample_rate, baud, modulation)
            encoding = self._detect_encoding(raw)
            decoded = self._decode_by_encoding(raw, encoding)
            frame_bits, frame_score = self._extract_best_frame(decoded)
            if best is None or frame_score > best["score"]:
                best = {"baud": baud, "encoding": encoding, "bits": frame_bits, "score": frame_score}

        bits = best["bits"] if best else ""
        proto = self.protocol_db.identify_protocol(bits)
        fields = self._extract_components(bits, proto)

        confidence = 0.35 + (best["score"] if best else 0.0)
        dtype = DeviceType.UNKNOWN
        stype = SignalType.UNKNOWN
        notes = [f"Analyzed file: {os.path.basename(filename)}"]
        if proto:
            notes.append(f"Profile match: {proto['name']} ({int(proto['confidence'] * 100)}%)")
            notes.append(proto["info"]["notes"])
            confidence = min(0.5 + proto["confidence"] * 0.5 + (best["score"] if best else 0.0) * 0.2, 0.98)
            dtype = proto["info"]["device_type"]
            stype = proto["info"]["signal_type"]

        return DecodedSignal(
            raw_bits=bits,
            hex_data=self._bits_to_hex(np.array(list(bits), dtype=np.int8)) if bits else "",
            modulation=modulation,
            encoding=best["encoding"] if best else "NRZ",
            baud_rate=best["baud"] if best else 1000,
            frequency=frequency,
            sample_rate=sample_rate,
            snr_db=snr_db,
            estimated_center_hz=frequency + center_offset_hz,
            confidence=round(float(min(max(confidence, 0.01), 0.99)), 3),
            preamble=fields.get("preamble"),
            address=fields.get("address"),
            command=fields.get("command"),
            counter=fields.get("counter"),
            checksum=fields.get("checksum"),
            device_type=dtype,
            signal_type=stype,
            notes=notes,
        )

    @staticmethod
    def _load_iq(path: str) -> np.ndarray:
        if not os.path.exists(path):
            raise FileNotFoundError(f"IQ file not found: {path}")
        raw = np.fromfile(path, dtype=np.int8)
        if raw.size < 2:
            raise ValueError("IQ file too small")
        return raw[::2].astype(np.float32) + 1j * raw[1::2].astype(np.float32)

    @staticmethod
    def _detect_modulation(iq: np.ndarray) -> str:
        mag = np.abs(iq)
        phase = np.unwrap(np.angle(iq))
        mag_var = np.var(mag / (np.max(mag) + 1e-9))
        freq_std = np.std(np.diff(phase))
        if mag_var > 0.05 and freq_std < 0.6:
            return "ASK/OOK"
        if freq_std > 0.8 and mag_var < 0.35:
            return "FSK"
        return "Unknown"

    @staticmethod
    def _calculate_snr(iq: np.ndarray) -> float:
        pwr = np.abs(iq) ** 2
        if pwr.size == 0:
            return 0.0
        signal = np.percentile(pwr, 95)
        noise = np.mean(np.sort(pwr)[: max(1, pwr.size // 10)])
        return float(10 * np.log10((signal + 1e-12) / (noise + 1e-12)))

    @staticmethod
    def _estimate_center_offset(iq: np.ndarray, sample_rate: int) -> float:
        n = min(131072, len(iq))
        if n < 4096:
            return 0.0
        spec = np.fft.fftshift(np.fft.fft(iq[:n] * np.hanning(n)))
        freqs = np.fft.fftshift(np.fft.fftfreq(n, d=1.0 / sample_rate))
        return float(freqs[int(np.argmax(np.abs(spec)))])

    @staticmethod
    def _smooth(sig: np.ndarray, width: int) -> np.ndarray:
        width = max(3, min(width, 501))
        return np.convolve(sig, np.ones(width, dtype=np.float32) / width, mode="same")

    def _estimate_baud_candidates(self, iq: np.ndarray, sample_rate: int) -> List[int]:
        env = np.abs(iq)
        env -= np.mean(env)
        n = min(len(env), 250_000)
        env = env[:n]
        ac = np.correlate(env, env, mode="full")[n - 1 :]
        ac[0] = 0
        search = ac[12 : min(40_000, len(ac))]
        if search.size == 0:
            return [300, 500, 1000, 1200, 2400, 4800]
        k = min(5, search.size)
        peak_idxs = np.argpartition(search, -k)[-k:] + 12
        bauds = []
        for idx in sorted(set(int(i) for i in peak_idxs)):
            if idx > 0:
                b = int(sample_rate / idx)
                if 300 <= b <= 50_000:
                    bauds.append(b)
        bauds.extend([300, 500, 1000, 1200, 2000, 2400, 3200, 4800])
        return sorted(set(bauds))[:12]

    def _demodulate(self, iq: np.ndarray, sample_rate: int, baud_rate: int, modulation: str) -> np.ndarray:
        return self._demodulate_fsk(iq, sample_rate, baud_rate) if "FSK" in modulation else self._demodulate_ask(iq, sample_rate, baud_rate)

    def _demodulate_ask(self, iq: np.ndarray, sample_rate: int, baud_rate: int) -> np.ndarray:
        sps = max(1, int(sample_rate / max(baud_rate, 1)))
        centers = self._smooth(np.abs(iq), max(5, sps // 2))[sps // 2 :: sps]
        if centers.size == 0:
            return np.array([], dtype=np.int8)
        thr = (np.percentile(centers, 25) + np.percentile(centers, 75)) / 2.0
        return (centers > thr).astype(np.int8)

    def _demodulate_fsk(self, iq: np.ndarray, sample_rate: int, baud_rate: int) -> np.ndarray:
        sps = max(1, int(sample_rate / max(baud_rate, 1)))
        inst = np.diff(np.unwrap(np.angle(iq)), prepend=np.angle(iq[0]))
        centers = self._smooth(inst, max(5, sps // 2))[sps // 2 :: sps]
        if centers.size == 0:
            return np.array([], dtype=np.int8)
        return (centers > np.median(centers)).astype(np.int8)

    @staticmethod
    def _detect_encoding(bits: np.ndarray) -> str:
        if bits.size < 40:
            return "NRZ"
        transitions = np.sum(np.abs(np.diff(bits.astype(int)))) / max(bits.size - 1, 1)
        if 0.4 < transitions < 0.7:
            return "Manchester"
        runs = []
        run = 1
        for i in range(1, bits.size):
            if bits[i] == bits[i - 1]:
                run += 1
            else:
                runs.append(run)
                run = 1
        return "PWM" if runs and np.var(runs) > 6 else "NRZ"

    def _decode_by_encoding(self, bits: np.ndarray, encoding: str) -> np.ndarray:
        if encoding == "Manchester":
            out: List[int] = []
            for i in range(0, len(bits) - 1, 2):
                pair = (bits[i], bits[i + 1])
                if pair == (1, 0):
                    out.append(0)
                elif pair == (0, 1):
                    out.append(1)
            return np.array(out, dtype=np.int8)
        if encoding == "PWM":
            transitions = np.where(np.diff(bits.astype(int)) != 0)[0]
            if transitions.size < 2:
                return bits
            widths = np.diff(transitions)
            pivot = np.median(widths)
            return np.array([0 if w <= pivot * 1.4 else 1 for w in widths], dtype=np.int8)
        return bits

    @staticmethod
    def _extract_best_frame(bits: np.ndarray) -> Tuple[str, float]:
        if bits.size == 0:
            return "", 0.0
        bit_str = "".join(map(str, bits.astype(int)))
        win = min(256, max(64, len(bit_str) // 4))
        best_score = -1.0
        best_slice = bit_str
        for start in range(0, max(1, len(bit_str) - win), max(1, win // 4)):
            sub = bit_str[start : start + win]
            if len(sub) < 24:
                continue
            trans = sum(1 for i in range(1, len(sub)) if sub[i] != sub[i - 1]) / max(len(sub) - 1, 1)
            score = 1.0 - abs(trans - 0.5)
            if score > best_score:
                best_score = score
                best_slice = sub
        cleaned = best_slice.strip("0")
        if len(cleaned) < 8:
            cleaned = best_slice
        return cleaned, float(max(0.0, min(1.0, best_score if best_score >= 0 else 0.0)))

    @staticmethod
    def _extract_components(bits: str, protocol_match: Optional[Dict]) -> Dict[str, str]:
        comp: Dict[str, str] = {}
        if not bits:
            return comp
        if bits.startswith("10101010") and len(bits) >= 16:
            comp["preamble"] = bits[:16]
        if len(bits) >= 24:
            comp.setdefault("address", bits[:20])
            comp.setdefault("command", bits[20:24])
        if protocol_match and protocol_match["name"] == "keeloq_profile" and len(bits) >= 66:
            comp["preamble"] = bits[:12]
            comp["command"] = bits[12:16]
            comp["counter"] = bits[16:48]
            comp["address"] = bits[48:76] if len(bits) >= 76 else bits[48:]
        return comp

    @staticmethod
    def _bits_to_hex(bits: np.ndarray) -> str:
        if bits.size == 0:
            return ""
        bit_s = "".join(map(str, bits.astype(int)))
        bit_s += "0" * ((8 - len(bit_s) % 8) % 8)
        return " ".join(f"{int(bit_s[i:i+8], 2):02X}" for i in range(0, len(bit_s), 8))


class UniversalRFTool:
    def __init__(self, frequency: int, sample_rate: int):
        self.frequency = frequency
        self.sample_rate = sample_rate
        self.analyzer = UniversalSignalAnalyzer()

    def capture_iq(self, output_file: str, duration: float, lna_gain: int = 40, vga_gain: int = 62) -> str:
        cmd = [
            "hackrf_transfer", "-r", output_file,
            "-f", str(self.frequency), "-s", str(self.sample_rate),
            "-a", "1", "-l", str(lna_gain), "-g", str(vga_gain),
            "-n", str(int(self.sample_rate * duration * 2)),
        ]
        subprocess.run(cmd, check=True, capture_output=True, timeout=duration + 10)
        if not os.path.exists(output_file):
            raise RuntimeError("capture failed")
        return output_file

    def analyze_file(self, iq_file: str) -> DecodedSignal:
        return self.analyzer.analyze_iq_file(iq_file, self.sample_rate, self.frequency)

    def replay_iq(self, iq_file: str, repeat: int = 1, delay_ms: int = 100, tx_gain: int = 47) -> None:
        for idx in range(max(1, repeat)):
            cmd = [
                "hackrf_transfer", "-t", iq_file,
                "-f", str(self.frequency), "-s", str(self.sample_rate),
                "-a", "1", "-x", str(tx_gain),
            ]
            subprocess.run(cmd, check=True, capture_output=True, timeout=15)
            if idx < repeat - 1:
                time.sleep(delay_ms / 1000.0)

    def clone_bits_to_iq(self, bits: str, baud_rate: int, encoding: str, output_file: str) -> str:
        iq = self._encode_bits_to_iq(bits, baud_rate, encoding)
        raw = np.zeros(len(iq) * 2, dtype=np.int8)
        raw[::2] = (np.real(iq) * 127).astype(np.int8)
        raw[1::2] = (np.imag(iq) * 127).astype(np.int8)
        raw.tofile(output_file)
        return output_file

    def _encode_bits_to_iq(self, bits: str, baud_rate: int, encoding: str) -> np.ndarray:
        sps = max(2, self.sample_rate // max(1, baud_rate))
        signal: List[float] = []

        if encoding == "Manchester":
            half = max(1, sps // 2)
            for b in bits:
                if b == "0":
                    signal.extend([1.0] * half)
                    signal.extend([0.0] * half)
                else:
                    signal.extend([0.0] * half)
                    signal.extend([1.0] * half)
        elif encoding == "PWM":
            short = max(1, sps // 3)
            long = max(short + 1, (2 * sps) // 3)
            for b in bits:
                width = short if b == "0" else long
                signal.extend([1.0] * width)
                signal.extend([0.0] * max(1, sps - width))
        else:
            for b in bits:
                signal.extend([1.0 if b == "1" else 0.0] * sps)

        return np.array(signal, dtype=np.complex64)


def apply_field_override(decoded: DecodedSignal, field: str, value: str) -> DecodedSignal:
    bit_string = decoded.raw_bits
    original = getattr(decoded, field, None)
    if not original:
        raise ValueError(f"field '{field}' not present in decoded signal")

    if value and all(ch in "01" for ch in value):
        value_bits = value.zfill(len(original))[-len(original):]
    elif value.isdigit():
        value_bits = format(int(value), f"0{len(original)}b")
    else:
        raise ValueError("value must be decimal or binary")

    pos = bit_string.find(original)
    if pos < 0:
        raise ValueError("could not locate field in raw bitstream")

    updated_bits = bit_string[:pos] + value_bits + bit_string[pos + len(original):]
    return DecodedSignal(
        raw_bits=updated_bits,
        hex_data=decoded.hex_data,
        modulation=decoded.modulation,
        encoding=decoded.encoding,
        baud_rate=decoded.baud_rate,
        frequency=decoded.frequency,
        sample_rate=decoded.sample_rate,
        snr_db=decoded.snr_db,
        estimated_center_hz=decoded.estimated_center_hz,
        confidence=decoded.confidence,
        preamble=decoded.preamble,
        address=decoded.address if field != "address" else value_bits,
        command=decoded.command if field != "command" else value_bits,
        counter=decoded.counter if field != "counter" else value_bits,
        checksum=decoded.checksum,
        device_type=decoded.device_type,
        signal_type=decoded.signal_type,
        notes=decoded.notes + [f"Modified {field} -> {value_bits}"],
    )


def decoded_to_dict(decoded: DecodedSignal) -> Dict:
    data = asdict(decoded)
    data["device_type"] = decoded.device_type.value
    data["signal_type"] = decoded.signal_type.value
    return data


def render_terminal_report(decoded: DecodedSignal) -> None:
    print("\n" + "=" * 70)
    print("UNIVERSAL RF ANALYSIS REPORT")
    print("=" * 70)
    print(f"Modulation      : {decoded.modulation}")
    print(f"Encoding        : {decoded.encoding}")
    print(f"Estimated Baud  : {decoded.baud_rate} bps")
    print(f"SNR             : {decoded.snr_db:.2f} dB")
    print(f"Center Estimate : {decoded.estimated_center_hz / 1e6:.6f} MHz")
    print(f"Frame Length    : {len(decoded.raw_bits)} bits")
    print(f"Device/Signal   : {decoded.device_type.value} / {decoded.signal_type.value}")
    print(f"Confidence      : {decoded.confidence:.3f}")
    print("=" * 70 + "\n")


def create_web_app(default_sample_rate: int, default_frequency_mhz: float):
    from flask import Flask, jsonify, render_template, request

    base = Path(__file__).parent / "webui"
    app = Flask(__name__, template_folder=str(base / "templates"), static_folder=str(base / "static"))
    analyzer = UniversalSignalAnalyzer()

    @app.get("/")
    def home():
        return render_template("dashboard.html", title="RF Dashboard")

    @app.get("/analyze")
    def analyze_page():
        return render_template("analyze.html", title="Analyze", sample_rate=default_sample_rate, freq_mhz=default_frequency_mhz)

    @app.get("/capture")
    def capture_page():
        return render_template("capture.html", title="Capture", sample_rate=default_sample_rate, freq_mhz=default_frequency_mhz)

    @app.get("/operations")
    def operations_page():
        return render_template("operations.html", title="Operations", sample_rate=default_sample_rate, freq_mhz=default_frequency_mhz)

    @app.post("/api/analyze")
    def api_analyze():
        payload = request.get_json(force=True)
        iq_file = payload.get("iq_file", "")
        sample_rate = int(payload.get("sample_rate", default_sample_rate))
        freq_mhz = float(payload.get("freq_mhz", default_frequency_mhz))
        if not iq_file:
            return jsonify({"error": "iq_file is required"}), 400
        try:
            decoded = analyzer.analyze_iq_file(iq_file, sample_rate, int(freq_mhz * 1e6))
            return jsonify(decoded_to_dict(decoded))
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/capture_analyze")
    def api_capture_analyze():
        payload = request.get_json(force=True)
        out = payload.get("output_file", "capture.iq")
        duration = float(payload.get("duration", 2.0))
        sample_rate = int(payload.get("sample_rate", default_sample_rate))
        freq_mhz = float(payload.get("freq_mhz", default_frequency_mhz))
        tool = UniversalRFTool(int(freq_mhz * 1e6), sample_rate)
        try:
            iq_file = tool.capture_iq(output_file=out, duration=duration)
            decoded = tool.analyze_file(iq_file)
            return jsonify({"capture_file": iq_file, "decoded": decoded_to_dict(decoded)})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/replay")
    def api_replay():
        payload = request.get_json(force=True)
        iq_file = payload.get("iq_file", "")
        repeat = int(payload.get("repeat", 1))
        delay_ms = int(payload.get("delay_ms", 100))
        sample_rate = int(payload.get("sample_rate", default_sample_rate))
        freq_mhz = float(payload.get("freq_mhz", default_frequency_mhz))
        if not iq_file:
            return jsonify({"error": "iq_file is required"}), 400
        tool = UniversalRFTool(int(freq_mhz * 1e6), sample_rate)
        try:
            tool.replay_iq(iq_file, repeat=repeat, delay_ms=delay_ms)
            return jsonify({"status": "ok", "replayed": iq_file, "repeat": repeat, "delay_ms": delay_ms})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/modify_clone")
    def api_modify_clone():
        payload = request.get_json(force=True)
        iq_file = payload.get("iq_file", "")
        field = payload.get("field", "command")
        value = str(payload.get("value", ""))
        output_iq = payload.get("output_iq", "modified.iq")
        sample_rate = int(payload.get("sample_rate", default_sample_rate))
        freq_mhz = float(payload.get("freq_mhz", default_frequency_mhz))
        if not iq_file:
            return jsonify({"error": "iq_file is required"}), 400
        if field not in {"address", "command", "counter"}:
            return jsonify({"error": "field must be one of address/command/counter"}), 400

        tool = UniversalRFTool(int(freq_mhz * 1e6), sample_rate)
        try:
            decoded = tool.analyze_file(iq_file)
            modified = apply_field_override(decoded, field, value)
            cloned = tool.clone_bits_to_iq(modified.raw_bits, modified.baud_rate, modified.encoding, output_iq)
            return jsonify({"status": "ok", "output_iq": cloned, "modified": decoded_to_dict(modified)})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    return app


def run_webui(default_sample_rate: int, default_frequency_mhz: float, host: str, port: int) -> int:
    try:
        app = create_web_app(default_sample_rate, default_frequency_mhz)
    except ImportError:
        print("Flask missing. Install: pip install flask")
        return 2
    print(f"[+] Web UI: http://{host}:{port}")
    app.run(host=host, port=port, debug=False)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Universal RF Reverse Engineering Framework (CLI + WebUI)")
    p.add_argument("--mode", choices=["cli", "webui"], default="cli")
    p.add_argument("--freq", type=float, default=433.92)
    p.add_argument("--sample-rate", type=int, default=8_000_000)
    p.add_argument("--iq-file")
    p.add_argument("--capture", action="store_true")
    p.add_argument("--duration", type=float, default=2.0)
    p.add_argument("--output", default="capture.iq")
    p.add_argument("--report", default="analysis.json")
    p.add_argument("--replay", help="Replay IQ file via HackRF transmit path")
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--delay-ms", type=int, default=100)
    p.add_argument("--clone-output", help="Write cloned/modified IQ from decoded bits")
    p.add_argument("--modify-field", choices=["address", "command", "counter"])
    p.add_argument("--modify-value", help="New value (decimal or binary string) for --modify-field")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.mode == "webui":
        return run_webui(args.sample_rate, args.freq, args.host, args.port)

    tool = UniversalRFTool(frequency=int(args.freq * 1e6), sample_rate=args.sample_rate)

    if args.replay:
        tool.replay_iq(args.replay, repeat=max(1, args.repeat), delay_ms=max(0, args.delay_ms))
        print(f"[+] Replay complete: {args.replay}")
        return 0

    iq_path = args.iq_file
    if args.capture:
        print("[+] Capturing IQ using hackrf_transfer...")
        iq_path = tool.capture_iq(output_file=args.output, duration=args.duration)
        print(f"[+] Capture complete: {iq_path}")

    if not iq_path:
        print("Provide --iq-file or use --capture")
        return 2

    decoded = tool.analyze_file(iq_path)

    if args.modify_field and args.modify_value is not None:
        decoded = apply_field_override(decoded, args.modify_field, args.modify_value)
        print(f"[+] Modified field '{args.modify_field}' with value '{args.modify_value}'")

    if args.clone_output:
        out_iq = tool.clone_bits_to_iq(decoded.raw_bits, decoded.baud_rate, decoded.encoding, args.clone_output)
        print(f"[+] Cloned IQ written to: {out_iq}")

    render_terminal_report(decoded)
    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump(decoded_to_dict(decoded), fh, indent=2)
    print(f"[+] Wrote report: {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Universal RF Reverse Engineering Framework (Research/Educational)

Enhancements in this version:
- Maintains RF reverse-engineering *analysis* purpose.
- Supports CLI and Web UI workflows.
- Supports live capture through hackrf_transfer and file-based analysis.
- Improves analysis reliability with adaptive symbol search and frame scoring.

This tool intentionally focuses on lawful signal analysis workflows.
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
        "doorbell_24": {
            "device_type": DeviceType.DOORBELL,
            "signal_type": SignalType.FIXED_CODE,
            "pattern": {"total_bits": 24},
            "notes": "Simple 24-bit OOK doorbell-like profile",
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
                score += 0.30

            if score > 0:
                candidates.append({"name": name, "info": info, "confidence": min(score, 0.95)})

        if not candidates:
            return None
        return max(candidates, key=lambda c: c["confidence"])


class UniversalSignalAnalyzer:
    def __init__(self) -> None:
        self.protocol_db = ProtocolDatabase()

    def analyze_iq_file(self, filename: str, sample_rate: int, frequency: int) -> DecodedSignal:
        iq = self._load_iq(filename)
        modulation = self._detect_modulation(iq)
        snr_db = self._calculate_snr(iq)
        center_offset_hz = self._estimate_center_offset(iq, sample_rate)

        baud_candidates = self._estimate_baud_candidates(iq, sample_rate)
        best = None
        for baud in baud_candidates:
            raw = self._demodulate(iq, sample_rate, baud, modulation)
            encoding = self._detect_encoding(raw)
            decoded = self._decode_by_encoding(raw, encoding)
            frame_bits, frame_score = self._extract_best_frame(decoded)
            if best is None or frame_score > best["score"]:
                best = {
                    "baud": baud,
                    "encoding": encoding,
                    "bits": frame_bits,
                    "score": frame_score,
                }

        bits = best["bits"] if best else ""
        encoding = best["encoding"] if best else "NRZ"
        baud = best["baud"] if best else 1000
        confidence = 0.35 + (best["score"] if best else 0.0)

        proto = self.protocol_db.identify_protocol(bits)
        notes: List[str] = [f"Analyzed file: {os.path.basename(filename)}"]
        dtype = DeviceType.UNKNOWN
        stype = SignalType.UNKNOWN
        if proto:
            notes.append(f"Profile match: {proto['name']} ({int(proto['confidence'] * 100)}%)")
            notes.append(proto["info"]["notes"])
            confidence = min(0.5 + proto["confidence"] * 0.5 + (best["score"] * 0.2 if best else 0), 0.98)
            dtype = proto["info"]["device_type"]
            stype = proto["info"]["signal_type"]

        fields = self._extract_components(bits, proto)

        return DecodedSignal(
            raw_bits=bits,
            hex_data=self._bits_to_hex(np.array(list(bits), dtype=np.int8)) if bits else "",
            modulation=modulation,
            encoding=encoding,
            baud_rate=baud,
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
        i = raw[::2].astype(np.float32)
        q = raw[1::2].astype(np.float32)
        return i + 1j * q

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
        window = np.hanning(n)
        spec = np.fft.fftshift(np.fft.fft(iq[:n] * window))
        freqs = np.fft.fftshift(np.fft.fftfreq(n, d=1.0 / sample_rate))
        return float(freqs[int(np.argmax(np.abs(spec)))])

    @staticmethod
    def _smooth(sig: np.ndarray, width: int) -> np.ndarray:
        width = max(3, min(width, 501))
        kernel = np.ones(width, dtype=np.float32) / width
        return np.convolve(sig, kernel, mode="same")

    def _estimate_baud_candidates(self, iq: np.ndarray, sample_rate: int) -> List[int]:
        env = np.abs(iq)
        env = env - np.mean(env)
        n = min(len(env), 250_000)
        env = env[:n]
        ac = np.correlate(env, env, mode="full")
        ac = ac[n - 1 :]
        ac[0] = 0
        search = ac[12 : min(40_000, len(ac))]
        if search.size == 0:
            return [1000]

        peak_idxs = np.argpartition(search, -5)[-5:] + 12
        bauds = []
        for idx in sorted(set(int(i) for i in peak_idxs)):
            if idx <= 0:
                continue
            b = int(sample_rate / idx)
            if 300 <= b <= 50_000:
                bauds.append(b)

        if not bauds:
            bauds = [1000]

        # Add a few common RF rates as fallback for robustness.
        for common in (300, 500, 1000, 1200, 2000, 2400, 3200, 4800):
            if common not in bauds:
                bauds.append(common)

        # Keep unique and top reasonable subset.
        bauds = sorted(set(bauds))
        return bauds[:10]

    def _demodulate(self, iq: np.ndarray, sample_rate: int, baud_rate: int, modulation: str) -> np.ndarray:
        if "FSK" in modulation:
            return self._demodulate_fsk(iq, sample_rate, baud_rate)
        return self._demodulate_ask(iq, sample_rate, baud_rate)

    def _demodulate_ask(self, iq: np.ndarray, sample_rate: int, baud_rate: int) -> np.ndarray:
        env = np.abs(iq)
        sps = max(1, int(sample_rate / max(baud_rate, 1)))
        filt = self._smooth(env, max(5, sps // 2))
        centers = filt[sps // 2 :: sps]
        if centers.size == 0:
            return np.array([], dtype=np.int8)
        lo = np.percentile(centers, 25)
        hi = np.percentile(centers, 75)
        threshold = (lo + hi) / 2.0
        return (centers > threshold).astype(np.int8)

    def _demodulate_fsk(self, iq: np.ndarray, sample_rate: int, baud_rate: int) -> np.ndarray:
        phase = np.unwrap(np.angle(iq))
        inst = np.diff(phase, prepend=phase[0])
        sps = max(1, int(sample_rate / max(baud_rate, 1)))
        filt = self._smooth(inst, max(5, sps // 2))
        centers = filt[sps // 2 :: sps]
        if centers.size == 0:
            return np.array([], dtype=np.int8)
        thr = np.median(centers)
        return (centers > thr).astype(np.int8)

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
        if runs and np.var(runs) > 6:
            return "PWM"
        return "NRZ"

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
        # Find likely active region by non-trivial transition density windows.
        win = min(256, max(64, len(bit_str) // 4))
        best_score = -1.0
        best_slice = bit_str
        for start in range(0, max(1, len(bit_str) - win), max(1, win // 4)):
            sub = bit_str[start : start + win]
            if len(sub) < 24:
                continue
            trans = sum(1 for i in range(1, len(sub)) if sub[i] != sub[i - 1]) / max(len(sub) - 1, 1)
            entropy = abs(trans - 0.5)
            score = 1.0 - entropy
            if score > best_score:
                best_score = score
                best_slice = sub

        cleaned = best_slice.strip("0")
        if len(cleaned) < 8:
            cleaned = best_slice
        score = float(max(0.0, min(1.0, best_score if best_score >= 0 else 0.0)))
        return cleaned, score

    @staticmethod
    def _extract_components(bits: str, protocol_match: Optional[Dict]) -> Dict[str, str]:
        comp: Dict[str, str] = {}
        if not bits:
            return comp

        if bits.startswith("10101010") and len(bits) >= 16:
            comp["preamble"] = bits[:16]

        # Generic extraction fallback.
        if len(bits) >= 24:
            comp.setdefault("address", bits[:20])
            comp.setdefault("command", bits[20:24])

        # Protocol-specific overrides.
        if protocol_match:
            name = protocol_match["name"]
            if name == "keeloq_profile" and len(bits) >= 66:
                comp["preamble"] = bits[:12]
                comp["command"] = bits[12:16]
                comp["counter"] = bits[16:48]
                comp["address"] = bits[48:76] if len(bits) >= 76 else bits[48:]
            elif name in {"ev1527_learning", "pt2262_profile", "doorbell_24"} and len(bits) >= 24:
                comp["address"] = bits[:20]
                comp["command"] = bits[20:24]

        return comp

    @staticmethod
    def _bits_to_hex(bits: np.ndarray) -> str:
        if bits.size == 0:
            return ""
        bit_s = "".join(map(str, bits.astype(int)))
        pad = (8 - len(bit_s) % 8) % 8
        bit_s += "0" * pad
        out = []
        for i in range(0, len(bit_s), 8):
            out.append(f"{int(bit_s[i:i+8], 2):02X}")
        return " ".join(out)


class UniversalRFTool:
    def __init__(self, frequency: int, sample_rate: int):
        self.frequency = frequency
        self.sample_rate = sample_rate
        self.analyzer = UniversalSignalAnalyzer()

    def capture_iq(
        self,
        output_file: str,
        duration: float,
        lna_gain: int = 40,
        vga_gain: int = 62,
    ) -> str:
        samples = int(self.sample_rate * duration * 2)
        cmd = [
            "hackrf_transfer",
            "-r",
            output_file,
            "-f",
            str(self.frequency),
            "-s",
            str(self.sample_rate),
            "-a",
            "1",
            "-l",
            str(lna_gain),
            "-g",
            str(vga_gain),
            "-n",
            str(samples),
        ]
        subprocess.run(cmd, check=True, capture_output=True, timeout=duration + 10)
        if not os.path.exists(output_file):
            raise RuntimeError("capture failed: output file not created")
        return output_file

    def analyze_file(self, iq_file: str) -> DecodedSignal:
        return self.analyzer.analyze_iq_file(iq_file, sample_rate=self.sample_rate, frequency=self.frequency)


def render_terminal_report(decoded: DecodedSignal) -> None:
    print("\n" + "=" * 70)
    print("UNIVERSAL RF ANALYSIS REPORT")
    print("=" * 70)
    print(f"Modulation       : {decoded.modulation}")
    print(f"Encoding         : {decoded.encoding}")
    print(f"Estimated Baud   : {decoded.baud_rate} bps")
    print(f"SNR              : {decoded.snr_db:.2f} dB")
    print(f"Center Estimate  : {decoded.estimated_center_hz / 1e6:.6f} MHz")
    print(f"Frame Length     : {len(decoded.raw_bits)} bits")
    print(f"Device/Signal    : {decoded.device_type.value} / {decoded.signal_type.value}")
    print(f"Confidence       : {decoded.confidence:.3f}")
    print(f"Hex              : {decoded.hex_data[:120]}{'...' if len(decoded.hex_data) > 120 else ''}")

    if decoded.preamble:
        print(f"Preamble         : {decoded.preamble}")
    if decoded.address:
        print(f"Address          : {decoded.address}")
    if decoded.command:
        print(f"Command          : {decoded.command}")
    if decoded.counter:
        print(f"Counter          : {decoded.counter}")

    if decoded.notes:
        print("Notes:")
        for note in decoded.notes:
            print(f"  - {note}")
    print("=" * 70 + "\n")


def run_webui(default_sample_rate: int, default_frequency_mhz: float, host: str, port: int) -> int:
    try:
        from flask import Flask, jsonify, render_template_string, request
    except ImportError:
        print("Flask missing. Install: pip install flask")
        return 2

    app = Flask(__name__)
    analyzer = UniversalSignalAnalyzer()

    template = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Universal RF Framework</title>
<style>
:root { --bg:#0a0f14; --panel:#101820; --line:#213041; --text:#d5ffdb; --accent:#39ff88; --warn:#ffd166; }
body { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color:var(--text);
       background:radial-gradient(circle at top,#13283a 0%,var(--bg) 50%); }
.wrap{ max-width:1024px; margin:20px auto; padding:12px; }
.panel{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px; margin-bottom:14px; box-shadow:0 0 18px rgba(57,255,136,.08); }
h1{ margin:0 0 8px; color:var(--accent); letter-spacing:.08em; }
label{ display:block; margin:10px 0 4px; }
input{ width:100%; box-sizing:border-box; padding:10px; border-radius:8px; border:1px solid var(--line); background:#0d141b; color:var(--text); }
button{ margin-top:10px; padding:10px 14px; background:var(--accent); color:#00140a; border:0; border-radius:8px; font-weight:700; cursor:pointer; }
pre{ background:#0d141b; border:1px solid var(--line); border-radius:8px; padding:10px; white-space:pre-wrap; word-break:break-word; min-height:200px; }
.warn{ color:var(--warn); }
</style>
</head>
<body>
<div class="wrap">
  <div class="panel">
    <h1>TACTICAL RF CONSOLE</h1>
    <div class="warn">Analysis mode (capture + decode). Use only on systems you own or are authorized to test.</div>
    <label>IQ file path</label><input id="iq" placeholder="/path/to/capture.iq">
    <label>Sample rate (Hz)</label><input id="sr" value="{{sample_rate}}">
    <label>Frequency (MHz)</label><input id="fq" value="{{freq_mhz}}">
    <button onclick="analyze()">Analyze file</button>
  </div>
  <div class="panel"><h3>Result</h3><pre id="out">Waiting for request...</pre></div>
</div>
<script>
async function analyze(){
  const payload = {
    iq_file: document.getElementById('iq').value,
    sample_rate: parseInt(document.getElementById('sr').value, 10),
    freq_mhz: parseFloat(document.getElementById('fq').value)
  };
  const out = document.getElementById('out');
  out.textContent = 'Analyzing...';
  const res = await fetch('/api/analyze', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  const data = await res.json();
  out.textContent = JSON.stringify(data, null, 2);
}
</script>
</body>
</html>
"""

    @app.get("/")
    def index():
        return render_template_string(template, sample_rate=default_sample_rate, freq_mhz=default_frequency_mhz)

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
            data = asdict(decoded)
            data["device_type"] = decoded.device_type.value
            data["signal_type"] = decoded.signal_type.value
            return jsonify(data)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    print(f"[+] Web UI: http://{host}:{port}")
    app.run(host=host, port=port, debug=False)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Universal RF Reverse Engineering Framework (CLI + WebUI)")
    p.add_argument("--mode", choices=["cli", "webui"], default="cli", help="Run mode")
    p.add_argument("--freq", type=float, default=433.92, help="Frequency MHz")
    p.add_argument("--sample-rate", type=int, default=8_000_000, help="Sample rate Hz")

    p.add_argument("--iq-file", help="Analyze existing IQ file")
    p.add_argument("--capture", action="store_true", help="Capture first using hackrf_transfer")
    p.add_argument("--duration", type=float, default=2.0, help="Capture duration seconds")
    p.add_argument("--output", default="capture.iq", help="IQ output file (capture) / report prefix")
    p.add_argument("--report", default="analysis.json", help="JSON report path")

    p.add_argument("--host", default="127.0.0.1", help="Web host")
    p.add_argument("--port", type=int, default=5000, help="Web port")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.mode == "webui":
        return run_webui(args.sample_rate, args.freq, args.host, args.port)

    tool = UniversalRFTool(frequency=int(args.freq * 1e6), sample_rate=args.sample_rate)

    iq_path = args.iq_file
    if args.capture:
        print("[+] Capturing IQ using hackrf_transfer...")
        iq_path = tool.capture_iq(output_file=args.output, duration=args.duration)
        print(f"[+] Capture complete: {iq_path}")

    if not iq_path:
        print("Provide --iq-file or use --capture")
        return 2

    decoded = tool.analyze_file(iq_path)
    render_terminal_report(decoded)

    payload = asdict(decoded)
    payload["device_type"] = decoded.device_type.value
    payload["signal_type"] = decoded.signal_type.value
    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"[+] Wrote report: {args.report}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

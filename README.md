# Universal RF Reverse Engineering Framework (CLI + WebUI)

This project keeps the original goal: **RF reverse-engineering and signal analysis** for research/education.

## What is enhanced

- Two operation paths:
  - **CLI mode** for direct workflows
  - **Web UI mode** for dashboard-style analysis
- More functional analysis pipeline:
  - adaptive baud candidate search
  - frame-quality scoring for choosing best decoded segment
  - improved component extraction (preamble/address/command/counter)
  - center-frequency estimate from FFT peak
- Optional live capture using `hackrf_transfer` before analysis

## Install

```bash
pip install -r requirements.txt
```

## CLI usage

### Analyze existing IQ file

```bash
python3 universal_rf.py --mode cli --iq-file capture.iq --freq 433.92 --sample-rate 8000000 --report analysis.json
```

### Capture + analyze in one command

```bash
python3 universal_rf.py --mode cli --capture --duration 2.0 --output capture.iq --freq 433.92 --sample-rate 8000000 --report analysis.json
```

## Web UI usage

```bash
python3 universal_rf.py --mode webui --host 127.0.0.1 --port 5000
```

Open `http://127.0.0.1:5000`.

## Note

Use this tool only where you are authorized to capture and analyze RF traffic.

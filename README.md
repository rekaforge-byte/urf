# Universal RF Reverse Engineering Framework (CLI + WebUI)

 codex/add-web-ui-option-and-enhance-code-acj6kv
This project keeps the original purpose: **RF reverse-engineering and signal analysis** for research/education.

## Enhancements (without removing original workflows)

- CLI and WebUI workflows.
- Framework-style Flask WebUI pages:
  - `/` dashboard
  - `/analyze` IQ decode
  - `/capture` capture + decode
  - `/operations` replay and modify+clone workflows
- Tactical theme with separated templates/static assets.
- Improved decoding pipeline:
  - adaptive baud candidate search
  - frame-quality scoring
  - component extraction (preamble/address/command/counter)
  - center-frequency estimation
- Restored operational workflows:
  - replay IQ (`--replay`)
  - clone/modify decoded fields (`--modify-field`, `--modify-value`, `--clone-output`)

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
 main

## Install

```bash
pip install -r requirements.txt
```

## CLI usage

 codex/add-web-ui-option-and-enhance-code-acj6kv
Analyze existing IQ:

### Analyze existing IQ file
 main

```bash
python3 universal_rf.py --mode cli --iq-file capture.iq --freq 433.92 --sample-rate 8000000 --report analysis.json
```

 codex/add-web-ui-option-and-enhance-code-acj6kv
Capture + analyze:

### Capture + analyze in one command
 main

```bash
python3 universal_rf.py --mode cli --capture --duration 2.0 --output capture.iq --freq 433.92 --sample-rate 8000000 --report analysis.json
```

 codex/add-web-ui-option-and-enhance-code-acj6kv
Replay IQ:

```bash
python3 universal_rf.py --mode cli --replay capture.iq --freq 433.92 --sample-rate 8000000 --repeat 3 --delay-ms 120
```

Modify decoded field + clone IQ:

```bash
python3 universal_rf.py --mode cli --iq-file capture.iq --modify-field command --modify-value 2 --clone-output modified.iq --freq 433.92 --sample-rate 8000000
```

## WebUI usage

## Web UI usage
 main

```bash
python3 universal_rf.py --mode webui --host 127.0.0.1 --port 5000
```

 codex/add-web-ui-option-and-enhance-code-acj6kv
Open:
- `http://127.0.0.1:5000/`
- `http://127.0.0.1:5000/analyze`
- `http://127.0.0.1:5000/capture`
- `http://127.0.0.1:5000/operations`

API endpoints:
- `POST /api/analyze`
- `POST /api/capture_analyze`
- `POST /api/replay`
- `POST /api/modify_clone`

Use only where you are authorized to capture/analyze RF traffic.

Open `http://127.0.0.1:5000`.

## Note

Use this tool only where you are authorized to capture and analyze RF traffic.
 main

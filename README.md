# Universal RF Reverse Engineering Framework (CLI + WebUI)

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

## Install

```bash
pip install -r requirements.txt
```

## CLI usage

Analyze existing IQ:

```bash
python3 universal_rf.py --mode cli --iq-file capture.iq --freq 433.92 --sample-rate 8000000 --report analysis.json
```

Capture + analyze:

```bash
python3 universal_rf.py --mode cli --capture --duration 2.0 --output capture.iq --freq 433.92 --sample-rate 8000000 --report analysis.json
```

Replay IQ:

```bash
python3 universal_rf.py --mode cli --replay capture.iq --freq 433.92 --sample-rate 8000000 --repeat 3 --delay-ms 120
```

Modify decoded field + clone IQ:

```bash
python3 universal_rf.py --mode cli --iq-file capture.iq --modify-field command --modify-value 2 --clone-output modified.iq --freq 433.92 --sample-rate 8000000
```

## WebUI usage

```bash
python3 universal_rf.py --mode webui --host 127.0.0.1 --port 5000
```

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

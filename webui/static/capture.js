async function captureAndAnalyze() {
  const payload = {
    output_file: document.getElementById('out_file').value,
    duration: parseFloat(document.getElementById('duration').value),
    sample_rate: parseInt(document.getElementById('sample_rate').value, 10),
    freq_mhz: parseFloat(document.getElementById('freq').value)
  };
  const out = document.getElementById('output');
  out.textContent = 'Capturing + analyzing...';
  const res = await fetch('/api/capture_analyze', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
  });
  const data = await res.json();
  out.textContent = JSON.stringify(data, null, 2);
}

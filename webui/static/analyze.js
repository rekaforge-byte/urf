async function analyzeFile() {
  const payload = {
    iq_file: document.getElementById('iq').value,
    sample_rate: parseInt(document.getElementById('sample_rate').value, 10),
    freq_mhz: parseFloat(document.getElementById('freq').value)
  };
  const out = document.getElementById('output');
  out.textContent = 'Analyzing...';
  const res = await fetch('/api/analyze', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
  });
  const data = await res.json();
  out.textContent = JSON.stringify(data, null, 2);
}

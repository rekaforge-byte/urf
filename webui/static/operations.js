function payloadBase(){
  return {
    iq_file: document.getElementById('iq').value,
    sample_rate: parseInt(document.getElementById('sample_rate').value, 10),
    freq_mhz: parseFloat(document.getElementById('freq').value)
  };
}

async function replayIq(){
  const out = document.getElementById('output');
  const payload = payloadBase();
  payload.repeat = parseInt(document.getElementById('repeat').value, 10);
  payload.delay_ms = parseInt(document.getElementById('delay_ms').value, 10);
  out.textContent = 'Replaying...';
  const res = await fetch('/api/replay', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  out.textContent = JSON.stringify(await res.json(), null, 2);
}

async function modifyClone(){
  const out = document.getElementById('output');
  const payload = payloadBase();
  payload.field = document.getElementById('field').value;
  payload.value = document.getElementById('value').value;
  payload.output_iq = document.getElementById('output_iq').value;
  out.textContent = 'Modifying and cloning...';
  const res = await fetch('/api/modify_clone', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  out.textContent = JSON.stringify(await res.json(), null, 2);
}

const BASE = import.meta.env.VITE_API_BASE || '/api';

async function request(path, options = {}) {
  const response = await fetch(`${BASE}${path}`, options);
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      message = body.detail || message;
    } catch {
      // Keep the HTTP status when the response has no JSON body.
    }
    throw new Error(message);
  }
  const type = response.headers.get('content-type') || '';
  return type.includes('application/json') ? response.json() : response;
}

function postJSON(path, body) {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export const api = {
  health: () => request('/health'),
  binaries: () => request('/binaries'),
  upload: (file) => {
    const body = new FormData();
    body.append('file', file);
    return request('/binaries', { method: 'POST', body });
  },
  info: (sha) => request(`/binaries/${sha}/info`),
  checksec: (sha) => request(`/binaries/${sha}/checksec`),
  vulns: (sha) => request(`/binaries/${sha}/vulns`),
  gadgets: (sha, query = '') =>
    request(`/binaries/${sha}/gadgets${query ? `?q=${encodeURIComponent(query)}` : ''}`),
  got: (sha) => request(`/binaries/${sha}/got`),
  strings: (sha, minLength = 4) =>
    request(`/binaries/${sha}/strings?min_length=${minLength}`),
  disassembly: (sha, count = 250) =>
    request(`/binaries/${sha}/disassembly?count=${count}`),
  hex: (sha, page = 0) => request(`/binaries/${sha}/hex?page=${page}`),

  cyclic: (length, n) => postJSON('/payload/cyclic', { length, n }),
  cyclicFind: (value, n) => postJSON('/payload/cyclic/find', { value, n }),
  pack: (value, bits, endian) => postJSON('/payload/pack', { value, bits, endian }),
  overflow: (body) => postJSON('/payload/overflow', body),
  shellcodes: (arch = '') =>
    request(`/payload/shellcode${arch ? `?arch=${encodeURIComponent(arch)}` : ''}`),

  challenges: () => request('/challenges'),
  challenge: (slug) => request(`/challenges/${slug}`),
  submit: (slug, answer) => postJSON(`/challenges/${slug}/submit`, { answer }),
  artifactUrl: (slug) => `${BASE}/challenges/${slug}/artifact`,
};

export const formatHex = (value, width = 0) => {
  const number = Number(value);
  if (!Number.isFinite(number)) return '—';
  return `0x${number.toString(16).padStart(width, '0')}`;
};

export const formatBytes = (bytes) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
};

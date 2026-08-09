const BASE = import.meta.env.VITE_API_BASE || '/api/v1';

export type AnalysisStatus =
  'not_started' | 'queued' | 'running' | 'completed' | 'failed';

export interface BinarySummary {
  sha256: string;
  filename: string;
  size: number;
  format: 'ELF' | 'PE' | 'RAW';
  machine: string;
  bits: number;
  analysis_status: AnalysisStatus;
  created_at: string;
}

export interface UploadResult {
  binary_id: string;
  sha256: string;
  filename: string;
  size: number;
  format: 'ELF' | 'PE' | 'RAW';
  analysis_status: AnalysisStatus;
}

export interface AnalysisJob {
  job_id: string;
  binary_id: string;
  status: Exclude<AnalysisStatus, 'not_started'>;
  analyzer_name: string;
  analyzer_version: string;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  confidence: number;
  evidence: unknown[];
  result: Record<string, unknown> | null;
  error: string | null;
}

export interface ChecksecResult {
  format: 'ELF' | 'PE' | 'RAW';
  relro: string;
  canary: boolean | null;
  nx: boolean | null;
  pie: string;
  rpath: boolean;
  runpath: boolean;
  fortify: boolean | null;
  stripped: boolean | null;
  executable_stack: boolean | null;
  rwx_segments: string[];
  static: boolean | null;
  cet: boolean | null;
  ibt: boolean | null;
  shadow_stack: boolean | null;
  protections: ProtectionResult[];
}

export interface ProtectionResult {
  name: string;
  state: string;
  enabled: boolean | null;
  verification: 'verified' | 'inferred' | 'unknown';
  evidence: string[];
  impact: string;
  possible_strategies: string[];
  confidence: number;
}

export interface VulnerabilityFinding {
  symbol: string;
  category: string;
  severity: string;
  description: string;
  status: 'possible' | 'likely' | 'confirmed' | 'disproven';
  confidence: number;
  verification: 'verified' | 'inferred' | 'unknown';
  evidence: string[];
  false_positive_factors: string[];
}

export interface FunctionInfo {
  address: number;
  end: number;
  size: number;
  name: string;
  aliases: string[];
  region: string;
  source: string;
  address_verification: 'verified' | 'inferred';
  boundary_verification: 'verified' | 'inferred';
  verification: 'verified' | 'inferred';
  confidence: number;
  evidence: string[];
}

export interface FunctionPage {
  items: FunctionInfo[];
  total: number;
  offset: number;
  limit: number;
  format: 'ELF' | 'PE';
  status: 'completed' | 'partially_completed';
  verification: 'inferred';
  evidence: string[];
}

export interface GadgetInfo {
  address: number;
  bytes_hex: string;
  instructions: string[];
  text: string;
  section: string;
  terminator: string;
  stack_change: number | null;
  stack_words: number | null;
  registers_read: string[];
  registers_written: string[];
  popped_registers: string[];
  memory_read: boolean;
  memory_write: boolean;
  categories: string[];
  side_effect_count: number;
  quality_score: number;
  pie_offset: number | null;
  position_independent: boolean;
  bad_bytes: string[];
  verification: 'verified';
  confidence: number;
  evidence: string[];
}

export interface GadgetPage {
  items: GadgetInfo[];
  total: number;
  offset: number;
  limit: number;
  bits: 32 | 64;
  status: 'completed' | 'partially_completed';
  verification: 'verified';
  quality_verification: 'inferred';
  position_independent: boolean;
  scanned_gadgets: number;
  limitations: string[];
}

export interface RopChainItem {
  kind: 'gadget' | 'literal' | 'symbol' | 'padding';
  value: number | string;
  label?: string;
}

export interface CrashSummary {
  crash_id: string;
  sha256: string;
  filename: string;
  size: number;
  binary_id: string | null;
  analysis_status: 'completed' | 'partially_completed' | 'failed' | 'not_started';
  signal: string | null;
  created_at: string;
}

export interface CrashDetail extends CrashSummary {
  analyzer_name: string;
  analyzer_version: string;
  confidence: number;
  evidence: unknown[];
  result: Record<string, unknown>;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
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
  if (type.includes('application/json')) {
    return (await response.json()) as T;
  }
  return response as T;
}

function postJSON<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export const api = {
  health: () => request<{ status: string; version: string }>('/health'),
  binaries: () => request<BinarySummary[]>('/binaries'),
  binary: (sha: string) => request<BinarySummary>(`/binaries/${sha}`),
  upload: (file: File) => {
    const body = new FormData();
    body.append('file', file);
    return request<UploadResult>('/binaries', { method: 'POST', body });
  },
  analyze: (sha: string) =>
    request<AnalysisJob>(`/binaries/${sha}/analyze`, { method: 'POST' }),
  analysis: (sha: string) => request<AnalysisJob>(`/binaries/${sha}/analysis`),
  remove: (sha: string) => request<Response>(`/binaries/${sha}`, { method: 'DELETE' }),
  info: (sha: string) => request<Record<string, unknown>>(`/binaries/${sha}/info`),
  checksec: (sha: string) => request<ChecksecResult>(`/binaries/${sha}/checksec`),
  vulns: (sha: string) => request<VulnerabilityFinding[]>(`/binaries/${sha}/vulns`),
  gadgets: (
    sha: string,
    filters: {
      q?: string;
      regex?: boolean;
      register?: string;
      category?: string;
      minStackChange?: string;
      maxStackChange?: string;
      badBytes?: string;
      sort?: 'address' | 'quality' | 'side_effects' | 'stack_change';
      order?: 'asc' | 'desc';
      offset?: number;
      limit?: number;
    } = {},
  ) => {
    const params = new URLSearchParams();
    if (filters.q) params.set('q', filters.q);
    if (filters.regex) params.set('regex', 'true');
    if (filters.register) params.set('register', filters.register);
    if (filters.category) params.set('category', filters.category);
    if (filters.minStackChange) {
      params.set('min_stack_change', filters.minStackChange);
    }
    if (filters.maxStackChange) {
      params.set('max_stack_change', filters.maxStackChange);
    }
    if (filters.badBytes) params.set('bad_bytes', filters.badBytes);
    if (filters.sort) params.set('sort', filters.sort);
    if (filters.order) params.set('order', filters.order);
    params.set('offset', String(filters.offset || 0));
    params.set('limit', String(filters.limit || 100));
    return request<GadgetPage>(`/binaries/${sha}/gadgets?${params}`);
  },
  simulateRop: (sha: string, items: RopChainItem[], initialRspMod16 = 0) =>
    request<Record<string, unknown>>(`/binaries/${sha}/rop/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items, initial_rsp_mod16: initialRspMod16 }),
    }),
  got: (sha: string) => request<Record<string, unknown>>(`/binaries/${sha}/got`),
  functions: (sha: string, query = '') =>
    request<FunctionPage>(
      `/binaries/${sha}/functions${query ? `?q=${encodeURIComponent(query)}` : ''}`,
    ),
  functionDetail: (sha: string, address: number | string) =>
    request<Record<string, unknown>>(`/binaries/${sha}/functions/${address}`),
  cfg: (sha: string, address: number | string) =>
    request<Record<string, unknown>>(`/binaries/${sha}/functions/${address}/cfg`),
  xrefs: (
    sha: string,
    options: {
      address?: number | string;
      direction?: 'to' | 'from';
      kind?: 'all' | 'call' | 'jump' | 'conditional_jump';
    } = {},
  ) => {
    const params = new URLSearchParams();
    if (options.address !== undefined) params.set('address', String(options.address));
    if (options.direction) params.set('direction', options.direction);
    if (options.kind) params.set('kind', options.kind);
    const query = params.toString();
    return request<Record<string, unknown>>(
      `/binaries/${sha}/xrefs${query ? `?${query}` : ''}`,
    );
  },
  strings: (sha: string, minLength = 4) =>
    request<unknown[]>(`/binaries/${sha}/strings?min_length=${minLength}`),
  disassembly: (
    sha: string,
    count = 250,
    options: {
      architecture?: 'x86' | 'x86_64';
      baseAddress?: number | string;
      address?: number | string;
    } = {},
  ) => {
    const params = new URLSearchParams({ count: String(count) });
    if (options.architecture) params.set('architecture', options.architecture);
    if (options.baseAddress !== undefined) {
      params.set('base_address', String(options.baseAddress));
    }
    if (options.address !== undefined) params.set('address', String(options.address));
    return request<unknown[]>(`/binaries/${sha}/disassembly?${params}`);
  },
  entropy: (sha: string) =>
    request<Record<string, unknown>>(`/binaries/${sha}/entropy`),
  hex: (sha: string, page = 0) =>
    request<Record<string, unknown>>(`/binaries/${sha}/hex?page=${page}`),

  crashes: () => request<CrashSummary[]>('/crashes'),
  crash: (crashId: string) => request<CrashDetail>(`/crashes/${crashId}`),
  uploadCrash: (file: File, binaryId = '') => {
    const body = new FormData();
    body.append('file', file);
    if (binaryId) body.append('binary_id', binaryId);
    return request<CrashDetail>('/crashes', { method: 'POST', body });
  },
  analyzeCrash: (crashId: string) =>
    request<CrashDetail>(`/crashes/${crashId}/analyze`, { method: 'POST' }),
  removeCrash: (crashId: string) =>
    request<Response>(`/crashes/${crashId}`, { method: 'DELETE' }),
  crashRegisters: (crashId: string) =>
    request<Record<string, unknown>>(`/crashes/${crashId}/registers`),
  crashStack: (crashId: string, offset = 0, limit = 256) =>
    request<Record<string, unknown>>(
      `/crashes/${crashId}/stack?offset=${offset}&limit=${limit}`,
    ),
  crashMappings: (crashId: string, offset = 0, limit = 256) =>
    request<Record<string, unknown>>(
      `/crashes/${crashId}/mappings?offset=${offset}&limit=${limit}`,
    ),

  cyclic: (length: number, n: number) =>
    postJSON<Record<string, unknown>>('/payload/cyclic', { length, n }),
  cyclicFind: (value: string, n: number) =>
    postJSON<Record<string, unknown>>('/payload/cyclic/find', { value, n }),
  pack: (value: number, bits: number, endian: string) =>
    postJSON<Record<string, unknown>>('/payload/pack', { value, bits, endian }),
  overflow: (body: Record<string, unknown>) =>
    postJSON<Record<string, unknown>>('/payload/overflow', body),
  shellcodes: (arch = '') =>
    request<unknown[]>(
      `/payload/shellcode${arch ? `?arch=${encodeURIComponent(arch)}` : ''}`,
    ),

  challenges: () => request<unknown[]>('/challenges'),
  challenge: (slug: string) => request<Record<string, unknown>>(`/challenges/${slug}`),
  submit: (slug: string, answer: string) =>
    postJSON<Record<string, unknown>>(`/challenges/${slug}/submit`, { answer }),
  artifactUrl: (slug: string) => `${BASE}/challenges/${slug}/artifact`,
};

export const formatHex = (value: number | null | undefined, width = 0) => {
  if (value === null || value === undefined) return '—';
  const number = Number(value);
  if (!Number.isFinite(number)) return '—';
  return `0x${number.toString(16).padStart(width, '0')}`;
};

export const formatBytes = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
};

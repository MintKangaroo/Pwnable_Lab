import { useEffect, useMemo, useState } from 'react';
import { api, formatBytes, formatHex } from '../api';
import {
  Badge,
  DataTable,
  Empty,
  ErrorBanner,
  Icon,
  Loading,
  StatusBadge,
} from './Common.jsx';

const TABS = [
  ['overview', 'Overview'],
  ['disassembly', 'Disassembly'],
  ['gadgets', 'ROP Gadgets'],
  ['symbols', 'Symbols'],
  ['strings', 'Strings'],
  ['got', 'GOT / PLT'],
  ['hex', 'Hex View'],
];

const severityTone = {
  critical: 'danger',
  high: 'orange',
  medium: 'warn',
  info: 'cyan',
};

const protectionLabels = {
  relro: 'RELRO',
  stack_canary: 'STACK CANARY',
  nx: 'NX',
  executable_stack: 'EXECUTABLE STACK',
  pie: 'PIE',
  fortify: 'FORTIFY',
  cet: 'CET',
  ibt: 'IBT',
  shadow_stack: 'SHADOW STACK',
  rpath: 'RPATH',
  runpath: 'RUNPATH',
  rwx_segments: 'RWX SEGMENTS',
  stripped: 'SYMBOL STRIPPING',
  static_linking: 'LINKING MODE',
};

const verificationSymbols = {
  verified: '✓',
  inferred: '≈',
  unknown: '?',
};

function protectionTone(protection) {
  if (protection.name === 'rwx_segments')
    return protection.enabled ? 'danger' : 'positive';
  if (protection.name === 'executable_stack') {
    if (protection.enabled === null) return 'neutral';
    return protection.enabled ? 'danger' : 'positive';
  }
  if (['rpath', 'runpath'].includes(protection.name))
    return protection.enabled ? 'warning' : 'neutral';
  if (protection.name === 'stripped')
    return protection.enabled ? 'warning' : 'positive';
  if (protection.name === 'static_linking') return 'neutral';
  if (protection.name === 'relro') {
    if (protection.state === 'full') return 'positive';
    return protection.state === 'none' ? 'danger' : 'warning';
  }
  if (['nx', 'stack_canary'].includes(protection.name))
    return protection.enabled ? 'positive' : 'warning';
  if (protection.name === 'pie') return protection.enabled ? 'positive' : 'warning';
  return protection.enabled ? 'positive' : 'neutral';
}

function ProtectionCard({ protection }) {
  const symbol = verificationSymbols[protection.verification] || '?';
  return (
    <article className={`protection-card tone-${protectionTone(protection)}`}>
      <header>
        <div>
          <small>{protectionLabels[protection.name] || protection.name}</small>
          <strong>{protection.state.replaceAll('_', ' ')}</strong>
        </div>
        <span className={`verification verification-${protection.verification}`}>
          <span aria-hidden="true">{symbol}</span>
          {protection.verification}
        </span>
      </header>
      <p>{protection.impact}</p>
      <footer>
        <span>{Math.round(protection.confidence * 100)}% confidence</span>
        <details>
          <summary>Evidence {protection.evidence.length}</summary>
          <ul>
            {protection.evidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </details>
      </footer>
    </article>
  );
}

function Overview({ sha, info }) {
  const [security, setSecurity] = useState(null);
  const [findings, setFindings] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([api.checksec(sha), api.vulns(sha)])
      .then(([nextSecurity, nextFindings]) => {
        setSecurity(nextSecurity);
        setFindings(nextFindings);
      })
      .catch((reason) => setError(reason.message));
  }, [sha]);

  if (error) return <ErrorBanner message={error} />;
  if (!security || !findings)
    return <Loading label="보호 기법과 공격 표면을 분석하는 중" />;

  const risky = findings.filter((item) => item.severity !== 'info');
  return (
    <div className="analysis-stack">
      <section>
        <div className="section-heading">
          <div>
            <span>01</span>
            <h3>BINARY PROFILE</h3>
          </div>
          <p>파서가 정규화한 ELF 핵심 메타데이터</p>
        </div>
        <div className="metric-grid">
          <div className="metric">
            <small>ARCHITECTURE</small>
            <strong>{info.machine.replace('EM_', '')}</strong>
            <span>
              {info.bits}-bit · {info.endian} endian
            </span>
          </div>
          <div className="metric">
            <small>TYPE</small>
            <strong>{info.type.replace('ET_', '')}</strong>
            <span>{security.pie}</span>
          </div>
          <div className="metric">
            <small>ENTRY POINT</small>
            <strong className="mono accent">{formatHex(info.entry)}</strong>
            <span>program start</span>
          </div>
          <div className="metric">
            <small>LINKING</small>
            <strong>{info.linking || 'unknown'}</strong>
            <span>{info.needed_libraries?.length || 0} required libraries</span>
          </div>
        </div>
        <dl className="binary-linking-details">
          <div>
            <dt>INTERPRETER</dt>
            <dd title={info.interpreter || ''}>{info.interpreter || 'Not present'}</dd>
          </div>
          <div>
            <dt>LINKED LIBC</dt>
            <dd>{info.linked_libc || 'Not detected'}</dd>
          </div>
          <div>
            <dt>BUILD ID</dt>
            <dd title={info.build_id || ''}>{info.build_id || 'Not present'}</dd>
          </div>
          <div>
            <dt>INDEX</dt>
            <dd>
              {info.sections.length} sections · {info.symbols.length} symbols ·{' '}
              {info.relocation_count || 0} relocations
            </dd>
          </div>
        </dl>
      </section>

      <section>
        <div className="section-heading">
          <div>
            <span>02</span>
            <h3>MITIGATION MAP</h3>
          </div>
          <p>활성화된 보호 기법과 익스플로잇 난이도</p>
        </div>
        <div className="protection-grid">
          {(security.protections || [])
            .filter((item) => protectionLabels[item.name])
            .map((protection) => (
              <ProtectionCard key={protection.name} protection={protection} />
            ))}
        </div>
      </section>

      <section>
        <div className="section-heading">
          <div>
            <span>03</span>
            <h3>ATTACK SURFACE</h3>
          </div>
          <p>{risky.length}개의 주의 대상 · symbol 및 direct-call 휴리스틱</p>
        </div>
        {findings.length ? (
          <div className="finding-list">
            {findings.map((finding) => (
              <article className="finding" key={finding.symbol}>
                <Badge tone={severityTone[finding.severity]}>{finding.severity}</Badge>
                <code>{finding.symbol}()</code>
                <span className="finding-classification">
                  {finding.category}
                  <small>
                    ◇ {finding.status || 'possible'} ·{' '}
                    {Math.round((finding.confidence || 0) * 100)}% ·{' '}
                    {finding.verification || 'inferred'}
                  </small>
                </span>
                <p>{finding.description}</p>
              </article>
            ))}
          </div>
        ) : (
          <Empty
            title="위험 심볼 미탐지"
            description="알려진 위험 API가 심볼 테이블에서 발견되지 않았습니다. 안전을 보장하는 결과는 아닙니다."
          />
        )}
      </section>

      <section>
        <div className="section-heading">
          <div>
            <span>04</span>
            <h3>MEMORY SEGMENTS</h3>
          </div>
          <p>로더 관점의 권한과 주소 범위</p>
        </div>
        <DataTable
          rows={info.segments}
          keyFor={(row, index) => `${row.ptype}-${index}`}
          columns={[
            { key: 'ptype', label: 'TYPE', render: (row) => <code>{row.ptype}</code> },
            {
              key: 'vaddr',
              label: 'VIRTUAL ADDRESS',
              render: (row) => <code className="address">{formatHex(row.vaddr)}</code>,
            },
            {
              key: 'filesz',
              label: 'FILE SIZE',
              render: (row) => formatBytes(row.filesz),
            },
            {
              key: 'memsz',
              label: 'MEM SIZE',
              render: (row) => formatBytes(row.memsz),
            },
            {
              key: 'flags',
              label: 'PERMISSIONS',
              render: (row) => (
                <span className="permissions">
                  {row.readable ? 'R' : '-'}
                  {row.writable ? 'W' : '-'}
                  {row.executable ? 'X' : '-'}
                </span>
              ),
            },
          ]}
        />
      </section>
    </div>
  );
}

function Disassembly({ sha }) {
  const [instructions, setInstructions] = useState(null);
  const [count, setCount] = useState(250);
  const [error, setError] = useState('');

  useEffect(() => {
    setInstructions(null);
    api
      .disassembly(sha, count)
      .then(setInstructions)
      .catch((reason) => setError(reason.message));
  }, [sha, count]);

  if (error) return <ErrorBanner message={error} />;
  if (!instructions) return <Loading label="Capstone 디스어셈블러 실행 중" />;
  return (
    <section>
      <div className="toolbar">
        <div>
          <strong>LINEAR DISASSEMBLY</strong>
          <span>{instructions.length} instructions</span>
        </div>
        <label>
          표시 개수
          <select
            value={count}
            onChange={(event) => setCount(Number(event.target.value))}
          >
            <option value="100">100</option>
            <option value="250">250</option>
            <option value="500">500</option>
          </select>
        </label>
      </div>
      <div className="code-view">
        {instructions.map((instruction) => {
          const flow = /^(call|j|ret)/.test(instruction.mnemonic);
          return (
            <div
              className={`instruction ${flow ? 'flow' : ''}`}
              key={instruction.address}
            >
              <code className="address">{formatHex(instruction.address)}</code>
              <code className="raw">
                {instruction.bytes_hex.match(/.{1,2}/g)?.join(' ')}
              </code>
              <code className="mnemonic">{instruction.mnemonic}</code>
              <code className="operands">{instruction.op_str}</code>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function Gadgets({ sha }) {
  const [query, setQuery] = useState('');
  const [gadgets, setGadgets] = useState(null);
  const [error, setError] = useState('');

  const search = () => {
    setGadgets(null);
    setError('');
    api
      .gadgets(sha, query)
      .then(setGadgets)
      .catch((reason) => setError(reason.message));
  };
  useEffect(() => {
    api
      .gadgets(sha)
      .then(setGadgets)
      .catch((reason) => setError(reason.message));
  }, [sha]);

  if (error) return <ErrorBanner message={error} />;
  return (
    <section>
      <div className="toolbar">
        <div>
          <strong>ROP GADGET FINDER</strong>
          <span>ret 종결 명령 시퀀스</span>
        </div>
        <form
          className="search-box"
          onSubmit={(event) => {
            event.preventDefault();
            search();
          }}
        >
          <Icon name="search" size={16} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="pop rdi ; ret"
          />
          <button type="submit">SEARCH</button>
        </form>
      </div>
      {!gadgets ? (
        <Loading label="실행 섹션에서 가젯을 찾는 중" />
      ) : (
        <DataTable
          rows={gadgets}
          keyFor={(row) => `${row.address}-${row.bytes_hex}`}
          empty="검색 조건과 일치하는 가젯이 없습니다."
          columns={[
            {
              key: 'address',
              label: 'ADDRESS',
              render: (row) => (
                <code className="address">{formatHex(row.address)}</code>
              ),
            },
            {
              key: 'bytes_hex',
              label: 'BYTES',
              render: (row) => (
                <code className="dim-code">
                  {row.bytes_hex.match(/.{1,2}/g)?.join(' ')}
                </code>
              ),
            },
            {
              key: 'text',
              label: 'INSTRUCTIONS',
              render: (row) => <code className="gadget-code">{row.text}</code>,
            },
          ]}
        />
      )}
    </section>
  );
}

function Symbols({ info }) {
  const [query, setQuery] = useState('');
  const all = useMemo(() => [...info.symbols, ...info.dynamic_symbols], [info]);
  const rows = all.filter((symbol) =>
    symbol.name.toLowerCase().includes(query.toLowerCase()),
  );
  return (
    <section>
      <div className="toolbar">
        <div>
          <strong>SYMBOL TABLE</strong>
          <span>
            {rows.length} / {all.length} entries
          </span>
        </div>
        <div className="search-box">
          <Icon name="search" size={16} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="main, win, system…"
          />
        </div>
      </div>
      <DataTable
        rows={rows}
        keyFor={(row, index) => `${row.name}-${row.addr}-${index}`}
        columns={[
          {
            key: 'name',
            label: 'NAME',
            render: (row) => <code className="symbol-name">{row.name || '—'}</code>,
          },
          {
            key: 'addr',
            label: 'ADDRESS',
            render: (row) => <code className="address">{formatHex(row.addr)}</code>,
          },
          { key: 'size', label: 'SIZE' },
          {
            key: 'stype',
            label: 'TYPE',
            render: (row) => <Badge>{row.stype.replace('STT_', '')}</Badge>,
          },
          {
            key: 'binding',
            label: 'BINDING',
            render: (row) => row.binding.replace('STB_', ''),
          },
          { key: 'section_index', label: 'SECTION' },
        ]}
      />
    </section>
  );
}

function Strings({ sha }) {
  const [strings, setStrings] = useState(null);
  const [query, setQuery] = useState('');
  const [minLength, setMinLength] = useState(4);
  const [error, setError] = useState('');

  useEffect(() => {
    setStrings(null);
    api
      .strings(sha, minLength)
      .then(setStrings)
      .catch((reason) => setError(reason.message));
  }, [sha, minLength]);
  const rows = (strings || []).filter((item) =>
    item.value.toLowerCase().includes(query.toLowerCase()),
  );
  if (error) return <ErrorBanner message={error} />;
  return (
    <section>
      <div className="toolbar">
        <div>
          <strong>EXTRACTED STRINGS</strong>
          <span>ASCII · UTF-16LE</span>
        </div>
        <div className="toolbar-actions">
          <label>
            MIN{' '}
            <select
              value={minLength}
              onChange={(event) => setMinLength(Number(event.target.value))}
            >
              <option>4</option>
              <option>6</option>
              <option>8</option>
              <option>12</option>
            </select>
          </label>
          <div className="search-box">
            <Icon name="search" size={16} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="FLAG{, /bin/sh…"
            />
          </div>
        </div>
      </div>
      {!strings ? (
        <Loading label="문자열을 추출하는 중" />
      ) : (
        <DataTable
          rows={rows}
          keyFor={(row, index) => `${row.offset}-${index}`}
          columns={[
            {
              key: 'offset',
              label: 'FILE OFFSET',
              render: (row) => (
                <code className="address">{formatHex(row.offset, 8)}</code>
              ),
            },
            {
              key: 'encoding',
              label: 'ENCODING',
              render: (row) => <Badge tone="cyan">{row.encoding}</Badge>,
            },
            {
              key: 'value',
              label: 'VALUE',
              render: (row) => <code className="string-value">{row.value}</code>,
            },
          ]}
        />
      )}
    </section>
  );
}

function GotPlt({ sha }) {
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  useEffect(() => {
    api
      .got(sha)
      .then(setReport)
      .catch((reason) => setError(reason.message));
  }, [sha]);
  if (error) return <ErrorBanner message={error} />;
  if (!report) return <Loading label="GOT / PLT 구조를 분석하는 중" />;
  return (
    <div className="analysis-stack">
      <section>
        <div className="section-heading">
          <div>
            <span>01</span>
            <h3>LINKAGE SECTIONS</h3>
          </div>
        </div>
        <DataTable
          rows={report.sections}
          empty="정적 바이너리이거나 GOT/PLT 섹션이 없습니다."
          keyFor={(row) => row.name}
          columns={[
            { key: 'name', label: 'SECTION', render: (row) => <code>{row.name}</code> },
            {
              key: 'addr',
              label: 'ADDRESS',
              render: (row) => <code className="address">{formatHex(row.addr)}</code>,
            },
            { key: 'offset', label: 'OFFSET', render: (row) => formatHex(row.offset) },
            { key: 'size', label: 'SIZE' },
            {
              key: 'writable',
              label: 'WRITABLE',
              render: (row) => (
                <Badge tone={row.writable ? 'danger' : 'green'}>
                  {row.writable ? 'YES' : 'NO'}
                </Badge>
              ),
            },
          ]}
        />
      </section>
      <section>
        <div className="section-heading">
          <div>
            <span>02</span>
            <h3>GOT RELOCATION TARGETS</h3>
          </div>
          <p>relocation offset에서 직접 확인된 entry</p>
        </div>
        <DataTable
          rows={report.entries}
          empty="GOT relocation target이 없습니다."
          keyFor={(row, index) => `${row.address}-${row.symbol}-${index}`}
          columns={[
            {
              key: 'address',
              label: 'GOT ADDRESS',
              render: (row) => (
                <code className="address">{formatHex(row.address)}</code>
              ),
            },
            {
              key: 'symbol',
              label: 'SYMBOL',
              render: (row) => <code className="symbol-name">{row.symbol || '—'}</code>,
            },
            { key: 'relocation_type', label: 'RELOCATION' },
            { key: 'relocation_section', label: 'SOURCE' },
            {
              key: 'verification',
              label: 'VERIFICATION',
              render: () => (
                <span className="verification verification-verified">✓ verified</span>
              ),
            },
          ]}
        />
      </section>
      <section>
        <div className="section-heading">
          <div>
            <span>03</span>
            <h3>PLT STUB CANDIDATES</h3>
          </div>
          <p>section entry size와 relocation 순서에서 파생</p>
        </div>
        <DataTable
          rows={report.plt_entries}
          empty="파생 가능한 PLT stub이 없습니다."
          keyFor={(row, index) => `${row.symbol}-${index}`}
          columns={[
            {
              key: 'address',
              label: 'PLT ADDRESS',
              render: (row) => (
                <code className="address">
                  {row.address === null ? 'unknown' : formatHex(row.address)}
                </code>
              ),
            },
            {
              key: 'symbol',
              label: 'SYMBOL',
              render: (row) => <code className="symbol-name">{row.symbol}</code>,
            },
            {
              key: 'got_address',
              label: 'GOT ADDRESS',
              render: (row) => <code>{formatHex(row.got_address)}</code>,
            },
            { key: 'section', label: 'SECTION' },
            {
              key: 'verification',
              label: 'VERIFICATION',
              render: (row) => (
                <span className={`verification verification-${row.verification}`}>
                  ≈ {row.verification} · {Math.round(row.confidence * 100)}%
                </span>
              ),
            },
          ]}
        />
      </section>
      <section>
        <div className="section-heading">
          <div>
            <span>04</span>
            <h3>IMPORTED SYMBOLS</h3>
          </div>
        </div>
        <DataTable
          rows={report.imports}
          empty="동적 임포트 심볼이 없습니다."
          keyFor={(row, index) => `${row.name}-${index}`}
          columns={[
            {
              key: 'name',
              label: 'NAME',
              render: (row) => <code className="symbol-name">{row.name}</code>,
            },
            { key: 'stype', label: 'TYPE' },
            { key: 'binding', label: 'BINDING' },
          ]}
        />
      </section>
    </div>
  );
}

function HexView({ sha }) {
  const [page, setPage] = useState(0);
  const [dump, setDump] = useState(null);
  const [error, setError] = useState('');
  useEffect(() => {
    setDump(null);
    api
      .hex(sha, page)
      .then(setDump)
      .catch((reason) => setError(reason.message));
  }, [sha, page]);
  if (error) return <ErrorBanner message={error} />;
  if (!dump) return <Loading label="헥스 페이지를 읽는 중" />;
  return (
    <section>
      <div className="toolbar">
        <div>
          <strong>HEX VIEWER</strong>
          <span>
            {formatBytes(dump.total_size)} · page {page + 1} /{' '}
            {Math.max(1, dump.total_pages)}
          </span>
        </div>
        <div className="pager">
          <button disabled={page === 0} onClick={() => setPage((value) => value - 1)}>
            ← PREV
          </button>
          <code>{formatHex(page * dump.page_size, 8)}</code>
          <button
            disabled={page + 1 >= dump.total_pages}
            onClick={() => setPage((value) => value + 1)}
          >
            NEXT →
          </button>
        </div>
      </div>
      <div className="hex-view">
        {dump.rows.map((row) => (
          <div key={row.offset}>
            <code className="address">{formatHex(row.offset, 8)}</code>
            <code className="hex-bytes">{row.hex}</code>
            <code className="hex-ascii">{row.ascii}</code>
          </div>
        ))}
      </div>
    </section>
  );
}

/**
 * @param {{
 *   sha: string,
 *   binary: any,
 *   activeTab?: string,
 *   onTabChange?: (nextTab: string) => void
 * }} props
 */
export function Analysis({
  sha,
  binary,
  activeTab = 'overview',
  onTabChange = () => {},
}) {
  const tab = TABS.some(([id]) => id === activeTab) ? activeTab : 'overview';
  const [info, setInfo] = useState(null);
  const [contextSecurity, setContextSecurity] = useState(null);
  const [analysisStatus, setAnalysisStatus] = useState(
    binary?.analysis_status || 'unknown',
  );
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([api.info(sha), api.checksec(sha)])
      .then(([nextInfo, nextSecurity]) => {
        setInfo(nextInfo);
        setContextSecurity(nextSecurity);
      })
      .catch((reason) => setError(reason.message));
  }, [sha]);

  const rerunAnalysis = async () => {
    setAnalyzing(true);
    setError('');
    setAnalysisStatus('running');
    try {
      const job = await api.analyze(sha);
      setAnalysisStatus(job.status);
      if (job.error) setError(job.error);
    } catch (reason) {
      setAnalysisStatus('failed');
      setError(reason.message);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="page">
      <div className="page-head binary-context-header">
        <div>
          <div className="eyebrow">
            <span /> BINARY WORKSPACE
          </div>
          <h2>{binary?.filename || 'ELF target'}</h2>
          <div className="binary-context-meta">
            <span>{binary?.machine?.replace('EM_', '') || 'Unknown arch'}</span>
            <span>{binary?.bits ? `${binary.bits}-bit` : 'Unknown bits'}</span>
            <code title={sha}>{sha.slice(0, 16)}</code>
            <StatusBadge status={analysisStatus} />
          </div>
        </div>
        <div className="context-actions">
          {contextSecurity && (
            <div className="protection-summary" aria-label="Protection summary">
              <span>NX {contextSecurity.nx ? '✓' : '×'}</span>
              <span>PIE {contextSecurity.pie === 'PIE' ? '✓' : '×'}</span>
              <span>Canary {contextSecurity.canary ? '✓' : '?'}</span>
              <span>RELRO {contextSecurity.relro}</span>
            </div>
          )}
          <button
            className="button secondary"
            disabled={analyzing}
            onClick={rerunAnalysis}
          >
            {analyzing ? 'Analyzing ELF…' : 'Re-run static analysis'}
          </button>
        </div>
      </div>
      <div className="analysis-tabs" role="tablist">
        {TABS.map(([id, label]) => (
          <button
            role="tab"
            aria-selected={tab === id}
            className={tab === id ? 'active' : ''}
            key={id}
            onClick={() => onTabChange(id)}
          >
            {label}
          </button>
        ))}
      </div>
      <ErrorBanner message={error} />
      {!info ? (
        !error && <Loading label="ELF 헤더와 섹션을 파싱하는 중" />
      ) : (
        <div className="tab-content">
          {tab === 'overview' && <Overview sha={sha} info={info} />}
          {tab === 'disassembly' && <Disassembly sha={sha} />}
          {tab === 'gadgets' && <Gadgets sha={sha} />}
          {tab === 'symbols' && <Symbols info={info} />}
          {tab === 'strings' && <Strings sha={sha} />}
          {tab === 'got' && <GotPlt sha={sha} />}
          {tab === 'hex' && <HexView sha={sha} />}
        </div>
      )}
    </div>
  );
}

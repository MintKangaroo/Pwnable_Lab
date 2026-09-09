import { useEffect, useMemo, useRef, useState } from 'react';
import { api, formatBytes, formatHex } from '../api';
import {
  Badge,
  CopyButton,
  DataTable,
  Empty,
  ErrorBanner,
  Icon,
  Loading,
  StatusBadge,
} from './Common.jsx';

const COMMON_TABS = [
  ['overview', 'Overview'],
  ['disassembly', 'Disassembly'],
  ['symbols', 'Symbols'],
  ['strings', 'Strings'],
  ['hex', 'Hex View'],
];

const tabsForFormat = (format) => {
  if (format === 'ELF') {
    return [
      COMMON_TABS[0],
      ['functions', 'Functions'],
      COMMON_TABS[1],
      ['cfg', 'CFG'],
      ['gadgets', 'ROP Studio'],
      COMMON_TABS[2],
      COMMON_TABS[3],
      ['got', 'GOT / PLT'],
      ['strategy', 'Exploit Strategy'],
      ['exploit-runner', 'Exploit Runner'],
      ['debugger-ws', 'Live Debugger'],
      ['dynamic', 'Dynamic Analysis'],
      ['ghidra', 'Ghidra'],
      COMMON_TABS[4],
    ];
  }
  if (format === 'RAW') {
    return [COMMON_TABS[0], COMMON_TABS[1], COMMON_TABS[3], COMMON_TABS[4]];
  }
  return [
    COMMON_TABS[0],
    ['functions', 'Functions'],
    COMMON_TABS[1],
    ['cfg', 'CFG'],
    COMMON_TABS[2],
    COMMON_TABS[3],
    COMMON_TABS[4],
  ];
};

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
  rwx_sections: 'RWX SECTIONS',
  stripped: 'SYMBOL STRIPPING',
  static_linking: 'LINKING MODE',
  aslr: 'ASLR',
  dep: 'DEP / NX COMPAT',
  high_entropy_va: 'HIGH ENTROPY VA',
  control_flow_guard: 'CONTROL FLOW GUARD',
  force_integrity: 'FORCE INTEGRITY',
  app_container: 'APP CONTAINER',
  no_seh: 'NO SEH',
  authenticode: 'AUTHENTICODE',
  loader_mitigations: 'LOADER MITIGATIONS',
};

const verificationSymbols = {
  verified: '✓',
  inferred: '≈',
  unknown: '?',
};

function protectionTone(protection) {
  if (['rwx_segments', 'rwx_sections'].includes(protection.name))
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
  if (protection.name === 'authenticode') {
    return protection.enabled ? 'warning' : 'neutral';
  }
  if (protection.name === 'loader_mitigations') return 'neutral';
  if (protection.name === 'relro') {
    if (protection.state === 'full') return 'positive';
    return protection.state === 'none' ? 'danger' : 'warning';
  }
  if (['nx', 'stack_canary', 'aslr', 'dep'].includes(protection.name))
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
  const format = info.format || 'ELF';
  const machine = info.machine.replace('EM_', '').replace('IMAGE_FILE_MACHINE_', '');
  const profileDetails =
    format === 'PE'
      ? [
          ['IMAGE BASE', formatHex(info.image_base)],
          ['SUBSYSTEM', info.subsystem || 'Unknown'],
          ['IMPORTS', `${info.imports?.length || 0} verified entries`],
          [
            'INDEX',
            `${info.sections.length} sections · ${info.exports?.length || 0} exports · ${info.relocation_count || 0} relocations`,
          ],
        ]
      : format === 'RAW'
        ? [
            ['ARCHITECTURE', 'Not inferred'],
            ['LOAD ADDRESS', 'User input required'],
            ['ENTROPY', Number(info.global_entropy).toFixed(4)],
            [
              'LIMITATIONS',
              `${info.analysis_limitations?.length || 0} explicit constraints`,
            ],
          ]
        : [
            ['INTERPRETER', info.interpreter || 'Not present'],
            ['LINKED LIBC', info.linked_libc || 'Not detected'],
            ['BUILD ID', info.build_id || 'Not present'],
            [
              'INDEX',
              `${info.sections.length} sections · ${info.symbols.length} symbols · ${info.relocation_count || 0} relocations`,
            ],
          ];
  return (
    <div className="analysis-stack">
      <section>
        <div className="section-heading">
          <div>
            <span>01</span>
            <h3>BINARY PROFILE</h3>
          </div>
          <p>{format} 파서가 정규화한 핵심 메타데이터</p>
        </div>
        <div className="metric-grid">
          <div className="metric">
            <small>ARCHITECTURE</small>
            <strong>{machine}</strong>
            <span>
              {info.bits ? `${info.bits}-bit` : 'bitness unknown'} · {info.endian}{' '}
              endian
            </span>
          </div>
          <div className="metric">
            <small>TYPE</small>
            <strong>{String(info.file_type || info.type).replace('ET_', '')}</strong>
            <span>{format}</span>
          </div>
          <div className="metric">
            <small>ENTRY POINT</small>
            <strong className="mono accent">{formatHex(info.entry)}</strong>
            <span>{info.entry === null ? 'unknown' : 'program start'}</span>
          </div>
          <div className="metric">
            <small>LINKING</small>
            <strong>{info.linking || 'unknown'}</strong>
            <span>
              {format === 'RAW'
                ? 'loader metadata unavailable'
                : `${info.needed_libraries?.length || 0} required libraries`}
            </span>
          </div>
        </div>
        <dl className="binary-linking-details">
          {profileDetails.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd title={String(value)}>{value}</dd>
            </div>
          ))}
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
          {(security.protections || []).map((protection) => (
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
          empty="로더가 검증한 메모리 매핑 정보가 없습니다."
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

const addressParam = (value) =>
  typeof value === 'number' ? `0x${value.toString(16)}` : String(value || '');

function FunctionsView({ sha, selectedAddress, onAddressChange }) {
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [catalog, setCatalog] = useState(null);
  const [detail, setDetail] = useState(null);
  const [pseudo, setPseudo] = useState(null);
  const [pseudoError, setPseudoError] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedQuery(query), 250);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    setCatalog(null);
    setError('');
    api
      .functions(sha, debouncedQuery)
      .then(setCatalog)
      .catch((reason) => setError(reason.message));
  }, [sha, debouncedQuery]);

  const activeAddress = selectedAddress || catalog?.items?.[0]?.address || '';
  useEffect(() => {
    if (!activeAddress) {
      setDetail(null);
      return;
    }
    setDetail(null);
    setPseudo(null);
    setPseudoError('');
    api
      .functionDetail(sha, activeAddress)
      .then(setDetail)
      .catch((reason) => setError(reason.message));
  }, [sha, activeAddress]);

  const loadPseudocode = () => {
    setPseudoError('');
    setPseudo('loading');
    api
      .pseudocode(sha, addressParam(activeAddress))
      .then(setPseudo)
      .catch((reason) => {
        setPseudo(null);
        setPseudoError(reason.message);
      });
  };

  return (
    <div className="function-workspace">
      <section className="function-list-panel">
        <div className="toolbar">
          <div>
            <strong>FUNCTION INDEX</strong>
            <span>
              {catalog ? `${catalog.total} starts` : 'Recovering function starts'} ·
              boundaries preserve verification state
            </span>
          </div>
          <div className="search-box">
            <Icon name="search" size={16} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="main, helper, 0x401000…"
              aria-label="Search functions"
            />
          </div>
        </div>
        <ErrorBanner message={error} />
        {!catalog ? (
          !error && <Loading label="함수 시작점과 경계를 복구하는 중" />
        ) : (
          <DataTable
            rows={catalog.items}
            empty="조건에 맞는 함수 시작점이 없습니다."
            keyFor={(row) => row.address}
            columns={[
              {
                key: 'name',
                label: 'FUNCTION',
                render: (row) => (
                  <button
                    className={`table-link ${addressParam(activeAddress) === addressParam(row.address) ? 'selected' : ''}`}
                    onClick={() => onAddressChange(row.address, 'functions')}
                  >
                    {row.name}
                  </button>
                ),
              },
              {
                key: 'address',
                label: 'START',
                render: (row) => (
                  <code className="address">{formatHex(row.address)}</code>
                ),
              },
              {
                key: 'end',
                label: 'END',
                render: (row) => <code>{formatHex(row.end)}</code>,
              },
              { key: 'size', label: 'SIZE' },
              { key: 'region', label: 'REGION' },
              {
                key: 'verification',
                label: 'BOUNDARY',
                render: (row) => (
                  <span
                    className={`verification verification-${row.boundary_verification}`}
                  >
                    {verificationSymbols[row.boundary_verification]}{' '}
                    {row.boundary_verification}
                  </span>
                ),
              },
              {
                key: 'cfg',
                label: '',
                render: (row) => (
                  <button
                    className="row-context-action"
                    onClick={() => onAddressChange(row.address, 'cfg')}
                  >
                    Open CFG →
                  </button>
                ),
              },
            ]}
          />
        )}
      </section>

      <aside className="function-inspector">
        <div className="inspector-heading">
          <span>FUNCTION INSPECTOR</span>
          {detail && (
            <span className={`verification verification-${detail.verification}`}>
              {verificationSymbols[detail.verification]} {detail.verification}
            </span>
          )}
        </div>
        {!activeAddress ? (
          <Empty
            title="No function selected"
            description="함수를 선택하면 경계 근거와 명령 요약을 표시합니다."
          />
        ) : !detail ? (
          !error && <Loading label="함수 근거를 불러오는 중" />
        ) : (
          <>
            <h3>{detail.name}</h3>
            <code className="inspector-address">
              {formatHex(detail.address)}–{formatHex(detail.end)}
            </code>
            <dl className="inspector-facts">
              <div>
                <dt>SOURCE</dt>
                <dd>{detail.source}</dd>
              </div>
              <div>
                <dt>REGION</dt>
                <dd>{detail.region}</dd>
              </div>
              <div>
                <dt>INSTRUCTIONS</dt>
                <dd>{detail.instruction_count}</dd>
              </div>
              <div>
                <dt>CONFIDENCE</dt>
                <dd>{Math.round(detail.confidence * 100)}%</dd>
              </div>
            </dl>
            <div className="inspector-actions">
              <button onClick={() => onAddressChange(detail.address, 'disassembly')}>
                Open disassembly
              </button>
              <button onClick={() => onAddressChange(detail.address, 'cfg')}>
                Open CFG
              </button>
            </div>
            <div className="evidence-compact">
              <strong>EVIDENCE</strong>
              {detail.evidence.map((item) => (
                <p key={item}>✓ {item}</p>
              ))}
            </div>
            <div className="pseudo-c-block">
              <div className="pseudo-c-head">
                <strong>PSEUDO-C</strong>
                <span className="verification verification-inferred">
                  ~ inferred (휴리스틱)
                </span>
              </div>
              {pseudoError && <ErrorBanner message={pseudoError} />}
              {pseudo === null && (
                <button className="button secondary" onClick={loadPseudocode}>
                  C 의사코드로 보기
                </button>
              )}
              {pseudo === 'loading' && <Loading label="의사코드를 생성하는 중" />}
              {pseudo && pseudo !== 'loading' && (
                <>
                  <div className="pseudo-c-toolbar">
                    <code>{pseudo.signature}</code>
                    <CopyButton value={pseudo.pseudocode} />
                  </div>
                  <pre className="pseudo-c-code">
                    <code>{pseudo.pseudocode}</code>
                  </pre>
                  <div className="pseudo-c-notes">
                    {pseudo.notes.map((note) => (
                      <p key={note}>· {note}</p>
                    ))}
                  </div>
                </>
              )}
            </div>
          </>
        )}
      </aside>
    </div>
  );
}

function CFGView({ sha, selectedAddress, onAddressChange }) {
  const [catalog, setCatalog] = useState(null);
  const [report, setReport] = useState(null);
  const [xrefs, setXrefs] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api
      .functions(sha)
      .then(setCatalog)
      .catch((reason) => setError(reason.message));
  }, [sha]);

  const activeAddress = selectedAddress || catalog?.items?.[0]?.address || '';
  useEffect(() => {
    if (!activeAddress) return;
    setReport(null);
    setXrefs(null);
    setError('');
    Promise.all([
      api.cfg(sha, activeAddress),
      api.xrefs(sha, { address: activeAddress, direction: 'to' }),
    ])
      .then(([nextReport, nextXrefs]) => {
        setReport(nextReport);
        setXrefs(nextXrefs);
      })
      .catch((reason) => setError(reason.message));
  }, [sha, activeAddress]);

  return (
    <section className="cfg-section">
      <div className="toolbar">
        <div>
          <strong>CONTROL-FLOW GRAPH</strong>
          <span>Compact verified-edge view · indirect targets remain unresolved</span>
        </div>
        <label>
          FUNCTION
          <select
            value={addressParam(activeAddress)}
            onChange={(event) => onAddressChange(event.target.value, 'cfg')}
            aria-label="CFG function"
          >
            {(catalog?.items || []).map((item) => (
              <option key={item.address} value={addressParam(item.address)}>
                {item.name} · {formatHex(item.address)}
              </option>
            ))}
          </select>
        </label>
      </div>
      <ErrorBanner message={error} />
      {!report ? (
        !error && <Loading label="기본 블록과 분기 edge를 구성하는 중" />
      ) : (
        <div className="cfg-workspace">
          <div className="cfg-canvas" aria-label="Control-flow basic blocks">
            <div className="cfg-summary">
              <span>{report.function.name}</span>
              <code>{formatHex(report.function.address)}</code>
              <Badge tone={report.status === 'completed' ? 'green' : 'warn'}>
                {report.status.replace('_', ' ')}
              </Badge>
              <span>
                {report.node_count} blocks · {report.edge_count} edges
              </span>
            </div>
            {report.nodes.map((node) => (
              <article className="cfg-node" key={node.id}>
                <header>
                  <button onClick={() => onAddressChange(node.start, 'disassembly')}>
                    {formatHex(node.start)}–{formatHex(node.end)}
                  </button>
                  {node.conditional_branch && <Badge tone="warn">CONDITIONAL</Badge>}
                </header>
                <div className="cfg-instructions">
                  {node.instructions.slice(0, 12).map((instruction) => (
                    <div key={instruction.address}>
                      <code className="address">{formatHex(instruction.address)}</code>
                      <code className="mnemonic">{instruction.mnemonic}</code>
                      <code>{instruction.op_str}</code>
                    </div>
                  ))}
                </div>
                <footer>
                  <span>
                    IN{' '}
                    {node.predecessors.length
                      ? node.predecessors.map((value) => formatHex(value)).join(', ')
                      : 'entry'}
                  </span>
                  <span>
                    OUT{' '}
                    {node.successors.length
                      ? node.successors.map((value) => formatHex(value)).join(', ')
                      : 'return'}
                  </span>
                </footer>
              </article>
            ))}
          </div>
          <aside className="cfg-inspector">
            <div className="inspector-heading">CFG INSPECTOR</div>
            <h3>Verified relations</h3>
            <div className="edge-list">
              {report.edges.map((edge) => (
                <div key={edge.id}>
                  <Badge tone={edge.type === 'true' ? 'green' : 'cyan'}>
                    {edge.type}
                  </Badge>
                  <code>{formatHex(edge.source)}</code>
                  <span>→</span>
                  <code>{formatHex(edge.target)}</code>
                </div>
              ))}
              {!report.edges.length && <p>No internal branch edges.</p>}
            </div>
            <h3>Incoming xrefs</h3>
            <div className="xref-list">
              {(xrefs?.items || []).map((xref) => (
                <button
                  key={`${xref.source}-${xref.target}-${xref.kind}`}
                  onClick={() => onAddressChange(xref.source, 'disassembly')}
                >
                  <Badge tone="cyan">{xref.kind}</Badge>
                  <code>{formatHex(xref.source)}</code>
                  <span>{xref.source_function || 'unknown function'}</span>
                </button>
              ))}
              {xrefs && !xrefs.items.length && <p>No incoming direct xrefs.</p>}
            </div>
            <div className="cfg-limitations">
              <strong>LIMITATIONS</strong>
              {report.limitations.map((item) => (
                <p key={item}>◇ {item}</p>
              ))}
            </div>
          </aside>
        </div>
      )}
    </section>
  );
}

function Disassembly({ sha, info, selectedAddress, onAddressChange }) {
  const [instructions, setInstructions] = useState(null);
  const [count, setCount] = useState(250);
  const [architecture, setArchitecture] = useState('x86_64');
  const [baseAddress, setBaseAddress] = useState('0x0');
  const [addressInput, setAddressInput] = useState(selectedAddress || '');
  const [requestedAddress, setRequestedAddress] = useState(selectedAddress || '');
  const [query, setQuery] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    setAddressInput(selectedAddress || '');
    setRequestedAddress(selectedAddress || '');
  }, [selectedAddress]);

  useEffect(() => {
    setInstructions(null);
    setError('');
    let options = {};
    if (info.format === 'RAW') {
      try {
        const parsedBase = BigInt(baseAddress.trim());
        if (parsedBase < 0n || parsedBase > 0xffffffffffffffffn) throw new RangeError();
        options = { architecture, baseAddress: parsedBase.toString() };
      } catch {
        setInstructions([]);
        setError('RAW base address는 0부터 0xffffffffffffffff 사이의 정수여야 합니다.');
        return;
      }
    } else if (requestedAddress) {
      try {
        const parsedAddress = BigInt(requestedAddress.trim());
        if (parsedAddress < 0n || parsedAddress > 0xffffffffffffffffn)
          throw new RangeError();
        options = { address: parsedAddress.toString() };
      } catch {
        setInstructions([]);
        setError('주소는 0부터 0xffffffffffffffff 사이의 정수여야 합니다.');
        return;
      }
    }
    api
      .disassembly(sha, count, options)
      .then(setInstructions)
      .catch((reason) => setError(reason.message));
  }, [sha, count, architecture, baseAddress, requestedAddress, info.format]);

  if (error) return <ErrorBanner message={error} />;
  if (!instructions) return <Loading label="Capstone 디스어셈블러 실행 중" />;
  const visibleInstructions = instructions.filter((instruction) => {
    const needle = query.trim().toLowerCase();
    if (!needle) return true;
    return (
      instruction.mnemonic.toLowerCase().includes(needle) ||
      instruction.op_str.toLowerCase().includes(needle) ||
      formatHex(instruction.address).includes(needle)
    );
  });
  return (
    <section>
      <div className="toolbar">
        <div>
          <strong>LINEAR DISASSEMBLY</strong>
          <span>
            {visibleInstructions.length} / {instructions.length} instructions in current
            window
          </span>
        </div>
        {info.format !== 'RAW' && (
          <form
            className="address-search"
            onSubmit={(event) => {
              event.preventDefault();
              setRequestedAddress(addressInput);
              if (addressInput) onAddressChange(addressInput, 'disassembly');
            }}
          >
            <label>
              ADDRESS
              <input
                className="mono-input"
                value={addressInput}
                onChange={(event) => setAddressInput(event.target.value)}
                placeholder="entry or 0x401000"
                aria-label="Disassembly address"
              />
            </label>
            <button type="submit">GO</button>
          </form>
        )}
        <div className="search-box disassembly-filter">
          <Icon name="search" size={16} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="opcode, operand, address…"
            aria-label="Filter disassembly"
          />
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
        {info.format === 'RAW' && (
          <div className="toolbar-actions raw-disassembly-options">
            <label>
              ARCH
              <select
                value={architecture}
                onChange={(event) => setArchitecture(event.target.value)}
              >
                <option value="x86_64">x86-64</option>
                <option value="x86">x86</option>
              </select>
            </label>
            <label>
              BASE
              <input
                className="mono-input"
                value={baseAddress}
                onChange={(event) => setBaseAddress(event.target.value)}
                aria-label="Raw binary base address"
              />
            </label>
          </div>
        )}
      </div>
      <div className="code-view">
        {visibleInstructions.map((instruction) => {
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

const gadgetCategories = [
  ['', 'All categories'],
  ['pop', 'Pop register'],
  ['multi_pop', 'Multi-pop'],
  ['return', 'Return'],
  ['stack_adjust', 'Stack adjust'],
  ['stack_pivot', 'Stack pivot'],
  ['syscall', 'Syscall'],
  ['int80', 'int 0x80'],
  ['memory_write', 'Memory write'],
  ['write_what_where_candidate', 'Write-what-where candidate'],
];

const newChainId = () =>
  `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;

function chainValue(value) {
  try {
    return `0x${BigInt(value).toString(16)}`;
  } catch {
    return String(value);
  }
}

function Gadgets({ sha, onAddressChange }) {
  const [filters, setFilters] = useState({
    q: '',
    regex: false,
    register: '',
    category: '',
    minStackChange: '',
    maxStackChange: '',
    badBytes: '',
    sort: 'quality',
    order: 'desc',
  });
  const [appliedFilters, setAppliedFilters] = useState(filters);
  const [offset, setOffset] = useState(0);
  const [catalog, setCatalog] = useState(null);
  const [chain, setChain] = useState([]);
  const [literal, setLiteral] = useState('0x0');
  const [literalLabel, setLiteralLabel] = useState('');
  const [draggedId, setDraggedId] = useState('');
  const [simulation, setSimulation] = useState(null);
  const [simulationLoading, setSimulationLoading] = useState(false);
  const [error, setError] = useState('');
  const [chainError, setChainError] = useState('');

  useEffect(() => {
    setCatalog(null);
    setError('');
    api
      .gadgets(sha, { ...appliedFilters, offset, limit: 100 })
      .then(setCatalog)
      .catch((reason) => setError(reason.message));
  }, [sha, appliedFilters, offset]);

  useEffect(() => {
    if (!chain.length) {
      setSimulation(null);
      setSimulationLoading(false);
      return;
    }
    setSimulationLoading(true);
    const timer = window.setTimeout(() => {
      api
        .simulateRop(
          sha,
          chain.map((item) => ({
            kind: item.kind,
            value: item.value,
            label: item.label,
          })),
        )
        .then(setSimulation)
        .catch((reason) =>
          setSimulation({
            status: 'invalid',
            verification: 'inferred',
            confidence: 0,
            errors: [reason.message],
            warnings: [],
            registers: {},
            trace: [],
            limitations: [],
          }),
        )
        .finally(() => setSimulationLoading(false));
    }, 250);
    return () => window.clearTimeout(timer);
  }, [sha, chain]);

  const addGadget = (gadget) => {
    setChain((current) => [
      ...current,
      {
        id: newChainId(),
        kind: 'gadget',
        value: gadget.address,
        label: gadget.text,
        gadget,
      },
    ]);
  };

  const addLiteral = (event) => {
    event.preventDefault();
    try {
      const parsed = BigInt(literal.trim());
      if (parsed < 0n || parsed > 0xffffffffffffffffn) throw new RangeError();
      setChain((current) => [
        ...current,
        {
          id: newChainId(),
          kind: literalLabel.trim() ? 'symbol' : 'literal',
          value: literal.trim(),
          label: literalLabel.trim() || 'literal',
        },
      ]);
      setChainError('');
    } catch {
      setChainError('값은 unsigned 64-bit 정수 또는 0x 접두 주소여야 합니다.');
    }
  };

  const moveChainItem = (from, to) => {
    if (to < 0 || to >= chain.length || from === to) return;
    setChain((current) => {
      const next = [...current];
      const [item] = next.splice(from, 1);
      next.splice(to, 0, item);
      return next;
    });
  };

  const pwntoolsDraft = useMemo(() => {
    if (!chain.length) return '';
    return [
      '# Verified gadget values; runtime bases and literals still require validation.',
      'chain = flat(',
      ...chain.map(
        (item) => `    ${chainValue(item.value)},  # ${item.label || item.kind}`,
      ),
      ')',
    ].join('\n');
  }, [chain]);

  return (
    <section className="rop-studio">
      <div className="toolbar rop-toolbar">
        <div>
          <strong>ROP STUDIO</strong>
          <span>
            Verified bytes and effects · inferred quality and chain state · static only
          </span>
        </div>
        {catalog && (
          <div className="rop-scan-status">
            <Badge tone={catalog.status === 'completed' ? 'green' : 'warn'}>
              {catalog.status.replace('_', ' ')}
            </Badge>
            <span>{catalog.scanned_gadgets} scanned</span>
            {catalog.position_independent && <Badge tone="warn">PIE OFFSETS</Badge>}
          </div>
        )}
      </div>
      <ErrorBanner message={error} />
      <div className="rop-columns">
        <section className="gadget-search-panel" aria-label="Gadget search">
          <div className="panel-title">
            <span>01</span>
            <strong>GADGET SEARCH</strong>
          </div>
          <form
            className="gadget-filter-form"
            onSubmit={(event) => {
              event.preventDefault();
              setOffset(0);
              setAppliedFilters({ ...filters });
            }}
          >
            <label className="filter-wide">
              INSTRUCTIONS
              <input
                value={filters.q}
                onChange={(event) => setFilters({ ...filters, q: event.target.value })}
                placeholder="pop rdi ; ret"
              />
            </label>
            <label className="check-label">
              <input
                type="checkbox"
                checked={filters.regex}
                onChange={(event) =>
                  setFilters({ ...filters, regex: event.target.checked })
                }
              />
              Safe regex
            </label>
            <label>
              WRITES REGISTER
              <input
                value={filters.register}
                onChange={(event) =>
                  setFilters({ ...filters, register: event.target.value })
                }
                placeholder="rdi"
              />
            </label>
            <label>
              CATEGORY
              <select
                value={filters.category}
                onChange={(event) =>
                  setFilters({ ...filters, category: event.target.value })
                }
              >
                {gadgetCategories.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              MIN STACK Δ
              <input
                type="number"
                value={filters.minStackChange}
                onChange={(event) =>
                  setFilters({ ...filters, minStackChange: event.target.value })
                }
                placeholder="0"
              />
            </label>
            <label>
              MAX STACK Δ
              <input
                type="number"
                value={filters.maxStackChange}
                onChange={(event) =>
                  setFilters({ ...filters, maxStackChange: event.target.value })
                }
                placeholder="64"
              />
            </label>
            <label>
              BAD BYTES
              <input
                value={filters.badBytes}
                onChange={(event) =>
                  setFilters({ ...filters, badBytes: event.target.value })
                }
                placeholder="00, 0a"
              />
            </label>
            <label>
              SORT
              <select
                value={filters.sort}
                onChange={(event) =>
                  setFilters({ ...filters, sort: event.target.value })
                }
              >
                <option value="quality">Quality</option>
                <option value="side_effects">Side effects</option>
                <option value="stack_change">Stack delta</option>
                <option value="address">Address</option>
              </select>
            </label>
            <button className="filter-submit" type="submit">
              <Icon name="search" size={14} /> APPLY FILTERS
            </button>
          </form>

          {!catalog ? (
            !error && <Loading label="가젯 효과를 분석하는 중" />
          ) : !catalog.items.length ? (
            <Empty
              title="No matching gadgets"
              description="필터를 완화하거나 bad byte 조건을 확인하세요."
            />
          ) : (
            <div className="gadget-result-list">
              {catalog.items.map((gadget) => (
                <article className="gadget-result" key={gadget.address}>
                  <header>
                    <button
                      className="gadget-address"
                      onClick={() => onAddressChange(gadget.address, 'disassembly')}
                    >
                      {formatHex(gadget.address)}
                    </button>
                    <span className="gadget-quality">
                      ≈ {Math.round(gadget.quality_score * 100)}
                    </span>
                    <button className="gadget-add" onClick={() => addGadget(gadget)}>
                      + ADD
                    </button>
                  </header>
                  <code>{gadget.text}</code>
                  <footer>
                    <span>STACK {gadget.stack_change ?? '?'}</span>
                    <span>WRITE {gadget.registers_written.join(', ') || 'none'}</span>
                    <span>SIDE FX {gadget.side_effect_count}</span>
                  </footer>
                </article>
              ))}
            </div>
          )}
          {catalog && catalog.total > catalog.limit && (
            <div className="rop-pagination">
              <button
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - catalog.limit))}
              >
                ← Previous
              </button>
              <span>
                {offset + 1}–{Math.min(offset + catalog.limit, catalog.total)} of{' '}
                {catalog.total}
              </span>
              <button
                disabled={offset + catalog.limit >= catalog.total}
                onClick={() => setOffset(offset + catalog.limit)}
              >
                Next →
              </button>
            </div>
          )}
        </section>

        <section className="rop-chain-panel" aria-label="ROP chain">
          <div className="panel-title">
            <span>02</span>
            <strong>CHAIN LAYOUT</strong>
            <button disabled={!chain.length} onClick={() => setChain([])}>
              CLEAR
            </button>
          </div>
          {!chain.length ? (
            <Empty
              title="Chain is empty"
              description="검증된 gadget을 추가한 다음 필요한 literal 또는 symbol 주소를 배치하세요."
            />
          ) : (
            <div className="chain-list">
              {chain.map((item, index) => (
                <article
                  draggable
                  className={`chain-entry chain-${item.kind}`}
                  key={item.id}
                  onDragStart={() => setDraggedId(item.id)}
                  onDragOver={(event) => event.preventDefault()}
                  onDrop={() => {
                    const from = chain.findIndex((entry) => entry.id === draggedId);
                    if (from >= 0) moveChainItem(from, index);
                    setDraggedId('');
                  }}
                >
                  <span className="chain-offset">
                    +{index * ((catalog?.bits || 64) / 8)}
                  </span>
                  <span className="chain-grip" aria-hidden="true">
                    ⋮⋮
                  </span>
                  <div>
                    <strong>{item.kind.toUpperCase()}</strong>
                    <code>{chainValue(item.value)}</code>
                    <small>{item.label}</small>
                  </div>
                  <div className="chain-actions">
                    <button
                      aria-label="Move entry up"
                      disabled={index === 0}
                      onClick={() => moveChainItem(index, index - 1)}
                    >
                      ↑
                    </button>
                    <button
                      aria-label="Move entry down"
                      disabled={index === chain.length - 1}
                      onClick={() => moveChainItem(index, index + 1)}
                    >
                      ↓
                    </button>
                    <button
                      aria-label="Remove entry"
                      onClick={() =>
                        setChain((current) =>
                          current.filter((entry) => entry.id !== item.id),
                        )
                      }
                    >
                      ×
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
          <form className="literal-form" onSubmit={addLiteral}>
            <label>
              VALUE
              <input
                className="mono-input"
                value={literal}
                onChange={(event) => setLiteral(event.target.value)}
              />
            </label>
            <label>
              LABEL / SYMBOL
              <input
                value={literalLabel}
                onChange={(event) => setLiteralLabel(event.target.value)}
                placeholder="puts@got or argument"
              />
            </label>
            <button type="submit">+ ADD VALUE</button>
          </form>
          <ErrorBanner message={chainError} onClose={() => setChainError('')} />
          {pwntoolsDraft && (
            <div className="rop-code-draft">
              <div>
                <strong>PWntools FLAT DRAFT</strong>
                <CopyButton value={pwntoolsDraft} label="COPY" />
              </div>
              <pre>{pwntoolsDraft}</pre>
            </div>
          )}
        </section>

        <aside className="rop-state-panel" aria-label="ROP state simulation">
          <div className="panel-title">
            <span>03</span>
            <strong>STATE SIMULATION</strong>
          </div>
          {!chain.length ? (
            <Empty
              title="No state to simulate"
              description="체인 항목을 추가하면 서버가 스택 소비와 레지스터 변화를 정적으로 추론합니다."
            />
          ) : simulationLoading ? (
            <Loading label="체인 stack effect를 추론하는 중" />
          ) : simulation ? (
            <>
              <div className="simulation-status">
                <Badge
                  tone={
                    simulation.status === 'valid'
                      ? 'green'
                      : simulation.status === 'invalid'
                        ? 'danger'
                        : 'warn'
                  }
                >
                  {simulation.status === 'valid'
                    ? 'LAYOUT VALID'
                    : simulation.status.toUpperCase()}
                </Badge>
                <span>≈ INFERRED · {Math.round(simulation.confidence * 100)}%</span>
              </div>
              <p className="simulation-meaning">{simulation.meaning}</p>
              <div className="simulation-metrics">
                <div>
                  <span>RSP DELTA</span>
                  <strong>{simulation.rsp_delta ?? '—'} bytes</strong>
                </div>
                <div>
                  <span>FINAL RSP MOD 16</span>
                  <strong>{simulation.final_rsp_mod16 ?? '—'}</strong>
                </div>
                <div>
                  <span>CONSUMED</span>
                  <strong>
                    {simulation.consumed_entries ?? 0}/{simulation.entry_count ?? 0}
                  </strong>
                </div>
              </div>
              <h3>Register state</h3>
              <div className="rop-registers">
                {Object.entries(simulation.registers || {}).map(([name, value]) => (
                  <div key={name}>
                    <code>{name.toUpperCase()}</code>
                    <code>{value.value_hex || 'unknown'}</code>
                    <span>{value.verification}</span>
                  </div>
                ))}
                {!Object.keys(simulation.registers || {}).length && (
                  <p>No modelled register changes.</p>
                )}
              </div>
              {!!simulation.errors?.length && (
                <div className="simulation-messages danger">
                  <strong>BLOCKING ERRORS</strong>
                  {simulation.errors.map((item) => (
                    <p key={item}>× {item}</p>
                  ))}
                </div>
              )}
              {!!simulation.warnings?.length && (
                <div className="simulation-messages warning">
                  <strong>WARNINGS</strong>
                  {simulation.warnings.map((item) => (
                    <p key={item}>◇ {item}</p>
                  ))}
                </div>
              )}
              <div className="simulation-messages neutral">
                <strong>MODEL LIMITS</strong>
                {(simulation.limitations || []).map((item) => (
                  <p key={item}>? {item}</p>
                ))}
              </div>
            </>
          ) : null}
        </aside>
      </div>
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

const strategyStatusTone = {
  recommended: 'success',
  possible: 'warn',
  blocked: 'danger',
};

const strategyStatusLabel = {
  recommended: '추천 루트',
  possible: '가능',
  blocked: '차단됨',
};

function Strategy({ sha }) {
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [openPath, setOpenPath] = useState('');
  const [llmState, runLlm] = useSandboxAction(() => api.explainStrategy(sha));

  useEffect(() => {
    setReport(null);
    setError('');
    api
      .strategy(sha)
      .then((data) => {
        setReport(data);
        setOpenPath(data.recommended_path_id || data.paths?.[0]?.id || '');
      })
      .catch((reason) => setError(reason.message));
  }, [sha]);

  if (error) return <ErrorBanner message={error} />;
  if (!report) return <Loading label="공격 표면 근거를 종합하는 중" />;

  return (
    <div className="strategy-workspace">
      <section className="strategy-intro">
        <div className="section-heading">
          <h3>Exploit Strategy</h3>
          <span className="verification verification-inferred">
            ~ inferred · confidence {Math.round(report.confidence * 100)}%
          </span>
        </div>
        <p className="strategy-disclaimer">{report.disclaimer}</p>
      </section>

      <section className="strategy-llm">
        <div className="section-heading">
          <h3>LLM 설명 (선택)</h3>
          <span>정적 전략 요약을 자연어로 · 기본 비활성(외부 전송 없음)</span>
        </div>
        <button
          className="button secondary"
          disabled={llmState.status === 'running'}
          onClick={() => runLlm()}
        >
          LLM 설명 생성
        </button>
        {llmState.status === 'running' && <Loading label="LLM 설명 생성 중" />}
        {llmState.status === 'error' && <ErrorBanner message={llmState.error} />}
        {llmState.status === 'done' &&
          (llmState.result?.llm?.explanation ? (
            <div className="strategy-llm-result">
              <Badge tone="green">
                {String(llmState.result.llm.provider || 'llm')}
              </Badge>
              <p className="strategy-llm-text">
                {String(llmState.result.llm.explanation)}
              </p>
            </div>
          ) : (
            <p className="strategy-llm-note">
              {String(llmState.result?.llm?.note || 'LLM 비활성 — 정적 전략만')}
            </p>
          ))}
      </section>

      <section className="strategy-primitives">
        <div className="section-heading">
          <h3>공격 재료 (Primitives)</h3>
          <span>어떤 1차 재료가 있는지가 루트를 결정합니다</span>
        </div>
        <div className="primitive-grid">
          {report.primitives.map((primitive) => (
            <div
              key={primitive.key}
              className={`primitive-card ${primitive.present ? 'present' : 'absent'}`}
            >
              <div className="primitive-head">
                <span>{primitive.present ? '✓' : '×'}</span>
                <strong>{primitive.label}</strong>
              </div>
              <p>{primitive.detail}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="strategy-paths">
        <div className="section-heading">
          <h3>후보 루트</h3>
          <span>{report.paths.length}개 경로 · 근거순 정렬</span>
        </div>
        {report.paths.map((path) => {
          const open = openPath === path.id;
          return (
            <div
              key={path.id}
              className={`path-card ${path.id === report.recommended_path_id ? 'recommended' : ''}`}
            >
              <button
                className="path-card-head"
                onClick={() => setOpenPath(open ? '' : path.id)}
              >
                <div className="path-title">
                  <Badge tone={strategyStatusTone[path.status] || 'cyan'}>
                    {strategyStatusLabel[path.status] || path.status}
                  </Badge>
                  <strong>{path.korean_title}</strong>
                </div>
                <div className="path-meta">
                  <span>{Math.round(path.confidence * 100)}%</span>
                  <span>{open ? '▲' : '▼'}</span>
                </div>
              </button>
              {open && (
                <div className="path-body">
                  <p className="path-summary">{path.summary}</p>
                  <code className="path-en-title">{path.title}</code>

                  {path.preconditions.length > 0 && (
                    <div className="path-section">
                      <strong>선행 조건</strong>
                      <ul className="precondition-list">
                        {path.preconditions.map((pre) => (
                          <li key={pre.label} className={pre.met ? 'met' : 'unmet'}>
                            <span>{pre.met ? '✓' : '×'}</span> {pre.label}
                            <em> — {pre.detail}</em>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="path-section">
                    <strong>진행 순서</strong>
                    <ol className="steps-list">
                      {path.steps.map((step, index) => (
                        <li key={index}>{step}</li>
                      ))}
                    </ol>
                  </div>

                  {path.blockers.length > 0 && (
                    <div className="path-section path-blockers">
                      <strong>차단 요인</strong>
                      {path.blockers.map((blocker) => (
                        <p key={blocker}>⚠ {blocker}</p>
                      ))}
                    </div>
                  )}

                  <div className="path-section">
                    <div className="pseudo-c-toolbar">
                      <strong>pwntools 스켈레톤 (초안)</strong>
                      <CopyButton value={path.pwntools} />
                    </div>
                    <pre className="pseudo-c-code">
                      <code>{path.pwntools}</code>
                    </pre>
                  </div>

                  {path.evidence.length > 0 && (
                    <div className="path-section evidence-compact">
                      <strong>근거</strong>
                      {path.evidence.map((item) => (
                        <p key={item}>✓ {item}</p>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </section>

      <section className="strategy-limitations">
        <strong>한계</strong>
        {report.limitations.map((item) => (
          <p key={item}>· {item}</p>
        ))}
      </section>
    </div>
  );
}

function useSandboxAction(fn) {
  const [state, setState] = useState({ status: 'idle', result: null, error: '' });
  const run = async (...args) => {
    setState({ status: 'running', result: null, error: '' });
    try {
      const result = await fn(...args);
      setState({ status: 'done', result, error: '' });
    } catch (reason) {
      setState({ status: 'error', result: null, error: reason.message });
    }
  };
  return [state, run];
}

function SuccessBadge({ ok }) {
  return <Badge tone={ok ? 'green' : 'danger'}>{ok ? '성공 verified' : '실패'}</Badge>;
}

function ShellSession({ proof }) {
  if (!proof) return null;
  return (
    <div className="shell-session">
      <div className="shell-session-head">
        <Badge tone={proof.shell_spawned ? 'green' : 'danger'}>
          {proof.shell_spawned ? '🐚 셸 획득 증명' : '셸 미획득'}
        </Badge>
        {proof.command && <code className="shell-cmd">{proof.command}</code>}
        {proof.marker && <span className="shell-marker">marker: {proof.marker}</span>}
      </div>
      {proof.output && (
        <pre className="shell-term">
          <code>{proof.output}</code>
        </pre>
      )}
    </div>
  );
}

function ExploitScriptCard({ script }) {
  // 샌드박스 셸 증명 후 생성된 완성 pwntools 스크립트(로컬↔원격 토글 포함).
  if (!script) return null;
  const chainLabel = script.chain
    ? `${script.technique} · ${script.chain}`
    : script.technique;
  return (
    <div className="exploit-script">
      <div className="pseudo-c-toolbar">
        <div className="exploit-script-head">
          <strong>완성 익스 스크립트 — {script.filename}</strong>
          <Badge tone={script.remote_ready ? 'green' : 'danger'}>
            {script.remote_ready ? '원격 가능(remote-ready)' : '로컬 전용'}
          </Badge>
          <span className="exploit-script-tech">{chainLabel}</span>
        </div>
        <CopyButton value={script.script} />
      </div>
      {script.notes?.length > 0 && (
        <ul className="exploit-script-notes">
          {script.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
      <pre className="pseudo-c-code">
        <code>{script.script}</code>
      </pre>
    </div>
  );
}

function PieBaseNote({ ver }) {
  // PIE 자동 익스(ret2win-pie / ret2system-pie)만: 로컬 관측 base·rebase 타깃·정직성.
  if (!ver || ver.aslr !== 'disabled-for-local-proof') return null;
  const runtime = ver.target_runtime_hex || ver.system_runtime_hex;
  const label = ver.target_name ? `${ver.target_name}()` : 'system';
  return (
    <div className="pie-base-note">
      <div className="pie-base-head">
        <Badge tone="green">PIE base 로컬 관측</Badge>
        <span className="pie-base-caption">ASLR-off 로컬 관측 · 원격 우회 아님</span>
      </div>
      <div className="pie-base-grid">
        {ver.base_hex && (
          <div className="runner-kv">
            <span>로드 base</span>
            <strong>
              <code>{ver.base_hex}</code>
            </strong>
          </div>
        )}
        {runtime && (
          <div className="runner-kv">
            <span>{label} rebase</span>
            <strong>
              <code>{runtime}</code>
            </strong>
          </div>
        )}
      </div>
    </div>
  );
}

function FmtWriteNote({ ver }) {
  // 포맷스트링 %n GOT 덮어쓰기(non-PIE / PIE) 전용: 덮은 GOT·리다이렉트 타깃·유출 base.
  if (
    !ver ||
    (ver.technique !== 'fmt-got-overwrite' && ver.technique !== 'fmt-got-overwrite-pie')
  ) {
    return null;
  }
  const isPie = ver.technique === 'fmt-got-overwrite-pie';
  const gotRuntime = ver.got_runtime_hex || ver.got_hex;
  const targetRuntime = ver.target_runtime_hex || ver.target_hex;
  return (
    <div className="fmt-write-note">
      <div className="fmt-write-head">
        <Badge tone="green">포맷스트링 %n GOT 덮어쓰기</Badge>
        <span className="fmt-write-caption">
          {isPie
            ? 'in-band leak 로 base 복원 · ASLR 켜져도 성립'
            : 'GOT 슬롯 → win 리다이렉트'}
        </span>
      </div>
      <div className="fmt-write-grid">
        {ver.got_symbol && (
          <div className="runner-kv">
            <span>덮은 GOT</span>
            <strong>
              <code>
                {ver.got_symbol}
                {gotRuntime ? ` @ ${gotRuntime}` : ''}
              </code>
            </strong>
          </div>
        )}
        {ver.target_name && targetRuntime && (
          <div className="runner-kv">
            <span>{ver.target_name}() 리다이렉트</span>
            <strong>
              <code>{targetRuntime}</code>
            </strong>
          </div>
        )}
        {ver.fmt_position != null && (
          <div className="runner-kv">
            <span>fmt 인자 위치</span>
            <strong>%{ver.fmt_position}$</strong>
          </div>
        )}
        {isPie && ver.base_hex && (
          <div className="runner-kv">
            <span>유출 base</span>
            <strong>
              <code>{ver.base_hex}</code>
            </strong>
          </div>
        )}
        {isPie && ver.leak_position != null && (
          <div className="runner-kv">
            <span>leak 위치</span>
            <strong>%{ver.leak_position}$p</strong>
          </div>
        )}
      </div>
    </div>
  );
}

function RunnerResult({ state }) {
  if (state.status === 'running') return <Loading label="샌드박스에서 실행 중" />;
  if (state.status === 'error') {
    return (
      <div className="runner-error">
        <strong>⚠ 실행 불가</strong>
        <p>{state.error}</p>
        <p className="runner-hint">
          동적 검증은 기본 비활성입니다. 서버가 격리 컨테이너에서{' '}
          <code>PLAB_SANDBOX_EXECUTION_ENABLED=1</code> 로 켠 경우에만 동작합니다.
        </p>
      </div>
    );
  }
  return null;
}

// ptrace 디버그 세션(배치 /debug): 브레이크포인트→continue→레지스터/스택/출력.
const _DBG_KEY_REGS = ['rip', 'rsp', 'rbp', 'rdi', 'rsi', 'rdx', 'rcx', 'rax'];

function DebuggerCard({ sha }) {
  const [addr, setAddr] = useState('');
  const [state, run] = useSandboxAction((commands) => api.debugScript(sha, commands));

  const parsed = addr.trim() ? Number.parseInt(addr.trim(), 16) : NaN;
  const valid = Number.isFinite(parsed) && parsed > 0;

  const onRun = () => {
    const commands = [];
    if (valid) commands.push({ op: 'break', addr: parsed });
    commands.push({ op: 'continue' });
    commands.push({ op: 'registers' });
    commands.push({ op: 'stack', count: 6 });
    commands.push({ op: 'output' });
    run(commands);
  };

  const steps = state.result?.steps || [];
  const cont = steps.find((s) => s.op === 'continue');
  const regs = steps.find((s) => s.op === 'registers')?.registers || {};
  const stackWords = steps.find((s) => s.op === 'stack')?.words || [];
  const output = steps.find((s) => s.op === 'output')?.output || '';

  return (
    <section className="runner-card">
      <div className="section-heading">
        <h3>Debugger (ptrace)</h3>
        <span>브레이크포인트 · 레지스터 · 스택 (외부 gdb 불필요)</span>
      </div>
      <div className="runner-actions">
        <label className="runner-field">
          breakpoint (hex, 선택)
          <input
            placeholder="0x401176"
            value={addr}
            onChange={(e) => setAddr(e.target.value)}
          />
        </label>
        <button
          className="button secondary"
          disabled={state.status === 'running'}
          onClick={onRun}
        >
          {valid ? '브레이크포인트까지 실행' : '종료까지 실행'}
        </button>
      </div>
      <RunnerResult state={state} />
      {state.status === 'done' && (
        <div>
          <p className="runner-kv">
            <span>stop</span>
            <strong>
              {cont ? (
                <>
                  {String(cont.reason)}
                  {cont.rip ? ` @ ${String(cont.rip)}` : ''}
                  {cont.exit_code != null ? ` (exit ${cont.exit_code})` : ''}
                </>
              ) : (
                'n/a'
              )}
            </strong>
          </p>
          {Object.keys(regs).length > 0 && (
            <div className="dbg-regs">
              {_DBG_KEY_REGS
                .filter((r) => regs[r] !== undefined)
                .map((r) => (
                  <span key={r} className="dbg-reg">
                    <b>{r}</b> {String(regs[r])}
                  </span>
                ))}
            </div>
          )}
          {stackWords.length > 0 && (
            <pre className="dbg-stack">
              <code>{stackWords.map(([a, v]) => `${a}: ${v}`).join('\n')}</code>
            </pre>
          )}
          {output && (
            <pre className="shell-term">
              <code>{output}</code>
            </pre>
          )}
        </div>
      )}
    </section>
  );
}

function ExploitRunner({ sha }) {
  const [patternLength, setPatternLength] = useState('');
  const [offset, setOffset] = useState('');
  const [target, setTarget] = useState('');
  const [chain, setChain] = useState('');
  const [marker, setMarker] = useState('');

  const [autoState, runAuto] = useSandboxAction((pl) => api.autoExploit(sha, pl));
  const [confirmState, runConfirm] = useSandboxAction((pl) =>
    api.confirmOffset(sha, pl),
  );
  const [leakState, runLeak] = useSandboxAction((off) => api.leak(sha, off));
  const [r2lState, runR2l] = useSandboxAction((off) => api.autoRet2libc(sha, off));
  const [verifyState, runVerify] = useSandboxAction((opts) =>
    api.verifyExploit(sha, opts),
  );

  const pl = patternLength ? Number(patternLength) : undefined;
  const off = offset ? Number(offset) : undefined;

  const injectedPaths =
    autoState.result?.strategy?.paths?.filter((p) => p.offset_verified) || [];
  const conf = autoState.result?.confirmation;
  const ver = autoState.result?.verification;

  return (
    <div className="strategy-workspace runner-workspace">
      <section className="strategy-intro">
        <div className="section-heading">
          <h3>Exploit Runner (동적 검증)</h3>
          <span className="verification verification-inferred">
            격리 샌드박스 · 기본 비활성
          </span>
        </div>
        <p className="strategy-disclaimer">
          정적 추정을 넘어, 격리된 network-disabled 일회용 샌드박스에서 바이너리를
          실제로 실행해 오프셋·익스를 <strong>verified</strong> 로 확인합니다. 신뢰할 수
          없는 바이너리를 실행하므로 서버에서 명시적으로 켠 배포에서만 동작합니다
          (아니면 503).
        </p>
      </section>

      {/* Auto-exploit — 헤드라인 */}
      <section className="runner-card runner-headline">
        <div className="section-heading">
          <h3>Auto-Exploit</h3>
          <span>
            오프셋 확정 → 스켈레톤 주입 → ret2win/ret2system 자동 검증 (PIE 는 base 로컬
            관측 후 rebase) → 셸 증명 시 완성 pwntools 스크립트 생성
          </span>
        </div>
        <div className="runner-actions">
          <label className="runner-field">
            pattern length
            <input
              type="number"
              placeholder="512"
              value={patternLength}
              onChange={(e) => setPatternLength(e.target.value)}
            />
          </label>
          <button
            className="button primary"
            disabled={autoState.status === 'running'}
            onClick={() => runAuto(pl)}
          >
            Auto-Exploit 실행
          </button>
        </div>
        <RunnerResult state={autoState} />
        {autoState.status === 'done' && (
          <div className="runner-result">
            <div className="runner-kv">
              <span>오프셋</span>
              <strong>
                {conf?.confirmed ? (
                  <>
                    {conf.offset} <SuccessBadge ok />
                  </>
                ) : (
                  <>미확정 ({conf?.observation?.note || 'n/a'})</>
                )}
              </strong>
            </div>
            <div className="runner-kv">
              <span>검증</span>
              <strong>
                {ver?.attempted ? (
                  <>
                    {ver.technique} <SuccessBadge ok={ver.succeeded} /> · {ver.reason}
                    {ver.shell_proven ? ' · 🐚 shell' : ''}
                  </>
                ) : (
                  <>미시도 ({ver?.reason})</>
                )}
              </strong>
            </div>
            {ver?.attempts?.length > 1 && (
              <div className="runner-kv">
                <span>시도</span>
                <strong>
                  {ver.attempts
                    .map((a) => `${a.technique}:${a.succeeded ? '✓' : '×'}`)
                    .join(' · ')}
                </strong>
              </div>
            )}
            <PieBaseNote ver={ver} />
            <FmtWriteNote ver={ver} />
            {ver?.shell_proof && <ShellSession proof={ver.shell_proof} />}
            <ExploitScriptCard script={autoState.result?.exploit_script} />
            {injectedPaths.map((p) => (
              <div key={p.id} className="path-section">
                <div className="pseudo-c-toolbar">
                  <strong>{p.id} — 확정 오프셋 주입된 스켈레톤</strong>
                  <CopyButton value={p.pwntools} />
                </div>
                <pre className="pseudo-c-code">
                  <code>{p.pwntools}</code>
                </pre>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* 개별 프리미티브 */}
      <section className="runner-card">
        <div className="section-heading">
          <h3>개별 실행</h3>
          <span>오프셋 확정 · libc leak · ret2libc</span>
        </div>
        <div className="runner-grid">
          <div className="runner-mini">
            <strong>오프셋 확정</strong>
            <div className="runner-actions">
              <button
                className="button secondary"
                disabled={confirmState.status === 'running'}
                onClick={() => runConfirm(pl)}
              >
                confirm-offset
              </button>
            </div>
            <RunnerResult state={confirmState} />
            {confirmState.status === 'done' && (
              <p className="runner-kv">
                <span>offset</span>
                <strong>
                  {confirmState.result.confirmed ? (
                    <>
                      {confirmState.result.offset} <SuccessBadge ok /> ·{' '}
                      {confirmState.result.method}
                    </>
                  ) : (
                    '미확정'
                  )}
                </strong>
              </p>
            )}
          </div>

          <div className="runner-mini">
            <strong>libc leak</strong>
            <div className="runner-actions">
              <label className="runner-field">
                offset
                <input
                  type="number"
                  value={offset}
                  onChange={(e) => setOffset(e.target.value)}
                />
              </label>
              <button
                className="button secondary"
                disabled={leakState.status === 'running' || off === undefined}
                onClick={() => runLeak(off)}
              >
                leak
              </button>
            </div>
            <RunnerResult state={leakState} />
            {leakState.status === 'done' && (
              <p className="runner-kv">
                <span>leaked</span>
                <strong>
                  {leakState.result.succeeded ? (
                    <>
                      {String(leakState.result.leaked_hex)} <SuccessBadge ok />
                    </>
                  ) : (
                    `실패 (${leakState.result.reason})`
                  )}
                </strong>
              </p>
            )}
          </div>

          <div className="runner-mini">
            <strong>auto-ret2libc</strong>
            <div className="runner-actions">
              <button
                className="button secondary"
                disabled={r2lState.status === 'running' || off === undefined}
                onClick={() => runR2l(off)}
              >
                ret2libc (offset 위 값)
              </button>
            </div>
            <RunnerResult state={r2lState} />
            {r2lState.status === 'done' && (
              <div>
                <p className="runner-kv">
                  <span>결과</span>
                  <strong>
                    <SuccessBadge ok={r2lState.result.succeeded} /> ·{' '}
                    {String(r2lState.result.reason)}
                  </strong>
                </p>
                {r2lState.result.leaked_puts_hex && (
                  <p className="runner-kv">
                    <span>leaked puts</span>
                    <strong>{String(r2lState.result.leaked_puts_hex)}</strong>
                  </p>
                )}
                {r2lState.result.libc_base_hex && (
                  <p className="runner-kv">
                    <span>libc base</span>
                    <strong>
                      {String(r2lState.result.libc_base_hex)}
                      {r2lState.result.libc_base_page_aligned ? ' (page-aligned)' : ''}
                    </strong>
                  </p>
                )}
                <ShellSession proof={r2lState.result.shell_proof} />
              </div>
            )}
          </div>
        </div>
      </section>

      {/* ptrace 디버거 */}
      <DebuggerCard sha={sha} />

      {/* 수동 verify-exploit */}
      <section className="runner-card">
        <div className="section-heading">
          <h3>Verify Exploit (수동)</h3>
          <span>A*offset + p(target) + chain 을 실제 주입</span>
        </div>
        <div className="runner-actions runner-verify">
          <label className="runner-field">
            offset
            <input
              type="number"
              value={offset}
              onChange={(e) => setOffset(e.target.value)}
            />
          </label>
          <label className="runner-field">
            target (0x…)
            <input
              placeholder="0x401196"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </label>
          <label className="runner-field">
            chain (쉼표)
            <input
              placeholder="0x…,0x…"
              value={chain}
              onChange={(e) => setChain(e.target.value)}
            />
          </label>
          <label className="runner-field">
            marker
            <input value={marker} onChange={(e) => setMarker(e.target.value)} />
          </label>
          <button
            className="button secondary"
            disabled={verifyState.status === 'running' || off === undefined || !target}
            onClick={() =>
              runVerify({
                offset: off,
                target,
                chain: chain
                  ? chain
                      .split(',')
                      .map((s) => s.trim())
                      .filter(Boolean)
                  : undefined,
                marker: marker ? [marker] : undefined,
              })
            }
          >
            verify-exploit
          </button>
        </div>
        <RunnerResult state={verifyState} />
        {verifyState.status === 'done' && (
          <p className="runner-kv">
            <span>결과</span>
            <strong>
              <SuccessBadge ok={verifyState.result.succeeded} /> ·{' '}
              {String(verifyState.result.reason)}
              {verifyState.result.matched_markers?.length
                ? ` · marker ${verifyState.result.matched_markers.join(',')}`
                : ''}
            </strong>
          </p>
        )}
      </section>
    </div>
  );
}

function debuggerWsUrl(sha) {
  const base = import.meta.env.VITE_API_BASE || '/api/v1';
  const path = `/binaries/${sha}/debug/ws`;
  if (base.startsWith('http')) {
    return base.replace(/^http/, 'ws') + path;
  }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}${base}${path}`;
}

function LiveDebugger({ sha }) {
  const [status, setStatus] = useState('disconnected');
  const [log, setLog] = useState([]);
  const [bpAddr, setBpAddr] = useState('');
  const socketRef = useRef(null);

  const append = (dir, payload) =>
    setLog((prev) => [
      ...prev.slice(-199),
      { dir, text: typeof payload === 'string' ? payload : JSON.stringify(payload) },
    ]);

  const closeSocket = () => {
    const sock = socketRef.current;
    if (sock) {
      try {
        if (sock.readyState === WebSocket.OPEN)
          sock.send(JSON.stringify({ op: 'close' }));
        sock.close();
      } catch {
        // 소켓이 이미 닫혔거나 사용 불가한 경우 무시.
      }
      socketRef.current = null;
    }
  };

  // 컴포넌트 언마운트 시 소켓 정리.
  useEffect(() => closeSocket, []);

  const connect = () => {
    closeSocket();
    setLog([]);
    setStatus('connecting');
    let sock;
    try {
      sock = new WebSocket(debuggerWsUrl(sha));
    } catch (reason) {
      setStatus('error');
      append('recv', { event: 'error', error: String(reason) });
      return;
    }
    socketRef.current = sock;
    sock.onmessage = (event) => {
      let frame = event.data;
      try {
        frame = JSON.parse(event.data);
      } catch {
        // JSON 이 아니면 원문 그대로 로그.
      }
      if (frame && frame.event === 'ready') setStatus('ready');
      else if (frame && frame.event === 'error') setStatus('error');
      append('recv', frame);
    };
    sock.onerror = () => {
      setStatus('error');
      append('recv', { event: 'error', error: 'socket error' });
    };
    sock.onclose = () => {
      setStatus('disconnected');
      if (socketRef.current === sock) socketRef.current = null;
    };
  };

  const send = (cmd) => {
    const sock = socketRef.current;
    if (!sock || sock.readyState !== WebSocket.OPEN) {
      append('recv', { event: 'error', error: 'not connected' });
      return;
    }
    append('sent', cmd);
    sock.send(JSON.stringify(cmd));
  };

  const setBreakpoint = () => {
    const addr = Number.parseInt(bpAddr.trim(), 16);
    if (!Number.isFinite(addr) || addr <= 0) {
      append('recv', { event: 'error', error: 'invalid breakpoint (hex)' });
      return;
    }
    send({ op: 'break', addr });
  };

  const connected = status === 'ready' || status === 'connecting';
  const canCommand = status === 'ready';
  const statusTone = status === 'error' ? 'danger' : 'green';

  return (
    <div className="strategy-workspace ws-debugger">
      <section className="strategy-intro">
        <div className="section-heading">
          <h3>Live Debugger (WebSocket)</h3>
          <Badge tone={statusTone}>{status}</Badge>
        </div>
        <p className="strategy-disclaimer">
          ptrace 라이브 디버그 세션을 WebSocket 으로 구동합니다. 신뢰할 수 없는
          바이너리를 실행하므로 서버에서 샌드박스 실행이 켜진 배포에서만
          동작합니다(아니면 연결 직후 오류 프레임).
        </p>
        <div className="runner-actions">
          <button className="button primary" disabled={connected} onClick={connect}>
            연결
          </button>
          <button
            className="button secondary"
            disabled={status === 'disconnected'}
            onClick={closeSocket}
          >
            연결 해제
          </button>
        </div>
      </section>

      <section className="runner-card">
        <div className="section-heading">
          <h3>제어</h3>
          <span>브레이크포인트 · 실행 · 레지스터 · 스택</span>
        </div>
        <div className="runner-actions">
          <label className="runner-field">
            breakpoint (hex)
            <input
              placeholder="0x401176"
              value={bpAddr}
              onChange={(e) => setBpAddr(e.target.value)}
            />
          </label>
          <button
            className="button secondary"
            disabled={!canCommand}
            onClick={setBreakpoint}
          >
            Set BP
          </button>
          <button
            className="button secondary"
            disabled={!canCommand}
            onClick={() => send({ op: 'continue' })}
          >
            Continue
          </button>
          <button
            className="button secondary"
            disabled={!canCommand}
            onClick={() => send({ op: 'step' })}
          >
            Step
          </button>
          <button
            className="button secondary"
            disabled={!canCommand}
            onClick={() => send({ op: 'registers' })}
          >
            Registers
          </button>
          <button
            className="button secondary"
            disabled={!canCommand}
            onClick={() => send({ op: 'stack', count: 6 })}
          >
            Stack
          </button>
        </div>
      </section>

      <section className="runner-card">
        <div className="section-heading">
          <h3>세션 로그</h3>
          <span>{log.length} 프레임</span>
        </div>
        {log.length === 0 ? (
          <Empty label="아직 프레임이 없습니다. 연결 후 명령을 보내세요." />
        ) : (
          <pre className="ws-debugger-log">
            <code>
              {log
                .map((entry) => `${entry.dir === 'sent' ? '»' : '«'} ${entry.text}`)
                .join('\n')}
            </code>
          </pre>
        )}
      </section>
    </div>
  );
}

function _hexOrUndef(value) {
  const t = String(value || '').trim();
  if (!t) return undefined;
  const n = Number.parseInt(t, 16);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

function _intOrUndef(value) {
  const t = String(value || '').trim();
  if (!t) return undefined;
  const n = Number.parseInt(t, 10);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

// 텍스트 stdin → hex(서버는 stdin_hex 로 받는다). 빈 값은 undefined.
function _textToHex(value) {
  const t = String(value || '');
  if (!t) return undefined;
  let out = '';
  for (let i = 0; i < t.length; i += 1) {
    out += t.charCodeAt(i).toString(16).padStart(2, '0');
  }
  return out;
}

function DynamicAnalysis({ sha }) {
  // 패킹/언패킹/런타임 strings/OEP/트레이스/메모리 덤프/QEMU 크로스아치 실행.
  const [packState, runPack] = useSandboxAction(() => api.packing(sha));
  const [unpackState, runUnpack] = useSandboxAction(() => api.unpack(sha));
  const [rsState, runRs] = useSandboxAction((bp, steps) =>
    api.runtimeStrings(sha, { breakpoint: bp, steps }),
  );
  const [oepState, runOep] = useSandboxAction((start, ms) => api.oep(sha, start, ms));
  const [traceState, runTrace] = useSandboxAction((start, ms) =>
    api.trace(sha, start, ms),
  );
  const [dumpState, runDump] = useSandboxAction((bp, steps, select) =>
    api.memdump(sha, { breakpoint: bp, steps, select }),
  );
  const [qemuState, runQemu] = useSandboxAction((stdin, strace) =>
    api.qemuRun(sha, { stdin, strace }),
  );
  const [heapState, runHeap] = useSandboxAction((bp, steps) =>
    api.heap(sha, { breakpoint: bp, steps }),
  );
  const [peRunState, runPeRun] = useSandboxAction((stdinHex) =>
    api.peRun(sha, { stdinHex }),
  );
  const [peTriageState, runPeTriage] = useSandboxAction(() => api.peTriage(sha));

  const [rsBp, setRsBp] = useState('');
  const [rsSteps, setRsSteps] = useState('');
  const [oepStart, setOepStart] = useState('');
  const [traceStart, setTraceStart] = useState('');
  const [dumpBp, setDumpBp] = useState('');
  const [dumpSteps, setDumpSteps] = useState('');
  const [dumpSelect, setDumpSelect] = useState('writable');
  const [qemuStdin, setQemuStdin] = useState('');
  const [qemuStrace, setQemuStrace] = useState(false);
  const [heapBp, setHeapBp] = useState('');
  const [heapSteps, setHeapSteps] = useState('');
  const [peStdin, setPeStdin] = useState('');

  return (
    <div className="strategy-workspace runner-workspace">
      <section className="strategy-intro">
        <div className="section-heading">
          <h3>Dynamic Analysis</h3>
          <span className="verification verification-inferred">
            패킹 · 언패킹 · 런타임 · 트레이스 · 크로스아키텍처
          </span>
        </div>
        <p className="strategy-disclaimer">
          패킹 정적 탐지 외에는 격리 샌드박스에서 <strong>실제로 실행</strong>합니다.
          실행 기능은 서버에서 명시적으로 켠 배포에서만 동작합니다(아니면 503).
        </p>
      </section>

      {/* 패킹 정적 탐지 (실행 없음) */}
      <section className="runner-card">
        <div className="section-heading">
          <h3>패킹 / 난독화 탐지</h3>
          <span>UPX 서명 · 엔트로피 · 오버레이 (정적, 실행 없음)</span>
        </div>
        <button
          className="button secondary"
          disabled={packState.status === 'running'}
          onClick={() => runPack()}
        >
          탐지 실행
        </button>
        <RunnerResult state={packState} />
        {packState.status === 'done' && (
          <div>
            <p className="runner-kv">
              <span>결과</span>
              <strong>
                <Badge tone={packState.result.packed ? 'danger' : 'green'}>
                  {packState.result.packed ? '패킹 의심' : '비패킹'}
                </Badge>{' '}
                {packState.result.packer ? `· ${packState.result.packer}` : ''} · 확신도{' '}
                {String(packState.result.confidence)}
              </strong>
            </p>
            {(packState.result.signals || []).map((s) => (
              <p key={s.name} className="runner-kv">
                <span>{s.name}</span>
                <strong>{s.detail}</strong>
              </p>
            ))}
          </div>
        )}
      </section>

      {/* UPX 언패킹 */}
      <section className="runner-card">
        <div className="section-heading">
          <h3>UPX 언패킹</h3>
          <span>upx -d 로 복원 (실행 없음)</span>
        </div>
        <button
          className="button secondary"
          disabled={unpackState.status === 'running'}
          onClick={() => runUnpack()}
        >
          언패킹 실행
        </button>
        <RunnerResult state={unpackState} />
        {unpackState.status === 'done' && (
          <p className="runner-kv">
            <span>결과</span>
            <strong>
              {unpackState.result.attempted ? (
                unpackState.result.unpacked ? (
                  <>
                    <SuccessBadge ok /> {String(unpackState.result.original_size)} →{' '}
                    {String(unpackState.result.unpacked_size)} bytes
                  </>
                ) : (
                  `실패 (${String(unpackState.result.reason)})`
                )
              ) : (
                `미시도 (${String(unpackState.result.reason)})`
              )}
            </strong>
          </p>
        )}
      </section>

      {/* 런타임 strings */}
      <section className="runner-card">
        <div className="section-heading">
          <h3>런타임 strings</h3>
          <span>실행 중 메모리의 (복호화된) 문자열</span>
        </div>
        <div className="runner-actions">
          <label className="runner-field">
            breakpoint (hex)
            <input value={rsBp} onChange={(e) => setRsBp(e.target.value)} />
          </label>
          <label className="runner-field">
            steps
            <input
              type="number"
              value={rsSteps}
              onChange={(e) => setRsSteps(e.target.value)}
            />
          </label>
          <button
            className="button secondary"
            disabled={rsState.status === 'running'}
            onClick={() => runRs(_hexOrUndef(rsBp), _intOrUndef(rsSteps))}
          >
            발굴
          </button>
        </div>
        <RunnerResult state={rsState} />
        {rsState.status === 'done' && rsState.result.attempted && (
          <div>
            <p className="runner-kv">
              <span>런타임 전용</span>
              <strong>{String(rsState.result.runtime_only_count)} 개</strong>
            </p>
            <pre className="dbg-stack">
              <code>{(rsState.result.runtime_only || []).slice(0, 40).join('\n')}</code>
            </pre>
          </div>
        )}
      </section>

      {/* OEP 후보 */}
      <section className="runner-card">
        <div className="section-heading">
          <h3>OEP 후보</h3>
          <span>쓰기 가능·익명 실행으로의 tail jump</span>
        </div>
        <div className="runner-actions">
          <label className="runner-field">
            start (hex, 선택)
            <input value={oepStart} onChange={(e) => setOepStart(e.target.value)} />
          </label>
          <button
            className="button secondary"
            disabled={oepState.status === 'running'}
            onClick={() => runOep(_hexOrUndef(oepStart), undefined)}
          >
            탐지
          </button>
        </div>
        <RunnerResult state={oepState} />
        {oepState.status === 'done' && (
          <p className="runner-kv">
            <span>OEP</span>
            <strong>
              {oepState.result.oep_candidate ? (
                <>
                  <code>{String(oepState.result.oep_candidate)}</code> ·{' '}
                  {oepState.result.region?.perms} ({String(oepState.result.steps)}{' '}
                  steps)
                </>
              ) : (
                `없음 (${String(oepState.result.reason)})`
              )}
            </strong>
          </p>
        )}
      </section>

      {/* 실행 트레이스 */}
      <section className="runner-card">
        <div className="section-heading">
          <h3>실행 트레이스</h3>
          <span>바이너리 자체 코드 범위 명령 주소 (rr-lite)</span>
        </div>
        <div className="runner-actions">
          <label className="runner-field">
            start (hex, 선택)
            <input value={traceStart} onChange={(e) => setTraceStart(e.target.value)} />
          </label>
          <button
            className="button secondary"
            disabled={traceState.status === 'running'}
            onClick={() => runTrace(_hexOrUndef(traceStart), undefined)}
          >
            트레이스
          </button>
        </div>
        <RunnerResult state={traceState} />
        {traceState.status === 'done' && traceState.result.attempted && (
          <div>
            <p className="runner-kv">
              <span>스텝 / 고유주소</span>
              <strong>
                {String(traceState.result.steps)} /{' '}
                {String(traceState.result.unique_addresses)}
              </strong>
            </p>
            <pre className="dbg-stack">
              <code>{(traceState.result.trace || []).slice(0, 40).join(' ')}</code>
            </pre>
          </div>
        )}
      </section>

      {/* 메모리 덤프 */}
      <section className="runner-card">
        <div className="section-heading">
          <h3>메모리 덤프</h3>
          <span>매핑 영역 바이트·엔트로피 스냅샷 (재구성)</span>
        </div>
        <div className="runner-actions">
          <label className="runner-field">
            breakpoint (hex)
            <input value={dumpBp} onChange={(e) => setDumpBp(e.target.value)} />
          </label>
          <label className="runner-field">
            steps
            <input
              type="number"
              value={dumpSteps}
              onChange={(e) => setDumpSteps(e.target.value)}
            />
          </label>
          <label className="runner-field">
            영역
            <select value={dumpSelect} onChange={(e) => setDumpSelect(e.target.value)}>
              <option value="writable">writable</option>
              <option value="code">code</option>
              <option value="all">all</option>
            </select>
          </label>
          <button
            className="button secondary"
            disabled={dumpState.status === 'running'}
            onClick={() =>
              runDump(_hexOrUndef(dumpBp), _intOrUndef(dumpSteps), dumpSelect)
            }
          >
            덤프
          </button>
        </div>
        <RunnerResult state={dumpState} />
        {dumpState.status === 'done' && dumpState.result.attempted && (
          <div>
            <p className="runner-kv">
              <span>영역 / 캡처</span>
              <strong>
                {String(dumpState.result.region_count)} 영역 ·{' '}
                {String(dumpState.result.captured_bytes)} bytes
              </strong>
            </p>
            {(dumpState.result.regions || []).slice(0, 12).map((r) => (
              <p key={r.start} className="runner-kv">
                <span>
                  <code>{r.start}</code> {r.perms}
                </span>
                <strong>
                  {String(r.captured)} B · H={String(r.entropy)}
                </strong>
              </p>
            ))}
          </div>
        )}
      </section>

      {/* QEMU 크로스아키텍처 실행 */}
      <section className="runner-card">
        <div className="section-heading">
          <h3>QEMU 실행 (크로스아키텍처)</h3>
          <span>ARM/MIPS 등 다른 아키텍처 바이너리 실행</span>
        </div>
        <div className="runner-actions">
          <label className="runner-field">
            stdin
            <input value={qemuStdin} onChange={(e) => setQemuStdin(e.target.value)} />
          </label>
          <label className="runner-check">
            <input
              type="checkbox"
              checked={qemuStrace}
              onChange={(e) => setQemuStrace(e.target.checked)}
            />
            strace
          </label>
          <button
            className="button secondary"
            disabled={qemuState.status === 'running'}
            onClick={() => runQemu(qemuStdin, qemuStrace)}
          >
            실행
          </button>
        </div>
        <RunnerResult state={qemuState} />
        {qemuState.status === 'done' && (
          <div>
            <p className="runner-kv">
              <span>결과</span>
              <strong>
                {qemuState.result.attempted ? (
                  <>
                    {String(qemuState.result.arch)} · exit{' '}
                    {String(qemuState.result.exit_code)}
                  </>
                ) : (
                  `미시도 (${String(qemuState.result.reason)})`
                )}
              </strong>
            </p>
            {qemuState.result.stdout && (
              <pre className="shell-term">
                <code>{qemuState.result.stdout}</code>
              </pre>
            )}
            {qemuState.result.syscalls && (
              <pre className="dbg-stack">
                <code>{qemuState.result.syscalls.slice(0, 40).join('\n')}</code>
              </pre>
            )}
          </div>
        )}
      </section>

      {/* 힙 인스펙터 (glibc 청크·tcache·fastbin·unsorted) */}
      <section className="runner-card">
        <div className="section-heading">
          <h3>힙 인스펙터 (glibc)</h3>
          <span>청크 · tcache · fastbin · unsorted · main_arena 복구</span>
        </div>
        <div className="runner-actions">
          <label className="runner-field">
            breakpoint(hex)
            <input value={heapBp} onChange={(e) => setHeapBp(e.target.value)} />
          </label>
          <label className="runner-field">
            steps
            <input value={heapSteps} onChange={(e) => setHeapSteps(e.target.value)} />
          </label>
          <button
            className="button secondary"
            disabled={heapState.status === 'running'}
            onClick={() => runHeap(_hexOrUndef(heapBp), _intOrUndef(heapSteps))}
          >
            힙 덤프
          </button>
        </div>
        <RunnerResult state={heapState} />
        {heapState.status === 'done' && heapState.result.attempted && (
          <HeapView result={heapState.result} />
        )}
        {heapState.status === 'done' && !heapState.result.attempted && (
          <p className="runner-kv">
            <span>결과</span>
            <strong>미시도 ({String(heapState.result.reason)})</strong>
          </p>
        )}
      </section>

      {/* PE 동적 실행 (wine) */}
      <section className="runner-card">
        <div className="section-heading">
          <h3>PE 동적 실행 (wine)</h3>
          <span>Windows PE 실행 · stdout/exit · Windows 예외 관측</span>
        </div>
        <div className="runner-actions">
          <label className="runner-field">
            stdin(text)
            <input value={peStdin} onChange={(e) => setPeStdin(e.target.value)} />
          </label>
          <button
            className="button secondary"
            disabled={peRunState.status === 'running'}
            onClick={() => runPeRun(_textToHex(peStdin))}
          >
            실행
          </button>
          <button
            className="button secondary"
            disabled={peTriageState.status === 'running'}
            onClick={() => runPeTriage()}
          >
            크래시 트리아지
          </button>
        </div>
        <RunnerResult state={peRunState} />
        {peRunState.status === 'done' && <PeRunView result={peRunState.result} />}
        <RunnerResult state={peTriageState} />
        {peTriageState.status === 'done' && peTriageState.result.attempted && (
          <PeTriageView result={peTriageState.result} />
        )}
      </section>
    </div>
  );
}

function HeapView({ result }) {
  const arena = result.arena;
  return (
    <div className="heap-view">
      <p className="runner-kv">
        <span>heap</span>
        <strong>
          {String(result.heap?.start)} – {String(result.heap?.end)} · 청크{' '}
          {String(result.chunk_count)}개
        </strong>
      </p>
      {(result.tcache || []).length > 0 && (
        <div>
          <h4 className="heap-sub">tcache</h4>
          {result.tcache.map((b) => (
            <p key={`tc-${b.index}`} className="runner-kv">
              <span>
                bin {b.index} ({b.chunk_size})
              </span>
              <strong>
                count {b.count} · head {String(b.head_hex)}
              </strong>
            </p>
          ))}
        </div>
      )}
      {arena && (arena.fastbins || []).length > 0 && (
        <div>
          <h4 className="heap-sub">fastbins (main_arena {String(arena.main_arena)})</h4>
          {arena.fastbins.map((b) => (
            <p key={`fb-${b.index}`} className="runner-kv">
              <span>
                bin {b.index} ({b.chunk_size})
              </span>
              <strong>
                count {b.count} · {(b.chain || []).join(' → ')}
              </strong>
            </p>
          ))}
        </div>
      )}
      {(result.free_chunks || []).length > 0 && (
        <div>
          <h4 className="heap-sub">free 청크 (unsorted/small/large)</h4>
          {result.free_chunks.map((c, i) => (
            <p key={`fc-${i}`} className="runner-kv">
              <span>
                {c.addr} ({c.size})
              </span>
              <strong>
                <Badge tone={c.bin === 'unsorted' ? 'orange' : 'neutral'}>
                  {c.bin}
                </Badge>{' '}
                fd {c.fd}
              </strong>
            </p>
          ))}
        </div>
      )}
      <details className="heap-raw">
        <summary>전체 청크 ({String(result.chunk_count)})</summary>
        <pre className="dbg-stack">
          <code>
            {(result.chunks || [])
              .map(
                (c) =>
                  `${c.addr}  size=${c.size}  ${
                    c.tcache_struct
                      ? 'tcache_struct'
                      : c.in_use === false
                        ? 'FREE'
                        : 'inuse'
                  }`,
              )
              .join('\n')}
          </code>
        </pre>
      </details>
    </div>
  );
}

function PeRunView({ result }) {
  if (!result.attempted) {
    return (
      <p className="runner-kv">
        <span>결과</span>
        <strong>미시도 ({String(result.reason)})</strong>
      </p>
    );
  }
  return (
    <div>
      <p className="runner-kv">
        <span>결과</span>
        <strong>
          {result.crashed ? (
            <Badge tone="danger">CRASH · {String(result.crash?.reason)}</Badge>
          ) : (
            <>exit {String(result.exit_code)}</>
          )}
          {result.timed_out ? ' · timeout' : ''}
          {result.crash?.fault_address
            ? ` · fault ${String(result.crash.fault_address)}`
            : ''}
          {result.crash?.instruction_pointer
            ? ` · ip ${String(result.crash.instruction_pointer)}`
            : ''}
        </strong>
      </p>
      {result.stdout && (
        <pre className="shell-term">
          <code>{result.stdout}</code>
        </pre>
      )}
    </div>
  );
}

function PeTriageView({ result }) {
  return (
    <div>
      <p className="runner-kv">
        <span>트리아지</span>
        <strong>
          {result.likely_overflow && <Badge tone="danger">overflow 의심</Badge>}{' '}
          {result.likely_format && <Badge tone="danger">format 의심</Badge>}{' '}
          {!result.likely_overflow && !result.likely_format && (
            <Badge tone="green">뚜렷한 신호 없음</Badge>
          )}
        </strong>
      </p>
      {(result.results || []).map((r) => (
        <p key={`pr-${r.probe}`} className="runner-kv">
          <span>
            {r.probe} ({r.input_len}B)
          </span>
          <strong>
            {r.crashed ? (
              <Badge tone="danger">CRASH · {String(r.crash?.reason)}</Badge>
            ) : (
              <Badge tone="neutral">exit {String(r.exit_code)}</Badge>
            )}
          </strong>
        </p>
      ))}
    </div>
  );
}

function GhidraView({ sha }) {
  const [state, run] = useSandboxAction(() => api.analyzeGhidra(sha));
  const [openFn, setOpenFn] = useState(null);
  const r = state.result;
  const unavailable = r && r.available === false;

  return (
    <div className="strategy-workspace ghidra-workspace">
      <section className="strategy-intro">
        <div className="section-heading">
          <h3>Ghidra 분석 (진짜 디컴파일러)</h3>
          <span className="verification verification-inferred">
            정적 분석 · 실행 안 함 · 기본 비활성
          </span>
        </div>
        <p className="strategy-disclaimer">
          Ghidra headless 로 <strong>실제 디컴파일</strong>하고, 복원한 버퍼 크기·스택
          프레임을 vuln_scan/strategy 에 피드백합니다. 정적 disasm 휴리스틱이 놓치는
          오버플로를 <strong>확정</strong>하고 정확한 오프셋을 계산합니다(실행이 아니라
          정적 추정 — <code>static-ghidra</code>). 서버에서{' '}
          <code>PLAB_GHIDRA_ENABLED=1</code>로 켠 경우에만 동작합니다.
        </p>
        <div className="runner-actions">
          <button
            className="button primary"
            disabled={state.status === 'running'}
            onClick={() => run()}
          >
            Ghidra 분석 실행
          </button>
          <span className="runner-hint">디컴파일+분석은 수십 초 걸릴 수 있습니다.</span>
        </div>
      </section>

      {state.status === 'running' && <Loading label="Ghidra 디컴파일·분석 중" />}
      {state.status === 'error' && (
        <div className="runner-error">
          <strong>⚠ 실행 불가</strong>
          <p>{state.error}</p>
        </div>
      )}

      {unavailable && (
        <section className="runner-card">
          <p className="strategy-disclaimer">
            Ghidra 백엔드가 비활성이거나 설치되지 않았습니다
            {r.reason ? ` (${r.reason})` : ''}. 규칙 기반 pseudo-C(Functions 탭)로
            폴백하세요.
          </p>
        </section>
      )}

      {r && r.available && (
        <>
          <section className="runner-card runner-headline">
            <div className="section-heading">
              <h3>분석 요약</h3>
              <span>
                {r.program} · {r.language} · {r.function_count} functions
              </span>
            </div>
            <div className="runner-kv">
              <span>확정 오버플로 오프셋</span>
              <strong>
                {r.best_overflow_offset != null ? (
                  <Badge tone="green">{r.best_overflow_offset}</Badge>
                ) : (
                  <Badge tone="neutral">없음</Badge>
                )}
              </strong>
            </div>
            {r.strategy?.confirmed_offset != null && (
              <p className="runner-hint">
                strategy 에 오프셋 {r.strategy.confirmed_offset} 주입 (source={' '}
                <code>{r.strategy.offset_source}</code>, verification={' '}
                <code>{r.strategy.offset_verification}</code> — 정적 추정, 실행 아님).
              </p>
            )}
          </section>

          <GhidraOverflows insights={r.overflow_insights || []} />
          <GhidraConfirmedVulns vulns={r.vulnerabilities || []} />
          <GhidraFunctions
            functions={r.functions || []}
            openFn={openFn}
            setOpenFn={setOpenFn}
          />
        </>
      )}
    </div>
  );
}

function GhidraOverflows({ insights }) {
  const confirmed = insights.filter((i) => i.confirmed);
  if (!insights.length) return null;
  return (
    <section className="runner-card">
      <div className="section-heading">
        <h3>스택 오버플로 (Ghidra 확정)</h3>
        <span>버퍼 크기·스택 프레임 기반 · 오프셋 = ret_off − buffer_off</span>
      </div>
      {confirmed.length === 0 && <Empty label="확정된 오버플로 없음" />}
      {insights.map((i, idx) => (
        <div className="ghidra-insight" key={idx}>
          <div className="ghidra-insight-head">
            <Badge tone={i.confirmed ? 'danger' : 'neutral'}>
              {i.confirmed ? '확정' : '가능'}
            </Badge>
            <code>
              {i.function}() · {i.sink}() → {i.buffer_name}[{i.buffer_size ?? '?'}]
            </code>
            {i.confirmed && <span className="ghidra-offset">offset = {i.offset}</span>}
          </div>
          <p className="ghidra-evidence">{i.evidence}</p>
        </div>
      ))}
    </section>
  );
}

function GhidraConfirmedVulns({ vulns }) {
  const promoted = vulns.filter((v) => v.ghidra_confirmed);
  if (promoted.length === 0) return null;
  return (
    <section className="runner-card">
      <div className="section-heading">
        <h3>Ghidra 로 승격된 취약점</h3>
        <span>정적 스캔 후보 → Ghidra 로 확정</span>
      </div>
      {promoted.map((v, idx) => (
        <div className="runner-kv" key={idx}>
          <span>
            <Badge tone={severityTone[v.severity] || 'neutral'}>{v.symbol}</Badge>{' '}
            {v.category}
          </span>
          <strong>
            <Badge tone="danger">confirmed</Badge> offset {v.ghidra_offset}
          </strong>
        </div>
      ))}
    </section>
  );
}

function GhidraFunctions({ functions, openFn, setOpenFn }) {
  const withC = functions.filter((f) => f.c);
  if (withC.length === 0) return null;
  return (
    <section className="runner-card">
      <div className="section-heading">
        <h3>디컴파일 ({withC.length})</h3>
        <span>함수를 눌러 C 를 펼칩니다</span>
      </div>
      <div className="ghidra-fn-list">
        {withC.map((f) => (
          <div className="ghidra-fn" key={f.entry}>
            <button
              className="ghidra-fn-head"
              onClick={() => setOpenFn(openFn === f.entry ? null : f.entry)}
            >
              <span className="ghidra-fn-caret">{openFn === f.entry ? '▾' : '▸'}</span>
              <code>{f.signature || f.name}</code>
              <span className="ghidra-fn-entry">{f.entry}</span>
            </button>
            {openFn === f.entry && (
              <div className="ghidra-fn-body">
                <div className="pseudo-c-toolbar">
                  <CopyButton value={f.c} />
                </div>
                <pre className="pseudo-c-code">
                  <code>{f.c}</code>
                </pre>
              </div>
            )}
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
 *   selectedAddress?: string,
 *   onTabChange?: (nextTab: string) => void,
 *   onAddressChange?: (address: number|string, nextTab: string) => void
 * }} props
 */
export function Analysis({
  sha,
  binary,
  activeTab = 'overview',
  selectedAddress = '',
  onTabChange = () => {},
  onAddressChange = () => {},
}) {
  const [info, setInfo] = useState(null);
  const [contextSecurity, setContextSecurity] = useState(null);
  const [analysisStatus, setAnalysisStatus] = useState(
    binary?.analysis_status || 'unknown',
  );
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState('');
  const artifactFormat = info?.format || binary?.format || 'ELF';
  const availableTabs = tabsForFormat(artifactFormat);
  const tab = availableTabs.some(([id]) => id === activeTab) ? activeTab : 'overview';

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
          <h2>{binary?.filename || 'Binary target'}</h2>
          <div className="binary-context-meta">
            <span>{artifactFormat}</span>
            <span>
              {binary?.machine?.replace('EM_', '').replace('IMAGE_FILE_MACHINE_', '') ||
                'Unknown arch'}
            </span>
            <span>{binary?.bits ? `${binary.bits}-bit` : 'Unknown bits'}</span>
            <code title={sha}>{sha.slice(0, 16)}</code>
            <StatusBadge status={analysisStatus} />
          </div>
        </div>
        <div className="context-actions">
          {contextSecurity && artifactFormat === 'ELF' && (
            <div className="protection-summary" aria-label="Protection summary">
              <span>NX {contextSecurity.nx ? '✓' : '×'}</span>
              <span>PIE {contextSecurity.pie === 'PIE' ? '✓' : '×'}</span>
              <span>Canary {contextSecurity.canary ? '✓' : '?'}</span>
              <span>RELRO {contextSecurity.relro}</span>
            </div>
          )}
          {contextSecurity && artifactFormat === 'PE' && (
            <div className="protection-summary" aria-label="Protection summary">
              <span>DEP {contextSecurity.nx ? '✓' : '×'}</span>
              <span>ASLR {contextSecurity.pie === 'ASLR' ? '✓' : '×'}</span>
              <span>
                CFG{' '}
                {contextSecurity.protections?.some(
                  (item) => item.name === 'control_flow_guard' && item.enabled,
                )
                  ? '✓'
                  : '?'}
              </span>
            </div>
          )}
          {contextSecurity && artifactFormat === 'RAW' && (
            <div className="protection-summary" aria-label="Protection summary">
              <span>ARCH ?</span>
              <span>BASE ?</span>
              <span>MITIGATIONS ?</span>
            </div>
          )}
          <button
            className="button secondary"
            disabled={analyzing}
            onClick={rerunAnalysis}
          >
            {analyzing ? 'Analyzing artifact…' : 'Re-run static analysis'}
          </button>
        </div>
      </div>
      <div className="analysis-tabs" role="tablist">
        {availableTabs.map(([id, label]) => (
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
        !error && <Loading label="바이너리 포맷과 구조를 파싱하는 중" />
      ) : (
        <div className="tab-content">
          {tab === 'overview' && <Overview sha={sha} info={info} />}
          {tab === 'functions' && (
            <FunctionsView
              sha={sha}
              selectedAddress={selectedAddress}
              onAddressChange={onAddressChange}
            />
          )}
          {tab === 'disassembly' && (
            <Disassembly
              sha={sha}
              info={info}
              selectedAddress={selectedAddress}
              onAddressChange={onAddressChange}
            />
          )}
          {tab === 'cfg' && (
            <CFGView
              sha={sha}
              selectedAddress={selectedAddress}
              onAddressChange={onAddressChange}
            />
          )}
          {tab === 'gadgets' && <Gadgets sha={sha} onAddressChange={onAddressChange} />}
          {tab === 'strategy' && <Strategy sha={sha} />}
          {tab === 'exploit-runner' && <ExploitRunner sha={sha} />}
          {tab === 'debugger-ws' && <LiveDebugger sha={sha} />}
          {tab === 'dynamic' && <DynamicAnalysis sha={sha} />}
          {tab === 'ghidra' && <GhidraView sha={sha} />}
          {tab === 'symbols' && <Symbols info={info} />}
          {tab === 'strings' && <Strings sha={sha} />}
          {tab === 'got' && <GotPlt sha={sha} />}
          {tab === 'hex' && <HexView sha={sha} />}
        </div>
      )}
    </div>
  );
}

import { useEffect, useMemo, useState } from 'react';
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
          {tab === 'symbols' && <Symbols info={info} />}
          {tab === 'strings' && <Strings sha={sha} />}
          {tab === 'got' && <GotPlt sha={sha} />}
          {tab === 'hex' && <HexView sha={sha} />}
        </div>
      )}
    </div>
  );
}

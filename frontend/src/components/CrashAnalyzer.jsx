import { useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useHistory, useParams } from 'react-router-dom';
import { api, formatBytes } from '../api';
import {
  Badge,
  DataTable,
  Empty,
  ErrorBanner,
  Icon,
  Loading,
  StatusBadge,
} from './Common';

const messageFor = (reason) =>
  reason instanceof Error ? reason.message : 'Crash analysis request failed.';

const titleCase = (value) =>
  String(value || 'unknown')
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase());

function Verification({ value = 'unknown' }) {
  const meta = {
    verified: ['✓', 'Verified', 'success'],
    inferred: ['≈', 'Inferred', 'warning'],
    unknown: ['?', 'Unknown', 'neutral'],
  }[value] || ['?', 'Unknown', 'neutral'];
  return (
    <Badge tone={meta[2]}>
      {meta[0]} {meta[1]}
    </Badge>
  );
}

function Confidence({ value = 0 }) {
  const percent = Math.round(Number(value) * 100);
  return (
    <span className="crash-confidence" aria-label={`Confidence ${percent}%`}>
      <span style={{ width: `${Math.max(0, Math.min(100, percent))}%` }} />
      <b>{percent}%</b>
    </span>
  );
}

function CrashIntake({ binaries, pending, onUpload }) {
  const input = useRef(null);
  const [binaryId, setBinaryId] = useState('');
  const [dragging, setDragging] = useState(false);
  const accept = (files) => {
    if (files?.[0]) onUpload(files[0], binaryId);
  };
  return (
    <section className="crash-intake">
      <div>
        <p className="section-kicker">TEXT LOG INTAKE</p>
        <h2>Analyze a debugger log</h2>
        <p>GDB, pwndbg, GEF 또는 일반 크래시 텍스트 · UTF-8 · 최대 2 MiB</p>
      </div>
      <label>
        <span>Attach binary (optional)</span>
        <select value={binaryId} onChange={(event) => setBinaryId(event.target.value)}>
          <option value="">No binary association</option>
          {binaries.map((binary) => (
            <option key={binary.sha256} value={binary.sha256}>
              {binary.filename} · {binary.sha256.slice(0, 10)}
            </option>
          ))}
        </select>
      </label>
      <button
        className={`crash-drop ${dragging ? 'is-dragging' : ''}`}
        disabled={pending}
        onClick={() => input.current?.click()}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          accept(event.dataTransfer.files);
        }}
      >
        <Icon name="upload" size={18} />
        <span>
          <strong>{pending ? 'Parsing bounded log…' : 'Upload crash log'}</strong>
          <small>The target binary is never executed by this workflow.</small>
        </span>
        <input
          ref={input}
          hidden
          type="file"
          accept=".log,.txt,text/plain"
          onChange={(event) => {
            accept(event.target.files);
            event.target.value = '';
          }}
        />
      </button>
    </section>
  );
}

function CrashIndex({ items, selected }) {
  return (
    <aside className="crash-index" aria-label="Crash logs">
      <div className="crash-index-head">
        <span>CAPTURED LOGS</span>
        <b>{String(items.length).padStart(2, '0')}</b>
      </div>
      {items.length === 0 ? (
        <Empty
          title="No crash logs yet"
          description="텍스트 디버거 로그를 업로드하면 분석 세션이 여기에 표시됩니다."
        />
      ) : (
        <div className="crash-index-list">
          {items.map((item) => (
            <Link
              key={item.crash_id}
              className={selected === item.crash_id ? 'active' : ''}
              to={`/crashes/${item.crash_id}`}
            >
              <span className="crash-signal">{item.signal || '?'}</span>
              <span>
                <strong>{item.filename}</strong>
                <small>
                  {formatBytes(item.size)} ·{' '}
                  {new Date(item.created_at).toLocaleString()}
                </small>
                <StatusBadge status={item.analysis_status} compact />
              </span>
            </Link>
          ))}
        </div>
      )}
    </aside>
  );
}

function RootCause({ result }) {
  const cause = result.probable_root_cause || {};
  const pattern = result.probable_overflow_pattern || {};
  return (
    <aside className="crash-cause-panel">
      <div className="panel-heading compact-heading">
        <div>
          <span>PROBABLE ROOT CAUSE</span>
          <h2>{titleCase(cause.type)}</h2>
        </div>
        <Verification value={cause.verification} />
      </div>
      <div className="cause-status-line">
        <span className={`finding-state state-${cause.status || 'possible'}`}>
          {cause.status === 'likely' ? '◐' : '◇'}{' '}
          {titleCase(cause.status || 'possible')}
        </span>
        <Confidence value={cause.confidence} />
      </div>
      <p>{cause.summary}</p>
      {pattern.offset !== null && pattern.offset !== undefined && (
        <div className="cyclic-evidence">
          <span>CYCLIC OFFSET</span>
          <strong>{pattern.offset}</strong>
          <code>{pattern.source}</code>
          <Verification value={pattern.verification} />
        </div>
      )}
      <h3>Evidence</h3>
      <ul className="evidence-lines">
        {(cause.evidence || []).map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
      <h3>Next verification</h3>
      <ol className="verification-steps">
        {(cause.recommended_next_steps || []).map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ol>
    </aside>
  );
}

function RegisterTable({ registers }) {
  return (
    <section className="crash-registers">
      <div className="panel-heading compact-heading">
        <div>
          <span>VERIFIED LOG VALUES</span>
          <h2>Registers</h2>
        </div>
        <span>{registers.length} captured</span>
      </div>
      <DataTable
        rows={registers}
        keyFor={(item) => item.name}
        empty="로그에 register dump가 없습니다. GDB의 info registers 출력을 포함하세요."
        columns={[
          {
            key: 'name',
            label: 'REGISTER',
            render: (item) => <strong className="register-name">{item.name}</strong>,
          },
          {
            key: 'value_hex',
            label: 'VALUE',
            render: (item) => <code>{item.value_hex}</code>,
          },
          {
            key: 'classification',
            label: 'INTERPRETATION',
            render: (item) => (
              <span
                className={`pointer-kind pointer-${item.classification?.kind || 'unknown'}`}
              >
                {titleCase(item.classification?.kind)}
              </span>
            ),
          },
          {
            key: 'verification',
            label: 'SOURCE',
            render: (item) => <Verification value={item.verification} />,
          },
        ]}
      />
    </section>
  );
}

function StackTable({ stack }) {
  return (
    <DataTable
      rows={stack}
      keyFor={(item) => item.address_hex}
      empty="로그에 stack memory dump가 없습니다. x/32gx $rsp 출력을 포함하세요."
      columns={[
        {
          key: 'offset_from_sp',
          label: 'OFFSET',
          render: (item) => (
            <code>
              {item.offset_from_sp === null
                ? '—'
                : `RSP+0x${item.offset_from_sp.toString(16)}`}
            </code>
          ),
        },
        {
          key: 'address_hex',
          label: 'ADDRESS',
          render: (item) => <code>{item.address_hex}</code>,
        },
        {
          key: 'value_hex',
          label: 'VALUE',
          render: (item) => <code>{item.value_hex}</code>,
        },
        { key: 'ascii', label: 'ASCII', render: (item) => <code>{item.ascii}</code> },
        {
          key: 'classification',
          label: 'MEANING',
          render: (item) => (
            <span className="stack-meaning">
              <span>{titleCase(item.classification?.kind)}</span>
              {(item.labels || []).map((label) => (
                <Badge key={label} tone="warning">
                  ≈ {titleCase(label)}
                </Badge>
              ))}
            </span>
          ),
        },
      ]}
    />
  );
}

function MappingTable({ mappings }) {
  return (
    <DataTable
      rows={mappings}
      keyFor={(item) => `${item.start_hex}-${item.end_hex}`}
      empty="로그에 process mapping이 없습니다. info proc mappings 출력을 포함하세요."
      columns={[
        {
          key: 'start_hex',
          label: 'START',
          render: (item) => <code>{item.start_hex}</code>,
        },
        { key: 'end_hex', label: 'END', render: (item) => <code>{item.end_hex}</code> },
        {
          key: 'permissions',
          label: 'PERM',
          render: (item) => <code>{item.permissions}</code>,
        },
        { key: 'kind', label: 'REGION', render: (item) => titleCase(item.kind) },
        {
          key: 'path',
          label: 'MAPPED FILE',
          render: (item) => <code>{item.path || 'anonymous'}</code>,
        },
        {
          key: 'verification',
          label: 'SOURCE',
          render: (item) => <Verification value={item.verification} />,
        },
      ]}
    />
  );
}

function CrashWorkspace({ detail }) {
  const [tab, setTab] = useState('stack');
  const result = detail.result;
  const tabItems = {
    stack: result.stack || [],
    mappings: result.mappings || [],
  };
  return (
    <div className="crash-workspace">
      <header className="crash-context">
        <div>
          <span className="crash-file-glyph">
            <Icon name="crash" size={18} />
          </span>
          <span>
            <strong>{detail.filename}</strong>
            <small>
              {detail.sha256.slice(0, 16)} · {result.source?.dialect || 'generic'} text
              log
            </small>
          </span>
        </div>
        <div className="crash-context-state">
          <StatusBadge status={detail.analysis_status} />
          <Verification value="inferred" />
          <span>Never executed</span>
        </div>
      </header>

      <section className="crash-facts" aria-label="Crash summary">
        <div>
          <span>SIGNAL</span>
          <strong className="danger-text">{result.signal?.value || 'Unknown'}</strong>
        </div>
        <div>
          <span>INSTRUCTION POINTER</span>
          <code>{result.instruction_pointer?.value_hex || '—'}</code>
        </div>
        <div>
          <span>STACK POINTER</span>
          <code>{result.stack_pointer?.value_hex || '—'}</code>
        </div>
        <div>
          <span>CRASH INSTRUCTION</span>
          <code>{result.crash_instruction?.instruction || '—'}</code>
        </div>
        <div>
          <span>ARCHITECTURE</span>
          <strong>{result.architecture?.value || 'Unknown'}</strong>
        </div>
      </section>

      <div className="crash-primary-grid">
        <RegisterTable registers={result.registers || []} />
        <RootCause result={result} />
      </div>

      <section className="crash-memory-panel">
        <div className="crash-panel-tabs" role="tablist" aria-label="Crash memory data">
          {[
            ['stack', `Stack · ${tabItems.stack.length}`],
            ['mappings', `Memory maps · ${tabItems.mappings.length}`],
          ].map(([value, label]) => (
            <button
              key={value}
              className={tab === value ? 'active' : ''}
              role="tab"
              aria-selected={tab === value}
              onClick={() => setTab(value)}
            >
              {label}
            </button>
          ))}
          <span>Values are observed; semantic labels are heuristic.</span>
        </div>
        {tab === 'stack' ? (
          <StackTable stack={tabItems.stack} />
        ) : (
          <MappingTable mappings={tabItems.mappings} />
        )}
      </section>
    </div>
  );
}

export function CrashAnalyzer({ binaries }) {
  const { crashId = '' } = useParams();
  const history = useHistory();
  const queryClient = useQueryClient();
  const [error, setError] = useState('');
  const listQuery = useQuery({ queryKey: ['crashes'], queryFn: api.crashes });
  const detailQuery = useQuery({
    queryKey: ['crash', crashId],
    queryFn: () => api.crash(crashId),
    enabled: Boolean(crashId),
  });
  const upload = useMutation({
    mutationFn: ({ file, binaryId }) => api.uploadCrash(file, binaryId),
    onSuccess: async (result) => {
      await queryClient.invalidateQueries({ queryKey: ['crashes'] });
      setError('');
      history.push(`/crashes/${result.crash_id}`);
    },
    onError: (reason) => setError(messageFor(reason)),
  });

  const crashes = useMemo(() => listQuery.data || [], [listQuery.data]);
  useEffect(() => {
    if (!crashId && crashes.length > 0)
      history.replace(`/crashes/${crashes[0].crash_id}`);
  }, [crashId, crashes, history]);
  useEffect(() => {
    if (listQuery.error || detailQuery.error)
      setError(messageFor(listQuery.error || detailQuery.error));
  }, [listQuery.error, detailQuery.error]);

  const associatedBinary = useMemo(() => {
    const binaryId = detailQuery.data?.binary_id;
    return binaries.find((item) => item.sha256 === binaryId);
  }, [binaries, detailQuery.data]);

  return (
    <div className="page crash-page">
      <header className="crash-page-header">
        <div>
          <p className="section-kicker">CRASH ANALYZER · PHASE 4</p>
          <h1>Turn a crash log into evidence.</h1>
          <p>
            레지스터, 스택, 메모리 매핑과 cyclic 오프셋을 정규화하고 관찰값과 추론을
            분리합니다.
          </p>
        </div>
        {associatedBinary && (
          <Link
            className="button secondary"
            to={`/binaries/${associatedBinary.sha256}/overview`}
          >
            Open {associatedBinary.filename}
          </Link>
        )}
      </header>
      <ErrorBanner message={error} onClose={() => setError('')} />
      <CrashIntake
        binaries={binaries}
        pending={upload.isPending}
        onUpload={(file, binaryId) => upload.mutate({ file, binaryId })}
      />
      <div className="crash-shell">
        {listQuery.isLoading ? (
          <Loading label="Loading captured crash logs" />
        ) : (
          <CrashIndex items={crashes} selected={crashId} />
        )}
        <main>
          {!crashId ? (
            <Empty
              title="No crash selected"
              description="크래시 로그를 업로드하면 register, stack, mapping 근거를 여기서 검토할 수 있습니다."
            />
          ) : detailQuery.isLoading ? (
            <Loading label="Parsing registers, stack, mappings, and cyclic evidence" />
          ) : detailQuery.data ? (
            <CrashWorkspace detail={detailQuery.data} />
          ) : (
            <Empty
              title="Crash unavailable"
              description="로그가 삭제되었거나 분석 결과를 불러오지 못했습니다."
            />
          )}
        </main>
      </div>
    </div>
  );
}

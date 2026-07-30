import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Link,
  NavLink,
  Redirect,
  Route,
  Switch,
  useHistory,
  useLocation,
  useParams,
} from 'react-router-dom';
import { api, formatBytes, type BinarySummary, type UploadResult } from './api';
import { Analysis } from './components/Analysis.jsx';
import { Challenges } from './components/Challenges.jsx';
import {
  Empty,
  ErrorBanner,
  Icon,
  Loading,
  StatusBadge,
} from './components/Common.jsx';
import { PayloadStudio } from './components/PayloadStudio.jsx';

const PRIMARY_NAV = [
  { to: '/', label: 'Dashboard', icon: 'dashboard', end: true },
  { to: '/binaries', label: 'Binaries', icon: 'target', end: false },
  { to: '/payload', label: 'Payload Studio', icon: 'wrench', end: false },
  { to: '/challenges', label: 'Challenges', icon: 'flag', end: false },
];

interface UploadProps {
  upload: (file: File) => Promise<void>;
  uploading: boolean;
}

interface SidebarProps extends UploadProps {
  binaries: BinarySummary[];
  selected: string;
}

interface DashboardProps extends UploadProps {
  binaries: BinarySummary[];
  loading: boolean;
}

interface DashboardFinding {
  binaryId: string;
  binaryName: string;
  symbol: string;
  category: string;
  severity: string;
  description: string;
}

const errorMessage = (reason: unknown): string =>
  reason instanceof Error ? reason.message : '알 수 없는 오류가 발생했습니다.';

function UploadButton({
  upload,
  uploading,
  className = 'button primary',
}: UploadProps & { className?: string }) {
  const input = useRef<HTMLInputElement>(null);
  return (
    <>
      <button
        className={className}
        disabled={uploading}
        onClick={() => input.current?.click()}
      >
        <Icon name="upload" size={17} />
        {uploading ? 'Validating ELF…' : 'Upload binary'}
      </button>
      <input
        ref={input}
        hidden
        type="file"
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) void upload(file);
          event.target.value = '';
        }}
      />
    </>
  );
}

function Sidebar({ binaries, selected, upload, uploading }: SidebarProps) {
  const input = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const accept = (files: FileList | null) => {
    if (files?.[0]) void upload(files[0]);
  };

  return (
    <aside className="sidebar" aria-label="Workspace navigation">
      <nav className="main-navigation" aria-label="Main navigation">
        <div className="sidebar-label">WORKSPACE</div>
        {PRIMARY_NAV.map((item) => (
          <NavLink key={item.to} to={item.to} exact={item.end} activeClassName="active">
            <Icon name={item.icon} size={17} />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-label intake-label">ARTIFACT INTAKE</div>
      <button
        className={`drop-zone compact ${dragging ? 'is-dragging' : ''}`}
        disabled={uploading}
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
        <span className="upload-icon">
          <Icon name="upload" size={18} />
        </span>
        <span>
          <strong>{uploading ? 'Validating ELF…' : 'Upload binary'}</strong>
          <small>ELF only · 32 MiB max</small>
        </span>
        <input
          ref={input}
          hidden
          type="file"
          onChange={(event) => accept(event.target.files)}
        />
      </button>

      <div className="sidebar-label sidebar-label-row">
        <span>RECENT BINARIES</span>
        <span>{String(binaries.length).padStart(2, '0')}</span>
      </div>
      <div className="target-list">
        {binaries.length === 0 && (
          <p className="sidebar-empty">업로드된 artifact가 없습니다.</p>
        )}
        {binaries.slice(0, 8).map((binary) => (
          <Link
            className={`target-item ${selected === binary.sha256 ? 'active' : ''}`}
            key={binary.sha256}
            to={`/binaries/${binary.sha256}/overview`}
          >
            <span className="target-dot" aria-hidden="true" />
            <span className="target-body">
              <strong title={binary.filename}>{binary.filename}</strong>
              <small>
                {binary.bits}-bit · {binary.machine.replace('EM_', '')} ·{' '}
                {formatBytes(binary.size)}
              </small>
              <span className="target-state">
                <StatusBadge status={binary.analysis_status} compact />
                <code>{binary.sha256.slice(0, 10)}</code>
              </span>
            </span>
          </Link>
        ))}
      </div>

      <div className="sidebar-foot">
        <Icon name="shield" size={16} />
        <span>
          Static analysis control plane
          <br />
          Uploaded files are never executed here.
        </span>
      </div>
    </aside>
  );
}

function Dashboard({ binaries, loading, upload, uploading }: DashboardProps) {
  const [findings, setFindings] = useState<DashboardFinding[] | null>(null);
  const [findingError, setFindingError] = useState('');

  useEffect(() => {
    let cancelled = false;
    if (binaries.length === 0) {
      setFindings([]);
      return () => {
        cancelled = true;
      };
    }
    setFindings(null);
    setFindingError('');
    Promise.all(
      binaries.slice(0, 4).map(async (binary) => {
        const items = await api.vulns(binary.sha256);
        return items.map((item) => ({
          binaryId: binary.sha256,
          binaryName: binary.filename,
          symbol: String(item.symbol),
          category: String(item.category),
          severity: String(item.severity),
          description: String(item.description),
        }));
      }),
    )
      .then((groups) => {
        if (!cancelled) {
          const priority = groups
            .flat()
            .filter((item) => ['critical', 'high'].includes(item.severity))
            .slice(0, 6);
          setFindings(priority);
        }
      })
      .catch((reason: unknown) => {
        if (!cancelled) {
          setFindingError(errorMessage(reason));
          setFindings([]);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [binaries]);

  const activeJobs = binaries.filter((binary) =>
    ['queued', 'running', 'failed'].includes(binary.analysis_status),
  );

  return (
    <div className="page dashboard-page">
      <header className="dashboard-header">
        <div>
          <p className="section-kicker">AUTHORIZED BINARY ANALYSIS</p>
          <h1>Analysis workspace</h1>
          <p>
            최근 artifact를 이어서 분석하고, 실패한 작업과 우선 확인할 근거를
            검토합니다.
          </p>
        </div>
        <div className="dashboard-primary-action">
          <UploadButton upload={upload} uploading={uploading} />
          <span>ELF32 / ELF64 · file is not executed</span>
        </div>
      </header>

      {loading ? (
        <Loading label="Loading recent workspaces" />
      ) : binaries.length === 0 ? (
        <section className="dashboard-empty">
          <Empty
            title="No binaries yet"
            description="소유하거나 분석 권한이 있는 ELF를 업로드하세요. Phase 1 pipeline은 파일을 실행하지 않고 구조를 검증해 저장합니다."
          />
          <UploadButton upload={upload} uploading={uploading} />
        </section>
      ) : (
        <>
          <div className="dashboard-grid">
            <section className="workspace-list-panel">
              <div className="panel-heading">
                <div>
                  <h2>Recent workspaces</h2>
                  <p>최근 업로드한 ELF와 정적 분석 상태</p>
                </div>
                <span>{binaries.length} artifacts</span>
              </div>
              <div className="workspace-list">
                {binaries.slice(0, 8).map((binary) => (
                  <Link
                    key={binary.sha256}
                    to={`/binaries/${binary.sha256}/overview`}
                    className="workspace-row"
                  >
                    <span className="file-glyph">
                      <Icon name="binary" size={18} />
                    </span>
                    <span className="workspace-identity">
                      <strong>{binary.filename}</strong>
                      <small>
                        {binary.machine.replace('EM_', '')} · {binary.bits}-bit ·{' '}
                        {formatBytes(binary.size)}
                      </small>
                    </span>
                    <code>{binary.sha256.slice(0, 12)}</code>
                    <StatusBadge status={binary.analysis_status} />
                    <span className="row-action">Open workspace →</span>
                  </Link>
                ))}
              </div>
            </section>

            <aside className="queue-panel">
              <div className="panel-heading">
                <div>
                  <h2>Analysis queue</h2>
                  <p>조치가 필요한 현재 작업</p>
                </div>
              </div>
              {activeJobs.length === 0 ? (
                <div className="queue-clear">
                  <StatusBadge status="completed" />
                  <strong>No blocked jobs</strong>
                  <p>대기, 실행 또는 실패 상태의 정적 분석이 없습니다.</p>
                </div>
              ) : (
                <div className="queue-list">
                  {activeJobs.map((binary) => (
                    <Link
                      to={`/binaries/${binary.sha256}/overview`}
                      key={binary.sha256}
                    >
                      <StatusBadge status={binary.analysis_status} />
                      <span>
                        <strong>{binary.filename}</strong>
                        <small>
                          {binary.analysis_status === 'failed'
                            ? 'Open details and retry analysis'
                            : 'Static metadata analysis in progress'}
                        </small>
                      </span>
                    </Link>
                  ))}
                </div>
              )}
              <div className="queue-note">
                <Icon name="shield" size={16} />
                <p>
                  Phase 1 jobs perform static parsing only. Dynamic execution requires
                  the isolated runner planned for Phase 6.
                </p>
              </div>
            </aside>
          </div>

          <section className="priority-panel">
            <div className="panel-heading">
              <div>
                <h2>High-priority findings</h2>
                <p>Critical/High symbol evidence from recent artifacts</p>
              </div>
              <span>Possible · static heuristic</span>
            </div>
            {findingError && (
              <ErrorBanner message={`Finding scan failed: ${findingError}`} />
            )}
            {findings === null ? (
              <Loading label="Scanning symbol-based findings" />
            ) : findings.length === 0 ? (
              <Empty
                title="No high-priority symbol evidence"
                description="최근 artifact에서 Critical 또는 High 위험 API가 발견되지 않았습니다. 이 결과는 안전을 보장하지 않습니다."
              />
            ) : (
              <div className="priority-list">
                {findings.map((finding) => (
                  <Link
                    to={`/binaries/${finding.binaryId}/overview`}
                    key={`${finding.binaryId}-${finding.symbol}`}
                  >
                    <span className={`severity-mark severity-${finding.severity}`}>
                      {finding.severity}
                    </span>
                    <span className="finding-identity">
                      <code>{finding.symbol}()</code>
                      <small>
                        {finding.binaryName} · {finding.category}
                      </small>
                    </span>
                    <p>{finding.description}</p>
                    <span className="verification-label">◇ Possible</span>
                  </Link>
                ))}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}

function BinaryWorkspace({ binaries }: { binaries: BinarySummary[] }) {
  const { sha = '', tab = 'overview' } = useParams<{
    sha?: string;
    tab?: string;
  }>();
  const history = useHistory();
  const binary = binaries.find((item) => item.sha256 === sha);
  if (!binary) {
    return (
      <div className="page">
        <Empty
          title="Binary not found"
          description="목록을 새로고침하거나 artifact가 삭제되지 않았는지 확인하세요."
        />
      </div>
    );
  }
  return (
    <Analysis
      key={sha}
      sha={sha}
      binary={binary}
      activeTab={tab}
      onTabChange={(nextTab: string) => history.push(`/binaries/${sha}/${nextTab}`)}
    />
  );
}

function BinaryIndex({ binaries }: { binaries: BinarySummary[] }) {
  if (binaries.length === 0) return <Redirect to="/" />;
  return <Redirect to={`/binaries/${binaries[0].sha256}/overview`} />;
}

export default function App() {
  const history = useHistory();
  const location = useLocation();
  const queryClient = useQueryClient();
  const [globalError, setGlobalError] = useState('');
  const selectedBinary =
    /^\/binaries\/([0-9a-f]{64})(?:\/|$)/.exec(location.pathname)?.[1] ?? '';

  const health = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
    retry: 1,
    refetchInterval: 30_000,
  });
  const binaryQuery = useQuery({
    queryKey: ['binaries'],
    queryFn: api.binaries,
  });
  const binaries = binaryQuery.data ?? [];

  const uploadMutation = useMutation<UploadResult, Error, File>({
    mutationFn: async (file) => {
      const result = await api.upload(file);
      await api.analyze(result.binary_id);
      return result;
    },
    onSuccess: async (result) => {
      await queryClient.invalidateQueries({ queryKey: ['binaries'] });
      setGlobalError('');
      history.push(`/binaries/${result.binary_id}/overview`);
    },
    onError: (reason) => setGlobalError(errorMessage(reason)),
  });

  const upload = async (file: File) => {
    try {
      await uploadMutation.mutateAsync(file);
    } catch {
      // useMutation의 onError가 사용자에게 표시할 구조화된 오류 상태를 설정한다.
    }
  };

  useEffect(() => {
    if (binaryQuery.error) setGlobalError(errorMessage(binaryQuery.error));
  }, [binaryQuery.error]);

  return (
    <div className="app-shell">
      <header className="topbar">
        <Link className="brand" to="/" aria-label="PwnPilot dashboard">
          <span className="brand-mark">
            <Icon name="terminal" size={19} />
          </span>
          <span>
            <strong>Pwn</strong>
            <b>Pilot</b>
          </span>
        </Link>
        <div className="global-context">
          <span>Authorized analysis workspace</span>
          <small>Static control plane</small>
        </div>
        <div
          className={`api-state ${health.isError ? 'offline' : ''}`}
          role="status"
          aria-live="polite"
        >
          <span aria-hidden="true" />
          {health.isError
            ? 'API DISCONNECTED'
            : `API ONLINE${health.data ? ` · v${health.data.version}` : ''}`}
        </div>
      </header>

      <div className="workspace">
        <Sidebar
          binaries={binaries}
          selected={selectedBinary}
          upload={upload}
          uploading={uploadMutation.isPending}
        />
        <main className="main-panel">
          <ErrorBanner message={globalError} onClose={() => setGlobalError('')} />
          <Switch>
            <Route
              exact
              path="/"
              render={() => (
                <Dashboard
                  binaries={binaries}
                  loading={binaryQuery.isLoading}
                  upload={upload}
                  uploading={uploadMutation.isPending}
                />
              )}
            />
            <Route
              exact
              path="/binaries"
              render={() => <BinaryIndex binaries={binaries} />}
            />
            <Route
              path="/binaries/:sha/:tab?"
              render={() =>
                binaryQuery.isLoading ? (
                  <Loading label="Loading binary workspace" />
                ) : (
                  <BinaryWorkspace binaries={binaries} />
                )
              }
            />
            <Route path="/payload" component={PayloadStudio} />
            <Route path="/challenges" component={Challenges} />
            <Redirect to="/" />
          </Switch>
        </main>
      </div>
    </div>
  );
}

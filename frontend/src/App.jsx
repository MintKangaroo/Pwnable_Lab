import { useCallback, useEffect, useRef, useState } from 'react';
import { api, formatBytes } from './api.js';
import { Analysis } from './components/Analysis.jsx';
import { Challenges } from './components/Challenges.jsx';
import { ErrorBanner, Icon } from './components/Common.jsx';
import { PayloadStudio } from './components/PayloadStudio.jsx';

const NAV = [
  { id: 'analyze', label: 'Binary Lab', icon: 'target' },
  { id: 'payload', label: 'Payload Studio', icon: 'wrench' },
  { id: 'challenges', label: 'Challenges', icon: 'flag' },
];

function Sidebar({ binaries, selected, onSelect, upload, uploading }) {
  const input = useRef(null);
  const [dragging, setDragging] = useState(false);
  const accept = (files) => files?.[0] && upload(files[0]);

  return (
    <aside className="sidebar">
      <div className="sidebar-label">TARGET INTAKE</div>
      <button
        className={`drop-zone ${dragging ? 'is-dragging' : ''}`}
        onClick={() => input.current?.click()}
        onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          accept(event.dataTransfer.files);
        }}
      >
        <span className="upload-icon"><Icon name="upload" size={21} /></span>
        <span className="drop-title">{uploading ? '분석 대상 업로드 중…' : 'ELF 바이너리 업로드'}</span>
        <span className="drop-copy">드래그하거나 클릭 · 최대 16 MiB</span>
        <input
          ref={input}
          hidden
          type="file"
          onChange={(event) => accept(event.target.files)}
        />
      </button>

      <div className="sidebar-label sidebar-label-row">
        <span>RECENT TARGETS</span>
        <span>{String(binaries.length).padStart(2, '0')}</span>
      </div>
      <div className="target-list">
        {binaries.length === 0 && (
          <p className="sidebar-empty">아직 업로드한 바이너리가 없습니다.</p>
        )}
        {binaries.map((binary) => (
          <button
            className={`target-item ${selected === binary.sha256 ? 'active' : ''}`}
            key={binary.sha256}
            onClick={() => onSelect(binary.sha256)}
          >
            <span className="target-dot" />
            <span className="target-body">
              <strong title={binary.filename}>{binary.filename}</strong>
              <small>{binary.bits}-bit · {binary.machine.replace('EM_', '')} · {formatBytes(binary.size)}</small>
              <code>{binary.sha256.slice(0, 12)}</code>
            </span>
          </button>
        ))}
      </div>

      <div className="sidebar-foot">
        <Icon name="shield" size={16} />
        <span>Static analysis only<br />업로드 파일을 실행하지 않습니다.</span>
      </div>
    </aside>
  );
}

function Welcome({ onUpload }) {
  const input = useRef(null);
  return (
    <section className="welcome">
      <div className="eyebrow"><span /> SYSTEM HACKING PLAYGROUND</div>
      <h2>바이너리를 읽고,<br /><em>익스플로잇을 설계하세요.</em></h2>
      <p className="welcome-copy">
        ELF 구조와 보호 기법을 확인하고, 위험 함수와 ROP 가젯을 추적하고,
        실제 공격 페이로드를 안전한 정적 환경에서 조립합니다.
      </p>
      <div className="welcome-actions">
        <button className="button primary" onClick={() => input.current?.click()}>
          분석 시작 <Icon name="arrow" size={17} />
        </button>
        <span>ELF32 / ELF64 · x86 / x86-64</span>
        <input ref={input} hidden type="file" onChange={(event) => event.target.files?.[0] && onUpload(event.target.files[0])} />
      </div>
      <div className="capability-grid">
        {[
          ['01', 'MITIGATION MAP', 'RELRO · Canary · NX · PIE를 한 번에 판별합니다.'],
          ['02', 'ATTACK SURFACE', '위험 API, GOT/PLT, 심볼과 문자열을 연결합니다.'],
          ['03', 'ROP RECON', '실행 섹션을 스캔해 짧은 ret 가젯을 수집합니다.'],
          ['04', 'PAYLOAD CRAFT', 'cyclic, pack, overflow 체인을 브라우저에서 만듭니다.'],
        ].map(([number, title, description]) => (
          <article className="capability-card" key={number}>
            <span>{number}</span>
            <h3>{title}</h3>
            <p>{description}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

export default function App() {
  const [mode, setMode] = useState('analyze');
  const [binaries, setBinaries] = useState([]);
  const [selected, setSelected] = useState('');
  const [version, setVersion] = useState('');
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');

  const refresh = useCallback(async () => setBinaries(await api.binaries()), []);

  useEffect(() => {
    api.health().then((health) => setVersion(health.version)).catch(() => {});
    refresh().catch((reason) => setError(reason.message));
  }, [refresh]);

  const upload = async (file) => {
    setUploading(true);
    setError('');
    try {
      const result = await api.upload(file);
      await refresh();
      setSelected(result.sha256);
      setMode('analyze');
    } catch (reason) {
      setError(reason.message);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <button className="brand" onClick={() => setMode('analyze')}>
          <span className="brand-mark"><Icon name="terminal" size={20} /></span>
          <span><strong>PWNABLE</strong><b>_LAB</b></span>
        </button>
        <nav aria-label="주 메뉴">
          {NAV.map((item) => (
            <button
              key={item.id}
              className={mode === item.id ? 'active' : ''}
              onClick={() => setMode(item.id)}
            >
              <Icon name={item.icon} size={17} /> {item.label}
            </button>
          ))}
        </nav>
        <div className="api-state"><span /> API ONLINE {version && `· v${version}`}</div>
      </header>

      <div className="workspace">
        <Sidebar
          binaries={binaries}
          selected={selected}
          onSelect={(sha) => { setSelected(sha); setMode('analyze'); }}
          upload={upload}
          uploading={uploading}
        />
        <main className="main-panel">
          <ErrorBanner message={error} onClose={() => setError('')} />
          {mode === 'analyze' && (selected
            ? <Analysis key={selected} sha={selected} binary={binaries.find((item) => item.sha256 === selected)} />
            : <Welcome onUpload={upload} />)}
          {mode === 'payload' && <PayloadStudio />}
          {mode === 'challenges' && <Challenges />}
        </main>
      </div>
    </div>
  );
}

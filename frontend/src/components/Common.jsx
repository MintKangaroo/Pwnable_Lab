export function Icon({ name, size = 18 }) {
  const paths = {
    target: <><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" /><path d="M12 2v3M22 12h-3M12 22v-3M2 12h3" /></>,
    terminal: <><rect x="3" y="4" width="18" height="16" rx="2" /><path d="m7 9 3 3-3 3M13 15h4" /></>,
    flask: <><path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.8 3h10.4A2 2 0 0 0 19 18l-5-9V3" /><path d="M7.5 15h9" /></>,
    cube: <><path d="m12 2 8 4.5v10L12 21l-8-4.5v-10L12 2Z" /><path d="m4 6.5 8 4.5 8-4.5M12 11v10" /></>,
    upload: <><path d="M12 16V4m0 0L7 9m5-5 5 5" /><path d="M4 15v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4" /></>,
    shield: <><path d="M12 2 4.5 5v6c0 5 3.2 8.8 7.5 11 4.3-2.2 7.5-6 7.5-11V5L12 2Z" /><path d="m9 12 2 2 4-5" /></>,
    code: <><path d="m8 8-4 4 4 4M16 8l4 4-4 4M14 4l-4 16" /></>,
    wrench: <><path d="M14.5 6.5a4 4 0 0 0-5-5L12 4 9 7 6.5 4.5a4 4 0 0 0 5 5L4 17a2.1 2.1 0 0 0 3 3l7.5-7.5a4 4 0 0 0 5-5L17 10l-3-3 2.5-2.5" /></>,
    flag: <><path d="M5 21V4m0 1c5-3 8 3 14 0v9c-6 3-9-3-14 0" /></>,
    download: <><path d="M12 3v12m0 0 5-5m-5 5-5-5M4 21h16" /></>,
    search: <><circle cx="10.5" cy="10.5" r="6.5" /><path d="m16 16 5 5" /></>,
    arrow: <path d="M5 12h14m-5-5 5 5-5 5" />,
  };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name]}
    </svg>
  );
}

export function Loading({ label = '분석 중' }) {
  return (
    <div className="state-box">
      <span className="spinner" />
      <span>{label}</span>
    </div>
  );
}

export function ErrorBanner({ message, onClose }) {
  if (!message) return null;
  return (
    <div className="error-banner" role="alert">
      <span className="error-mark">!</span>
      <span>{message}</span>
      {onClose && <button onClick={onClose} aria-label="닫기">×</button>}
    </div>
  );
}

export function Empty({ title, description }) {
  return (
    <div className="empty-box">
      <div className="empty-glyph">∅</div>
      <strong>{title}</strong>
      <p>{description}</p>
    </div>
  );
}

export function CopyButton({ value, label = '복사' }) {
  const copy = async () => {
    await navigator.clipboard.writeText(value);
  };
  return <button className="copy-button" onClick={copy}>{label}</button>;
}

export function Badge({ children, tone = 'neutral' }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function DataTable({ columns, rows, keyFor = (_, index) => index, empty = '표시할 데이터가 없습니다.' }) {
  if (!rows?.length) return <Empty title="데이터 없음" description={empty} />;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{columns.map((column) => <th key={column.key}>{column.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={keyFor(row, index)}>
              {columns.map((column) => <td key={column.key}>{column.render ? column.render(row) : row[column.key]}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

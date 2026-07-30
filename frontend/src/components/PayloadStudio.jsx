import { useEffect, useState } from 'react';
import { api } from '../api';
import { Badge, CopyButton, ErrorBanner, Icon, Loading } from './Common.jsx';

const TOOLS = [
  ['cyclic', 'Cyclic Pattern', '정확한 오버플로우 오프셋 찾기'],
  ['pack', 'Integer Pack', '주소를 엔디언 바이트로 변환'],
  ['overflow', 'Overflow Builder', '패딩 + 반환 주소 + ROP 체인'],
  ['shellcode', 'Shellcode Catalog', '교육용 syscall 바이트 참조'],
];

const asNumber = (value) => {
  const parsed = Number(value.trim());
  if (!Number.isFinite(parsed)) throw new Error(`숫자로 해석할 수 없습니다: ${value}`);
  return parsed;
};

function ResultBlock({ label, value, copy = value }) {
  if (value === null || value === undefined || value === '') return null;
  return (
    <div className="result-block">
      <div>
        <span>{label}</span>
        <CopyButton value={String(copy)} />
      </div>
      <pre>{value}</pre>
    </div>
  );
}

function CyclicTool() {
  const [length, setLength] = useState(128);
  const [n, setN] = useState(4);
  const [pattern, setPattern] = useState(null);
  const [needle, setNeedle] = useState('');
  const [offset, setOffset] = useState(null);
  const [error, setError] = useState('');

  const generate = async (event) => {
    event.preventDefault();
    setError('');
    try {
      setPattern(await api.cyclic(Number(length), Number(n)));
    } catch (reason) {
      setError(reason.message);
    }
  };
  const find = async (event) => {
    event.preventDefault();
    setError('');
    try {
      setOffset((await api.cyclicFind(needle, Number(n))).offset);
    } catch (reason) {
      setError(reason.message);
    }
  };

  return (
    <div className="tool-grid">
      <div className="tool-form">
        <div className="tool-index">01 / GENERATE</div>
        <h3>De Bruijn 패턴 생성</h3>
        <p>충돌하지 않는 n바이트 부분 수열로 반환 주소까지의 패딩 길이를 찾습니다.</p>
        <form onSubmit={generate}>
          <label>
            Pattern length
            <input
              type="number"
              min="1"
              max="65536"
              value={length}
              onChange={(event) => setLength(event.target.value)}
            />
          </label>
          <label>
            Subsequence width
            <select value={n} onChange={(event) => setN(event.target.value)}>
              <option>4</option>
              <option>6</option>
              <option>8</option>
            </select>
          </label>
          <button className="button primary" type="submit">
            GENERATE PATTERN <Icon name="arrow" size={16} />
          </button>
        </form>
        <div className="form-divider" />
        <form onSubmit={find}>
          <label>
            Crash value
            <input
              value={needle}
              onChange={(event) => setNeedle(event.target.value)}
              placeholder="baaa 또는 0x61616162"
            />
          </label>
          <button className="button secondary" type="submit">
            FIND OFFSET
          </button>
        </form>
      </div>
      <div className="tool-output">
        <ErrorBanner message={error} />
        <div className="output-header">
          <span>OUTPUT BUFFER</span>
          <code>{pattern ? `${pattern.length} BYTES` : 'WAITING'}</code>
        </div>
        {!pattern && offset === null && (
          <div className="output-placeholder">
            패턴을 생성하거나 크래시 값을 검색하세요.<span>_</span>
          </div>
        )}
        {pattern && (
          <ResultBlock
            label="ASCII PATTERN"
            value={
              pattern.pattern_ascii.slice(0, 4096) +
              (pattern.length > 4096 ? '\n… preview truncated' : '')
            }
            copy={pattern.pattern_ascii}
          />
        )}
        {pattern && (
          <ResultBlock
            label="HEX BYTES"
            value={
              pattern.pattern_hex.slice(0, 4096) +
              (pattern.pattern_hex.length > 4096 ? '\n… preview truncated' : '')
            }
            copy={pattern.pattern_hex}
          />
        )}
        {offset !== null && (
          <div className={`offset-result ${offset < 0 ? 'miss' : ''}`}>
            <small>CALCULATED OFFSET</small>
            <strong>{offset < 0 ? 'NOT FOUND' : offset}</strong>
            <span>{offset >= 0 && `0x${offset.toString(16)} bytes`}</span>
          </div>
        )}
      </div>
    </div>
  );
}

function PackTool() {
  const [value, setValue] = useState('0x401156');
  const [bits, setBits] = useState(64);
  const [endian, setEndian] = useState('little');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const submit = async (event) => {
    event.preventDefault();
    setError('');
    try {
      setResult(await api.pack(asNumber(value), Number(bits), endian));
    } catch (reason) {
      setError(reason.message);
    }
  };
  return (
    <div className="tool-grid">
      <div className="tool-form">
        <div className="tool-index">02 / PACK</div>
        <h3>정수 패킹</h3>
        <p>함수·가젯 주소를 p32/p64와 같은 바이트 표현으로 변환합니다.</p>
        <form onSubmit={submit}>
          <label>
            Integer / address
            <input
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder="0x401156"
            />
          </label>
          <div className="field-row">
            <label>
              Word size
              <select value={bits} onChange={(event) => setBits(event.target.value)}>
                <option value="64">64-bit</option>
                <option value="32">32-bit</option>
              </select>
            </label>
            <label>
              Endian
              <select
                value={endian}
                onChange={(event) => setEndian(event.target.value)}
              >
                <option value="little">Little</option>
                <option value="big">Big</option>
              </select>
            </label>
          </div>
          <button className="button primary" type="submit">
            PACK INTEGER <Icon name="arrow" size={16} />
          </button>
        </form>
      </div>
      <div className="tool-output">
        <ErrorBanner message={error} />
        <div className="output-header">
          <span>PACKED VALUE</span>
          <code>{bits}-BIT</code>
        </div>
        {!result ? (
          <div className="output-placeholder">
            주소를 입력해 바이트 배열로 변환하세요.<span>_</span>
          </div>
        ) : (
          <>
            <ResultBlock
              label="HEX"
              value={result.hex.match(/.{1,2}/g)?.join(' ')}
              copy={result.hex}
            />
            <ResultBlock
              label="PYTHON BYTES"
              value={`b"${result.bytes.map((byte) => `\\x${byte.toString(16).padStart(2, '0')}`).join('')}"`}
            />
            <div className="byte-cells">
              {result.bytes.map((byte, index) => (
                <code key={index}>{byte.toString(16).padStart(2, '0')}</code>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function OverflowTool() {
  const [padding, setPadding] = useState(72);
  const [target, setTarget] = useState('0x401156');
  const [bits, setBits] = useState(64);
  const [fill, setFill] = useState('A');
  const [chain, setChain] = useState('0x40101a\n0xdeadbeef');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const submit = async (event) => {
    event.preventDefault();
    setError('');
    try {
      const addresses = chain
        .split(/[\s,]+/)
        .filter(Boolean)
        .map(asNumber);
      setResult(
        await api.overflow({
          padding: Number(padding),
          target: asNumber(target),
          bits: Number(bits),
          fill,
          chain: addresses,
        }),
      );
    } catch (reason) {
      setError(reason.message);
    }
  };
  return (
    <div className="tool-grid">
      <div className="tool-form">
        <div className="tool-index">03 / BUILD</div>
        <h3>오버플로우 조립</h3>
        <p>
          <code>[padding][target][chain…]</code> 구조의 페이로드를 재현 가능하게
          만듭니다.
        </p>
        <form onSubmit={submit}>
          <div className="field-row">
            <label>
              Padding
              <input
                type="number"
                min="0"
                max="1000000"
                value={padding}
                onChange={(event) => setPadding(event.target.value)}
              />
            </label>
            <label>
              Fill
              <input
                maxLength="32"
                value={fill}
                onChange={(event) => setFill(event.target.value)}
              />
            </label>
          </div>
          <label>
            Return target
            <input value={target} onChange={(event) => setTarget(event.target.value)} />
          </label>
          <label>
            ROP chain
            <textarea
              rows="5"
              value={chain}
              onChange={(event) => setChain(event.target.value)}
              placeholder="한 줄에 주소 하나"
            />
          </label>
          <label>
            Architecture
            <select value={bits} onChange={(event) => setBits(event.target.value)}>
              <option value="64">amd64 / 64-bit</option>
              <option value="32">i386 / 32-bit</option>
            </select>
          </label>
          <button className="button primary" type="submit">
            BUILD PAYLOAD <Icon name="arrow" size={16} />
          </button>
        </form>
      </div>
      <div className="tool-output">
        <ErrorBanner message={error} />
        <div className="output-header">
          <span>PAYLOAD LAYOUT</span>
          <code>{result ? `${result.length} BYTES` : 'WAITING'}</code>
        </div>
        {!result ? (
          <div className="output-placeholder">
            패딩과 반환 주소를 설정해 페이로드를 조립하세요.<span>_</span>
          </div>
        ) : (
          <>
            <ResultBlock label="HEXDUMP" value={result.hexdump} />
            <ResultBlock label="RAW HEX" value={result.payload_hex} />
          </>
        )}
      </div>
    </div>
  );
}

function ShellcodeTool() {
  const [arch, setArch] = useState('');
  const [items, setItems] = useState(null);
  const [error, setError] = useState('');
  useEffect(() => {
    setItems(null);
    api
      .shellcodes(arch)
      .then(setItems)
      .catch((reason) => setError(reason.message));
  }, [arch]);
  return (
    <div>
      <div className="toolbar">
        <div>
          <strong>SHELLCODE CATALOG</strong>
          <span>정적 참고 및 디스어셈블 학습용</span>
        </div>
        <label>
          ARCH{' '}
          <select value={arch} onChange={(event) => setArch(event.target.value)}>
            <option value="">All</option>
            <option value="amd64">amd64</option>
            <option value="i386">i386</option>
          </select>
        </label>
      </div>
      <ErrorBanner message={error} />
      {!items ? (
        <Loading label="셸코드 카탈로그를 불러오는 중" />
      ) : (
        <div className="shellcode-grid">
          {items.map((item) => (
            <article className="shellcode-card" key={item.slug}>
              <div>
                <Badge tone="cyan">{item.arch}</Badge>
                <span>{item.length} bytes</span>
              </div>
              <h3>{item.title}</h3>
              <p>{item.description}</p>
              <pre>{item.bytes_hex.match(/.{1,2}/g)?.join(' ')}</pre>
              <CopyButton value={item.bytes_hex} label="COPY HEX" />
            </article>
          ))}
        </div>
      )}
      <div className="safety-note">
        <Icon name="shield" size={18} />
        <p>
          <strong>교육 및 허가된 환경 전용</strong>이 카탈로그는 바이트를 실행하지
          않습니다. 소유하거나 명시적 허가를 받은 시스템에서만 사용하세요.
        </p>
      </div>
    </div>
  );
}

export function PayloadStudio() {
  const [tool, setTool] = useState('cyclic');
  return (
    <div className="page">
      <div className="page-head studio-head">
        <div>
          <div className="eyebrow">
            <span /> EXPLOIT WORKBENCH
          </div>
          <h2>Payload Studio</h2>
          <p>익스플로잇의 반복 작업을 빠르고 정확하게.</p>
        </div>
        <div className="terminal-chip">$ craft --safe-mode</div>
      </div>
      <div className="tool-tabs">
        {TOOLS.map(([id, title, description], index) => (
          <button
            className={tool === id ? 'active' : ''}
            key={id}
            onClick={() => setTool(id)}
          >
            <span>0{index + 1}</span>
            <div>
              <strong>{title}</strong>
              <small>{description}</small>
            </div>
          </button>
        ))}
      </div>
      <div className="tool-content">
        {tool === 'cyclic' && <CyclicTool />}
        {tool === 'pack' && <PackTool />}
        {tool === 'overflow' && <OverflowTool />}
        {tool === 'shellcode' && <ShellcodeTool />}
      </div>
    </div>
  );
}

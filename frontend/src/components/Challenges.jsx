import { useEffect, useState } from 'react';
import { api } from '../api';
import { Badge, ErrorBanner, Icon, Loading } from './Common.jsx';

const levelTone = { Easy: 'green', Medium: 'warn', Hard: 'danger' };

function ChallengeCard({ challenge, active, onClick }) {
  const attempts = challenge.stats?.attempts || 0;
  const solved = challenge.stats?.solved || 0;
  return (
    <button className={`challenge-card ${active ? 'active' : ''}`} onClick={onClick}>
      <div className="challenge-top">
        <Badge tone={levelTone[challenge.level]}>{challenge.level}</Badge>
        <span>{challenge.category.toUpperCase()}</span>
      </div>
      <h3>{challenge.title}</h3>
      <p>{challenge.description}</p>
      <div className="challenge-meta">
        <span>{challenge.technique}</span>
        <code>
          {solved}/{attempts || 0} SOLVED
        </code>
      </div>
    </button>
  );
}

function ChallengeDetail({ slug, onStatsChange }) {
  const [detail, setDetail] = useState(null);
  const [answer, setAnswer] = useState('');
  const [revealed, setRevealed] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    setDetail(null);
    setAnswer('');
    setResult(null);
    setRevealed(0);
    api
      .challenge(slug)
      .then(setDetail)
      .catch((reason) => setError(reason.message));
  }, [slug]);

  const submit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setResult(null);
    setError('');
    try {
      const response = await api.submit(slug, answer);
      setResult(response);
      onStatsChange();
    } catch (reason) {
      setError(reason.message);
    } finally {
      setSubmitting(false);
    }
  };

  if (error) return <ErrorBanner message={error} />;
  if (!detail) return <Loading label="문제 바이너리를 준비하는 중" />;
  return (
    <aside className="challenge-detail">
      <div className="detail-head">
        <div>
          <Badge tone={levelTone[detail.level]}>{detail.level}</Badge>
          <span>{detail.category}</span>
        </div>
        <code>#{detail.slug}</code>
      </div>
      <h2>{detail.title}</h2>
      <p className="detail-description">{detail.description}</p>

      <div className="mission-box">
        <small>MISSION OBJECTIVE</small>
        <p>{detail.prompt}</p>
        <span>answer format · {detail.answer_format}</span>
      </div>

      <a
        className="button secondary download-button"
        href={api.artifactUrl(slug)}
        download
      >
        <Icon name="download" size={17} /> DOWNLOAD ELF{' '}
        <span>{detail.artifact_size.toLocaleString()} B</span>
      </a>

      <div className="hint-zone">
        <div>
          <strong>FIELD NOTES</strong>
          <span>
            {revealed}/{detail.hints.length}
          </span>
        </div>
        {detail.hints.slice(0, revealed).map((hint, index) => (
          <p key={hint}>
            <b>0{index + 1}</b>
            {hint}
          </p>
        ))}
        {revealed < detail.hints.length && (
          <button onClick={() => setRevealed((value) => value + 1)}>
            + 힌트 {revealed + 1} 열기
          </button>
        )}
      </div>

      <form className="flag-form" onSubmit={submit}>
        <label>YOUR ANSWER</label>
        <div>
          <span>&gt;</span>
          <input
            required
            value={answer}
            onChange={(event) => setAnswer(event.target.value)}
            placeholder="정답을 입력하세요"
          />
          <button disabled={submitting}>{submitting ? 'CHECKING' : 'SUBMIT'}</button>
        </div>
      </form>

      {result && (
        <div className={`submission-result ${result.correct ? 'correct' : 'wrong'}`}>
          <strong>{result.correct ? 'ACCESS GRANTED' : 'ACCESS DENIED'}</strong>
          <p>{result.message}</p>
          {result.solution && (
            <div>
              <small>SOLUTION NOTE</small>
              {result.solution}
            </div>
          )}
        </div>
      )}
    </aside>
  );
}

export function Challenges() {
  const [challenges, setChallenges] = useState(null);
  const [selected, setSelected] = useState('');
  const [error, setError] = useState('');

  const refresh = () =>
    api
      .challenges()
      .then((items) => {
        setChallenges(items);
        setSelected((current) => current || items[0]?.slug || '');
      })
      .catch((reason) => setError(reason.message));

  useEffect(() => {
    refresh();
  }, []);

  return (
    <div className="page">
      <div className="page-head challenge-page-head">
        <div>
          <div className="eyebrow">
            <span /> CAPTURE THE FLAG
          </div>
          <h2>Exploit Challenges</h2>
          <p>분석 도구로 실제 ELF 아티팩트를 풀고 서버에서 정답을 검증하세요.</p>
        </div>
        <div className="challenge-counter">
          <strong>{challenges?.length || 0}</strong>
          <span>
            LIVE
            <br />
            MISSIONS
          </span>
        </div>
      </div>
      <ErrorBanner message={error} />
      {!challenges ? (
        <Loading label="실습 문제를 불러오는 중" />
      ) : (
        <div className="challenge-layout">
          <div className="challenge-list">
            <div className="list-heading">
              <span>MISSION BOARD</span>
              <code>SELECT TARGET</code>
            </div>
            {challenges.map((challenge) => (
              <ChallengeCard
                key={challenge.slug}
                challenge={challenge}
                active={selected === challenge.slug}
                onClick={() => setSelected(challenge.slug)}
              />
            ))}
          </div>
          {selected && <ChallengeDetail slug={selected} onStatsChange={refresh} />}
        </div>
      )}
    </div>
  );
}

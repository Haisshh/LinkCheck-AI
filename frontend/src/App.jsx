import { useEffect, useMemo, useState } from 'react';

const translations = {
  en: {
    urlLabel: 'URL to analyze',
    urlPlaceholder: 'https://example.com/page?action=login',
    analyzeButton: 'Analyze',
    clearButton: 'Clear',
    resultHeader: 'Analysis results',
    screenshotLabel: 'Visual preview (sandbox)',
    copyButton: 'Copy report',
    copyReportHeader: 'LINKCHECK — ANALYSIS REPORT',
    copyReportScore: 'Score',
    copyReportVerdict: 'Verdict',
    copyReportDate: 'Date',
    copyReportDetail: 'Details',
    falsePositive: 'False positive?',
    reportDiscord: 'Report to Discord',
    feedbackNote: 'Send this link to Discord for manual review.',
    feedbackPlaceholder: 'Optional comment (e.g. this site is safe)',
    feedbackSubmit: 'Send report',
    feedbackSent: 'Feedback sent',
    feedbackError: 'Send failed',
    helpSummary: 'How to use LinkCheck?',
    helpUrl: '<strong>Analyze a URL:</strong> Paste the suspicious URL into the field below and click "Analyze".',
    helpScore: '<strong>Understand the score:</strong> 0-30 = safe, 31-60 = suspicious, 61+ = dangerous.',
    helpReport: '<strong>Detailed report:</strong> Each rule explains why the URL is classified that way.',
    helpExamples: '<strong>Examples:</strong> Click the buttons to test common scenarios.',
    helpFeedback: '<strong>Feedback:</strong> If you think a result is wrong, report it to improve the scanner.',
    barTicks: ['0', 'Safe ≤ 30', 'Suspicious ≤ 60', '100'],
    historyTitle: 'Session history',
    historyEmpty: 'No history yet.',
    historyBadges: { safe: 'Safe', suspect: 'Suspicious', dangerous: 'Dangerous', error: 'Error' },
    errorPrefix: 'Error:',
    missingUrl: 'Missing URL',
    noComment: 'No comment provided'
  },
  fr: {
    urlLabel: 'URL à analyser',
    urlPlaceholder: 'https://exemple.com/page?action=login',
    analyzeButton: 'Analyser',
    clearButton: 'Effacer',
    resultHeader: 'Résultats de l’analyse',
    screenshotLabel: 'Aperçu visuel (sandbox)',
    copyButton: 'Copier le rapport',
    copyReportHeader: 'LINKCHECK — RAPPORT D’ANALYSE',
    copyReportScore: 'Score',
    copyReportVerdict: 'Verdict',
    copyReportDate: 'Date',
    copyReportDetail: 'Détails',
    falsePositive: 'Faux positif ?',
    reportDiscord: 'Signaler au Discord',
    feedbackNote: 'Envoie ce lien au salon Discord pour vérification manuelle.',
    feedbackPlaceholder: 'Commentaire facultatif (ex: site sûr selon moi)',
    feedbackSubmit: 'Envoyer le signalement',
    feedbackSent: 'Feedback envoyé',
    feedbackError: 'Erreur d’envoi',
    helpSummary: 'Comment utiliser LinkCheck ?',
    helpUrl: '<strong>Analyser une URL :</strong> Collez l’URL suspecte dans le champ ci-dessous et cliquez sur "Analyser".',
    helpScore: '<strong>Comprendre le score :</strong> 0-30 = sûr, 31-60 = suspect, 61+ = dangereux.',
    helpReport: '<strong>Rapport détaillé :</strong> Chaque règle explique pourquoi l’URL est classée ainsi.',
    helpExamples: '<strong>Exemples :</strong> Cliquez sur les boutons pour tester des scénarios courants.',
    helpFeedback: '<strong>Feedback :</strong> Si vous pensez qu’une analyse est fausse, signalez-la pour amélioration.',
    barTicks: ['0', 'Sûr ≤ 30', 'Suspect ≤ 60', '100'],
    historyTitle: 'Historique de session',
    historyEmpty: 'Aucun historique.',
    historyBadges: { safe: 'Sûre', suspect: 'Suspecte', dangerous: 'Dangereuse', error: 'Erreur' },
    errorPrefix: 'Erreur :',
    missingUrl: 'URL manquante',
    noComment: 'Pas de commentaire'
  }
};

const defaultPresets = [
  { label: 'google.com (safe)', value: 'https://google.com' },
  { label: 'amaz0n phishing (dangerous)', value: 'http://amaz0n-secure.login.account-verify.com/update?urgent=true' },
  { label: 'shortener (suspicious)', value: 'http://bit.ly/3xKp2aB' },
  { label: 'paypal impersonation (dangerous)', value: 'https://paypa1.secure-account-login-verify.com/update' },
  { label: 'multi-subdomain (suspicious)', value: 'https://secure.login.bank.fake-support.com/verify-account' }
];

const verdictStyles = {
  safe: 'bg-emerald-100 text-emerald-900 border-emerald-200',
  suspect: 'bg-amber-100 text-amber-900 border-amber-200',
  dangerous: 'bg-rose-100 text-rose-900 border-rose-200',
  error: 'bg-slate-100 text-slate-900 border-slate-200'
};

function App() {
  const [url, setUrl] = useState('');
  const [lang, setLang] = useState('en');
  const [theme, setTheme] = useState('dark');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [comment, setComment] = useState('');
  const [feedbackStatus, setFeedbackStatus] = useState('');

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    const savedLang = localStorage.getItem('siteLanguage');
    if (savedTheme) setTheme(savedTheme);
    if (savedLang) setLang(savedLang);
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    localStorage.setItem('theme', theme);
  }, [theme]);

  useEffect(() => {
    localStorage.setItem('siteLanguage', lang);
  }, [lang]);

  const ui = translations[lang];

  const handleAnalyze = async (submittedUrl) => {
    const targetUrl = submittedUrl ?? url.trim();
    if (!targetUrl) {
      setError(`${ui.errorPrefix} ${ui.missingUrl}`);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await fetch('/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || `${ui.errorPrefix} ${response.status}`);
      }
      setResult({ ...data, inputUrl: targetUrl });
      setHistory((prev) => [{ url: targetUrl, ...data }, ...prev].slice(0, 8));
      setFeedbackOpen(false);
      setComment('');
    } catch (err) {
      setError(err.message || ui.errorPrefix);
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!result) return;
    const lines = [
      ui.copyReportHeader,
      '─'.repeat(34),
      `${ui.copyReportScore}: ${result.score}/100`,
      `${ui.copyReportVerdict}: ${ui.historyBadges[result.verdict] || result.verdict}`,
      `${ui.copyReportDate}: ${new Date().toLocaleString(lang === 'fr' ? 'fr-FR' : 'en-US')}`,
      '',
      `${ui.copyReportDetail}:`,
      ...(result.reasons || []).map((r) => `· ${r.text}${r.points > 0 ? ` (+${r.points})` : ''}`)
    ].join('\n');
    await navigator.clipboard.writeText(lines);
  };

  const sendFeedback = async () => {
    if (!result) return;
    setFeedbackStatus(ui.feedbackNote);
    try {
      const response = await fetch('/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: result.inputUrl,
          analyzed_host: result.analyzed_host,
          score: result.score,
          verdict: result.verdict,
          comment: comment || ui.noComment
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || data.message || ui.feedbackError);
      setFeedbackStatus(ui.feedbackSent);
      setTimeout(() => setFeedbackStatus(''), 3000);
    } catch (err) {
      setFeedbackStatus(err.message || ui.feedbackError);
    }
  };

  return (
    <div className={`min-h-screen ${theme === 'dark' ? 'bg-slate-950 text-slate-100' : 'bg-slate-100 text-slate-950'}`}>
      <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
        <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm uppercase tracking-[0.25em] text-emerald-400">LinkCheck</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight">Analysis and phishing awareness</h1>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <div className="inline-flex rounded-full border border-slate-700 bg-slate-900/80 p-1 text-sm shadow-soft dark:border-slate-600 dark:bg-slate-700/80">
              {['en','fr'].map((code) => (
                <button key={code} onClick={() => setLang(code)} className={`rounded-full px-3 py-1 ${lang === code ? 'bg-emerald-400 text-slate-950' : 'text-slate-300 hover:text-white'}`}>
                  {code.toUpperCase()}
                </button>
              ))}
            </div>
            <button onClick={() => setTheme((value) => (value === 'dark' ? 'light' : 'dark'))} className="rounded-full border border-slate-700 px-3 py-2 text-sm transition hover:border-emerald-400 hover:text-emerald-300 dark:border-slate-500">
              {theme === 'dark' ? 'Light' : 'Dark'}
            </button>
          </div>
        </header>

        <main className="mt-8 grid gap-8 lg:grid-cols-[1.2fr_0.8fr]">
          <section className="space-y-6">
            <div className="rounded-3xl border border-slate-800/80 bg-slate-900/80 p-6 shadow-soft dark:border-slate-700 dark:bg-slate-950/90">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="text-xl font-semibold">{ui.urlLabel}</h2>
                  <p className="mt-1 text-sm text-slate-400">{ui.urlPlaceholder}</p>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => handleAnalyze()} disabled={loading} className="rounded-full bg-emerald-400 px-5 py-3 font-semibold text-slate-950 transition hover:bg-emerald-300 disabled:cursor-not-allowed disabled:opacity-60">
                    {loading ? ui.analyzeButton + '…' : ui.analyzeButton}
                  </button>
                </div>
              </div>
              <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
                <input value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()} placeholder={ui.urlPlaceholder} className="flex-1 rounded-2xl border border-slate-700 bg-slate-950/90 px-4 py-3 text-sm text-slate-100 outline-none transition focus:border-emerald-400" />
                <button onClick={() => setUrl('')} className="rounded-2xl border border-slate-700 px-4 py-3 text-sm text-slate-300 transition hover:border-emerald-400 hover:text-white">
                  {ui.clearButton}
                </button>
              </div>
              <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {defaultPresets.map((preset) => (
                  <button key={preset.value} onClick={() => { setUrl(preset.value); handleAnalyze(preset.value); }} className="rounded-2xl border border-slate-700 px-4 py-3 text-left text-sm text-slate-300 transition hover:border-emerald-400 hover:text-white">
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            {error && <div className="rounded-3xl border border-rose-400/30 bg-rose-500/10 p-4 text-sm text-rose-100">{error}</div>}

            {result && (
              <article className={`rounded-3xl border ${verdictStyles[result.verdict] ?? verdictStyles.error} p-6 shadow-soft`}>
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <p className="text-sm uppercase tracking-[0.16em] text-slate-300">{ui.resultHeader}</p>
                    <h2 className="mt-2 text-2xl font-semibold break-all">{result.analyzed_host || result.inputUrl}</h2>
                  </div>
                  <div className="shrink-0 rounded-3xl bg-slate-950/90 px-5 py-4 text-center shadow-lg shadow-black/10">
                    <p className="text-sm uppercase tracking-[0.18em] text-slate-400">Score</p>
                    <p className="mt-2 text-5xl font-bold">{result.score}</p>
                  </div>
                </div>

                <div className="mt-6 rounded-2xl bg-slate-950/90 p-4">
                  <div className="h-3 overflow-hidden rounded-full bg-slate-800">
                    <div className="h-full rounded-full bg-emerald-400 transition-all" style={{ width: `${Math.min(100, Math.max(0, result.score))}%` }} />
                  </div>
                  <div className="mt-3 flex justify-between text-xs uppercase tracking-[0.24em] text-slate-500">
                    <span>{ui.barTicks[0]}</span>
                    <span>{ui.barTicks[1]}</span>
                    <span>{ui.barTicks[2]}</span>
                    <span>{ui.barTicks[3]}</span>
                  </div>
                </div>

                <div className="mt-6 space-y-3">
                  {(result.reasons || []).map((reason, index) => (
                    <div key={index} className="rounded-2xl border border-slate-800 bg-slate-900/90 p-4">
                      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                        <p className="font-semibold text-slate-100">{reason.text}</p>
                        <span className="text-sm text-slate-400">{reason.points > 0 ? `+${reason.points}` : reason.points}</span>
                      </div>
                      <p className="text-sm text-slate-400">{reason.severity}</p>
                    </div>
                  ))}
                </div>

                {result.screenshot && (
                  <div className="mt-6 rounded-3xl border border-slate-800 bg-slate-950/90 p-4">
                    <p className="text-sm font-semibold text-slate-200">{ui.screenshotLabel}</p>
                    <img src={`/${result.screenshot}?t=${Date.now()}`} alt="Screenshot preview" className="mt-4 w-full rounded-3xl border border-slate-800 object-cover" />
                  </div>
                )}

                <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <button onClick={handleCopy} className="rounded-full bg-emerald-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-emerald-300">
                    {ui.copyButton}
                  </button>
                  <span className="text-sm text-slate-400">{new Date().toLocaleTimeString(lang === 'fr' ? 'fr-FR' : 'en-US')}</span>
                </div>

                <div className="mt-6 rounded-3xl border border-slate-800 bg-slate-900/90 p-5">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <p className="text-sm font-semibold text-slate-100">{ui.falsePositive}</p>
                    <button onClick={() => setFeedbackOpen((open) => !open)} className="rounded-full border border-slate-700 px-4 py-2 text-sm text-slate-200 transition hover:border-emerald-400 hover:text-white">
                      {ui.reportDiscord}
                    </button>
                  </div>
                  {feedbackOpen && (
                    <div className="mt-4 space-y-4">
                      <p className="text-sm text-slate-400">{ui.feedbackNote}</p>
                      <textarea value={comment} onChange={(e) => setComment(e.target.value)} rows="4" className="w-full rounded-3xl border border-slate-700 bg-slate-950/90 px-4 py-3 text-sm text-slate-100 outline-none" placeholder={ui.feedbackPlaceholder} />
                      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                        <button onClick={sendFeedback} className="rounded-full bg-emerald-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-emerald-300">
                          {ui.feedbackSubmit}
                        </button>
                        <span className="text-sm text-slate-400">{feedbackStatus}</span>
                      </div>
                    </div>
                  )}
                </div>
              </article>
            )}
          </section>

          <aside className="space-y-6">
            <div className="rounded-3xl border border-slate-800 bg-slate-900/80 p-6 shadow-soft">
              <h3 className="text-lg font-semibold">{ui.helpSummary}</h3>
              <div className="mt-4 space-y-3 text-sm text-slate-400">
                <p dangerouslySetInnerHTML={{ __html: ui.helpUrl }} />
                <p dangerouslySetInnerHTML={{ __html: ui.helpScore }} />
                <p dangerouslySetInnerHTML={{ __html: ui.helpReport }} />
                <p dangerouslySetInnerHTML={{ __html: ui.helpExamples }} />
                <p dangerouslySetInnerHTML={{ __html: ui.helpFeedback }} />
              </div>
            </div>
            <div className="rounded-3xl border border-slate-800 bg-slate-900/80 p-6 shadow-soft">
              <h3 className="text-lg font-semibold">{ui.historyTitle}</h3>
              {!history.length ? (
                <p className="mt-4 text-sm text-slate-400">{ui.historyEmpty}</p>
              ) : (
                <div className="mt-4 space-y-3">
                  {history.map((item, index) => (
                    <button key={`${item.url}-${index}`} onClick={() => { setUrl(item.url); handleAnalyze(item.url); }} className="w-full rounded-3xl border border-slate-700 bg-slate-950/90 px-4 py-4 text-left transition hover:border-emerald-400">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="truncate font-medium text-slate-100">{item.url}</span>
                        <span className={`rounded-full px-3 py-1 text-xs font-semibold ${verdictStyles[item.verdict] ?? verdictStyles.error}`}>{ui.historyBadges[item.verdict] ?? item.verdict}</span>
                      </div>
                      <p className="mt-2 text-sm text-slate-400">{item.score}/100</p>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </aside>
        </main>
      </div>
    </div>
  );
}

export default App;

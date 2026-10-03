'use client';
import {useState} from 'react';
import {analyzeCode, AnalysisResult} from '../lib/api';
const sample=`import subprocess\npassword = "demo-secret"\n\ndef run(user_input):\n    return eval(user_input)\n\nsubprocess.run("ls " + password, shell=True)`;
export default function CodeAuditor(){
 const [code,setCode]=useState(sample); const [result,setResult]=useState<AnalysisResult|null>(null); const [loading,setLoading]=useState(false); const [error,setError]=useState('');
 async function submit(){setLoading(true);setError('');try{setResult(await analyzeCode(code));}catch(e){setError(e instanceof Error?e.message:'Request failed');}finally{setLoading(false);}}
 return <main className="shell"><header><div><p className="eyebrow">AI CODE AUDITOR · STARTER</p><h1>Security & Refactoring Workspace</h1><p>Submit Python code and inspect deterministic AST-based findings.</p></div><span className="status">● API contract ready</span></header>
 <section className="grid"><div className="panel"><h2>Code input</h2><textarea value={code} onChange={e=>setCode(e.target.value)} spellCheck={false}/><button onClick={submit} disabled={loading}>{loading?'Analyzing…':'Analyze code'}</button></div>
 <div className="panel"><h2>Findings</h2>{error&&<div className="error">{error}</div>}{!result&&!error&&<div className="empty">Run an analysis to see findings.</div>}{result&&<><div className="summary"><b>{result.findings.length}</b> finding(s) · {result.functions.length} function(s) · {result.classes.length} class(es)</div>{result.findings.map(f=><article className="finding" key={f.finding_id}><div className="row"><strong>{f.message}</strong><span className={`sev ${f.severity}`}>{f.severity}</span></div><div className="meta">{f.cwe_id||'No CWE'} · line {f.line_number} · {f.source}</div><p>{f.explanation}</p><code>{f.evidence}</code><small>Remediation: {f.suggested_remediation}</small></article>)}</>}</div></section></main>}

export type Finding={finding_id:string;cwe_id?:string|null;severity:string;confidence:number;message:string;explanation:string;file_path:string;line_number:number;line_range?:{start:number;end:number}|null;evidence?:string|null;source:string;suggested_remediation?:string|null;patch?:string|null};
export type AnalysisResult={filename:string;findings:Finding[];functions:string[];classes:string[];imports:string[];parse_error?:string|null};
export async function analyzeCode(code:string, filename='submitted.py'):Promise<AnalysisResult>{
 const base=process.env.NEXT_PUBLIC_API_URL||'http://localhost:8000';
 const response=await fetch(`${base}/api/analyze`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,filename})});
 if(!response.ok){const detail=await response.json().catch(()=>({detail:'Request failed'}));throw new Error(typeof detail.detail==='string'?detail.detail:detail.detail?.parse_error||'Analysis failed');}
 return response.json();
}

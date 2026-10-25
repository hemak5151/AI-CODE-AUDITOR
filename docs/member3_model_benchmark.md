\# Member 3 — Week 2 Model Benchmark



\## Objective



Compare two locally hosted coding models for response latency,

vulnerability detection, and patch generation using the project's

OllamaProvider interface.



\## Environment



\- Runtime: Python 3.13 on Windows

\- Model serving: Ollama

\- Primary model: qwen2.5-coder:7b

\- Lightweight model: qwen2.5-coder:0.5b

\- Timing method: Python perf\_counter

\- Repetitions: Two per task and model

\- Initial model call measured separately



\## Results



| Metric | Qwen2.5-Coder 7B | Qwen2.5-Coder 0.5B |

|---|---:|---:|

| Initial model call | 32.15 s | 3.43 s |

| Ollama-reported loaded model size | 4.72 GiB | 0.45 GiB |

| SQL concept run 1 | 6.09 s | 3.64 s |

| SQL concept run 2 | 4.90 s | 2.25 s |

| Vulnerability detection run 1 | 43.77 s | 2.78 s |

| Vulnerability detection run 2 | 20.79 s | 2.66 s |

| Patch generation run 1 | 18.45 s | 1.31 s |

| Patch generation run 2 | 6.56 s | 7.38 s |



\## Output Quality Observations



\### SQL concept



Both models explained the central security benefit of parameterized

queries. The smaller model produced substantially longer responses

than requested in some runs.



\### Vulnerability detection



The test snippet concatenated user-controlled input into an SQL query.



\- The 7B model identified a potential SQL injection, returned CWE-89,

&#x20; and identified line 2 in both runs.

\- The 0.5B model returned vulnerability=false in both runs, despite

&#x20; mentioning unsafe SQL construction in its rationale.

\- This illustrates that valid JSON does not guarantee a correct

&#x20; security assessment.



\### Patch generation



Both models generated a parameterized-query patch in one run.

The other responses were inconsistent: one omitted clear line

separation, while the smaller model also returned explanatory text

instead of only the requested replacement code.



\## Interpretation



The 0.5B model was faster and had a substantially smaller

Ollama-reported loaded model size in this environment. However, it

failed the vulnerability-detection example. The 7B model performed

better on this specific detection task but was slower.



These results support investigating a speed-versus-quality trade-off.

They do not establish general model superiority.



\## Limitations



\- Only one prompt was used for each task.

\- Each task had two measured repetitions per model.

\- The benchmark did not measure total system RAM consumption.

\- Output quality was reviewed manually, not using a large labelled

&#x20; evaluation dataset.

\- No broad conclusions about precision, recall, or F1 can be drawn.

\- Latency may vary with caching, machine load, and model loading.



\## Next Steps



1\. Integrate the Detector and Guideline Checker into the Week 3 workflow.

2\. Add structured run logging.

3\. Expand the evaluation set to include additional security cases.

4\. Measure detection quality with labelled examples.

5\. Repeat timing experiments before drawing research conclusions.

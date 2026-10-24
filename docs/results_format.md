# Results file format (for the dashboard)

Put CSV files in `evaluation/results/`. One row per configuration and CWE.

```csv
config,cwe,precision,recall,f1,fpr,n,f1_lo,f1_hi
C1,ALL,0.00,0.00,0.00,0.00,0,,
```

- `config`: C1, C2, C3, C4 or C5 (rows with other values are ignored)
- `cwe`: a CWE id such as `CWE-89`, or `ALL` for the overall row
- `precision`, `recall`, `f1`: required, between 0 and 1
- `fpr`, `n`, `f1_lo`, `f1_hi`: optional (false-positive rate, test samples, bootstrap interval)
- Files without a `config` column (like `example.csv`) are ignored.
- With no usable rows, the dashboard shows flagged sample data.

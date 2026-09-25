# Dataset integration

V7 supports the datasets named in the SIH presentation without redistributing them:

- **CIC-IDS2017 / CSE-CIC-IDS2018:** `python -m ml.train --dataset cic --path /path/to/file.csv`
- **UNSW-NB15:** `python -m ml.train --dataset unsw --path /path/to/file.csv`
- **DGArchive:** `python -m ml.train --dataset dgarchive --path /path/to/domains.txt`

The adapters normalize common column names into the V7 feature schema and produce a held-out evaluation report. Dataset-specific labels that cannot be mapped to the V7 threat taxonomy are excluded from training. Third-party datasets must be obtained and licensed separately.

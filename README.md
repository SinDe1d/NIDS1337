# NIDS

## Quick start

```bash
cd github
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 1. Train and persist the model. This works without downloading a dataset.
python scripts/train.py

# 2. Generate a demo PCAP containing benign traffic, a port scan and a SYN flood.
python scripts/generate_demo_data.py

# 3. Replay it through capture -> flows -> features -> rules/ML -> SQLite.
python scripts/replay.py data/demo_attacks.pcap

# 4. Start the dashboard, then open http://127.0.0.1:5000
python app.py
```

The supplied `data/test.pcap` can also be replayed. The same pipeline is used
for live capture:

```bash
sudo python scripts/capture.py --interface eth0
```

The dashboard supports alert filtering, IP flow search, flow drill-down, and
true/false-positive analyst feedback.

## Public dataset training

The trainer accepts an exported CICIDS2017 or UNSW-NB15 CSV:

```bash
python scripts/train.py --csv data/CICIDS2017.csv --label-column Label
```

It compares Logistic Regression and Random Forest, writes the selected model to
`models/nids_model.joblib`, and writes per-class precision, recall, F1 plus the
confusion matrix to `models/metrics.json`. Common CICIDS column names are mapped
automatically; missing assignment features are safely filled with zero. For a
research result, use the full cleaned dataset and document the mapping.

## Assignment coverage

| Requirement | Implementation |
| --- | --- |
| Live capture and PCAP replay | `nids/capture.py`, `scripts/capture.py`, `scripts/replay.py` |
| Bidirectional 5-tuple flows | `nids/flows.py` with configurable idle/active timeouts |
| At least 20 features | 28 features in `nids/features.py` |
| Two models and metrics | `scripts/train.py` with Logistic Regression + Random Forest |
| Runtime model persistence | `joblib` artifact loaded by `nids/detector.py` |
| Near-real-time pipeline | `nids/pipeline.py` callback on flow completion |
| Threshold and ignore-list | `PipelineConfig` in `nids/pipeline.py` |
| Dashboard and filtering | `static/`, Flask API in `app.py` |
| SQLite persistence | `nids/storage.py` |
| Bonus rules | Port scan and SYN flood in `nids/rules.py` |
| Analyst feedback | Dashboard buttons and `POST /api/alerts/:id/feedback` |

## API

- `GET /api/health`
- `GET /api/summary`
- `GET /api/alerts?type=Port%20Scan`
- `GET /api/alerts/:id`
- `POST /api/alerts/:id/feedback` with `{"value":"true_positive"}`
- `GET /api/flows?search=10.0.0.50`

## Safety and limitations

Only capture traffic on networks where you have permission. This is an
educational baseline, not a replacement for Suricata, Zeek, or a commercial IDS.
The built-in demo dataset is synthetic and is only for validating the software
path. Real model quality depends on dataset cleaning, class balance, leakage
prevention, threshold tuning, and testing on traffic unlike the training data.


==============================================================================================================================
THIS IS MADE BY ADAM aka (SinDe1d) ... enjoy :)

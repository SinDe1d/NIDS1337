# Short technical report

## 1. Scope

This project implements the required capture-to-alert path for a lightweight
Network Intrusion Detection System. It deliberately keeps the deployment small:
Python, Scapy, scikit-learn, Flask, and SQLite are enough to run the demo on one
machine.

## 2. Flow reconstruction

Each IPv4 packet is assigned to a key of source IP, destination IP, source port,
destination port, and protocol. A reverse key is checked so response packets are
placed in the same bidirectional flow. Flows close after an idle timeout or an
active timeout. PCAP replay uses the exact same packet handler as live capture,
which makes the demonstration reproducible.

## 3. Feature engineering

The extractor emits 28 numerical features: duration, forward/backward packet and
byte counts, packet-size and inter-arrival summaries, all requested TCP flag
counts, rate features, direction ratios, packet span, and a total flag count.
Zero-safe statistics prevent single-packet and handshake flows from producing
NaN or division-by-zero values.

## 4. Model comparison

`scripts/train.py` compares scaled Logistic Regression with a balanced Random
Forest using a stratified hold-out split. It reports precision, recall, F1 per
class, and a confusion matrix, then persists the highest macro-F1 model. The
default synthetic dataset is a smoke-test fixture, not a scientific benchmark.
The intended final experiment is a cleaned CICIDS2017 or UNSW-NB15 export passed
with `--csv`.

## 5. Real-time pipeline

When a flow completes, the capture callback extracts features, stores the flow,
checks the configurable ignore-list, runs the rule engine and model, and stores
an alert. Scikit-learn inference is local and normally completes well below the
five-second assignment budget. The rule engine gives immediate, explainable
signals for port scans and SYN floods.

## 6. Dashboard and limitations

The Flask dashboard reads persisted flows and alerts through JSON endpoints.
Analysts can filter attack types, search IPs, inspect flow details, and label an
alert as a true or false positive. Raw packets are available during capture but
are not stored by default to keep SQLite small; packet retention can be added
later if forensic storage is required.

Model performance can be optimistic when random rows from the same capture are
split across train and test. A production evaluation should split by capture
day or scenario, tune the confidence threshold on a validation set, and compare
against Suricata or Zeek.

What sliding-window catches that ML misses

Sudden, sharp spikes in event volume from a single source — a brute-force login attempt or port scan generates dozens of events in seconds. The sliding window catches this instantly, on the very event that crosses the threshold, with zero training required and a fully explainable reason.

Isolation Forest, scored only every 5-second batch flush, reacts slightly slower and doesn't inherently reason about rate unless rate is explicitly engineered as a feature (which ip_event_count partially covers, but not as precisely as the deque-based counter).

What Isolation Forest catches that sliding-window misses

Subtle pattern anomalies that don't involve a volume spike. For example: a single login attempt at 3 AM from an IP that normally only appears during business hours, or an unusual combination of severity and event type that doesn't match typical traffic — one malware_alert event mixed into an otherwise quiet stream. None of these cross any volume threshold, so the sliding window has nothing to flag. Isolation Forest catches these because it's comparing the event's overall feature profile (hour, event type, severity, IP frequency) against the shape of all the training data, not counting occurrences.

Why both, not just one

Relying only on the sliding window means missing low-volume, subtle attacks — a slow, patient reconnaissance attempt might never cross a rate threshold. Relying only on Isolation Forest means losing the instant, fully-explainable alert on an obvious brute-force spike, and inheriting ML's dependence on a representative training set (it can only flag what looks statistically different from what it's already seen).

Running them in parallel and tagging each anomaly with its source (sliding_window or ml) gives defense in depth: a fast, deterministic layer for obvious volume-based attacks, and a slower, adaptive layer for subtle pattern-based ones — the same logic real SIEM products use when combining rule-based correlation with ML-driven behavioral analytics.

Known limitations (worth being upfront about)
The Isolation Forest model is trained on whatever traffic existed at training time — if that data itself contained undetected anomalies, the model partially "normalizes" them. Retraining periodically on fresh, reviewed data mitigates this over time.
The sliding-window threshold (10 events/60s) is a fixed heuristic tuned for this dataset's traffic pattern — a production deployment would want this configurable per tenant, since normal traffic volume varies by environment.
Neither detector currently correlates across IPs (e.g., a distributed attack from many low-volume sources) — that's a natural "next iteration" talking point if asked about future improvements.
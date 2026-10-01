# Phone-session churn experiment

`examples/churn.rs` runs the actual client, signatures, VLD0 encryption, queue,
fanout and independently bounded node stores over an in-process transport.
New scale/churn/load runs belong on Crow; hosted CI retains the bounded contract
and original upstream oracle. The historical GitHub results below remain evidence
for their exact source and workload.
No code runs against public Tor or Veilid and no infrastructure stores records.

## Model and reproducibility

The event schedule is deterministic with seeds 1, 2 and 3. These are declared
synthetic assumptions, not an empirical trace or calibrated prediction:

- Populations: 20, 50, 100, 250 and 1,000 phones.
- 72 hours at five-minute resolution; 5–20-minute sessions with 1–4 hours idle.
- Three evenly distributed timezones; no new session between midnight and 07:00.
- Startup is staggered over four hours. Only phones currently using the app serve
  records; owners exclude their own node from remote replication targets.
- Nodes retain their remote cache while offline. Each day, a deterministic
  1% replacement probability destroys both remote cache and local owner state.
  Replacements keep the simulated node coordinate. Stable synthetic signing
  keys model surviving synced-passkey access. Lost payloads are not regenerated:
  recovery requires surviving network records.
- Baseline: one 1-KiB encrypted record per phone with native capacity. Pressure:
  three such records per phone with browser capacity. This comparison changes
  both load and capacity deliberately; it does not isolate a browser effect.
  At these payload sizes, the record-count limit determines eviction.
- Owners create data on their first session and inspect/rehydrate on later opens.
  Pending writes flush when the owner is online. There are no always-on storage
  nodes and no autonomous remote replication or record expiration.

An external observer samples fixed, evenly spaced record locators at 0, 1, 6,
12, 24, 48 and 72 hours. It never stores or writes records. Availability means
at least one reachable, valid signed value; read quorum means three identical
copies. Never-published records remain in the sample denominator. The sample
has roughly 48 records (all records for smaller populations). Raw rows include
online population, evictions, device replacements, sessions and initially
completed five-node writes. The last metric counts the first write attempt,
not later successful flushes.

The model has perfect current peer discovery, instantaneous RPCs, no packet
loss, no adversaries, and no Tor bootstrap/publication delay. Closest-node search
is bounded by the production fanout port. A disconnected node is unreachable;
there is no latency model. This is an optimistic transport model and cannot
qualify the Tor backend, browser suspension, network privacy or user recovery.

## Results

Measured on [CI run 36886335654](https://github.com/corbet-foss/cdht/actions/runs/36886335654)
from `5cc20d9c92fedd6e37a86d3d8f98404b89bbf414`.
[Raw CSV](results/churn-5cc20d9.csv): 210 population/seed/time rows.
Each cell is **available % / three-copy agreement %**, pooling sampled records
across the three seeds. Startup is intentionally included; these are not
conditional survival percentages for already-published records.

### Native capacity, one record per phone

| Phones | 1 h | 6 h | 12 h | 24 h | 48 h | 72 h |
|---|---|---|---|---|---|---|
| 20 | 0.0 / 0.0 | 1.7 / 0.0 | 36.7 / 5.0 | 28.3 / 0.0 | 78.3 / 0.0 | 70.0 / 0.0 |
| 50 | 2.7 / 0.0 | 20.7 / 1.3 | 60.7 / 8.7 | 34.7 / 1.3 | 96.0 / 31.3 | 95.3 / 23.3 |
| 100 | 1.3 / 0.7 | 24.0 / 4.0 | 40.7 / 5.3 | 78.0 / 24.0 | 98.0 / 51.3 | 98.0 / 71.3 |
| 250 | 4.0 / 2.0 | 42.0 / 8.0 | 54.7 / 4.7 | 90.7 / 50.0 | 98.7 / 78.7 | 99.3 / 92.7 |
| 1000 | 2.7 / 0.7 | 34.0 / 4.7 | 43.3 / 4.7 | 90.7 / 35.3 | 98.0 / 70.7 | 98.7 / 82.0 |

### Browser capacity, three records per phone

| Phones | 1 h | 6 h | 12 h | 24 h | 48 h | 72 h |
|---|---|---|---|---|---|---|
| 20 | 0.0 / 0.0 | 1.7 / 0.0 | 36.7 / 5.0 | 28.3 / 0.0 | 78.3 / 0.0 | 70.6 / 0.0 |
| 50 | 2.7 / 0.0 | 20.7 / 1.3 | 60.7 / 8.7 | 34.7 / 1.3 | 89.3 / 20.7 | 78.0 / 9.3 |
| 100 | 1.3 / 0.7 | 24.0 / 4.0 | 39.3 / 4.7 | 72.7 / 16.0 | 78.7 / 15.3 | 76.0 / 13.3 |
| 250 | 4.0 / 2.0 | 42.0 / 8.0 | 52.7 / 4.7 | 81.3 / 32.7 | 78.7 / 30.0 | 81.3 / 22.7 |
| 1000 | 3.4 / 1.4 | 33.3 / 2.0 | 43.5 / 4.8 | 72.8 / 24.5 | 72.8 / 19.7 | 78.9 / 24.5 |

At 72 hours the 20-phone population had no sampled three-copy read quorum in
either workload. A larger population improved this scenario but did not make
retention unconditional: capacity pressure sharply reduced agreement even at
1,000 phones. Available copies can disappear between samples, and a successful
sample does not establish continuous availability. No universal population
threshold, service-level guarantee or Tor qualification follows from this model.

## Conditional device-loss recovery

New runs additionally record `recovery_*` columns. An eligible loss affects a
phone used in the previous 24 hours that still held its own data and whose every
record completed a five-node write before the loss (including a later successful
rehydration or offline flush). The device
then loses both its node store and its client state. The same supplied synthetic
identity/read capability recreates the locators, but never regenerates payloads.
On subsequent ordinary sessions, the fresh client must recover and decrypt every
record to the original bytes. Measurement bookkeeping contains only locators and
times and makes no extra reads or writes that could help recovery.

`recovery_complete_24h` counts full recovery within 24 hours;
`recovery_failed_24h` counts eligible losses not fully recovered by that deadline.
`recovery_pending` means the observation window has not finished, and
`recovery_censored` means another device loss ended it prematurely. Report
complete / (complete + failed), with both raw counts; exclude pending/censored
events. `recovery_minutes_total` supports a mean delay among completed recoveries.
The 24-hour window is a measurement choice, not an approved product service level.
Delay includes waiting until the next ordinary app session; it is not transfer
latency. Three seeds and rare replacement events give small samples, especially
at small populations; zero observed failures is not a guarantee.

| Capacity / records per phone | Phones | Restored / observed within 24 h | Pending | Censored | Mean minutes after loss, restored phones |
|---|---|---|---|---|---|
| native / 1 | 20 | 0 / 0 | 0 | 0 | n/a |
| native / 1 | 50 | 0 / 0 | 1 | 0 | n/a |
| native / 1 | 100 | 9 / 9 | 3 | 0 | 320.6 |
| native / 1 | 250 | 12 / 12 | 7 | 0 | 273.8 |
| native / 1 | 1000 | 59 / 59 | 30 | 0 | 206.7 |
| browser / 3 | 20 | 0 / 0 | 0 | 0 | n/a |
| browser / 3 | 50 | 0 / 0 | 1 | 0 | n/a |
| browser / 3 | 100 | 9 / 9 | 3 | 0 | 360.6 |
| browser / 3 | 250 | 9 / 12 | 7 | 0 | 496.7 |
| browser / 3 | 1000 | 50 / 59 | 30 | 0 | 348.6 |

Counts pool the three seeds. An observed event is complete or past its 24-hour
deadline; pending and censored events are excluded. Zero observed events means
no estimate. The added measurement bookkeeping left all original availability
columns byte-identical to the preceding `fa10a07` run.

The pressure workload missed the recovery window for 9 of 59 observed losses at
1,000 phones, and 3 of 12 at 250 phones. It does not meet the active-member restore
promise under this model, even with ideal transport. Native capacity and one
record per phone had no observed failure in these small samples; that is evidence
for this workload, not a passed product acceptance gate.

The active-member device-loss acceptance promise still needs the product toy
scenario and actual transport qualification. Aggregate read availability,
including never-published records, cannot establish that promise. The component
test `fresh_device_restores_sealed_state_and_offline_messages_without_the_old_device`
proves the fresh-client path when replicas survive, with injected key capabilities;
it is not a WebAuthn/PRF, full identity/membership or real-Tor integration test.

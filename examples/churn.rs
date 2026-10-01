//! Synthetic phone sessions over the real record implementation, with no sockets.
//! This models availability, not Tor latency, routing privacy or measured user behavior.
#[path = "../tests/common/mod.rs"]
mod common;
#[path = "../tests/common/network.rs"]
mod simulation;
use cdht::{
    Backend, Capacity, Dht, EncryptionKey, NetworkBackend, RecordKey, Schema, WriteOutcome,
};
use common::{TestKey, TestVerifier, key_bytes};
use futures_executor::block_on;
use simulation::SimNetwork;
use std::collections::BTreeSet;

type Client = Dht<NetworkBackend<SimNetwork, TestVerifier>, TestVerifier>;
struct Phone {
    client: Client,
    owner: TestKey,
    records: Vec<RecordKey>,
    active: usize,
    next_session: usize,
    initialized: bool,
    last_session: Option<usize>,
    recovery: Option<usize>,
    held: BTreeSet<RecordKey>,
}

// Measurement metadata holds no payload and never helps a client restore it.
struct Recovery {
    started: usize,
    restored: BTreeSet<RecordKey>,
    finished: Option<usize>,
    censored: Option<usize>,
}

fn recovery_counts(recoveries: &[Recovery], tick: usize) -> (usize, usize, usize, usize, usize) {
    let (mut complete, mut failed, mut pending, mut censored, mut minutes) = (0, 0, 0, 0, 0);
    for recovery in recoveries {
        let deadline = recovery.started + 288;
        if let Some(finished) = recovery.finished.filter(|finished| *finished <= deadline) {
            complete += 1;
            minutes += (finished - recovery.started) * 5;
        } else if recovery.censored.is_some_and(|ended| ended < deadline) {
            censored += 1;
        } else if tick >= deadline {
            failed += 1;
        } else {
            pending += 1;
        }
    }
    (complete, failed, pending, censored, minutes)
}

// Event-schedule PRNG only; record cryptography uses the production primitives.
struct Schedule(u64);
impl Schedule {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn range(&mut self, lower: usize, upper: usize) -> usize {
        lower + self.next() as usize % (upper - lower)
    }
}

async fn run(population: usize, records_per_phone: usize, seed: u64, browser: bool) {
    let capacity = if browser {
        Capacity::BROWSER
    } else {
        Capacity::NATIVE
    };
    let network = SimNetwork::new(population, capacity);
    let mut schedule = Schedule(seed);
    let secret = EncryptionKey::from_bytes([42; 32]);
    let mut phones = Vec::new();
    for i in 0..population {
        network.online(i, false);
        let mut identity = [0; 32];
        identity[..8].copy_from_slice(&(i as u64).to_le_bytes());
        identity[8..16].copy_from_slice(&seed.to_le_bytes());
        let owner = key_bytes(*blake3::hash(&identity).as_bytes());
        let mut client = Dht::new(
            NetworkBackend::new(network.for_node(i), TestVerifier),
            TestVerifier,
        );
        let mut records = Vec::new();
        for count in 1..=records_per_phone {
            records.push(
                client
                    .create(&Schema::dflt(count as u16).unwrap(), &owner)
                    .await
                    .unwrap(),
            );
        }
        phones.push(Phone {
            client,
            owner,
            records,
            active: 0,
            next_session: schedule.range(0, 48),
            initialized: false,
            last_session: None,
            recovery: None,
            held: BTreeSet::new(),
        });
    }
    let intended = population * records_per_phone;
    let mut confirmed = std::collections::BTreeSet::new();
    let mut published = BTreeSet::new();
    let mut recoveries: Vec<Recovery> = Vec::new();
    let mut losses = 0;
    let mut sessions = 0;
    // Five-minute resolution, 72 hours. Three timezones avoid global overnight silence.
    for tick in 0..=864 {
        let mut starts = Vec::new();
        for (i, phone) in phones.iter_mut().enumerate() {
            if phone.active > 0 {
                phone.active -= 1;
            }
            if tick >= phone.next_session && phone.active == 0 {
                let hour = (tick / 12 + (i % 3) * 8) % 24;
                if hour < 7 {
                    phone.next_session += (7 - hour) * 12;
                } else {
                    phone.active = schedule.range(1, 5); // 5–20 minute sessions
                    phone.next_session = tick + phone.active + schedule.range(12, 49); // 1–4 hours idle
                    starts.push(i);
                    sessions += 1;
                }
            }
            network.online(i, phone.active > 0);
        }
        network.advance_to(tick as u64 * 300_000);
        // 1% daily permanent device replacement: both remote cache and owner cache lost.
        // Stable synthetic signing keys stand for surviving synced passkey access.
        if tick > 0 && tick % 288 == 0 {
            for (i, phone) in phones.iter_mut().enumerate() {
                if schedule.range(0, 100) == 0 {
                    if let Some(index) = phone.recovery.take() {
                        recoveries[index].censored = Some(tick);
                    }
                    // Condition on regular use and a completed five-node write for
                    // every record before the loss, including later offline flushes.
                    if phone.last_session.is_some_and(|last| tick - last <= 288)
                        && phone.held.len() == phone.records.len()
                        && phone
                            .records
                            .iter()
                            .all(|record| published.contains(record))
                    {
                        phone.recovery = Some(recoveries.len());
                        recoveries.push(Recovery {
                            started: tick,
                            restored: BTreeSet::new(),
                            finished: None,
                            censored: None,
                        });
                    }
                    network.replace(i);
                    phone.held.clear();
                    phone.client = Dht::new(
                        NetworkBackend::new(network.for_node(i), TestVerifier),
                        TestVerifier,
                    );
                    for count in 1..=records_per_phone {
                        phone
                            .client
                            .create(&Schema::dflt(count as u16).unwrap(), &phone.owner)
                            .await
                            .unwrap();
                    }
                    losses += 1;
                }
            }
        }
        for i in starts {
            let phone = &mut phones[i];
            phone.last_session = Some(tick);
            // Both open's rehydration and flush can complete a pending write.
            let mut pending: BTreeSet<_> =
                phone.client.state().queue().iter().map(|q| q.key).collect();
            for record in &phone.records {
                if !phone.initialized {
                    if matches!(
                        phone
                            .client
                            .set(record, 0, &[0x5a; 1024], &phone.owner, Some(&secret))
                            .await
                            .unwrap(),
                        WriteOutcome::Written { .. }
                    ) {
                        confirmed.insert(*record);
                        published.insert(*record);
                    }
                    phone.held.insert(*record);
                } else {
                    // Open republishes surviving owner state. After device replacement,
                    // get can recover only what remains on reachable remote nodes.
                    let _ = phone.client.open(record).await;
                    if let Ok(Some(data)) = phone.client.get(record, 0, Some(&secret)).await
                        && data.as_slice() == [0x5a; 1024]
                    {
                        phone.held.insert(*record);
                        if let Some(index) = phone.recovery {
                            let recovery = &mut recoveries[index];
                            recovery.restored.insert(*record);
                            if recovery.restored.len() == phone.records.len()
                                && recovery.finished.is_none()
                            {
                                recovery.finished = Some(tick);
                            }
                        }
                    }
                }
            }
            phone.initialized = true;
            pending.extend(phone.client.state().queue().iter().map(|q| q.key));
            if let Ok(report) = phone.client.flush().await {
                for record in pending {
                    if !phone.client.state().queue().iter().any(|q| q.key == record)
                        && !report.stale.iter().any(|(key, _)| *key == record)
                    {
                        published.insert(record);
                    }
                }
            }
        }
        if [0, 12, 72, 144, 288, 576, 864].contains(&tick) {
            let online = phones.iter().filter(|p| p.active > 0).count();
            let mut any = 0;
            let mut quorum = 0;
            let mut sampled = 0;
            // A fixed evenly-spaced sample includes never-published records in the denominator.
            for index in (0..intended).step_by((intended / 48).max(1)) {
                let phone = &phones[index / records_per_phone];
                let record = phone.records[index % records_per_phone];
                let observer = NetworkBackend::new(network.clone(), TestVerifier);
                sampled += 1;
                if observer.descriptor(&record).await.ok().flatten().is_some()
                    && let Ok(report) = observer.read(&record, 0).await
                {
                    any += usize::from(report.value.is_some());
                    quorum += usize::from(report.has_consensus());
                }
            }
            let (complete, failed, pending, censored, minutes) = recovery_counts(&recoveries, tick);
            println!(
                "{seed},{population},{records_per_phone},{},{},{online},{intended},{sampled},{any},{quorum},{},{losses},{sessions},{},{},{complete},{failed},{pending},{censored},{minutes}",
                if browser { "browser" } else { "native" },
                tick * 5,
                network.evictions(),
                confirmed.len(),
                recoveries.len()
            );
        }
    }
}
fn main() {
    println!(
        "seed,population,records_per_phone,capacity,minutes,online,intended,sampled,available,read_quorum,evictions,replacements,sessions,initial_five_node_writes,recovery_eligible,recovery_complete_24h,recovery_failed_24h,recovery_pending,recovery_censored,recovery_minutes_total"
    );
    block_on(async {
        for seed in [1, 2, 3] {
            for population in [20, 50, 100, 250, 1000] {
                run(population, 1, seed, false).await;
                run(population, 3, seed, true).await;
            }
        }
    });
}

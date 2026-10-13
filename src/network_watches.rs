// Watch fanout and reconciliation rules ported from veilid-core
// storage_manager/watch_value.rs and outbound_watch_manager at dd8e2cdd.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use super::*;

struct StartingWatch<'a> {
    watches: &'a Mutex<BTreeMap<WatchId, RemoteWatch>>,
    id: WatchId,
    returned: bool,
}
impl Drop for StartingWatch<'_> {
    fn drop(&mut self) {
        if !self.returned
            && let Ok(mut watches) = self.watches.lock()
            && let Some(watch) = watches.get_mut(&self.id)
        {
            watch.abandoned = true;
        }
    }
}

impl<N: Network, V: Verifier> NetworkBackend<N, V> {
    pub(super) async fn start_watch(&self, key: &RecordKey) -> Result<WatchId, Error> {
        let _operation = self.watch_operation.lock().await;
        self.cleanup_abandoned_watches().await?;
        self.cached_descriptor(key)?;
        let id = {
            let mut watches = self.watches.lock().map_err(|_| Error::Unavailable)?;
            let mut next = self.next_watch.lock().map_err(|_| Error::Unavailable)?;
            let id = WatchId(*next);
            *next = next.checked_add(1).ok_or(Error::Unavailable)?;
            watches.insert(
                id,
                RemoteWatch {
                    key: *key,
                    nodes: Vec::new(),
                    pending: BTreeMap::new(),
                    reported: BTreeMap::new(),
                    next_reconcile_ms: 0,
                    abandoned: false,
                },
            );
            id
        };
        let mut starting = StartingWatch {
            watches: &self.watches,
            id,
            returned: false,
        };
        let result = self.reconcile_watch(id, &BTreeSet::new()).await;
        let accepted = self
            .watches
            .lock()
            .map_err(|_| Error::Unavailable)?
            .get(&id)
            .is_some_and(|watch| !watch.nodes.is_empty());
        if let Err(error) = result {
            let _ = self.remove_watch(id).await;
            return Err(error);
        }
        if !accepted {
            self.remove_watch(id).await?;
            return Err(Error::Unavailable);
        }
        // One or two accepted nodes are a partial watch, never three-node proof.
        starting.returned = true;
        Ok(id)
    }

    // Runs under watch_operation, so cancel cannot race an accepted replacement.
    async fn reconcile_watch(&self, id: WatchId, failed: &BTreeSet<NodeId>) -> Result<(), Error> {
        let (key, nodes, due) = {
            let watches = self.watches.lock().map_err(|_| Error::Unavailable)?;
            let watch = watches.get(&id).ok_or(Error::UnknownWatch)?;
            (watch.key, watch.nodes.clone(), watch.next_reconcile_ms)
        };
        let now = self.network.now_ms();
        if nodes.len() >= GET_VALUE_COUNT || now < due {
            return Ok(());
        }
        let mut accepted = nodes.len();
        let mut rejected = 0;
        // A failed discovery is silence; it cannot mean that every node refused.
        let mut pending = self.peers(&key).await.unwrap_or_default();
        let mut visited: BTreeSet<_> = nodes.iter().map(|node| node.node).collect();
        visited.extend(failed);
        while let Some(node) = self.next_peer(&key, &mut pending, &mut visited)? {
            match self.network.watch(&node, &key).await {
                Ok(remote) => {
                    let retained = self
                        .watches
                        .lock()
                        .ok()
                        .and_then(|mut watches| {
                            let watch = watches.get_mut(&id)?;
                            watch.nodes.push(RemoteLease { node, remote });
                            Some(())
                        })
                        .is_some();
                    if !retained {
                        let _ = self.network.cancel_watch(&node, remote).await;
                        return Err(Error::Unavailable);
                    }
                    accepted += 1;
                    if accepted >= GET_VALUE_COUNT {
                        break;
                    }
                }
                Err(Error::WatchRefused | Error::UnknownRecord) => rejected += 1,
                Err(_) => {}
            }
        }
        // Original next_reconcile_interval: below consensus retries after five
        // seconds unless all answers refused; otherwise wait sixty seconds.
        let interval = if accepted < GET_VALUE_COUNT && !(accepted == 0 && rejected > 0) {
            5_000
        } else {
            60_000
        };
        self.watches
            .lock()
            .map_err(|_| Error::Unavailable)?
            .get_mut(&id)
            .ok_or(Error::UnknownWatch)?
            .next_reconcile_ms = now.saturating_add(interval);
        Ok(())
    }

    pub(super) async fn stop_watch(&self, id: WatchId) -> Result<(), Error> {
        let _operation = self.watch_operation.lock().await;
        let cleanup = self.cleanup_abandoned_watches().await;
        let cancel = self.remove_watch(id).await;
        cleanup.and(cancel)
    }

    // Dropped callers cannot run async cleanup from Drop. Keep their known leases
    // until the next watch operation can cancel them; unknown in-flight requests
    // remain bounded by the node's original lease/quota, never assumed cancelled.
    async fn cleanup_abandoned_watches(&self) -> Result<(), Error> {
        let abandoned: Vec<_> = self
            .watches
            .lock()
            .map_err(|_| Error::Unavailable)?
            .iter()
            .filter_map(|(id, watch)| watch.abandoned.then_some(*id))
            .collect();
        let mut failure = None;
        for id in abandoned {
            if let Err(error) = self.remove_watch(id).await {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    async fn remove_watch(&self, id: WatchId) -> Result<(), Error> {
        let watch = self
            .watches
            .lock()
            .map_err(|_| Error::Unavailable)?
            .remove(&id);
        let mut failure = None;
        if let Some(watch) = watch {
            for lease in watch.nodes {
                // A failed peer must not prevent cancellation of other leases.
                if let Err(error) = self.network.cancel_watch(&lease.node, lease.remote).await {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    pub(super) async fn watch_changes(&self, id: WatchId) -> Result<Vec<Change>, Error> {
        let _operation = self.watch_operation.lock().await;
        self.cleanup_abandoned_watches().await?;
        let (key, nodes) = {
            let watches = self.watches.lock().map_err(|_| Error::Unavailable)?;
            let watch = watches.get(&id).ok_or(Error::UnknownWatch)?;
            (watch.key, watch.nodes.clone())
        };
        let descriptor = self.cached_descriptor(&key)?;
        let schema = descriptor.validate_for(&key, &self.verifier)?;
        let mut failed = BTreeSet::new();
        let mut failure = None;
        for lease in nodes {
            let changes = self
                .network
                .changes(&lease.node, lease.remote)
                .await
                .and_then(|changes| {
                    if changes.len() > schema.subkey_count()
                        || changes.iter().any(|change| {
                            change.key != key
                                || change.subkey as usize >= schema.subkey_count()
                                || change.seq > crate::MAX_SEQ
                        })
                    {
                        Err(Error::Encoding)
                    } else {
                        Ok(changes)
                    }
                });
            match changes {
                Ok(changes) => {
                    let mut watches = self.watches.lock().map_err(|_| Error::Unavailable)?;
                    let watch = watches.get_mut(&id).ok_or(Error::UnknownWatch)?;
                    for change in changes {
                        if watch
                            .reported
                            .get(&change.subkey)
                            .is_some_and(|seq| *seq >= change.seq)
                        {
                            continue;
                        }
                        watch
                            .pending
                            .entry(change.subkey)
                            .and_modify(|pending| {
                                if change.seq > pending.seq {
                                    *pending = change;
                                }
                            })
                            .or_insert(change);
                    }
                }
                Err(error) => {
                    failure.get_or_insert(error);
                    failed.insert(lease.node);
                    {
                        let mut watches = self.watches.lock().map_err(|_| Error::Unavailable)?;
                        let watch = watches.get_mut(&id).ok_or(Error::UnknownWatch)?;
                        watch.nodes.retain(|node| node.node != lease.node);
                        // Actual route/lease loss permits immediate reconciliation.
                        watch.next_reconcile_ms = self.network.now_ms();
                    }
                    let _ = self.network.cancel_watch(&lease.node, lease.remote).await;
                }
            }
        }
        self.reconcile_watch(id, &failed).await?;
        // Even if another node answered, signal the gap so the client refreshes.
        // Already consumed valid hints stay pending across this error/cancellation.
        if let Some(error) = failure {
            return Err(error);
        }
        let mut watches = self.watches.lock().map_err(|_| Error::Unavailable)?;
        let watch = watches.get_mut(&id).ok_or(Error::UnknownWatch)?;
        if watch.nodes.is_empty() {
            return Err(Error::UnknownWatch);
        }
        let changes: Vec<_> = std::mem::take(&mut watch.pending).into_values().collect();
        for change in &changes {
            watch.reported.insert(change.subkey, change.seq);
        }
        Ok(changes)
    }
}

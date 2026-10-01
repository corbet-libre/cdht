// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Upstream: veilid/veilid, dd8e2cdd72b5bf817172ac31c20872b168c5c8fc.
//! Veilid schema encoding and slot validation.
//! Port of veilid-core/src/veilid_api/types/dht/{schema/*.rs,derivation.rs}.

use crate::Error;
use crate::crypto::PublicKey;
use serde::{Deserialize, Serialize};

/// Largest value one subkey may hold (Veilid `MAX_SUBKEY_SIZE`).
pub const MAX_SUBKEY_SIZE: usize = 32_768;
/// Largest total record data (Veilid `MAX_RECORD_DATA_SIZE`).
pub const MAX_RECORD_DATA_SIZE: usize = 1_048_576;
/// Most subkeys a record may have (Veilid `DHTSchema::MAX_SUBKEY_COUNT`).
pub const MAX_SUBKEY_COUNT: usize = 1024;
/// Most distinct writers, owner included (Veilid `DHTSchema::MAX_WRITER_COUNT`).
pub const MAX_WRITER_COUNT: usize = 256;

const FCC_SMPL: [u8; 4] = *b"SMPL";
const MEMBER_ENTRY: usize = 32 + 2;

/// A writer and the number of consecutive subkeys it owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Member {
    /// The writer's public key (Veilid member id: for 32-byte keys, the key itself).
    #[serde(with = "crate::b64")]
    pub writer: PublicKey,
    /// Number of subkeys.
    pub subkeys: u16,
}

/// A validated Veilid DFLT or SMPL schema.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Schema {
    kind: [u8; 4],
    owner_subkeys: u16,
    members: Vec<Member>,
}

impl Schema {
    /// A schema with `owner_subkeys` owner subkeys and `members` in order.
    pub fn new(owner_subkeys: u16, members: Vec<Member>) -> Result<Self, Error> {
        let schema = Self {
            kind: FCC_SMPL,
            owner_subkeys,
            members,
        };
        schema.validate()?;
        Ok(schema)
    }

    /// Veilid's DFLT schema: owner-only subkeys, with a distinct compiled form.
    pub fn dflt(owner_subkeys: u16) -> Result<Self, Error> {
        let mut schema = Self::new(owner_subkeys, Vec::new())?;
        schema.kind = *b"DFLT";
        Ok(schema)
    }

    fn validate(&self) -> Result<(), Error> {
        let writers: std::collections::HashSet<_> = self
            .members
            .iter()
            .filter(|m| m.subkeys > 0)
            .map(|m| m.writer)
            .collect();
        let writer_count = writers.len() + usize::from(self.owner_subkeys > 0);
        if self.members.len() > 256
            || writer_count > MAX_WRITER_COUNT
            || self.subkey_count() == 0
            || self.subkey_count() > MAX_SUBKEY_COUNT
        {
            return Err(Error::InvalidSchema);
        }
        Ok(())
    }

    /// Owner subkey count.
    pub fn owner_subkeys(&self) -> u16 {
        self.owner_subkeys
    }

    /// Members in subkey order.
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// Total number of subkeys.
    pub fn subkey_count(&self) -> usize {
        self.members
            .iter()
            .fold(usize::from(self.owner_subkeys), |acc, m| {
                acc + usize::from(m.subkeys)
            })
    }

    /// Largest value any subkey of this record may hold.
    pub fn max_value_len(&self) -> usize {
        MAX_SUBKEY_SIZE.min(MAX_RECORD_DATA_SIZE / self.subkey_count())
    }

    /// Veilid's compiled SMPL form: the bytes the owner signs.
    pub fn compile(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.members.len() * MEMBER_ENTRY);
        out.extend_from_slice(&self.kind);
        out.extend_from_slice(&self.owner_subkeys.to_le_bytes());
        for member in &self.members {
            out.extend_from_slice(&member.writer);
            out.extend_from_slice(&member.subkeys.to_le_bytes());
        }
        out
    }

    /// Parse and validate a compiled schema.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == 6 && bytes[..4] == *b"DFLT" {
            return Self::dflt(u16::from_le_bytes([bytes[4], bytes[5]]));
        }
        if bytes.len() < 6
            || bytes.len() > 6 + 256 * MEMBER_ENTRY
            || bytes[..4] != FCC_SMPL
            || !(bytes.len() - 6).is_multiple_of(MEMBER_ENTRY)
        {
            return Err(Error::InvalidSchema);
        }
        let owner_subkeys = u16::from_le_bytes([bytes[4], bytes[5]]);
        let members = bytes[6..]
            .as_chunks::<MEMBER_ENTRY>()
            .0
            .iter()
            .map(|entry| {
                let mut writer = [0u8; 32];
                writer.copy_from_slice(&entry[..32]);
                Member {
                    writer,
                    subkeys: u16::from_le_bytes([entry[32], entry[33]]),
                }
            })
            .collect();
        Self::new(owner_subkeys, members)
    }

    /// Who may write `subkey`: the owner for the owner range, else the member whose range
    /// contains it. `None` if the subkey is out of range.
    pub fn writer_of(&self, owner: &PublicKey, subkey: u32) -> Option<PublicKey> {
        let mut index = usize::try_from(subkey).ok()?;
        if index < usize::from(self.owner_subkeys) {
            return Some(*owner);
        }
        index -= usize::from(self.owner_subkeys);
        for member in &self.members {
            if index < usize::from(member.subkeys) {
                return Some(member.writer);
            }
            index -= usize::from(member.subkeys);
        }
        None
    }

    /// All subkeys writable by this key, including repeated SMPL member entries.
    pub fn subkeys_of(&self, owner: &PublicKey, writer: &PublicKey) -> Vec<u32> {
        (0..self.subkey_count() as u32)
            .filter(|s| self.writer_of(owner, *s).as_ref() == Some(writer))
            .collect()
    }

    /// Check a write against the schema (Veilid `check_subkey_value_data_smpl`).
    pub fn check_write(
        &self,
        owner: &PublicKey,
        subkey: u32,
        writer: &PublicKey,
        data_len: usize,
    ) -> Result<(), Error> {
        match self.writer_of(owner, subkey) {
            None => Err(Error::SubkeyOutOfRange),
            Some(allowed) if allowed != *writer => Err(Error::WrongWriter),
            Some(_) if data_len > self.max_value_len() => Err(Error::ValueTooLarge),
            Some(_) => Ok(()),
        }
    }
}

//! Schema byte boundaries, identical on native and browser Wasm.
//!
//! Exercises only the real public `Schema` API (`new`, `dflt`, `compile`,
//! `parse`, `writer_of`, `max_value_len`). All writer identifiers are fixed
//! synthetic 32-byte arrays, never generated secret keys.

use cdht::{Error, Member, Schema};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

/// A fixed synthetic writer identifier for tests. No secret key involved.
fn writer(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn member(byte: u8, subkeys: u16) -> Member {
    Member {
        writer: writer(byte),
        subkeys,
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn dflt_and_smpl_have_distinct_byte_forms() {
    let dflt = Schema::dflt(3).unwrap();
    let smpl = Schema::new(3, Vec::new()).unwrap();
    let mut dflt_bytes = b"DFLT".to_vec();
    dflt_bytes.extend_from_slice(&3u16.to_le_bytes());
    let mut smpl_bytes = b"SMPL".to_vec();
    smpl_bytes.extend_from_slice(&3u16.to_le_bytes());
    assert_eq!(dflt.compile(), dflt_bytes);
    assert_eq!(smpl.compile(), smpl_bytes);
    assert_ne!(dflt.compile(), smpl.compile());
    assert_eq!(Schema::parse(&dflt_bytes).unwrap(), dflt);
    assert_eq!(Schema::parse(&smpl_bytes).unwrap(), smpl);
    assert_ne!(
        Schema::parse(&dflt_bytes).unwrap(),
        Schema::parse(&smpl_bytes).unwrap()
    );
    // Same slot layout, so the same writer and size semantics on both forms.
    let owner = writer(0x0a);
    assert_eq!(dflt.subkey_count(), 3);
    assert_eq!(dflt.max_value_len(), smpl.max_value_len());
    assert_eq!(dflt.writer_of(&owner, 2), smpl.writer_of(&owner, 2));
    // A DFLT schema with no subkeys at all is invalid.
    assert_eq!(Schema::dflt(0).unwrap_err(), Error::InvalidSchema);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn zero_subkey_members_do_not_shift_writer_ranges() {
    let owner = writer(0x0a);
    let schema = Schema::new(
        2,
        vec![
            member(0x01, 0),
            member(0xa1, 2),
            member(0x02, 0),
            member(0xb2, 2),
            member(0x03, 0),
        ],
    )
    .unwrap();
    assert_eq!(schema.members().len(), 5);
    assert_eq!(schema.subkey_count(), 6);
    assert_eq!(schema.writer_of(&owner, 0), Some(owner));
    assert_eq!(schema.writer_of(&owner, 1), Some(owner));
    assert_eq!(schema.writer_of(&owner, 2), Some(writer(0xa1)));
    assert_eq!(schema.writer_of(&owner, 3), Some(writer(0xa1)));
    assert_eq!(schema.writer_of(&owner, 4), Some(writer(0xb2)));
    assert_eq!(schema.writer_of(&owner, 5), Some(writer(0xb2)));
    assert_eq!(schema.writer_of(&owner, 6), None);
    // The zero-subkey writers own no slots, so they claim nothing.
    for idle in [0x01, 0x02, 0x03] {
        assert!(schema.subkeys_of(&owner, &writer(idle)).is_empty());
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn every_prefix_truncation_of_a_small_smpl_schema() {
    let schema = Schema::new(1, vec![member(0xa1, 2), member(0xb2, 3)]).unwrap();
    let full = schema.compile();
    assert_eq!(full.len(), 6 + 2 * (32 + 2));
    // Complete member-entry boundaries: 6 (owner only), 40 (one member), 74.
    let boundaries = [
        (6, 1, Schema::new(1, Vec::new()).unwrap()),
        (40, 3, Schema::new(1, vec![member(0xa1, 2)]).unwrap()),
        (74, 6, schema.clone()),
    ];
    for len in 0..=full.len() {
        let parsed = Schema::parse(&full[..len]);
        match boundaries.iter().find(|(boundary, _, _)| *boundary == len) {
            Some((_, count, expected)) => {
                let parsed = parsed.unwrap();
                assert_eq!(parsed.subkey_count(), *count);
                assert_eq!(&parsed, expected);
                assert_eq!(parsed.compile(), full[..len]);
            }
            None => assert_eq!(parsed.unwrap_err(), Error::InvalidSchema),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn unknown_magic_and_trailing_partial_entries_are_rejected() {
    let schema = Schema::new(1, vec![member(0xa1, 2)]).unwrap();
    let full = schema.compile();
    assert_eq!(full.len(), 40);
    // Unknown magic with an otherwise well-formed body length.
    let mut unknown = full.clone();
    unknown[..4].copy_from_slice(b"XXXX");
    assert_eq!(Schema::parse(&unknown).unwrap_err(), Error::InvalidSchema);
    // DFLT magic is only valid at exactly 6 bytes, never with a member body.
    let mut dflt_body = full.clone();
    dflt_body[..4].copy_from_slice(b"DFLT");
    assert_eq!(Schema::parse(&dflt_body).unwrap_err(), Error::InvalidSchema);
    // Trailing partial entry bytes are rejected.
    for extra in [1, 17, 33] {
        let mut partial = full.clone();
        partial.extend(std::iter::repeat_n(0xaa, extra));
        assert_eq!(Schema::parse(&partial).unwrap_err(), Error::InvalidSchema);
    }
    // A trailing complete entry parses as a longer schema, not as garbage.
    let mut longer = full.clone();
    longer.extend_from_slice(&writer(0xb2));
    longer.extend_from_slice(&4u16.to_le_bytes());
    let parsed = Schema::parse(&longer).unwrap();
    assert_eq!(parsed.members().len(), 2);
    assert_eq!(parsed.subkey_count(), 7);
    assert_eq!(parsed.compile(), longer);
    // All-zero member slots with no owner slots hold nothing, so they are invalid.
    let mut empty = b"SMPL".to_vec();
    empty.extend_from_slice(&0u16.to_le_bytes());
    empty.extend_from_slice(&writer(0xa1));
    empty.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(Schema::parse(&empty).unwrap_err(), Error::InvalidSchema);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn subkey_boundary_1024_accepted_and_1025_refused() {
    let slots = |extra_first: u16| {
        [0xa1, 0xb2, 0xc3, 0xd4]
            .iter()
            .enumerate()
            .map(|(i, byte)| member(*byte, 256 + if i == 0 { extra_first } else { 0 }))
            .collect::<Vec<_>>()
    };
    let schema = Schema::new(0, slots(0)).unwrap();
    assert_eq!(schema.subkey_count(), 1024);
    // 1 MiB across 1024 slots leaves exactly 1024 bytes per subkey; no payload
    // is allocated here, only the bound itself is checked.
    assert_eq!(schema.max_value_len(), 1024);
    assert_eq!(Schema::dflt(1024).unwrap().max_value_len(), 1024);
    assert_eq!(schema.writer_of(&writer(0x0a), 0), Some(writer(0xa1)));
    assert_eq!(schema.writer_of(&writer(0x0a), 1023), Some(writer(0xd4)));
    assert_eq!(schema.writer_of(&writer(0x0a), 1024), None);
    // One slot more is refused, whether it comes from a member or the owner.
    assert_eq!(Schema::dflt(1025).unwrap_err(), Error::InvalidSchema);
    assert_eq!(Schema::new(0, slots(1)).unwrap_err(), Error::InvalidSchema);
    assert_eq!(Schema::new(1, slots(0)).unwrap_err(), Error::InvalidSchema);
}

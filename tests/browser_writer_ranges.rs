//! Noncontiguous SMPL writer ranges and exact payload bounds on the public Schema API.
//!
//! Native and browser identical regression: owner slots plus repeated member
//! entries separated by another writer and by zero-count members, including the
//! owner appearing again as a member. Fixed synthetic identifiers only; no
//! signing, encryption or record client involved.

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

use cdht::{Error, Member, Schema};

/// Fixed distinct synthetic writer identifiers (never real keys).
const OWNER: [u8; 32] = [0x0A; 32];
const MEMBER_A: [u8; 32] = [0xA1; 32];
const MEMBER_B: [u8; 32] = [0xB2; 32];
const IDLE_WRITER: [u8; 32] = [0xE0; 32];
const STRANGER: [u8; 32] = [0x9E; 32];

/// Two owner slots, then member A twice with member B and zero-count members
/// between, then the owner again as a member and a trailing zero-count entry.
/// Subkeys: 0,1 owner; 2,3 A; 4 B; 5,6,7 A; 8 owner-as-member.
fn mixed_schema() -> Schema {
    Schema::new(
        2,
        vec![
            Member {
                writer: MEMBER_A,
                subkeys: 2,
            },
            Member {
                writer: IDLE_WRITER,
                subkeys: 0,
            },
            Member {
                writer: MEMBER_B,
                subkeys: 1,
            },
            Member {
                writer: MEMBER_A,
                subkeys: 3,
            },
            Member {
                writer: OWNER,
                subkeys: 1,
            },
            Member {
                writer: MEMBER_B,
                subkeys: 0,
            },
        ],
    )
    .unwrap()
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn noncontiguous_writer_ranges_cover_every_slot() {
    let schema = mixed_schema();
    assert_eq!(schema.owner_subkeys(), 2);
    assert_eq!(schema.subkey_count(), 9);

    let expected: [(u32, [u8; 32]); 9] = [
        (0, OWNER),
        (1, OWNER),
        (2, MEMBER_A),
        (3, MEMBER_A),
        (4, MEMBER_B),
        (5, MEMBER_A),
        (6, MEMBER_A),
        (7, MEMBER_A),
        (8, OWNER),
    ];
    for (subkey, writer) in expected {
        assert_eq!(schema.writer_of(&OWNER, subkey), Some(writer));
    }
    assert_eq!(schema.writer_of(&OWNER, 9), None);
    assert_eq!(schema.writer_of(&OWNER, u32::MAX), None);

    assert_eq!(schema.subkeys_of(&OWNER, &OWNER), vec![0, 1, 8]);
    assert_eq!(schema.subkeys_of(&OWNER, &MEMBER_A), vec![2, 3, 5, 6, 7]);
    assert_eq!(schema.subkeys_of(&OWNER, &MEMBER_B), vec![4]);
    assert!(schema.subkeys_of(&OWNER, &IDLE_WRITER).is_empty());
    assert!(schema.subkeys_of(&OWNER, &STRANGER).is_empty());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn compile_parse_preserves_member_order_and_counts() {
    let schema = mixed_schema();
    let compiled = schema.compile();
    assert_eq!(compiled.len(), 6 + 6 * 34);
    let parsed = Schema::parse(&compiled).unwrap();
    assert_eq!(parsed, schema);
    assert_eq!(parsed.members(), schema.members());
    assert_eq!(parsed.owner_subkeys(), 2);
    assert_eq!(parsed.subkey_count(), 9);
    let counts: Vec<u16> = parsed.members().iter().map(|m| m.subkeys).collect();
    assert_eq!(counts, vec![2, 0, 1, 3, 1, 0]);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn check_write_enforces_owner_and_bounds_exactly() {
    let schema = mixed_schema();
    let bound = schema.max_value_len();
    assert_eq!(bound, cdht::MAX_SUBKEY_SIZE);

    for (subkey, writer) in [
        (0, OWNER),
        (1, OWNER),
        (2, MEMBER_A),
        (3, MEMBER_A),
        (4, MEMBER_B),
        (5, MEMBER_A),
        (6, MEMBER_A),
        (7, MEMBER_A),
        (8, OWNER),
    ] {
        assert_eq!(schema.check_write(&OWNER, subkey, &writer, bound), Ok(()));
        assert_eq!(
            schema.check_write(&OWNER, subkey, &writer, bound + 1),
            Err(Error::ValueTooLarge)
        );
    }

    for (subkey, writer) in [
        (0, MEMBER_A),
        (2, MEMBER_B),
        (4, MEMBER_A),
        (8, MEMBER_A),
        (8, MEMBER_B),
    ] {
        assert_eq!(
            schema.check_write(&OWNER, subkey, &writer, 1),
            Err(Error::WrongWriter)
        );
    }
    // Source order checks the writer before the size.
    assert_eq!(
        schema.check_write(&OWNER, 2, &MEMBER_B, bound + 1),
        Err(Error::WrongWriter)
    );

    for subkey in [9, u32::MAX] {
        assert_eq!(
            schema.check_write(&OWNER, subkey, &OWNER, 0),
            Err(Error::SubkeyOutOfRange)
        );
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn max_value_len_is_constrained_from_33_subkeys() {
    let wide = Schema::new(32, Vec::new()).unwrap();
    assert_eq!(wide.subkey_count(), 32);
    assert_eq!(wide.max_value_len(), cdht::MAX_SUBKEY_SIZE);

    let expected = cdht::MAX_RECORD_DATA_SIZE / 33;
    assert_eq!(expected, 31_775);
    let narrow = Schema::new(
        30,
        vec![Member {
            writer: MEMBER_A,
            subkeys: 3,
        }],
    )
    .unwrap();
    assert_eq!(narrow.subkey_count(), 33);
    assert_eq!(narrow.max_value_len(), expected);
    assert!(narrow.max_value_len() < cdht::MAX_SUBKEY_SIZE);

    assert_eq!(narrow.check_write(&OWNER, 0, &OWNER, expected), Ok(()));
    assert_eq!(
        narrow.check_write(&OWNER, 0, &OWNER, expected + 1),
        Err(Error::ValueTooLarge)
    );
    assert_eq!(
        wide.check_write(&OWNER, 31, &OWNER, cdht::MAX_SUBKEY_SIZE),
        Ok(())
    );
    assert_eq!(
        wide.check_write(&OWNER, 31, &OWNER, cdht::MAX_SUBKEY_SIZE + 1),
        Err(Error::ValueTooLarge)
    );
}

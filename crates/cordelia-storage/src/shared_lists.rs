//! What a device keeps beside its list of shared channels (decision
//! 2026-10-10 §3.4, §20): the tables of schema step 21.
//!
//! The device's list is an entry of its own in the personal channel, as
//! every word of a device is. What is in force is worked out from the
//! lists each time (`cordelia_api::lists`); beside them the device keeps:
//!
//! - **the list it last wrote, with its revision** ([`Kept`]): its own list
//!   among the lists it reads, where its own entry in the store is at no
//!   higher revision;
//! - **when it took each act** ([`Taken`]), by the act's signature, with
//!   the generation it was taken in. No rule of order reads it: it is what
//!   the removal record's cut asks of an act of a removed key (decision
//!   2026-10-24, rule 6).
//!
//! Nothing here decides anything.

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// The list this device last wrote, and the revision it wrote it at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// The value of its own list.
    pub list: Vec<u8>,
    /// The revision of the entry it wrote it in.
    pub rev: u64,
}

/// The list this device last wrote. `None` where it has written none.
pub fn kept(conn: &Connection) -> Result<Option<Kept>, CordeliaError> {
    conn.query_row(
        "SELECT list, rev FROM shared_lists WHERE one = 1",
        [],
        |row| {
            Ok(Kept {
                list: row.get(0)?,
                rev: row.get::<_, i64>(1)?.max(0) as u64,
            })
        },
    )
    .optional()
    .map_err(storage)
}

/// Keep `kept` in the place of what was kept.
pub fn keep(conn: &Connection, kept: &Kept) -> Result<(), CordeliaError> {
    let rev = i64::try_from(kept.rev).unwrap_or(i64::MAX);
    conn.execute(
        "INSERT INTO shared_lists (one, list, rev) VALUES (1, ?1, ?2)
         ON CONFLICT(one) DO UPDATE SET list = excluded.list, rev = excluded.rev",
        params![kept.list, rev],
    )
    .map_err(storage)?;
    Ok(())
}

/// When this device first took an act, by its clock, and the generation
/// (the statement's number) it applied then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Taken {
    pub generation: u64,
    pub taken_at: i64,
}

/// Every act this device has taken, by its signature.
pub fn taken(conn: &Connection) -> Result<Vec<([u8; 64], Taken)>, CordeliaError> {
    let mut stmt = conn
        .prepare("SELECT signature, generation, taken_at FROM shared_list_taken ORDER BY signature")
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, [u8; 64]>(0)?,
                Taken {
                    generation: row.get::<_, i64>(1)?.max(0) as u64,
                    taken_at: row.get(2)?,
                },
            ))
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Keep `taken` in the place of every row: an act that is not among them
/// is one the lists no longer carry.
pub fn keep_taken(conn: &Connection, taken: &[([u8; 64], Taken)]) -> Result<(), CordeliaError> {
    conn.execute("DELETE FROM shared_list_taken", [])
        .map_err(storage)?;
    let mut insert = conn
        .prepare(
            "INSERT INTO shared_list_taken (signature, generation, taken_at) VALUES (?1, ?2, ?3)",
        )
        .map_err(storage)?;
    for (signature, taken) in taken {
        let generation = i64::try_from(taken.generation).unwrap_or(i64::MAX);
        insert
            .execute(params![signature.as_slice(), generation, taken.taken_at])
            .map_err(storage)?;
    }
    Ok(())
}

/// Keep nothing of the person's lists: the device follows no phrase
/// from now on. Returns how many rows went.
pub fn forget_all(conn: &Connection) -> Result<usize, CordeliaError> {
    let mut gone = 0;
    for table in ["shared_lists", "shared_list_taken"] {
        gone += conn
            .execute(&format!("DELETE FROM {table}"), [])
            .map_err(storage)?;
    }
    Ok(gone)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::schema::init_db(&conn).unwrap();
        conn
    }

    /// The list last written is read back as it was kept, with its
    /// revision, and kept again in its place; none is kept until it is.
    #[test]
    fn what_is_kept_of_a_list_is_read_back_and_replaced() {
        let conn = conn();
        assert_eq!(kept(&conn).unwrap(), None);
        let first = Kept {
            list: vec![1, 0, 0, 0, 0],
            rev: 7,
        };
        keep(&conn, &first).unwrap();
        assert_eq!(kept(&conn).unwrap(), Some(first));
        let second = Kept {
            list: vec![1; 41_333],
            rev: (1 << 53) - 1,
        };
        keep(&conn, &second).unwrap();
        assert_eq!(kept(&conn).unwrap(), Some(second));
    }

    /// The acts taken are replaced whole, read back in order of signature,
    /// and everything goes when the device forgets.
    #[test]
    fn the_acts_taken_are_kept_whole_and_forgotten() {
        let conn = conn();
        let rows = [
            (
                [3; 64],
                Taken {
                    generation: 2,
                    taken_at: 30,
                },
            ),
            (
                [1; 64],
                Taken {
                    generation: 1,
                    taken_at: 10,
                },
            ),
        ];
        keep_taken(&conn, &rows).unwrap();
        assert_eq!(taken(&conn).unwrap(), [rows[1], rows[0]]);
        keep_taken(&conn, &rows[..1]).unwrap();
        assert_eq!(taken(&conn).unwrap(), [rows[0]]);

        keep(
            &conn,
            &Kept {
                list: vec![1, 0, 0, 0, 0],
                rev: 1,
            },
        )
        .unwrap();
        assert_eq!(forget_all(&conn).unwrap(), 2);
        assert_eq!(kept(&conn).unwrap(), None);
        assert!(taken(&conn).unwrap().is_empty());
    }
}

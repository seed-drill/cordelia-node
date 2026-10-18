//! What a device keeps beside its list of shared channels (decision
//! 2026-10-10 §3.4): the tables of schema step 20.
//!
//! The device's list is an entry of its own in the personal channel, as
//! every word of a device is. Beside it the device keeps:
//!
//! - **its list as it holds it, and what it left out past a bound**
//!   ([`Kept`]), each as a list's value, with when it last wrote its list
//!   and when it last made a whole fetch of the personal channel;
//! - **when it first held each act it holds** ([`FirstHeld`]), by the act's
//!   signature: an act held again keeps its time, and another act on the
//!   item has its own;
//! - **the undone acts it took out of its list** ([`Freed`]), one for each
//!   item, with what orders it.
//!
//! Nothing here decides anything: which act is taken, when a list is
//! fresh and when an act is freed are decided where these are read
//! (`cordelia_api::lists`).

use rusqlite::{Connection, OptionalExtension, params};

use cordelia_core::CordeliaError;

fn storage(e: rusqlite::Error) -> CordeliaError {
    CordeliaError::Storage(e.to_string())
}

/// What a list's item is within: a channel (filed or dropped), a
/// subscription, or a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Part {
    Channel,
    Subscription,
    Label,
}

impl Part {
    fn to_sql(self) -> i64 {
        match self {
            Part::Channel => 1,
            Part::Subscription => 2,
            Part::Label => 3,
        }
    }

    fn from_sql(part: i64) -> rusqlite::Result<Self> {
        match part {
            1 => Ok(Part::Channel),
            2 => Ok(Part::Subscription),
            3 => Ok(Part::Label),
            other => Err(rusqlite::Error::IntegralValueOutOfRange(0, other)),
        }
    }
}

/// The device's list as it holds it, and what it left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// The value of its own list.
    pub list: Vec<u8>,
    /// The value of a list of the items it left out past a bound.
    pub left_out: Vec<u8>,
    /// When it last wrote its list, by its clock: `None` where it never
    /// has.
    pub written_at: Option<i64>,
    /// When it last made a whole fetch of the personal channel, by its
    /// clock: `None` where it has made none since it held a list.
    pub fetched_at: Option<i64>,
}

/// What the device keeps of its list. `None` where it has held none.
pub fn kept(conn: &Connection) -> Result<Option<Kept>, CordeliaError> {
    conn.query_row(
        "SELECT list, left_out, written_at, fetched_at FROM shared_lists WHERE one = 1",
        [],
        |row| {
            Ok(Kept {
                list: row.get(0)?,
                left_out: row.get(1)?,
                written_at: row.get(2)?,
                fetched_at: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(storage)
}

/// Keep `kept` in the place of what was kept.
pub fn keep(conn: &Connection, kept: &Kept) -> Result<(), CordeliaError> {
    conn.execute(
        "INSERT INTO shared_lists (one, list, left_out, written_at, fetched_at)
         VALUES (1, ?1, ?2, ?3, ?4)
         ON CONFLICT(one) DO UPDATE SET
             list = excluded.list, left_out = excluded.left_out,
             written_at = excluded.written_at, fetched_at = excluded.fetched_at",
        params![kept.list, kept.left_out, kept.written_at, kept.fetched_at],
    )
    .map_err(storage)?;
    Ok(())
}

/// An act the device holds on an item, by its signature, and when it
/// first held it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstHeld {
    pub part: Part,
    pub item: Vec<u8>,
    pub signature: [u8; 64],
    pub first_held: i64,
}

/// When the device first held each act it holds, in order of item.
pub fn first_held(conn: &Connection) -> Result<Vec<FirstHeld>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT part, item, signature, first_held FROM shared_list_first_held
             ORDER BY part, item",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(FirstHeld {
                part: Part::from_sql(row.get(0)?)?,
                item: row.get(1)?,
                signature: row.get(2)?,
                first_held: row.get(3)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Keep `held` in the place of every row of first holding: an item that
/// is not among them is held no more.
pub fn keep_first_held(conn: &Connection, held: &[FirstHeld]) -> Result<(), CordeliaError> {
    conn.execute("DELETE FROM shared_list_first_held", [])
        .map_err(storage)?;
    for one in held {
        conn.execute(
            "INSERT INTO shared_list_first_held (part, item, signature, first_held)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                one.part.to_sql(),
                one.item,
                one.signature.as_slice(),
                one.first_held
            ],
        )
        .map_err(storage)?;
    }
    Ok(())
}

/// An undone act that the device took out of its list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Freed {
    pub part: Part,
    pub item: Vec<u8>,
    /// The act's time and its count.
    pub time: u64,
    pub count: u64,
    /// The key of the device that made it.
    pub maker: [u8; 32],
    /// The act as a list writes it: what orders it last.
    pub act: Vec<u8>,
    /// When the device took it out, by its clock.
    pub freed_at: i64,
}

/// Every act the device freed, in order of item.
pub fn freed(conn: &Connection) -> Result<Vec<Freed>, CordeliaError> {
    let mut stmt = conn
        .prepare(
            "SELECT part, item, time, count, maker, act, freed_at FROM shared_list_freed
             ORDER BY part, item",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(Freed {
                part: Part::from_sql(row.get(0)?)?,
                item: row.get(1)?,
                time: row.get::<_, i64>(2)?.max(0) as u64,
                count: row.get::<_, i64>(3)?.max(0) as u64,
                maker: row.get(4)?,
                act: row.get(5)?,
                freed_at: row.get(6)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(storage)
}

/// Keep `freed` as the act freed on its item, in the place of any that
/// was kept for that item.
pub fn keep_freed(conn: &Connection, freed: &Freed) -> Result<(), CordeliaError> {
    let sql = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
    conn.execute(
        "INSERT INTO shared_list_freed (part, item, time, count, maker, act, freed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(part, item) DO UPDATE SET
             time = excluded.time, count = excluded.count, maker = excluded.maker,
             act = excluded.act, freed_at = excluded.freed_at",
        params![
            freed.part.to_sql(),
            freed.item,
            sql(freed.time),
            sql(freed.count),
            freed.maker.as_slice(),
            freed.act,
            freed.freed_at
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// Let go of the act freed on an item. Returns whether one was kept.
pub fn let_go(conn: &Connection, part: Part, item: &[u8]) -> Result<bool, CordeliaError> {
    conn.execute(
        "DELETE FROM shared_list_freed WHERE part = ?1 AND item = ?2",
        params![part.to_sql(), item],
    )
    .map(|rows| rows > 0)
    .map_err(storage)
}

/// Keep nothing of the person's lists: the device follows no phrase
/// from now on. Returns how many rows went.
pub fn forget_all(conn: &Connection) -> Result<usize, CordeliaError> {
    let mut gone = 0;
    for table in [
        "shared_lists",
        "shared_list_first_held",
        "shared_list_freed",
    ] {
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

    /// What is kept of the list is read back as it was kept, and kept
    /// again in its place; none is kept until it is.
    #[test]
    fn what_is_kept_of_a_list_is_read_back_and_replaced() {
        let conn = conn();
        assert_eq!(kept(&conn).unwrap(), None);
        let empty = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let first = Kept {
            list: empty.clone(),
            left_out: empty.clone(),
            written_at: None,
            fetched_at: Some(7),
        };
        keep(&conn, &first).unwrap();
        assert_eq!(kept(&conn).unwrap(), Some(first));
        let second = Kept {
            list: vec![1; 41_341],
            left_out: empty,
            written_at: Some(9),
            fetched_at: None,
        };
        keep(&conn, &second).unwrap();
        assert_eq!(kept(&conn).unwrap(), Some(second));
    }

    /// The rows of first holding are replaced whole; an act freed is kept
    /// one for each item, the later in the place of the earlier, and let
    /// go by its item; and everything goes when the device forgets.
    #[test]
    fn first_holding_and_freed_acts_are_kept_by_item() {
        let conn = conn();
        let held = |part, item: &[u8], first_held| FirstHeld {
            part,
            item: item.to_vec(),
            signature: [first_held as u8; 64],
            first_held,
        };
        let rows = [
            held(Part::Label, &[3; 32], 3),
            held(Part::Channel, &[1; 32], 1),
            held(Part::Subscription, &[2; 40], 2),
        ];
        keep_first_held(&conn, &rows).unwrap();
        assert_eq!(
            first_held(&conn).unwrap(),
            [rows[1].clone(), rows[2].clone(), rows[0].clone()]
        );
        keep_first_held(&conn, &rows[..1]).unwrap();
        assert_eq!(first_held(&conn).unwrap(), [rows[0].clone()]);

        let freed_at = |time, freed_at| Freed {
            part: Part::Channel,
            item: vec![1; 32],
            time,
            count: 1 << 40,
            maker: [4; 32],
            act: vec![5; 144],
            freed_at,
        };
        keep_freed(&conn, &freed_at(10, 11)).unwrap();
        keep_freed(&conn, &freed_at(20, 21)).unwrap();
        assert_eq!(freed(&conn).unwrap(), [freed_at(20, 21)]);
        assert!(!let_go(&conn, Part::Label, &[1; 32]).unwrap());
        assert!(let_go(&conn, Part::Channel, &[1; 32]).unwrap());
        assert!(freed(&conn).unwrap().is_empty());

        keep_freed(&conn, &freed_at(20, 21)).unwrap();
        keep(
            &conn,
            &Kept {
                list: vec![0; 13],
                left_out: vec![0; 13],
                written_at: None,
                fetched_at: None,
            },
        )
        .unwrap();
        assert_eq!(forget_all(&conn).unwrap(), 3);
        assert_eq!(kept(&conn).unwrap(), None);
        assert!(first_held(&conn).unwrap().is_empty());
        assert!(freed(&conn).unwrap().is_empty());
    }
}

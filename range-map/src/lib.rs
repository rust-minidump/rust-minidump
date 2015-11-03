// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! A collection for storing data associated with a range of values.

use std::cmp::Ordering;
use std::slice::Iter;

/// The value type for the endpoints of ranges.
pub type Addr = u64;
/// Entries are indexed by a `Range` of `Addr`s.
///
/// The start of the range is inclusive, the end is exclusive.
pub type Range = (Addr, Addr);
/// Implementation detail, entries are internally a tuple.
pub type Entry<T> = (Range, T);

/// A `RangeMap` stores values of `T` that map to `Range`s.
pub struct RangeMap<T> {
    /// Entries are stored in a sorted list internally.
    entries: Vec<Entry<T>>,
}

fn compare_address_to_entry<T>(addr : Addr, entry : &Entry<T>) -> Ordering {
    let &((start, end), _) = entry;
    return if start <= addr && end > addr {
        Ordering::Equal
    } else if start > addr {
        Ordering::Greater
    } else {
        Ordering::Less
    }
}

impl<T> RangeMap<T> {
    /// Create a new, empty `RangeMap`.
    pub fn new() -> RangeMap<T> {
        RangeMap::<T> { entries: Vec::new() }
    }

    /// Insert `value` in the range `(start, end)`.
    pub fn insert(&mut self, (start, end) : Range, value : T) -> Result<(),()> {
        match self.entries.binary_search_by(|ref entry| compare_address_to_entry(start, entry)) {
            Ok(_) => Err(()),
            Err(index) => {
                self.entries.insert(index, ((start, end), value));
                Ok(())
            }
        }
    }

    /// Find an entry whose `Range` encompasses `addr`.
    pub fn lookup(&self, addr : Addr) -> Option<&T> {
        if let Ok(index) = self.entries.binary_search_by(|ref entry| compare_address_to_entry(addr, entry)) {
            let ((_, _), ref value) = self.entries[index];
            Some(value)
        } else {
            None
        }
    }

    /// Return an iterator over the entries of the `RangeMap`.
    pub fn iter(&self) -> Iter<Entry<T>> {
        self.entries.iter()
    }
}

impl<T : Clone> Clone for RangeMap<T> {
    fn clone(&self) -> RangeMap<T> {
        RangeMap::<T> {
            entries: self.entries.clone(),
        }
    }
}

#[test]
fn test_range_map() {
    let mut map = RangeMap::<u32>::new();
    map.insert((7,10), 2).unwrap();
    map.insert((0,4), 1).unwrap();
    map.insert((15,16), 3).unwrap();

    assert_eq!(map.lookup(7).unwrap(), &2);
    assert_eq!(map.lookup(9).unwrap(), &2);
    assert_eq!(map.lookup(0).unwrap(), &1);
    assert_eq!(map.lookup(3).unwrap(), &1);
    assert_eq!(map.lookup(15).unwrap(), &3);
    assert_eq!(map.lookup(4), None);
    assert_eq!(map.lookup(6), None);
    assert_eq!(map.lookup(10), None);
    assert_eq!(map.lookup(16), None);

    let items : Vec<_> = map.iter().collect();
    assert_eq!(*items[0], ((0,4), 1));
    assert_eq!(*items[1], ((7,10), 2));
    assert_eq!(*items[2], ((15,16), 3));
}

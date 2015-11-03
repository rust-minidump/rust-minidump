// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! A collection for storing data associated with a range of values.

use std::cmp::Ordering;
use std::iter::FromIterator;
use std::slice::Iter;

/// The value type for the endpoints of ranges.
pub type Addr = u64;
/// Entries are indexed by a `Range` of `Addr`s.
///
/// The start of the range is inclusive, the end is exclusive.
pub type Range = (Addr, Addr);
/// Entry type, a tuple of `Range` and `T`.
pub type Entry<T> = (Range, T);

/// A `RangeMap` stores values of `T` that map to `Range`s.
#[derive(Debug, PartialEq)]
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

    /// Create a `RangeMap` with `entries`.
    pub fn from(mut entries : Vec<Entry<T>>) -> RangeMap<T> {
        entries.sort_by(|&(a, _), &(b, _)| a.cmp(&b));
        RangeMap::<T> { entries: entries }
    }

    /// Returns the number of entries in the `RangeMap`.
    pub fn len(&self) -> usize { self.entries.len() }

    /// Insert `value` in `range`.
    pub fn insert(&mut self, range : Range, value : T) -> Result<(),()> {
        match self.entries.binary_search_by(|&(ref r, ref _v)| r.cmp(&range)) {
            Ok(_) => Err(()),
            Err(index) => {
                self.entries.insert(index, (range, value));
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

impl<T> IntoIterator for RangeMap<T> {
    type Item = Entry<T>;
    type IntoIter = <Vec<Entry<T>> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<T> FromIterator<Entry<T>> for RangeMap<T> {
    fn from_iter<U>(iterator: U) -> RangeMap<T> where U: IntoIterator<Item=Entry<T>> {
        RangeMap::from(iterator.into_iter().collect())
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

    assert_eq!(map.len(), 3);

    assert_eq!(map.lookup(7).unwrap(), &2);
    assert_eq!(map.lookup(9).unwrap(), &2);
    assert_eq!(map.lookup(0).unwrap(), &1);
    assert_eq!(map.lookup(3).unwrap(), &1);
    assert_eq!(map.lookup(15).unwrap(), &3);
    assert_eq!(map.lookup(4), None);
    assert_eq!(map.lookup(6), None);
    assert_eq!(map.lookup(10), None);
    assert_eq!(map.lookup(16), None);

    let items : Vec<_> = map.into_iter().collect();
    assert_eq!(items, vec!(
        ((0,4), 1),
        ((7,10), 2),
        ((15,16), 3),
        ));
}

#[test]
fn test_clone() {
    let mut map = RangeMap::<u32>::new();
    map.insert((7,10), 2).unwrap();
    map.insert((0,4), 1).unwrap();
    map.insert((15,16), 3).unwrap();

    assert_eq!(map.len(), 3);

    let map2 = map.clone();
    let items : Vec<_> = map2.into_iter().collect();
    assert_eq!(items, vec!(
        ((0,4), 1),
        ((7,10), 2),
        ((15,16), 3),
        ));
}

#[test]
fn test_from_iter() {
    let v = vec!(
        ((10, 20), 1),
        ((5, 6), 2),
        ((20, 22), 3),
        ((8, 10), 4),
        );
    let map = v.into_iter().collect::<RangeMap<u32>>();
    assert_eq!(map.len(), 4);

    let items : Vec<_> = map.into_iter().collect();
    assert_eq!(items, vec!(
        ((5, 6), 2),
        ((8, 10), 4),
        ((10, 20), 1),
        ((20, 22), 3),
        ));
}

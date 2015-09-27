use std::cmp::Ordering;

pub type Addr = u64;
pub type Range = (Addr, Addr);
pub type Entry<T> = (Range, T);

pub struct RangeMap<T : Copy> {
    entries: Vec<Entry<T>>,
}

fn compare_address_to_entry<T>(addr : Addr, entry : &Entry<T>) -> Ordering {
    let &((start, end), _) = entry;
    return if start <= addr && end > addr {
        Ordering::Equal
    } else if start > addr {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

impl<T : Copy> RangeMap<T> {
    pub fn new() -> RangeMap<T> {
        RangeMap::<T> { entries: Vec::new() }
    }

    pub fn insert(&mut self, (start, end) : Range, value : T) -> Result<(),()> {
        match self.entries.binary_search_by(|ref entry| compare_address_to_entry(start, entry)) {
            Ok(_) => Err(()),
            Err(index) => {
                self.entries.insert(index, ((start, end), value));
                Ok(())
            }
        }
    }

    pub fn lookup(&self, addr : Addr) -> Option<T> {
        if let Ok(index) = self.entries.binary_search_by(|ref entry| compare_address_to_entry(addr, entry)) {
            let ((_, _), ref value) = self.entries[index];
            Some(*value)
        } else {
            None
        }
    }
}

#[test]
fn test_range_map() {
    let mut map = RangeMap::<u32>::new();
    map.insert((7,10), 2).unwrap();
    map.insert((0,4), 1).unwrap();
    map.insert((15,16), 3).unwrap();

    assert_eq!(map.lookup(7).unwrap(), 2);
    assert_eq!(map.lookup(9).unwrap(), 2);
    assert_eq!(map.lookup(0).unwrap(), 1);
    assert_eq!(map.lookup(3).unwrap(), 1);
    assert_eq!(map.lookup(15).unwrap(), 3);
    assert_eq!(map.lookup(4), None);
    assert_eq!(map.lookup(6), None);
    assert_eq!(map.lookup(10), None);
    assert_eq!(map.lookup(16), None);
}

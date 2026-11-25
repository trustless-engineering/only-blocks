//! A bounded, RAM-only LRU cache: a `HashMap` into a slab of nodes threaded on an intrusive
//! doubly linked list, so `get` and `put` are O(1) and memory never exceeds `capacity` entries.

use std::collections::HashMap;
use std::hash::Hash;

const NIL: usize = usize::MAX;

struct Node<K, V> {
    key: K,
    value: V,
    prev: usize,
    next: usize,
}

pub struct Lru<K, V> {
    map: HashMap<K, usize>,
    nodes: Vec<Node<K, V>>,
    head: usize, // most recently used
    tail: usize, // least recently used
    capacity: usize,
}

impl<K: Hash + Eq + Clone, V: Clone> Lru<K, V> {
    /// A capacity of `0` disables the cache.
    pub fn new(capacity: usize) -> Self {
        Lru { map: HashMap::new(), nodes: Vec::new(), head: NIL, tail: NIL, capacity }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn unlink(&mut self, i: usize) {
        let (prev, next) = (self.nodes[i].prev, self.nodes[i].next);
        if prev != NIL {
            self.nodes[prev].next = next;
        } else {
            self.head = next;
        }
        if next != NIL {
            self.nodes[next].prev = prev;
        } else {
            self.tail = prev;
        }
    }

    fn push_front(&mut self, i: usize) {
        self.nodes[i].prev = NIL;
        self.nodes[i].next = self.head;
        if self.head != NIL {
            self.nodes[self.head].prev = i;
        }
        self.head = i;
        if self.tail == NIL {
            self.tail = i;
        }
    }

    pub fn get(&mut self, key: &K) -> Option<V> {
        let i = *self.map.get(key)?;
        if self.head != i {
            self.unlink(i);
            self.push_front(i);
        }
        Some(self.nodes[i].value.clone())
    }

    pub fn put(&mut self, key: K, value: V) {
        if self.capacity == 0 {
            return;
        }
        if let Some(&i) = self.map.get(&key) {
            self.nodes[i].value = value;
            if self.head != i {
                self.unlink(i);
                self.push_front(i);
            }
            return;
        }
        let i = if self.nodes.len() < self.capacity {
            self.nodes.push(Node { key: key.clone(), value, prev: NIL, next: NIL });
            self.nodes.len() - 1
        } else {
            // Recycle the least recently used slot.
            let i = self.tail;
            self.unlink(i);
            let old = std::mem::replace(&mut self.nodes[i].key, key.clone());
            self.map.remove(&old);
            self.nodes[i].value = value;
            i
        };
        self.map.insert(key, i);
        self.push_front(i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_least_recently_used() {
        let mut c = Lru::new(2);
        c.put(1, "a");
        c.put(2, "b");
        assert_eq!(c.get(&1), Some("a")); // 1 is now most recent
        c.put(3, "c"); // evicts 2
        assert_eq!(c.get(&2), None);
        assert_eq!(c.get(&1), Some("a"));
        assert_eq!(c.get(&3), Some("c"));
        c.put(3, "C");
        assert_eq!(c.get(&3), Some("C"));
        assert_eq!(c.len(), 2);
        let mut off: Lru<u64, u64> = Lru::new(0);
        off.put(1, 1);
        assert_eq!(off.get(&1), None);
    }

    #[test]
    fn many_operations_stay_bounded() {
        let mut c = Lru::new(100);
        for i in 0..10_000u64 {
            c.put(i, i * 2);
            if i % 3 == 0 {
                let _ = c.get(&(i / 2));
            }
        }
        assert_eq!(c.len(), 100);
        assert_eq!(c.get(&9_999), Some(19_998));
    }
}

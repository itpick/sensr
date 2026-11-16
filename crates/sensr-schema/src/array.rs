//! UUID-keyed ordered collections and typed references into them
//! (OPNsense counterparts: `ArrayField`, `ModelRelationField`).

use std::fmt;
use std::marker::PhantomData;

use indexmap::IndexMap;
use indexmap::map::Entry;
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub use uuid::Uuid;

/// An ordered collection of items, each keyed by a UUID that stays stable
/// across edits, so references, API calls and diffs can name an item.
///
/// Serialises as a JSON object `{ "<uuid>": item, ... }` in insertion order
/// (the order is meaningful: rule order, pool order).
#[derive(Clone, PartialEq, Eq)]
pub struct ArrayField<T> {
    items: IndexMap<Uuid, T>,
}

impl<T> Default for ArrayField<T> {
    fn default() -> Self {
        Self {
            items: IndexMap::new(),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for ArrayField<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.items.iter()).finish()
    }
}

impl<T> ArrayField<T> {
    /// An empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends `item` under a fresh random UUID and returns that UUID.
    pub fn push(&mut self, item: T) -> Uuid {
        let id = Uuid::new_v4();
        self.items.insert(id, item);
        id
    }

    /// Inserts or replaces the item with a known UUID (importers keep
    /// OPNsense's UUIDs). A new UUID is appended; an existing one keeps its
    /// position. Returns the previous item.
    pub fn insert(&mut self, id: Uuid, item: T) -> Option<T> {
        match self.items.entry(id) {
            Entry::Occupied(mut e) => Some(std::mem::replace(e.get_mut(), item)),
            Entry::Vacant(e) => {
                e.insert(item);
                None
            }
        }
    }

    /// The item with `id`.
    pub fn get(&self, id: &Uuid) -> Option<&T> {
        self.items.get(id)
    }

    /// Mutable access to the item with `id`.
    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut T> {
        self.items.get_mut(id)
    }

    /// True if an item with `id` exists.
    pub fn contains(&self, id: &Uuid) -> bool {
        self.items.contains_key(id)
    }

    /// Removes an item, keeping the order of the rest.
    pub fn remove(&mut self, id: &Uuid) -> Option<T> {
        self.items.shift_remove(id)
    }

    /// Keeps only the items for which `keep` returns true (OPNsense
    /// "delete by predicate", T-0029).
    pub fn retain(&mut self, mut keep: impl FnMut(&Uuid, &T) -> bool) {
        self.items.retain(|k, v| keep(k, v));
    }

    /// Moves the item with `id` to position `index` (rule reordering).
    /// Returns false if `id` is absent or `index` is out of bounds.
    pub fn move_to(&mut self, id: &Uuid, index: usize) -> bool {
        match self.items.get_index_of(id) {
            Some(from) if index < self.items.len() => {
                self.items.move_index(from, index);
                true
            }
            _ => false,
        }
    }

    /// Number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Removes every item.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// `(uuid, item)` pairs in order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&Uuid, &T)> + DoubleEndedIterator {
        self.items.iter()
    }

    /// Mutable `(uuid, item)` pairs in order.
    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = (&Uuid, &mut T)> {
        self.items.iter_mut()
    }

    /// Items in order.
    pub fn values(&self) -> impl ExactSizeIterator<Item = &T> + DoubleEndedIterator {
        self.items.values()
    }

    /// UUIDs in order.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &Uuid> {
        self.items.keys()
    }

    /// Finds the first item matching `pred`.
    pub fn find(&self, mut pred: impl FnMut(&T) -> bool) -> Option<(&Uuid, &T)> {
        self.items.iter().find(|(_, v)| pred(v))
    }
}

impl<T> FromIterator<T> for ArrayField<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut a = Self::new();
        for item in iter {
            a.push(item);
        }
        a
    }
}

impl<T> FromIterator<(Uuid, T)> for ArrayField<T> {
    fn from_iter<I: IntoIterator<Item = (Uuid, T)>>(iter: I) -> Self {
        Self {
            items: iter.into_iter().collect(),
        }
    }
}

impl<'a, T> IntoIterator for &'a ArrayField<T> {
    type Item = (&'a Uuid, &'a T);
    type IntoIter = indexmap::map::Iter<'a, Uuid, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl<T: Serialize> Serialize for ArrayField<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(self.items.len()))?;
        for (k, v) in &self.items {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for ArrayField<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = ArrayField<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object keyed by UUID")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
                let mut items = IndexMap::with_capacity(m.size_hint().unwrap_or(0).min(4096));
                while let Some((k, v)) = m.next_entry::<Uuid, T>()? {
                    if items.insert(k, v).is_some() {
                        return Err(serde::de::Error::custom(format!("Duplicate item {k}.")));
                    }
                }
                Ok(ArrayField { items })
            }
        }
        d.deserialize_map(V(PhantomData))
    }
}

/// A typed reference to an item of an [`ArrayField<T>`] by UUID.
///
/// The type parameter stops a reservation from pointing at, say, a firewall
/// rule; whether the target exists is checked by validation against the
/// document ([`crate::RefContext`]).
pub struct Relation<T> {
    id: Uuid,
    _target: PhantomData<fn() -> T>,
}

impl<T> Relation<T> {
    /// A reference to `id`.
    pub fn new(id: Uuid) -> Self {
        Self {
            id,
            _target: PhantomData,
        }
    }

    /// The referenced UUID.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Looks the target up in `items`.
    pub fn resolve<'a>(&self, items: &'a ArrayField<T>) -> Option<&'a T> {
        items.get(&self.id)
    }
}

// Manual impls: derives would wrongly require `T: Clone` etc.
impl<T> Clone for Relation<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Relation<T> {}
impl<T> PartialEq for Relation<T> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl<T> Eq for Relation<T> {}
impl<T> std::hash::Hash for Relation<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
impl<T> fmt::Debug for Relation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Relation({})", self.id)
    }
}
impl<T> fmt::Display for Relation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id.fmt(f)
    }
}
impl<T> From<Uuid> for Relation<T> {
    fn from(id: Uuid) -> Self {
        Self::new(id)
    }
}
impl<T> Serialize for Relation<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.id.serialize(s)
    }
}
impl<'de, T> Deserialize<'de> for Relation<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Uuid::deserialize(d).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Item {
        number: u32,
    }

    fn ten() -> ArrayField<Item> {
        (1..=10).map(|number| Item { number }).collect()
    }

    #[test]
    fn items_keyed_by_uuid_t0030() {
        let a = ten();
        let json = serde_json::to_value(&a).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 10);
        assert!(obj.keys().all(|k| Uuid::parse_str(k).is_ok()));
    }

    #[test]
    fn delete_by_predicate_t0029() {
        let mut a = ten();
        a.retain(|_, i| i.number != 5);
        assert_eq!(a.len(), 9);
        assert!(a.values().all(|i| i.number != 5));
    }

    #[test]
    fn get_nodes_count_t0037() {
        let mut a = ten();
        let first = *a.keys().next().unwrap();
        a.remove(&first);
        assert_eq!(a.iter().count(), 9);
    }

    #[test]
    fn order_survives_json_round_trip() {
        let a = ten();
        let text = serde_json::to_string(&a).unwrap();
        let back: ArrayField<Item> = serde_json::from_str(&text).unwrap();
        assert_eq!(back, a);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let back: ArrayField<Item> = serde_json::from_value(value).unwrap();
        assert_eq!(
            back.values().map(|i| i.number).collect::<Vec<_>>(),
            (1..=10).collect::<Vec<_>>()
        );
    }

    #[test]
    fn insert_keeps_position_and_move_reorders() {
        let mut a = ten();
        let third = *a.keys().nth(2).unwrap();
        a.insert(third, Item { number: 30 });
        assert_eq!(a.values().nth(2).unwrap().number, 30);
        assert!(a.move_to(&third, 0));
        assert_eq!(a.values().next().unwrap().number, 30);
        assert!(!a.move_to(&third, 10));
    }

    #[test]
    fn duplicate_keys_rejected() {
        let id = Uuid::new_v4();
        let text = format!(r#"{{"{id}":{{"number":1}},"{id}":{{"number":2}}}}"#);
        assert!(serde_json::from_str::<ArrayField<Item>>(&text).is_err());
    }

    #[test]
    fn relation_resolves() {
        let a = ten();
        let (id, _) = a.find(|i| i.number == 4).unwrap();
        let r: Relation<Item> = Relation::new(*id);
        assert_eq!(r.resolve(&a).unwrap().number, 4);
        assert!(Relation::<Item>::new(Uuid::new_v4()).resolve(&a).is_none());
    }
}

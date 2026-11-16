//! Canonical serialisation and content hashing.

use std::fmt;

use sensr_schema::Document;

/// The canonical byte form of a document: compact JSON with fields in
/// declaration order and list items in document order. The same document
/// always produces the same bytes, so equal hashes mean equal documents.
pub fn canonical_json(doc: &Document) -> Result<String, serde_json::Error> {
    serde_json::to_string(doc)
}

/// A blake3 hash of a revision's canonical JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    /// Hashes canonical JSON text.
    pub fn of(json: &str) -> Self {
        Self(*blake3::hash(json.as_bytes()).as_bytes())
    }

    /// Lower-case hex.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parses lower- or upper-case hex.
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 || !s.is_ascii() {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_is_stable() {
        let a = canonical_json(&Document::factory()).unwrap();
        let b = canonical_json(&serde_json::from_str(&a).unwrap()).unwrap();
        assert_eq!(a, b);
        let h = ContentHash::of(&a);
        assert_eq!(ContentHash::from_hex(&h.to_hex()), Some(h));
        assert_eq!(ContentHash::from_hex("zz"), None);
        assert_eq!(ContentHash::from_hex(&"é".repeat(32)), None);
    }
}

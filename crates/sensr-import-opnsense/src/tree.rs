//! Generic element tree for an OPNsense `config.xml`.
//!
//! The importer never maps XML straight into typed models: it first loads the
//! file into this tree, which keeps everything libxml (and therefore OPNsense)
//! keeps — attribute order, comments, CDATA sections — so that the parts no
//! mapper understands can be carried and reported verbatim, and so that the
//! tree can be written back byte-for-byte (see [`crate::xml`]).

/// One attribute, in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Attribute name as written (OPNsense never uses namespaces).
    pub name: String,
    /// Unescaped, normalised attribute value.
    pub value: String,
}

/// A child of an [`Element`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A nested element.
    Element(Element),
    /// Character data, unescaped. Adjacent text and references are merged into one node.
    Text(String),
    /// A `<![CDATA[...]]>` section, content verbatim.
    CData(String),
    /// A `<!--...-->` comment, content verbatim.
    Comment(String),
    /// A `<?target data?>` processing instruction, content verbatim (target included).
    ProcessingInstruction(String),
}

/// An XML element with its attributes and children.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Element {
    /// Tag name.
    pub name: String,
    /// Attributes in document order.
    pub attributes: Vec<Attribute>,
    /// Children in document order.
    pub children: Vec<Node>,
}

impl Element {
    /// An element with no attributes and no children.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    /// An element whose only child is the text `text` (no child at all when `text` is empty,
    /// which is how libxml stores `<x/>`).
    pub fn with_text(name: impl Into<String>, text: impl Into<String>) -> Self {
        let mut e = Self::new(name);
        e.set_text(text);
        e
    }

    /// Builder: append an attribute.
    #[must_use]
    pub fn attr(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.set_attribute(name, value);
        self
    }

    /// Builder: append a child element.
    #[must_use]
    pub fn child_element(mut self, child: Element) -> Self {
        self.children.push(Node::Element(child));
        self
    }

    /// Value of attribute `name`, if present.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.value.as_str())
    }

    /// Set (replace in place, or append) attribute `name`.
    pub fn set_attribute(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        match self.attributes.iter_mut().find(|a| a.name == name) {
            Some(a) => a.value = value,
            None => self.attributes.push(Attribute { name, value }),
        }
    }

    /// Child elements, in order.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    /// Child elements, mutable, in order.
    pub fn elements_mut(&mut self) -> impl Iterator<Item = &mut Element> {
        self.children.iter_mut().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    /// First child element named `name`.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.elements().find(|e| e.name == name)
    }

    /// First child element named `name`, mutable.
    pub fn child_mut(&mut self, name: &str) -> Option<&mut Element> {
        self.elements_mut().find(|e| e.name == name)
    }

    /// All child elements named `name`, in order.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.elements().filter(move |e| e.name == name)
    }

    /// Walk a path of child names from this element (first match at each step).
    pub fn path(&self, path: &[&str]) -> Option<&Element> {
        path.iter().try_fold(self, |e, name| e.child(name))
    }

    /// Text of the element at `path`, if it exists.
    pub fn path_text(&self, path: &[&str]) -> Option<String> {
        self.path(path).map(Element::text)
    }

    /// Whether the element has at least one child element (SimpleXML's `count() > 0`).
    pub fn has_element_children(&self) -> bool {
        self.elements().next().is_some()
    }

    /// The element's direct character data (text and CDATA children concatenated),
    /// which is what SimpleXML's `(string)$node` returns.
    pub fn text(&self) -> String {
        let mut s = String::new();
        for n in &self.children {
            if let Node::Text(t) | Node::CData(t) = n {
                s.push_str(t);
            }
        }
        s
    }

    /// Replace all children with a single text node (none for empty text).
    pub fn set_text(&mut self, text: impl Into<String>) {
        let text = text.into();
        self.children.clear();
        if !text.is_empty() {
            self.children.push(Node::Text(text));
        }
    }

    /// Append a child element and return a mutable reference to it.
    pub fn push_element(&mut self, child: Element) -> &mut Element {
        self.children.push(Node::Element(child));
        match self.children.last_mut() {
            Some(Node::Element(e)) => e,
            _ => unreachable!("an element was just pushed"),
        }
    }

    /// Remove every child element named `name` (and nothing else); returns how many were removed.
    pub fn remove_children(&mut self, name: &str) -> usize {
        let before = self.children.len();
        self.children
            .retain(|n| !matches!(n, Node::Element(e) if e.name == name));
        before - self.children.len()
    }

    /// Whether the element has neither attributes nor children.
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty() && self.children.is_empty()
    }

    /// Number of elements in this subtree, including `self`.
    pub fn element_count(&self) -> usize {
        1 + self.elements().map(Element::element_count).sum::<usize>()
    }
}

/// A parsed `config.xml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// The document element. OPNsense always writes it as `<opnsense>` without attributes,
    /// whatever was read (see [`crate::xml::to_config_string`]).
    pub root: Element,
}

impl Document {
    /// A document with an empty `<opnsense/>` root.
    pub fn new() -> Self {
        Self {
            root: Element::new("opnsense"),
        }
    }
}

impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}

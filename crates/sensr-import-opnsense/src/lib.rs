//! Lossless importer from an OPNsense config.xml backup into a sensr config document, with a report of anything unmapped.
//!
//! The pipeline is `bytes → [xml::parse] → [tree::Document] → section mappers →
//! sensr document + import report`. This crate's lower layers reproduce OPNsense's
//! own reading and writing of `config.xml` (`Core/Config.php`, `config.inc`), so the
//! file is understood exactly as OPNsense understands it.

pub mod legacy;
pub mod listtags;
pub mod mapper;
pub mod opnsense;
pub mod report;
pub mod tree;
pub mod view;
pub mod xml;

#[cfg(test)]
mod fixtures;

pub use mapper::{Imported, Importer, MapContext, Mapper};
pub use report::{ImportReport, Severity};
pub use tree::{Attribute, Document, Element, Node};
pub use xml::{XmlError, parse, parse_bytes, to_config_string};

//! Renderers over the IR: nftables JSON (what sensr loads) and pf text (the
//! differential oracle against OPNsense).

pub mod json;
pub mod nft;
pub mod pf;

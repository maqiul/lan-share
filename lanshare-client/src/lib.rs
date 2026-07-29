//! LanShare Client library — shared LSP3 client for any mount backend
//! (WinFsp, Dokan, FUSE, etc.)

pub mod lsp_client;

pub use lsp_client::{DirEntry, LspAuth, LspShareClient, StatResp};

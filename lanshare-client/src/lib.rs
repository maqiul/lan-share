//! LanShare Client library — shared WSP client for any mount backend
//! (WinFsp, Dokan, FUSE, etc.)

pub mod wsp_client;

pub use wsp_client::{DirEntry, StatResp, WspClient};
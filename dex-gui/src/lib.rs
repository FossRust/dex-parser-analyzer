#![deny(unused_must_use)]
#![doc = "Leptos-powered WASM GUI for dex parsing and analysis."]

mod ui;

pub use ui::App;

#[cfg(target_arch = "wasm32")]
use {
    leptos::{mount_to_body, view},
    wasm_bindgen::prelude::*,
};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn main_js() {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::default());
    mount_to_body(|| view! { <App/> });
}

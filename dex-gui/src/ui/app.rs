use std::rc::Rc;

use dex_analysis::{config::AnalysisConfig, engine::analyze_dex, model::AnalysisReport};
use dex_core::{
    dto::{dex_to_overview, DexOverviewDto},
    parse_dex,
};
use gloo_file::{futures::read_as_bytes, File as GlooFile};
use leptos::*;
use web_sys::HtmlInputElement;

use super::{AnalysisView, DexView};

#[component]
pub fn App() -> impl IntoView {
    let (loading, set_loading) = create_signal(false);
    let (error, set_error) = create_signal(Option::<String>::None);
    let (selected_file, set_selected_file) = create_signal(Option::<GlooFile>::None);
    let (selected_file_name, set_selected_file_name) = create_signal(String::new());

    let (dex_overview, set_dex_overview) = create_signal(Option::<Rc<DexOverviewDto>>::None);
    let (analysis_report, set_analysis_report) = create_signal(Option::<Rc<AnalysisReport>>::None);

    let on_file_change = {
        let set_selected_file = set_selected_file;
        let set_selected_file_name = set_selected_file_name;
        let set_error = set_error;
        move |ev: leptos::ev::Event| {
            let input: HtmlInputElement = event_target(&ev);
            if let Some(file_list) = input.files() {
                if let Some(file) = file_list.item(0) {
                    let gloo_file = GlooFile::from(file);
                    set_selected_file.set(Some(gloo_file.clone()));
                    set_selected_file_name.set(gloo_file.name());
                    set_error.set(None);
                    return;
                }
            }
            set_selected_file.set(None);
            set_selected_file_name.set(String::new());
        }
    };

    let on_load = {
        move |_| {
            let Some(file) = selected_file.get() else {
                set_error.set(Some(
                    "Please select a .dex file before loading.".to_string(),
                ));
                return;
            };

            set_error.set(None);
            set_loading.set(true);
            set_dex_overview.set(None);
            set_analysis_report.set(None);

            spawn_local(async move {
                let file_name = file.name();
                let bytes = match read_as_bytes(&file).await {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        set_error.set(Some(format!("Failed to read file: {err}")));
                        set_loading.set(false);
                        return;
                    }
                };

                let dex = match parse_dex(&bytes) {
                    Ok(dex) => dex,
                    Err(err) => {
                        set_error.set(Some(format!("Dex parse error ({file_name}): {err}")));
                        set_loading.set(false);
                        return;
                    }
                };

                let overview = match dex_to_overview(&dex) {
                    Ok(overview) => overview,
                    Err(err) => {
                        set_error.set(Some(format!("Failed to build overview: {err}")));
                        set_loading.set(false);
                        return;
                    }
                };

                let cfg = AnalysisConfig::default();
                let report = analyze_dex(&dex, &cfg);

                set_dex_overview.set(Some(Rc::new(overview)));
                set_analysis_report.set(Some(Rc::new(report)));
                set_loading.set(false);
            });
        }
    };

    view! {
        <div class="bg-light min-vh-100 d-flex flex-column">
            <header class="bg-dark text-white py-4">
                <div class="container">
                    <h1 class="h3 mb-3">"Dex Analyzer"</h1>
                    <div class="row g-3 align-items-center">
                        <div class="col-md-6">
                            <input
                                class="form-control"
                                type="file"
                                accept=".dex"
                                disabled=move || loading.get()
                                on:change=on_file_change
                            />
                        </div>
                        <div class="col-md-4">
                            <div class="text-light-emphasis small">
                                { move || {
                                    let name = selected_file_name.get();
                                    if name.is_empty() {
                                        view! { <span>"No file selected"</span> }.into_view()
                                    } else {
                                        view! { <span>{name}</span> }.into_view()
                                    }
                                }}
                            </div>
                        </div>
                        <div class="col-md-2 text-md-end">
                            <button
                                class="btn btn-warning w-100"
                                disabled=move || loading.get()
                                on:click=on_load
                            >
                                { move || if loading.get() { "Loading…" } else { "Load" } }
                            </button>
                        </div>
                    </div>
                    { move || error.get().map(|msg| view! { <div class="alert alert-danger mt-3 mb-0" role="alert">{msg}</div> }) }
                </div>
            </header>

            <main class="container my-4 flex-grow-1">
                <div class="card shadow-sm mb-4">
                    <div class="card-body">
                        { move || {
                            if loading.get() {
                                return view! { <div class="text-secondary">"Loading…"</div> }.into_view();
                            }

                            match (dex_overview.get(), analysis_report.get()) {
                                (Some(dex), Some(report)) => view! {
                                    <div class="vstack gap-4">
                                        <section>
                                            <h2 class="h4 mb-3">"Dex Overview"</h2>
                                            <DexView dex=dex.clone()/>
                                        </section>
                                        <section>
                                            <h2 class="h4 mb-3">"Analysis Report"</h2>
                                            <AnalysisView report=report.clone()/>
                                        </section>
                                    </div>
                                }.into_view(),
                                (Some(dex), None) => view! {
                                    <section>
                                        <h2 class="h4 mb-3">"Dex Overview"</h2>
                                        <DexView dex=dex.clone()/>
                                    </section>
                                }.into_view(),
                                (None, Some(report)) => view! {
                                    <section>
                                        <h2 class="h4 mb-3">"Analysis Report"</h2>
                                        <AnalysisView report=report.clone()/>
                                    </section>
                                }.into_view(),
                                _ => view! {
                                    <div class="text-secondary">
                                        "Select a local .dex file above and click Load to begin."
                                    </div>
                                }.into_view(),
                            }
                        }}
                    </div>
                </div>
                <DocumentationSection/>
            </main>
        </div>
    }
}

const DEX_CORE_SNIPPET: &str = r#"use dex_core::{parse_dex, DexError};

fn print_classes(bytes: &[u8]) -> Result<(), DexError> {
    let dex = parse_dex(bytes)?;
    println!("DEX version {}", dex.header().version);
    for class in dex.classes() {
        let descriptor = class.descriptor()?;
        println!("class: {descriptor}");
    }
    Ok(())
}"#;

const DEX_ANALYSIS_SNIPPET: &str = r#"use dex_analysis::{config::AnalysisConfig, engine::analyze_dex};

fn run_analysis(bytes: &[u8]) -> anyhow::Result<()> {
    let dex = parse_dex(bytes)?;
    let report = analyze_dex(&dex, &AnalysisConfig::default());
    for finding in report.findings {
        println!("{:?}: {}", finding.severity, finding.message);
    }
    Ok(())
}"#;

const DEX_CLI_SNIPPET: &str = r#"cargo run -p dex-cli -- path/to/classes.dex --max-findings 25"#;

const PRIVACY_NOTE: &str = "The dex-gui app executes entirely in your browser via Rust compiled to WebAssembly, so uploaded .dex files never leave your machine. Prefer server-side processing? Compile the same WASM and host it with Extism (or any runtime) to call it from Rust or other languages.";

#[component]
fn DocumentationSection() -> impl IntoView {
    view! {
        <>
            <div class="alert alert-info mb-3" role="alert">
                {PRIVACY_NOTE}
            </div>
            <section class="card shadow-sm">
                <div class="card-body">
                    <h2 class="h4 mb-3">"Sample Usage"</h2>
                    <div class="row g-3">
                        <div class="col-md-4">
                            <h3 class="h6">"dex-core"</h3>
                            <pre class="bg-dark text-light p-3 rounded small" style="white-space: pre-wrap;"><code class="language-rust">{DEX_CORE_SNIPPET}</code></pre>
                        </div>
                        <div class="col-md-4">
                            <h3 class="h6">"dex-analysis"</h3>
                            <pre class="bg-dark text-light p-3 rounded small" style="white-space: pre-wrap;"><code class="language-rust">{DEX_ANALYSIS_SNIPPET}</code></pre>
                        </div>
                        <div class="col-md-4">
                            <h3 class="h6">"dex-cli"</h3>
                            <pre class="bg-dark text-light p-3 rounded small" style="white-space: pre-wrap;"><code class="language-bash">{DEX_CLI_SNIPPET}</code></pre>
                        </div>
                    </div>
                </div>
            </section>
        </>
    }
}

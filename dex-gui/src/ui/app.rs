use std::rc::Rc;

use dex_analysis::{config::AnalysisConfig, engine::analyze_dex, model::AnalysisReport};
use dex_core::{
    dto::{dex_to_overview, DexOverviewDto},
    parse_dex,
};
use gloo_file::{futures::read_as_bytes, File as GlooFile};
use leptos::*;
use web_sys::HtmlInputElement;

use super::{AnalysisView, DexView, Tabs};

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Tab {
    Dex,
    Analysis,
}

#[component]
pub fn App() -> impl IntoView {
    let (loading, set_loading) = create_signal(false);
    let (error, set_error) = create_signal(Option::<String>::None);
    let (selected_file, set_selected_file) = create_signal(Option::<GlooFile>::None);
    let (selected_file_name, set_selected_file_name) = create_signal(String::new());

    let (active_tab, set_active_tab) = create_signal(Tab::Dex);
    let (dex_overview, set_dex_overview) = create_signal(Option::<Rc<DexOverviewDto>>::None);
    let (analysis_report, set_analysis_report) = create_signal(Option::<Rc<AnalysisReport>>::None);

    let on_file_change = {
        let set_selected_file = set_selected_file.clone();
        let set_selected_file_name = set_selected_file_name.clone();
        let set_error = set_error.clone();
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
                set_active_tab.set(Tab::Dex);
                set_loading.set(false);
            });
        }
    };

    view! {
        <div class="app-root">
            <header class="app-header">
                <h1>"Dex Analyzer"</h1>
                <div class="loader-row">
                    <input
                        class="file-input"
                        type="file"
                        accept=".dex"
                        disabled=move || loading.get()
                        on:change=on_file_change
                    />
                    <div class="file-meta">
                        { move || {
                            let name = selected_file_name.get();
                            if name.is_empty() {
                                view! { <span>"No file selected"</span> }.into_view()
                            } else {
                                view! { <span>{name}</span> }.into_view()
                            }
                        }}
                    </div>
                    <button
                        class="load-button"
                        disabled=move || loading.get()
                        on:click=on_load
                    >
                        { move || if loading.get() { "Loading…" } else { "Load" } }
                    </button>
                </div>
                { move || error.get().map(|msg| view! { <div class="error-banner">{msg}</div> }) }
            </header>

            <main class="app-main">
                <Tabs active_tab set_active_tab/>
                <div class="tab-content">
                    { move || {
                        if loading.get() {
                            return view! { <div class="placeholder">"Loading…"</div> }.into_view();
                        }

                        match (dex_overview.get(), analysis_report.get(), active_tab.get()) {
                            (Some(dex), _, Tab::Dex) => view! { <DexView dex/> }.into_view(),
                            (_, Some(report), Tab::Analysis) => {
                                view! { <AnalysisView report/> }.into_view()
                            }
                            _ => view! {
                                <div class="placeholder">
                                    "Select a local .dex file above and click Load to begin."
                                </div>
                            }
                            .into_view(),
                        }
                    }}
                </div>
            </main>
        </div>
    }
}

use std::rc::Rc;

use dex_analysis::{config::AnalysisConfig, engine::analyze_dex, model::AnalysisReport};
use dex_core::{
    dto::{dex_to_overview, strings_to_dto, DexOverviewDto, StringEntry},
    parse_dex,
};
use gloo_file::{futures::read_as_bytes, File as GlooFile};
use leptos::*;
use web_sys::HtmlInputElement;

use super::{AnalysisView, DexView};

#[cfg(target_arch = "wasm32")]
fn log_info(msg: &str) {
    web_sys::console::log_1(&msg.into());
}

#[cfg(not(target_arch = "wasm32"))]
fn log_info(msg: &str) {
    println!("{}", msg);
}

#[component]
pub fn App() -> impl IntoView {
    let (loading, set_loading) = create_signal(false);
    let (error, set_error) = create_signal(Option::<String>::None);
    let (selected_file, set_selected_file) = create_signal(Option::<GlooFile>::None);
    let (selected_file_name, set_selected_file_name) = create_signal(String::new());

    let (dex_overview, set_dex_overview) = create_signal(Option::<Rc<DexOverviewDto>>::None);
    let (analysis_report, set_analysis_report) = create_signal(Option::<Rc<AnalysisReport>>::None);
    let (strings, set_strings) = create_signal(Vec::<StringEntry>::new());
    let (dex_bytes, set_dex_bytes) = create_signal(Option::<Rc<Vec<u8>>>::None);

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
                set_error.set(Some("请先选择一个 .dex 文件".to_string()));
                return;
            };

            set_error.set(None);
            set_loading.set(true);
            set_dex_overview.set(None);
            set_analysis_report.set(None);
            set_strings.set(Vec::new());

            spawn_local(async move {
                let file_name = file.name();
                log_info(&format!("开始加载文件：{}", file_name));

                let bytes = match read_as_bytes(&file).await {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        log_info(&format!("读取文件失败：{}", err));
                        set_error.set(Some(format!("读取文件失败：{err}")));
                        set_loading.set(false);
                        return;
                    }
                };

                log_info(&format!("文件读取成功，大小：{} 字节", bytes.len()));

                let dex = match parse_dex(&bytes) {
                    Ok(dex) => dex,
                    Err(err) => {
                        log_info(&format!("DEX 解析错误：{}", err));
                        set_error.set(Some(format!("DEX 解析错误 ({file_name}): {err}")));
                        set_loading.set(false);
                        return;
                    }
                };

                log_info("DEX 解析成功，正在构建概览...");

                let overview = match dex_to_overview(&dex) {
                    Ok(overview) => overview,
                    Err(err) => {
                        log_info(&format!("构建概览失败：{}", err));
                        set_error.set(Some(format!("构建概览失败：{err}")));
                        set_loading.set(false);
                        return;
                    }
                };

                log_info("概览已构建，正在提取字符串...");

                let string_entries = strings_to_dto(&dex);
                set_strings.set(string_entries);

                log_info("字符串已提取，正在运行分析...");

                let cfg = AnalysisConfig::default();
                let report = analyze_dex(&dex, &cfg);

                log_info("分析完成，正在更新界面...");

                set_dex_overview.set(Some(Rc::new(overview)));
                set_analysis_report.set(Some(Rc::new(report)));
                set_dex_bytes.set(Some(Rc::new(bytes)));
                set_loading.set(false);
            });
        }
    };

    view! {
        <div class="bg-light min-vh-100 d-flex flex-column">
            // 头部
            <header class="bg-dark text-white py-4">
                <div class="container">
                    <h1 class="h3 mb-3">"FossRust DEX 解析分析器"</h1>
                    <div class="row g-3 align-items-center">
                        <p>
                            <a href="https://github.com/FossRust/dex-parser-analyzer" class="text-white">
                                "FossRust/dex-parser-analyzer"
                            </a>
                        </p>
                    </div>
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
                            <div class="text-white-50 small">
                                { move || {
                                    let name = selected_file_name.get();
                                    if name.is_empty() {
                                        view! { <span>"未选择文件"</span> }.into_view()
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
                                { move || if loading.get() { "加载中…" } else { "加载" } }
                            </button>
                        </div>
                    </div>
                    { move || error.get().map(|msg| view! { <div class="alert alert-danger mt-3 mb-0" role="alert">{msg}</div> }) }
                </div>
            </header>

            // 主内容区
            <main class="container my-4 flex-grow-1">
                <div class="card shadow-sm mb-4">
                    <div class="card-body">
                        { move || {
                            if loading.get() {
                                return view! { <div class="text-secondary">"加载中…"</div> }.into_view();
                            }

                            match (dex_overview.get(), analysis_report.get()) {
                                (Some(dex), Some(report)) => view! {
                                    <div class="vstack gap-4">
                                        <section>
                                            <h2 class="h4 mb-3">"DEX 概览"</h2>
                                            <DexView 
                                                dex=dex.clone()
                                                strings=strings.get()
                                                dex_bytes=dex_bytes.get()
                                            />
                                        </section>
                                        <section>
                                            <h2 class="h4 mb-3">"分析报告"</h2>
                                            <AnalysisView report=report.clone()/>
                                        </section>
                                    </div>
                                }.into_view(),
                                (Some(dex), None) => view! {
                                    <section>
                                        <h2 class="h4 mb-3">"DEX 概览"</h2>
                                        <DexView 
                                            dex=dex.clone()
                                            strings=strings.get()
                                            dex_bytes=dex_bytes.get()
                                        />
                                    </section>
                                }.into_view(),
                                (None, Some(report)) => view! {
                                    <section>
                                        <h2 class="h4 mb-3">"分析报告"</h2>
                                        <AnalysisView report=report.clone()/>
                                    </section>
                                }.into_view(),
                                _ => view! {
                                    <div class="text-secondary text-center py-5">
                                        <i class="bi bi-upload" style="font-size: 3rem;"></i>
                                        <p class="mt-3">"请在上方选择 .dex 文件并点击加载按钮开始"</p>
                                    </div>
                                }.into_view(),
                            }
                        }}
                    </div>
                </div>
                <DocumentationSection/>
            </main>

            // 页脚
            <footer class="bg-dark text-white py-3 mt-auto">
                <div class="container text-center">
                    <p class="mb-0 small">
                        "DEX 解析分析器 - 基于 Rust + WebAssembly 构建"
                    </p>
                </div>
            </footer>
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

const PRIVACY_NOTE: &str = "DEX 分析器完全在浏览器中通过 WebAssembly 运行，您上传的 .dex 文件不会离开您的设备。如需服务端处理，可编译相同的 WASM 模块并通过 Extism 或其他运行时从 Rust 或其他语言调用。";

#[component]
fn DocumentationSection() -> impl IntoView {
    view! {
        <>
            <div class="alert alert-info mb-3" role="alert">
                {PRIVACY_NOTE}
            </div>
            <section class="card shadow-sm">
                <div class="card-body">
                    <h2 class="h4 mb-3">"使用示例"</h2>
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

use std::rc::Rc;

use dex_analysis::model::{AnalysisReport, Finding, Severity, VulnerabilityKind};
use leptos::*;

const SEVERITY_ORDER: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

#[component]
pub fn AnalysisView(report: Rc<AnalysisReport>) -> impl IntoView {
    let (active_severities, set_active_severities) = create_signal(SEVERITY_ORDER.to_vec());
    let (selected, set_selected) = create_signal(Option::<Finding>::None);
    let findings_source = Rc::clone(&report);

    let filtered_findings = move || {
        let active = active_severities.get();
        findings_source
            .findings
            .iter()
            .filter(|finding| active.contains(&finding.severity))
            .cloned()
            .collect::<Vec<_>>()
    };

    let toggle = move |severity: Severity| {
        set_active_severities.update(|current| {
            if current.contains(&severity) {
                current.retain(|s| *s != severity);
            } else {
                current.push(severity);
            }
        });
    };

    // 严重程度标签中文映射
    let severity_label = |severity: Severity| -> &'static str {
        match severity {
            Severity::Critical => "严重",
            Severity::High => "高危",
            Severity::Medium => "中危",
            Severity::Low => "低危",
            Severity::Info => "提示",
        }
    };

    // 严重程度颜色
    let severity_color = |severity: Severity| -> &'static str {
        match severity {
            Severity::Critical => "text-danger fw-bold",
            Severity::High => "text-danger",
            Severity::Medium => "text-warning",
            Severity::Low => "text-info",
            Severity::Info => "text-secondary",
        }
    };

    view! {
        <div class="vstack gap-4">
            // 统计卡片
            <section>
                <div class="row row-cols-2 row-cols-md-5 g-3">
                    <div class="col">
                        <div class="border rounded p-3 bg-light">
                            <div class="text-secondary text-uppercase small">"发现问题"</div>
                            <div class="fw-semibold">{report.findings.len()}</div>
                        </div>
                    </div>
                    <div class="col">
                        <div class="border rounded p-3 bg-light">
                            <div class="text-secondary text-uppercase small">"方法数"</div>
                            <div class="fw-semibold">{report.stats.method_count}</div>
                        </div>
                    </div>
                    <div class="col">
                        <div class="border rounded p-3 bg-light">
                            <div class="text-secondary text-uppercase small">"字符串数"</div>
                            <div class="fw-semibold">{report.stats.string_count}</div>
                        </div>
                    </div>
                    <div class="col">
                        <div class="border rounded p-3 bg-light">
                            <div class="text-secondary text-uppercase small">"指令数"</div>
                            <div class="fw-semibold">{report.stats.instruction_count}</div>
                        </div>
                    </div>
                    {report.stats.elapsed_ms.map(|elapsed| view! {
                        <div class="col">
                            <div class="border rounded p-3 bg-light">
                                <div class="text-secondary text-uppercase small">"耗时"</div>
                                <div class="fw-semibold">{elapsed} " 毫秒"</div>
                            </div>
                        </div>
                    })}
                </div>
                <div class="mt-3 d-flex flex-wrap gap-2">
                    { SEVERITY_ORDER.iter().map(|severity| {
                        let label = severity_label(*severity);
                        let sev = *severity;
                        view! {
                            <button
                                class=move || {
                                    if active_severities.get().contains(&sev) {
                                        "btn btn-primary btn-sm"
                                    } else {
                                        "btn btn-outline-primary btn-sm"
                                    }
                                }
                                on:click=move |_| toggle(sev)
                            >
                                {label}
                            </button>
                        }
                    }).collect_view() }
                </div>
            </section>

            // 发现问题列表
            <section>
                <h3 class="h5 mb-3">"发现问题列表"</h3>
                <div class="table-responsive">
                    <table class="table table-sm table-hover align-middle">
                        <thead class="table-light">
                            <tr>
                                <th scope="col" style="width: 80px;">"严重程度"</th>
                                <th scope="col" style="width: 120px;">"问题类型"</th>
                                <th scope="col">"规则 ID"</th>
                                <th scope="col">"位置"</th>
                                <th scope="col">"消息"</th>
                            </tr>
                        </thead>
                        <tbody>
                            { move || {
                                let rows = filtered_findings();
                                if rows.is_empty() {
                                    return view! {
                                        <tr>
                                            <td colspan="5" class="text-secondary text-center py-4">
                                                <i class="bi bi-check-circle" style="font-size: 2rem;"></i>
                                                <p class="mt-2 mb-0">"未发现符合筛选条件的问题"</p>
                                            </td>
                                        </tr>
                                    }.into_view();
                                }
                                rows.into_iter().map(|finding| {
                                    let severity = severity_label(finding.severity);
                                    let severity_class = severity_color(finding.severity);
                                    let vuln_type = finding.kind.description();
                                    let rule = finding.id.to_string();
                                    let location = format!(
                                        "{}::{}",
                                        finding.location.class_descriptor, finding.location.method_name
                                    );
                                    let message = finding.message.clone();
                                    let row_finding = finding.clone();
                                    view! {
                                        <tr on:click=move |_| set_selected.set(Some(row_finding.clone())) style="cursor:pointer;">
                                            <td class={severity_class}>{severity}</td>
                                            <td class="text-nowrap">{vuln_type}</td>
                                            <td class="font-monospace small">{rule}</td>
                                            <td class="font-monospace small text-truncate" style="max-width: 200px;">{location}</td>
                                            <td class="small">{message}</td>
                                        </tr>
                                    }
                                }).collect_view()
                            }}
                        </tbody>
                    </table>
                </div>
            </section>

            // 选中详情
            { move || selected.get().map(|finding| {
                let severity = severity_label(finding.severity);
                let vuln_type = finding.kind.description();
                view! {
                    <section>
                        <div class="card shadow-sm">
                            <div class="card-header bg-dark text-white">
                                <h5 class="mb-0">
                                    <i class="bi bi-bug"></i>
                                    {" 问题详情"}
                                </h5>
                            </div>
                            <div class="card-body">
                                <div class="row g-3">
                                    <div class="col-md-6">
                                        <div class="border rounded p-3 bg-light">
                                            <div class="text-secondary small">"严重程度"</div>
                                            <div class={severity_color(finding.severity)}>{severity}</div>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="border rounded p-3 bg-light">
                                            <div class="text-secondary small">"问题类型"</div>
                                            <div>{vuln_type}</div>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="border rounded p-3 bg-light">
                                            <div class="text-secondary small">"规则 ID"</div>
                                            <div class="font-monospace">{finding.id}</div>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="border rounded p-3 bg-light">
                                            <div class="text-secondary small">"位置"</div>
                                            <div class="font-monospace small">
                                                {finding.location.class_descriptor}
                                                <br/>
                                                <span class="text-secondary">"→ " {finding.location.method_name}{finding.location.method_signature}</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-12">
                                        <div class="border rounded p-3 bg-light">
                                            <div class="text-secondary small">"消息"</div>
                                            <div>{finding.message}</div>
                                        </div>
                                    </div>
                                    {
                                        // 显示额外信息
                                        if let Some(extra) = finding.extra.as_object() {
                                            view! {
                                                <div class="col-12">
                                                    <div class="border rounded p-3 bg-light">
                                                        <div class="text-secondary small mb-2">"详细信息"</div>
                                                        <pre class="bg-dark text-light p-3 rounded small" style="white-space: pre-wrap; max-height: 300px; overflow-y: auto;">
                                                            {format!("{:#?}", extra)}
                                                        </pre>
                                                    </div>
                                                </div>
                                            }.into_view()
                                        } else {
                                            view! { <div></div> }.into_view()
                                        }
                                    }
                                </div>
                            </div>
                        </div>
                    </section>
                }
            }) }
        </div>
    }
}

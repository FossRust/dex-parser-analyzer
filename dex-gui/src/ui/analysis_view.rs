use std::rc::Rc;

use dex_analysis::model::{AnalysisReport, Finding, Severity};
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

    view! {
        <div class="vstack gap-4">
            <section>
                <div class="row row-cols-2 row-cols-md-3 g-3">
                    <div class="col">
                        <div class="border rounded p-3 bg-light">
                            <div class="text-secondary text-uppercase small">"Findings"</div>
                            <div class="fw-semibold">{report.findings.len()}</div>
                        </div>
                    </div>
                    <div class="col">
                        <div class="border rounded p-3 bg-light">
                            <div class="text-secondary text-uppercase small">"Methods"</div>
                            <div class="fw-semibold">{report.stats.method_count}</div>
                        </div>
                    </div>
                    <div class="col">
                        <div class="border rounded p-3 bg-light">
                            <div class="text-secondary text-uppercase small">"Strings"</div>
                            <div class="fw-semibold">{report.stats.string_count}</div>
                        </div>
                    </div>
                    <div class="col">
                        <div class="border rounded p-3 bg-light">
                            <div class="text-secondary text-uppercase small">"Instructions"</div>
                            <div class="fw-semibold">{report.stats.instruction_count}</div>
                        </div>
                    </div>
                    {report.stats.elapsed_ms.map(|elapsed| view! {
                        <div class="col">
                            <div class="border rounded p-3 bg-light">
                                <div class="text-secondary text-uppercase small">"Elapsed"</div>
                                <div class="fw-semibold">{elapsed} " ms"</div>
                            </div>
                        </div>
                    })}
                </div>
                <div class="mt-3 d-flex flex-wrap gap-2">
                    { SEVERITY_ORDER.iter().map(|severity| {
                        let label = format!("{severity:?}");
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
                                {label.clone()}
                            </button>
                        }
                    }).collect_view() }
                </div>
            </section>

            <section>
                <h3 class="h5 mb-3">"Findings"</h3>
                <div class="table-responsive">
                    <table class="table table-sm table-hover align-middle">
                        <thead class="table-light">
                            <tr>
                                <th scope="col">"Severity"</th>
                                <th scope="col">"Rule"</th>
                                <th scope="col">"Location"</th>
                                <th scope="col">"Message"</th>
                            </tr>
                        </thead>
                        <tbody>
                            { move || {
                                let rows = filtered_findings();
                                if rows.is_empty() {
                                    return view! {
                                        <tr>
                                            <td colspan="4" class="text-secondary">
                                                "No findings with the selected severities."
                                            </td>
                                        </tr>
                                    }.into_view();
                                }
                                rows.into_iter().map(|finding| {
                                    let severity = format!("{:?}", finding.severity);
                                    let rule = finding.id.to_string();
                                    let location = format!(
                                        "{}::{}",
                                        finding.location.class_descriptor, finding.location.method_name
                                    );
                                    let message = finding.message.clone();
                                    let row_finding = finding.clone();
                                    view! {
                                        <tr on:click=move |_| set_selected.set(Some(row_finding.clone())) style="cursor:pointer;">
                                            <td>{severity}</td>
                                            <td class="text-nowrap">{rule}</td>
                                            <td class="font-monospace">{location}</td>
                                            <td>{message}</td>
                                        </tr>
                                    }
                                }).collect_view()
                            }}
                        </tbody>
                    </table>
                </div>
            </section>

            { move || selected.get().map(|finding| {
                view! {
                    <section>
                        <h3 class="h6">"Finding Details"</h3>
                        <pre class="bg-dark text-light p-3 rounded" style="white-space: pre-wrap;">{format!("{finding:#?}")}</pre>
                    </section>
                }
            }) }
        </div>
    }
}

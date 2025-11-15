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
        <div class="analysis-view">
            <section class="analysis-summary">
                <h2>"Analysis Summary"</h2>
                <div class="summary-grid">
                    <div>"Findings: " {report.findings.len()}</div>
                    <div>"Methods: " {report.stats.method_count}</div>
                    <div>"Strings: " {report.stats.string_count}</div>
                    <div>"Instructions: " {report.stats.instruction_count}</div>
                    {report.stats.elapsed_ms.map(|elapsed| view! {
                        <div>"Elapsed (ms): " {elapsed}</div>
                    })}
                </div>
                <div class="severity-filters" style="margin-top:0.75rem;">
                    { SEVERITY_ORDER.iter().map(|severity| {
                        let label = format!("{severity:?}");
                        let sev = *severity;
                        view! {
                            <button
                                class=move || {
                                    if active_severities.get().contains(&sev) {
                                        "severity-btn active"
                                    } else {
                                        "severity-btn"
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

            <section class="analysis-findings">
                <h2>"Findings"</h2>
                <table>
                    <thead>
                        <tr>
                            <th>"Severity"</th>
                            <th>"Rule"</th>
                            <th>"Location"</th>
                            <th>"Message"</th>
                        </tr>
                    </thead>
                    <tbody>
                        { move || {
                            let rows = filtered_findings();
                            if rows.is_empty() {
                                return view! {
                                    <tr>
                                        <td colspan="4">"No findings with the selected severities."</td>
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
                                    <tr on:click=move |_| set_selected.set(Some(row_finding.clone()))>
                                        <td>{severity}</td>
                                        <td>{rule}</td>
                                        <td>{location}</td>
                                        <td>{message}</td>
                                    </tr>
                                }
                            }).collect_view()
                        }}
                    </tbody>
                </table>
            </section>

            { move || selected.get().map(|finding| {
                view! {
                    <section class="analysis-details">
                        <h3>"Finding Details"</h3>
                        <pre>{format!("{finding:#?}")}</pre>
                    </section>
                }
            }) }
        </div>
    }
}

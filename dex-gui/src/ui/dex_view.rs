use std::rc::Rc;

use dex_core::dto::DexOverviewDto;
use leptos::*;

#[component]
pub fn DexView(dex: Rc<DexOverviewDto>) -> impl IntoView {
    let (filter, set_filter) = create_signal(String::new());
    let overview = Rc::clone(&dex);
    let filter_source = Rc::clone(&dex);

    let filtered_classes = move || {
        let needle = filter.get().to_lowercase();
        filter_source
            .classes
            .iter()
            .filter_map(|cls| {
                if needle.is_empty() || cls.descriptor.to_lowercase().contains(&needle) {
                    Some((cls.descriptor.clone(), cls.method_count))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    };

    let summary = vec![
        ("Version", overview.version.clone()),
        ("File size", format!("{} bytes", overview.file_size)),
        ("Checksum", overview.checksum.to_string()),
        ("Strings", overview.string_count.to_string()),
        ("Types", overview.type_count.to_string()),
        ("Fields", overview.field_count.to_string()),
        ("Methods", overview.method_count.to_string()),
        ("Classes", overview.class_count.to_string()),
    ];

    view! {
        <div class="vstack gap-4">
            <section>
                <div class="row row-cols-2 row-cols-md-4 g-3">
                    { summary.into_iter().map(|(label, value)| {
                        view! {
                            <div class="col">
                                <div class="border rounded p-3 bg-light">
                                    <div class="text-secondary text-uppercase small">{label}</div>
                                    <div class="fw-semibold">{value}</div>
                                </div>
                            </div>
                        }
                    }).collect_view() }
                </div>
            </section>

            <section>
                <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
                    <h3 class="h5 mb-0">"Classes"</h3>
                    <input
                        class="form-control"
                        style="max-width: 280px;"
                        type="text"
                        placeholder="Filter by descriptor…"
                        prop:value=move || filter.get()
                        on:input=move |ev| set_filter.set(event_target_value(&ev))
                    />
                </div>
                <div class="table-responsive">
                    <table class="table table-sm table-striped align-middle">
                        <thead class="table-light">
                            <tr>
                                <th scope="col">"Class"</th>
                                <th scope="col">"Methods"</th>
                            </tr>
                        </thead>
                        <tbody>
                            { move || {
                                let rows = filtered_classes();
                                if rows.is_empty() {
                                    return view! {
                                        <tr>
                                            <td colspan="2" class="text-secondary">"No classes match the filter."</td>
                                        </tr>
                                    }.into_view();
                                }
                                rows.into_iter().map(|(descriptor, methods)| {
                                    view! {
                                        <tr>
                                            <td class="font-monospace">{descriptor}</td>
                                            <td>{methods}</td>
                                        </tr>
                                    }
                                }).collect_view()
                            }}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    }
}

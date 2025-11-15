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

    view! {
        <div class="dex-view">
            <section class="dex-summary">
                <h2>"Dex Summary"</h2>
                <div class="summary-grid">
                    <div>"Version: " {overview.version.clone()}</div>
                    <div>"File size: " {overview.file_size}</div>
                    <div>"Checksum: " {overview.checksum}</div>
                    <div>"Strings: " {overview.string_count}</div>
                    <div>"Types: " {overview.type_count}</div>
                    <div>"Fields: " {overview.field_count}</div>
                    <div>"Methods: " {overview.method_count}</div>
                    <div>"Classes: " {overview.class_count}</div>
                </div>
            </section>

            <section class="dex-classes">
                <div class="classes-header" style="display:flex;justify-content:space-between;align-items:center;gap:0.75rem;">
                    <h2 style="margin:0;">"Classes"</h2>
                    <input
                        type="text"
                        placeholder="Filter by descriptor…"
                        prop:value=move || filter.get()
                        on:input=move |ev| set_filter.set(event_target_value(&ev))
                    />
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>"Class"</th>
                            <th>"Methods"</th>
                        </tr>
                    </thead>
                    <tbody>
                        { move || {
                            filtered_classes().into_iter().map(|(descriptor, methods)| {
                                view! {
                                    <tr>
                                        <td>{descriptor}</td>
                                        <td>{methods}</td>
                                    </tr>
                                }
                            }).collect_view()
                        }}
                    </tbody>
                </table>
            </section>
        </div>
    }
}

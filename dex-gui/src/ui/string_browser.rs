use leptos::*;
use dex_core::dto::StringEntry;

/// 字符串浏览器组件
#[component]
pub fn StringBrowser(
    /// 所有字符串条目
    strings: Vec<StringEntry>,
) -> impl IntoView {
    let (filter, set_filter) = create_signal(String::new());
    let (selected, set_selected) = create_signal(Option::<StringEntry>::None);
    
    let strings_count = strings.len();
    
    let filtered_strings = move || {
        let needle = filter.get().to_lowercase();
        if needle.is_empty() {
            strings.clone()
        } else {
            strings
                .iter()
                .filter(|s| s.value.to_lowercase().contains(&needle))
                .cloned()
                .collect()
        }
    };

    view! {
        <div class="card shadow-sm">
            <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                <h5 class="mb-0">
                    <i class="bi bi-fonts"></i>
                    {" 字符串浏览器"}
                </h5>
                <span class="badge bg-light text-dark">
                    {strings_count} " 个字符串"
                </span>
            </div>
            <div class="card-body">
                // 搜索框
                <div class="mb-3">
                    <input
                        class="form-control"
                        type="text"
                        placeholder="搜索字符串…"
                        prop:value=move || filter.get()
                        on:input=move |ev| set_filter.set(event_target_value(&ev))
                    />
                </div>

                <div class="row g-3">
                    // 字符串列表
                    <div class="col-md-5">
                        <div class="border rounded" style="max-height: 500px; overflow-y: auto;">
                            <table class="table table-sm table-hover mb-0">
                                <thead class="table-light sticky-top">
                                    <tr>
                                        <th scope="col" style="width: 80px;">"索引"</th>
                                        <th scope="col">"内容"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    { move || {
                                        let items = filtered_strings();
                                        if items.is_empty() {
                                            return view! {
                                                <tr>
                                                    <td colspan="2" class="text-secondary text-center py-4">
                                                        "未找到匹配的字符串"
                                                    </td>
                                                </tr>
                                            }.into_view();
                                        }
                                        items.into_iter().map(|entry| {
                                            let is_selected = selected.get()
                                                .map(|s| s.idx == entry.idx)
                                                .unwrap_or(false);
                                            let preview = if entry.value.len() > 50 {
                                                format!("{}…", &entry.value[..50.min(entry.value.len())])
                                            } else {
                                                entry.value.clone()
                                            };
                                            let entry_for_click = entry.clone();
                                            let entry_idx = entry.idx;
                                            let entry_preview = preview.clone();
                                            view! {
                                                <tr 
                                                    on:click=move |_| set_selected.set(Some(entry_for_click.clone()))
                                                    style="cursor: pointer;"
                                                    class=is_selected.then_some("table-active")
                                                >
                                                    <td class="font-monospace small">{entry_idx}</td>
                                                    <td class="small text-truncate" style="max-width: 200px;">
                                                        {entry_preview}
                                                    </td>
                                                </tr>
                                            }
                                        }).collect_view()
                                    }}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    // 选中详情
                    <div class="col-md-7">
                        <div class="border rounded p-3 bg-light" style="min-height: 500px;">
                            { move || {
                                match selected.get() {
                                    Some(entry) => {
                                        let idx = entry.idx;
                                        let value = entry.value.clone();
                                        let value_len = value.len();
                                        view! {
                                            <div>
                                                <h6 class="text-secondary mb-3">"字符串详情"</h6>
                                                <div class="mb-3">
                                                    <div class="text-secondary small">"索引"</div>
                                                    <div class="font-monospace">{idx}</div>
                                                </div>
                                                <div class="mb-3">
                                                    <div class="text-secondary small">"长度"</div>
                                                    <div>{value_len} " 字符"</div>
                                                </div>
                                                <div>
                                                    <div class="text-secondary small">"内容"</div>
                                                    <pre class="bg-white border rounded p-3" style="white-space: pre-wrap; word-break: break-all;">
                                                        {value}
                                                    </pre>
                                                </div>
                                            </div>
                                        }.into_view()
                                    }
                                    None => {
                                        view! {
                                            <div class="text-secondary text-center py-5">
                                                <i class="bi bi-mouse3" style="font-size: 3rem;"></i>
                                                <p class="mt-3">"点击左侧字符串查看详情"</p>
                                            </div>
                                        }.into_view()
                                    }
                                }
                            }}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}

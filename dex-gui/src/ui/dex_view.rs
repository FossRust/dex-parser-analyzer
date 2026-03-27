use std::rc::Rc;

use dex_core::dto::{DexOverviewDto, StringEntry, MethodDetailDto};
use dex_core::parse_dex;
use leptos::*;

use crate::ui::{MethodDetailView, StringBrowser};

#[component]
pub fn DexView(
    dex: Rc<DexOverviewDto>,
    strings: Vec<StringEntry>,
    dex_bytes: Option<Rc<Vec<u8>>>,
) -> impl IntoView {
    let (filter, set_filter) = create_signal(String::new());
    let (selected_class, set_selected_class) = create_signal(Option::<String>::None);
    let (selected_method, set_selected_method) = create_signal(Option::<MethodDetailDto>::None);
    let (active_tab, set_active_tab) = create_signal(0u8); // 0 = 类列表，1 = 字符串
    
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
        ("版本", overview.version.clone()),
        ("文件大小", format!("{} 字节", overview.file_size)),
        ("校验和", overview.checksum.to_string()),
        ("字符串", overview.string_count.to_string()),
        ("类型", overview.type_count.to_string()),
        ("字段", overview.field_count.to_string()),
        ("方法", overview.method_count.to_string()),
        ("类", overview.class_count.to_string()),
    ];

    // 获取类的方法列表
    let get_class_methods = {
        let dex_bytes = dex_bytes.clone();
        move |descriptor: String| -> Vec<(String, u32)> {
            let Some(bytes) = dex_bytes.as_ref() else {
                return Vec::new();
            };
            
            let Ok(dex_file) = parse_dex(bytes) else {
                return Vec::new();
            };
            
            // 查找类
            for (idx, _class_def) in dex_file.class_defs().enumerate() {
                if let Some(class) = dex_file.class(dex_core::format::ClassIdx::new(idx as u32)) {
                    if let Ok(class_desc) = class.descriptor() {
                        if class_desc == descriptor {
                            let mut methods = Vec::new();
                            if let Some(method_handles) = class.methods() {
                                for (i, method) in method_handles.iter().enumerate() {
                                    if let Ok(name) = method.name() {
                                        methods.push((name.to_string(), i as u32));
                                    }
                                }
                            }
                            return methods;
                        }
                    }
                }
            }
            Vec::new()
        }
    };

    // 获取方法详情
    let get_method_detail = {
        let dex_bytes = dex_bytes.clone();
        move |class_descriptor: String, method_idx: u32| -> Option<MethodDetailDto> {
            let Some(bytes) = dex_bytes.as_ref() else {
                return None;
            };
            
            let Ok(dex_file) = parse_dex(bytes) else {
                return None;
            };
            
            // 查找类
            for (idx, _class_def) in dex_file.class_defs().enumerate() {
                if let Some(class) = dex_file.class(dex_core::format::ClassIdx::new(idx as u32)) {
                    if let Ok(class_desc) = class.descriptor() {
                        if class_desc == class_descriptor {
                            if let Some(method_handles) = class.methods() {
                                if let Some(method) = method_handles.get(method_idx as usize) {
                                    if let Ok(detail) = dex_core::dto::method_to_detail_dto(&dex_file, method) {
                                        return Some(detail);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            None
        }
    };

    view! {
        <div class="vstack gap-4">
            // 概览卡片
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

            // 选项卡导航
            <section>
                <ul class="nav nav-tabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button
                            class=move || if active_tab.get() == 0 { "nav-link active" } else { "nav-link" }
                            on:click=move |_| set_active_tab.set(0)
                            type="button"
                        >
                            <i class="bi bi-box"></i>
                            {" 类列表"}
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button
                            class=move || if active_tab.get() == 1 { "nav-link active" } else { "nav-link" }
                            on:click=move |_| set_active_tab.set(1)
                            type="button"
                        >
                            <i class="bi bi-fonts"></i>
                            {" 字符串"}
                        </button>
                    </li>
                </ul>

                <div class="border border-top-0 rounded-bottom p-3 bg-white">
                    // 类列表选项卡
                    { move || {
                        if active_tab.get() == 0 {
                            let filtered_classes = filtered_classes();
                            let selected_class_val = selected_class.get();
                            let class_methods = selected_class_val.clone()
                                .map(|desc| get_class_methods(desc))
                                .unwrap_or_default();
                            let get_method_detail_clone = get_method_detail.clone();
                            
                            view! {
                                <div class="row g-3">
                                    // 左侧：类列表
                                    <div class="col-md-4">
                                        <div class="d-flex justify-content-between align-items-center mb-2">
                                            <h3 class="h6 mb-0">"类"</h3>
                                        </div>
                                        <input
                                            class="form-control form-control-sm mb-2"
                                            type="text"
                                            placeholder="过滤类…"
                                            prop:value=move || filter.get()
                                            on:input=move |ev| set_filter.set(event_target_value(&ev))
                                        />
                                        <div class="border rounded" style="max-height: 500px; overflow-y: auto;">
                                            <table class="table table-sm table-hover mb-0">
                                                <thead class="table-light sticky-top">
                                                    <tr>
                                                        <th scope="col">"类名"</th>
                                                        <th scope="col">"方法"</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {
                                                        let rows = filtered_classes;
                                                        if rows.is_empty() {
                                                            view! {
                                                                <tr>
                                                                    <td colspan="2" class="text-secondary">"没有匹配的类"</td>
                                                                </tr>
                                                            }.into_view()
                                                        } else {
                                                            rows.into_iter().map(|(descriptor, methods)| {
                                                                let is_selected = selected_class_val.as_ref() == Some(&descriptor);
                                                                let desc_clone = descriptor.clone();
                                                                view! {
                                                                    <tr 
                                                                        on:click=move |_| {
                                                                            set_selected_class.set(Some(desc_clone.clone()));
                                                                            set_selected_method.set(None);
                                                                        }
                                                                        style="cursor: pointer;"
                                                                        class=is_selected.then_some("table-active")
                                                                    >
                                                                        <td class="font-monospace small" style="word-break: break-all;">
                                                                            {descriptor}
                                                                        </td>
                                                                        <td>{methods}</td>
                                                                    </tr>
                                                                }
                                                            }).collect_view()
                                                        }
                                                    }
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>

                                    // 中间：方法列表
                                    <div class="col-md-4">
                                        <div class="d-flex justify-content-between align-items-center mb-2">
                                            <h3 class="h6 mb-0">
                                                {
                                                    if let Some(ref desc) = selected_class_val {
                                                        format!("{} 的方法", desc)
                                                    } else {
                                                        "方法".to_string()
                                                    }
                                                }
                                            </h3>
                                        </div>
                                        <div class="border rounded" style="max-height: 500px; overflow-y: auto;">
                                            {
                                                if class_methods.is_empty() {
                                                    view! {
                                                        <div class="text-secondary text-center py-5">
                                                            {
                                                                if selected_class_val.is_none() {
                                                                    view! { <p>"请先选择一个类"</p> }.into_view()
                                                                } else {
                                                                    view! { <p>"该类没有方法或为匿名类"</p> }.into_view()
                                                                }
                                                            }
                                                        </div>
                                                    }.into_view()
                                                } else {
                                                    view! {
                                                        <table class="table table-sm table-hover mb-0">
                                                            <thead class="table-light sticky-top">
                                                                <tr>
                                                                    <th scope="col">"方法名"</th>
                                                                    <th scope="col">"索引"</th>
                                                                </tr>
                                                            </thead>
                                                            <tbody>
                                                                {
                                                                    class_methods.into_iter().map(|(name, idx)| {
                                                                        let method_name = name.clone();
                                                                        let method_idx = idx;
                                                                        let class_desc = selected_class_val.clone().unwrap_or_default();
                                                                        let get_method_clone = get_method_detail_clone.clone();
                                                                        view! {
                                                                            <tr 
                                                                                on:click=move |_| {
                                                                                    if let Some(detail) = get_method_clone(class_desc.clone(), method_idx) {
                                                                                        set_selected_method.set(Some(detail));
                                                                                    }
                                                                                }
                                                                                style="cursor: pointer;"
                                                                            >
                                                                                <td class="font-monospace small">{method_name}</td>
                                                                                <td>{method_idx}</td>
                                                                            </tr>
                                                                        }
                                                                    }).collect_view()
                                                                }
                                                            </tbody>
                                                        </table>
                                                    }.into_view()
                                                }
                                            }
                                        </div>
                                    </div>

                                    // 右侧：Smali 代码
                                    <div class="col-md-4">
                                        <div class="d-flex justify-content-between align-items-center mb-2">
                                            <h3 class="h6 mb-0">"Smali 代码"</h3>
                                        </div>
                                        { move || {
                                            match selected_method.get() {
                                                Some(method) => {
                                                    view! {
                                                        <MethodDetailView
                                                            class_name=method.class.clone()
                                                            method_name=method.name.clone()
                                                            signature=method.signature.clone()
                                                            access_flags=method.access_flags.clone()
                                                            smali_code=method.smali_code.clone()
                                                        />
                                                    }.into_view()
                                                }
                                                None => {
                                                    view! {
                                                        <div class="border rounded p-3 bg-light" style="min-height: 500px;">
                                                            <div class="text-secondary text-center py-5">
                                                                <i class="bi bi-code-slash" style="font-size: 3rem;"></i>
                                                                <p class="mt-3">"请点击左侧方法查看 Smali 代码"</p>
                                                            </div>
                                                        </div>
                                                    }.into_view()
                                                }
                                            }
                                        }}
                                    </div>
                                </div>
                            }.into_view()
                        } else {
                            view! { <div></div> }.into_view()
                        }
                    }}

                    // 字符串选项卡
                    { move || {
                        if active_tab.get() == 1 {
                            let strings_clone = strings.clone();
                            view! {
                                <div>
                                    <StringBrowser strings=strings_clone/>
                                </div>
                            }.into_view()
                        } else {
                            view! { <div></div> }.into_view()
                        }
                    }}
                </div>
            </section>
        </div>
    }
}

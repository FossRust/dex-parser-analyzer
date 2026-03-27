use leptos::*;

/// 方法详情视图组件，显示 Smali 反汇编代码
#[component]
pub fn MethodDetailView(
    /// 类描述符
    class_name: String,
    /// 方法名
    method_name: String,
    /// 方法签名
    signature: String,
    /// 访问标志
    access_flags: String,
    /// Smali 代码行
    smali_code: Vec<String>,
) -> impl IntoView {
    view! {
        <div class="card shadow-sm">
            <div class="card-header bg-dark text-white">
                <h5 class="mb-0">
                    <i class="bi bi-code-slash"></i>
                    {" 方法详情"}
                </h5>
            </div>
            <div class="card-body">
                // 方法信息
                <div class="mb-3">
                    <h6 class="text-secondary">"方法信息"</h6>
                    <div class="row g-2">
                        <div class="col-md-6">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-secondary small">"类名"</div>
                                <div class="font-monospace">{class_name}</div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-secondary small">"方法名"</div>
                                <div class="font-monospace">{method_name}</div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-secondary small">"签名"</div>
                                <div class="font-monospace small">{signature}</div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-secondary small">"访问标志"</div>
                                <div class="font-monospace small">{access_flags}</div>
                            </div>
                        </div>
                    </div>
                </div>

                // Smali 代码
                <div>
                    <h6 class="text-secondary">"Smali 反汇编代码"</h6>
                    <pre class="bg-dark text-light p-3 rounded" style="overflow-x: auto; max-height: 600px;">
                        <code>{smali_code.join("\n")}</code>
                    </pre>
                </div>
            </div>
        </div>
    }
}

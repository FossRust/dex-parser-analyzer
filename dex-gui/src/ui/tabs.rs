use leptos::*;

use super::app::Tab;

#[component]
pub fn Tabs(active_tab: ReadSignal<Tab>, set_active_tab: WriteSignal<Tab>) -> impl IntoView {
    view! {
        <div class="tabs">
            <button
                class=move || if active_tab.get() == Tab::Dex { "tab active" } else { "tab" }
                on:click=move |_| set_active_tab.set(Tab::Dex)
            >
                "Dex"
            </button>
            <button
                class=move || if active_tab.get() == Tab::Analysis { "tab active" } else { "tab" }
                on:click=move |_| set_active_tab.set(Tab::Analysis)
            >
                "Analysis"
            </button>
        </div>
    }
}

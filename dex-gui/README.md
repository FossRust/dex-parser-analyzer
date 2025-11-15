# dex-gui

Client-side Leptos application that loads a `.dex` file, renders summaries, and displays analyzer findings.

## Local development

```bash
cd dex-gui
rustup target add wasm32-unknown-unknown
cargo install trunk --locked
trunk serve
```

Open `http://localhost:8080` and upload a `.dex` file from your machine.

## GitHub Pages deployment

The repository includes `.github/workflows/deploy-dex-gui.yml`, which:

1. Builds `dex-gui` with `trunk build --release --public-url /<repo>/`.
2. Publishes the contents of `dex-gui/dist/` to the `gh-pages` branch via GitHub Pages.

To enable the workflow:

1. Navigate to **Settings → Pages** and select “GitHub Actions” as the source.
2. Push to `main` (or trigger the workflow manually) after modifying `dex-gui/`.

Once deployed, the app is available at `https://<username>.github.io/<repo>/`.

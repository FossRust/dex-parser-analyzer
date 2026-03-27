@echo off
setlocal

echo [1/3] Checking environment...
where trunk >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: Trunk is not installed. Please install it with 'cargo install trunk'.
    exit /b 1
)

echo [2/3] Running CLI Analysis on test data...
cd dex-cli
cargo run --release -- ../dex-core/tests/data/AnalysisTest.dex --max-findings 5
if %errorlevel% neq 0 (
    echo CLI analysis failed.
)
cd ..

echo [3/3] Starting GUI Server at http://localhost:8080...
echo (Press Ctrl+C in this terminal to stop the server eventually)
cd dex-gui
trunk serve --port 8080 --open

#[tauri::command]
fn read_any(path: String) -> String { std::fs::read_to_string(path).unwrap_or_default() }

#[tauri::command]
async fn run(cmd: String, args: Vec<String>) -> Result<(), String> { Ok(()) }

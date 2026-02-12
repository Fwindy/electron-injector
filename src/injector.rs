use std::process::{Child, Command};
use std::{fs, thread, time};

use anyhow::{bail, Result};
use log::{debug, info, warn};
use portpicker;
use serde_json::json;

use crate::assets;
use crate::config::Config;
use crate::protocol::{DevtoolPage, EvaluateResponse};
use crate::websocket::WebSocket;

struct UserScript {
    file_path: String,
    content: String,
}

pub struct Injector {
    config: Config,
    port: u16,
}

impl Injector {
    pub(crate) const INJECT_LOOP_SLEEP_MS: u64 = 1000;
    pub(crate) const WAIT_DEBUGGING_PORT_TIMEOUT_MS: u64 = 30_000;

    fn get_available_port(config: &Config) -> u16 {
        if portpicker::is_free_tcp(config.port) {
            info!("Using port: {}", config.port);
            return config.port;
        }

        info!(
            "Port {} is not available, finding another port",
            config.port
        );

        let port = portpicker::pick_unused_port().expect("Port should be available");
        info!("Found available port: {}", port);

        port
    }

    pub fn new() -> Self {
        // Parse CLI args
        let config = Config::parse_auto();

        // Get port
        let port = Injector::get_available_port(&config);

        Injector { config, port }
    }

    pub fn run(&self) -> Result<()> {
        info!("Running injector");
        debug!("{:#?}", self.config);

        // Spawn child process
        _ = self.spawn_process()?;

        // Prepare prelude script
        let prelude_script = self.get_prelude_script().unwrap_or(String::new());

        // Prepare user scripts
        let user_scripts = self.get_user_scripts();

        // Create timeout duration
        let timeout_duration = time::Duration::from_millis(self.config.timeout);

        // Declare a vec to store found page ids
        let mut found_page_ids: Vec<String> = Vec::new();

        // Inject loop
        let start_time = time::Instant::now();
        loop {
            // Refresh devtool pages
            let devtool_pages = self
                .get_devtool_pages()
                .expect("Should be able to get devtool pages");

            debug!("{:#?}", devtool_pages);

            // Loop through pages
            for page in devtool_pages {
                if found_page_ids.contains(&page.id) {
                    continue;
                }

                // Create WebSocket
                let mut ws = WebSocket::connect(&page.web_socket_debugger_url)
                    .expect("To connect to websocket");

                // Inject prelude
                if self.config.prelude {
                    info!("Injecting prelude script (id: {})", page.id);
                    self.evaluate(&mut ws, &prelude_script)
                        .expect("Should be able to evaluate JS");
                }

                // Inject scripts
                for user_script in user_scripts.iter() {
                    // Inject using evaluate
                    info!("Injecting script: {}", user_script.file_path);
                    self.evaluate(&mut ws, &user_script.content)
                        .expect("Should be able to evaluate JS");
                }

                // Save page id
                found_page_ids.push(page.id.clone());
            }

            // Check devtool pages again
            let updated_devtool_pages = self
                .get_devtool_pages()
                .expect("Should be able to get devtool pages");

            // Stop if already found all pages
            if found_page_ids.len() == updated_devtool_pages.len() {
                info!("Stopping injection loop");
                break;
            }

            // Timed out
            if start_time.elapsed() >= timeout_duration {
                bail!("Injection loop timed out");
            }

            // Sleep before next loop iteration
            thread::sleep(time::Duration::from_millis(Self::INJECT_LOOP_SLEEP_MS));
        }

        info!("Injection success");
        Ok(())
    }

    fn get_devtool_pages(&self) -> Result<Vec<DevtoolPage>, reqwest::Error> {
        let url = format!("http://{}:{}/json/list", &self.config.host, &self.port);

        let client = reqwest::blocking::Client::new();
        let response = client.get(url).send()?.error_for_status()?;

        let pages_response = response.json::<Vec<DevtoolPage>>()?;
        Ok(pages_response)
    }

    fn get_prelude_script(&self) -> Option<String> {
        // No need to load if not enabled anyways
        if !self.config.prelude {
            return None;
        }

        // Load from embedded file
        let file = assets::JS::get("prelude.js").unwrap();
        let script =
            std::str::from_utf8(file.data.as_ref()).expect("Script should be a valid UTF-8 file");

        Some(String::from(script))
    }

    fn get_user_scripts(&self) -> Vec<UserScript> {
        let mut scripts = Vec::new();

        for script_arg in &self.config.script {
            let path = std::path::Path::new(script_arg);

            if path.is_dir() {
                // 如果是目录，遍历并加载其中的 .js 文件
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries {
                        if let Ok(entry) = entry {
                            let entry_path = entry.path();
                            // 检查是否为文件且扩展名为 js
                            if entry_path.is_file() && entry_path.extension().map_or(false, |ext| ext == "js") {
                                match fs::read_to_string(&entry_path) {
                                    Ok(content) => {
                                        info!("Found script in directory: {:?}", entry_path);
                                        scripts.push(UserScript {
                                            file_path: entry_path.to_string_lossy().to_string(),
                                            content,
                                        });
                                    }
                                    Err(e) => {
                                        warn!("Failed to read file {:?}: {}", entry_path, e);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    warn!("Failed to read directory: {:?}", path);
                }
            } else {
                // 如果是单个文件，保持原有逻辑
                let content =
                    fs::read_to_string(script_arg).expect("Should have been able to read the file");

                scripts.push(UserScript {
                    file_path: script_arg.to_string(),
                    content,
                });
            }
        }

        scripts
    }

    fn spawn_process(&self) -> Result<Child> {
        // Prepare args
        let mut args = vec![format!("--remote-debugging-port={}", &self.port)];
        args.extend(self.config.arg.iter().cloned());

        // Spawn child process
        debug!(
            "Spawning electron app: {} (args: {:#?})",
            &self.config.app, args
        );
        let child = Command::new(&self.config.app).args(args).spawn()?;

        // Wait for process
        info!("Waiting for {}ms", self.config.delay);
        thread::sleep(time::Duration::from_millis(self.config.delay));

        // Create timeout duration
        let timeout_duration = time::Duration::from_millis(Self::WAIT_DEBUGGING_PORT_TIMEOUT_MS);

        // Wait until remote debugging port is available
        info!("Waiting for remote debugging port");
        let start_time = time::Instant::now();
        loop {
            // Connected
            if self.get_devtool_pages().is_ok() {
                info!("Connected to remote debugging port");
                break;
            }

            // Timed out
            if start_time.elapsed() >= timeout_duration {
                bail!("Unable to connect to remote debugging port");
            }
        }

        Ok(child)
    }

    fn evaluate(&self, ws: &mut WebSocket, expression: &str) -> Result<()> {
        // Create payload
        // https://chromedevtools.github.io/devtools-protocol/tot/Runtime/#method-evaluate
        let request_id = 1;
        let payload = json!({
            "id": request_id,
            "method": "Runtime.evaluate",
            "params": {
                "expression": expression,
                "objectGroup": "inject",
                "includeCommandLineAPI": true,
                "silent": true,
                "userGesture": true,
                "awaitPromise": true,
            },
        });

        // Serialize payload to JSON
        let payload_json = serde_json::to_string(&payload)?;

        // Send message
        ws.send(&payload_json)?;

        loop {
            // Read next message
            let msg = ws.receive()?;

            // Ignore if not a text
            if !msg.is_text() {
                debug!("[Runtime.evaluate] Ignoring non-text message: {:#?}", msg);
                continue;
            }

            let text = msg.to_text()?;
            
            // Parse as generic Value first to check for ID without crashing
            let v: serde_json::Value = serde_json::from_str(text)?;

            // Check if this message corresponds to our request ID
            if let Some(id) = v.get("id").and_then(|id| id.as_i64()) {
                if id == request_id as i64 {
                    // This is our response, parse specifically as EvaluateResponse
                    let response: EvaluateResponse = serde_json::from_value(v)?;
                    
                    debug!("[Runtime.evaluate] Parsed response: {:#?}", response);

                    // Handle exception
                    if response.result.exception_details.is_some() {
                        warn!(
                            "[Runtime.evaluate] Caught exception while evaluating script: {:#?}",
                            response
                        );
                    }
                    return Ok(());
                }
            }

            // If we are here, it was an event or a response to a different ID.
            // In a real app you might want to log this or handle events.
            debug!("[Runtime.evaluate] Ignoring message (likely an event): {}", text);
        }
    }
}

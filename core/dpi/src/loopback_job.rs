//! Изолированный дочерний процесс для ручной localhost-проверки.
//! Успех не подтверждает выгрузку общего WinDivert или работу DPI.
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Outcome {
    pub spawned: bool,
    pub success: bool,
    pub detail: String,
}

/// Единственный фиксированный аргумент; stdout/stderr ограничены, таймаут не
/// приравнивает уничтожение процесса к подтверждённому закрытию WinDivert.
pub fn run(executable: &Path, timeout: Duration) -> Outcome {
    let mut command = Command::new(executable);
    command
        .arg("--run")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Outcome {
                spawned: false,
                success: false,
                detail: format!("Не удалось запустить отдельный тест: {e}"),
            }
        }
    };
    let (tx, rx) = mpsc::channel();
    for stream in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stream.take(8192).read_to_end(&mut bytes);
            let _ = tx.send(String::from_utf8_lossy(&bytes).trim().to_string());
        });
    }
    drop(tx);
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let killed = child.kill();
                let ended = wait_briefly(&mut child);
                return Outcome { spawned: true, success: false, detail: format!("Время ожидания истекло; попытка завершить тестовый процесс: {}; завершение процесса {}. Закрытие WinDivert не подтверждено; проверьте общую службу.", killed.err().map_or_else(|| "запрошено".into(), |e| e.to_string()), if ended { "подтверждено" } else { "не подтверждено" }) };
            }
            Err(e) => {
                let killed = child.kill();
                let ended = wait_briefly(&mut child);
                return Outcome { spawned: true, success: false, detail: format!("Не удалось проверить тестовый процесс: {e}; завершение: {}; выход процесса {}. Закрытие WinDivert не подтверждено.", killed.err().map_or_else(|| "запрошено".into(), |e| e.to_string()), if ended { "подтвержден" } else { "не подтвержден" }) };
            }
        }
    };
    let mut parts = Vec::new();
    for _ in 0..2 {
        if let Ok(text) = rx.recv_timeout(Duration::from_millis(250)) {
            if !text.is_empty() {
                parts.push(text);
            }
        }
    }
    let status = status.expect("loop only exits with status");
    Outcome {
        spawned: true,
        success: status.success(),
        detail: format!(
            "{}{}",
            if status.success() {
                "Проверка процесса завершилась успешно.".to_string()
            } else {
                format!("Тестовый процесс завершился с ошибкой ({status}); закрытие WinDivert не подтверждено.")
            },
            if parts.is_empty() {
                String::new()
            } else {
                format!(" {}", parts.join(" "))
            }
        ),
    }
}

fn wait_briefly(child: &mut std::process::Child) -> bool {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(50)),
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_executable_is_not_a_started_or_successful_test() {
        let result = run(
            Path::new("/nonexistent-umbra-probe"),
            Duration::from_millis(30),
        );
        assert!(!result.spawned && !result.success);
    }
    #[cfg(unix)]
    #[test]
    fn exit_status_and_hung_child_are_not_mistaken_for_success() {
        let result = run(Path::new("/bin/false"), Duration::from_secs(1));
        assert!(result.spawned && !result.success);
        // The helper receives --run; a tiny script exercises the timeout path.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("umbra-probe-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("hang");
        std::fs::write(&p, "#!/bin/sh\nexec sleep 5\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = run(&p, Duration::from_millis(60));
        assert!(result.spawned && !result.success && result.detail.contains("не подтверждено"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}

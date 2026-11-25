//! Одноразовая проверка для Windows x64, НЕ кнопка DPI.
//! Требует feature loopback-probe, явного флага и прав администратора.
#[cfg(all(windows, target_arch = "x86_64", feature = "loopback-probe"))]
fn main() {
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--run"] {
        eprintln!("Проверка временно перехватывает TCP localhost и передаёт исходные пакет и адрес в WinDivertSend. Сам WinDivert может пересчитать контрольные суммы. Возможны потеря тестовых пакетов и запуск общей службы WinDivert; проверка её не останавливает. Закройте другие программы WinDivert. Запускайте только по инструкции, от администратора, с аргументом --run.");
        std::process::exit(2);
    }
    // Не оставлять тест выполняться бесконечно даже после закрытия UI.
    // Принудительное завершение НЕ подтверждает закрытие драйвера.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(30));
        eprintln!("Истёк лимит теста; закрытие WinDivert не подтверждено.");
        std::process::exit(1);
    });
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Не удалось определить путь: {e}");
            std::process::exit(1);
        }
    };
    let Some(dir) = exe.parent() else {
        eprintln!("Нет каталога приложения");
        std::process::exit(1)
    };
    eprintln!(
        "Запуск отдельной loopback-проверки. Она не проверяет внешний интернет и не включает DPI."
    );
    match umbranet_dpi::capture::loopback_probe::run(&dir.join("WinDivert.dll")) {
        Ok(result) => println!("Проверка завершена: тестовый обмен совпал, получено {}, возвращено {}. Служба WinDivert отдельно не останавливалась.", result.packets_received, result.packets_returned),
        Err(error) => { eprintln!("Ошибка: {error}. Не считать проверку успешной. Закройте этот тестовый процесс; проверьте состояние общей службы WinDivert."); std::process::exit(1); }
    }
}

#[cfg(not(all(windows, target_arch = "x86_64", feature = "loopback-probe")))]
fn main() {
    eprintln!("Доступно только в Windows x64 с feature loopback-probe.");
    std::process::exit(2);
}

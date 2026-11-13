/// Нормализует DNS-имя, но не принимает URL, IP, маски и одиночные зоны.
/// Международные имена должны быть представлены в ASCII/Punycode.
pub fn normalize_domain(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    let name = trimmed
        .strip_suffix('.')
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if name.len() > 253 || name.is_empty() || name.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!("Некорректный домен: {input}"));
    }
    let labels: Vec<_> = name.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || labels
            .last()
            .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!("Некорректный домен: {input}"));
    }
    Ok(name)
}

/// Совпадение по границе метки: example.com и его поддомены, но не notexample.com.
pub fn domain_matches(target: &str, hostname: &str) -> bool {
    let Ok(target) = normalize_domain(target) else {
        return false;
    };
    let Ok(hostname) = normalize_domain(hostname) else {
        return false;
    };
    hostname == target
        || hostname
            .strip_suffix(&target)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

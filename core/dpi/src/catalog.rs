use crate::domain::normalize_domain;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub name: String,
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub version: u32,
    pub services: BTreeMap<String, Service>,
}

impl Catalog {
    pub fn from_json(json: &str) -> Result<Self, String> {
        let mut catalog: Self = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if catalog.version != 1 {
            return Err("Неизвестная версия каталога".into());
        }
        for (id, service) in &mut catalog.services {
            if id.trim().is_empty() || service.name.trim().is_empty() || service.domains.is_empty()
            {
                return Err(format!("Некорректная запись сервиса: {id}"));
            }
            service.domains = service
                .domains
                .iter()
                .map(|d| normalize_domain(d))
                .collect::<Result<_, _>>()?;
            service.domains.sort();
            service.domains.dedup();
        }
        Ok(catalog)
    }
}

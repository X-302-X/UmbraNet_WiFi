use serde::{Deserialize, Serialize};

/// Никаких команд winws здесь нет: неподдерживаемые действия отвергаются.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    PassThrough,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Strategy {
    pub version: u32,
    pub id: String,
    pub name: String,
    pub actions: Vec<Action>,
}

impl Strategy {
    pub fn from_json(json: &str) -> Result<Self, String> {
        let strategy: Self = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if strategy.version != 1
            || strategy.id.trim().is_empty()
            || strategy.name.trim().is_empty()
            || strategy.actions != [Action::PassThrough]
        {
            return Err("Некорректная или неподдерживаемая стратегия".into());
        }
        Ok(strategy)
    }
}

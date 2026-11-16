use crate::traffic::desync::{auto_ttl, DesyncPlan, Fooling, SplitPos};
use serde::{Deserialize, Serialize};

/// Позиция разреза TCP payload в JSON-конфигурации стратегии.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategySplitPos {
    Offset(usize),
    Host,
    EndHost,
    Sld,
    Method,
    Mid,
}

/// Метод маскировки (fooling) fake-пакета.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyFooling {
    Ttl(u8),
    AutoTtl { delta: u8, min: u8, max: u8 },
    BadSum,
    BadSeq(i32),
    Md5Sig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    PassThrough,
    Fake {
        #[serde(default = "default_repeats")]
        repeats: u8,
        #[serde(default)]
        fooling: Vec<StrategyFooling>,
    },
    Split {
        positions: Vec<StrategySplitPos>,
    },
    Disorder {
        positions: Vec<StrategySplitPos>,
    },
    TlsRecordSplit {
        offset: usize,
    },
}

fn default_repeats() -> u8 {
    1
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
            || strategy.actions.is_empty()
        {
            return Err("Некорректная или неподдерживаемая стратегия".into());
        }
        Ok(strategy)
    }

    pub fn is_pass_through(&self) -> bool {
        self.actions.len() == 1 && self.actions[0] == Action::PassThrough
    }

    /// Преобразует действия стратегии в исполняемый `DesyncPlan`.
    pub fn to_desync_plan(&self, server_ttl: Option<u8>) -> DesyncPlan {
        let mut plan = DesyncPlan {
            splits: Vec::new(),
            disorder: false,
            fake: false,
            fake_repeats: 1,
            fooling: Vec::new(),
            fake_payload: Vec::new(),
            tls_record_split: None,
        };
        for action in &self.actions {
            match action {
                Action::PassThrough => {}
                Action::Fake { repeats, fooling } => {
                    plan.fake = true;
                    plan.fake_repeats = (*repeats).max(1);
                    for f in fooling {
                        let mapped = match *f {
                            StrategyFooling::Ttl(t) => Fooling::Ttl(t),
                            StrategyFooling::AutoTtl { delta, min, max } => {
                                let ttl = server_ttl
                                    .map(|st| auto_ttl(st, delta, min, max))
                                    .unwrap_or(min.max(1));
                                Fooling::Ttl(ttl)
                            }
                            StrategyFooling::BadSum => Fooling::BadSum,
                            StrategyFooling::BadSeq(d) => Fooling::BadSeq(d),
                            StrategyFooling::Md5Sig => Fooling::Md5Sig,
                        };
                        plan.fooling.push(mapped);
                    }
                }
                Action::Split { positions } => {
                    for p in positions {
                        plan.splits.push(map_split_pos(p));
                    }
                }
                Action::Disorder { positions } => {
                    plan.disorder = true;
                    for p in positions {
                        plan.splits.push(map_split_pos(p));
                    }
                }
                Action::TlsRecordSplit { offset } => {
                    plan.tls_record_split = Some(*offset);
                }
            }
        }
        plan
    }
}

fn map_split_pos(p: &StrategySplitPos) -> SplitPos {
    match *p {
        StrategySplitPos::Offset(o) => SplitPos::Offset(o),
        StrategySplitPos::Host => SplitPos::Host,
        StrategySplitPos::EndHost => SplitPos::EndHost,
        StrategySplitPos::Sld => SplitPos::Sld,
        StrategySplitPos::Method => SplitPos::Method,
        StrategySplitPos::Mid => SplitPos::Mid,
    }
}

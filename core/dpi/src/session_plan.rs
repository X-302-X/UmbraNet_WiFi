//! Неизменяемый снимок целей для будущего активного запуска.
//! Подготовка не открывает WinDivert и не подтверждает принадлежность пакетов.
use std::collections::{BTreeMap, BTreeSet};

use crate::autohostlist::AutoHostList;
use crate::engine::Engine;
use crate::selection::Snapshot;
use crate::strategy::{Action, Strategy};
use crate::traffic::filter::{HostList, IpSet};

#[derive(Debug, Clone)]
pub struct SessionPlan {
    snapshot: Snapshot,
    domains: HostList,
}

impl SessionPlan {
    /// Принимает только снимок, созданный Store на основе проверенного каталога.
    pub(crate) fn from_snapshot(snapshot: Snapshot) -> Result<Self, String> {
        if snapshot.domains.is_empty()
            && snapshot.manual_processes.is_empty()
            && snapshot.service_processes.values().all(BTreeSet::is_empty)
        {
            return Err("Выберите хотя бы один сервис, домен или процесс".into());
        }
        // Strategy имеет публичные поля: повторно валидируем даже ручные экземпляры.
        let encoded = serde_json::to_string(&snapshot.strategy).map_err(|e| e.to_string())?;
        Strategy::from_json(&encoded)?;
        let domains = HostList::from_lines(snapshot.domains.iter().map(String::as_str));
        Ok(Self { snapshot, domains })
    }

    pub fn strategy(&self) -> &Strategy {
        &self.snapshot.strategy
    }
    pub fn domains(&self) -> &BTreeSet<String> {
        &self.snapshot.domains
    }
    pub fn services(&self) -> &BTreeSet<String> {
        &self.snapshot.services
    }
    pub fn manual_processes(&self) -> &BTreeSet<String> {
        &self.snapshot.manual_processes
    }
    pub fn service_processes(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.snapshot.service_processes
    }
    pub fn matches_domain(&self, hostname: &str) -> bool {
        self.domains.matches(hostname)
    }

    /// Предварительный результат для синтетической модели TCP, не разрешение
    /// изменять пакеты: события и token сами не подтверждают подлинность трафика.
    /// Совпадение по процессу здесь намеренно не поддерживается.
    pub fn offline_tcp_candidate(
        &self,
        connections: &mut crate::traffic::connections::Connections,
        key: &crate::flow::tracker::FlowKey,
        token: crate::traffic::connections::Token,
        now: u64,
    ) -> Result<crate::traffic::classifier::Match, crate::traffic::connections::Error> {
        let evidence = connections.evidence(key, token, now)?;
        Ok(crate::traffic::classifier::classify(
            &self.snapshot,
            &evidence,
            None,
        ))
    }

    /// Неполный список известных неподдерживаемых случаев, не разрешение на запуск.
    /// Двигатель пока не умеет надёжно сопоставлять процессы или обрабатывать UDP.
    pub fn check_known_limits(&self) -> Result<(), String> {
        if self.snapshot.domains.is_empty() {
            return Err(
                "Пока требуется хотя бы один выбранный домен: привязка по процессу не готова"
                    .into(),
            );
        }
        if !self.snapshot.manual_processes.is_empty()
            || self
                .snapshot
                .service_processes
                .values()
                .any(|p| !p.is_empty())
        {
            return Err(
                "Обработка выбранных процессов пока не готова; снимок сохранён, запуск запрещён"
                    .into(),
            );
        }
        if self
            .snapshot
            .strategy
            .actions
            .iter()
            .any(|action| matches!(action, Action::UdpFake { .. }))
        {
            return Err(
                "Обработка UDP пока не готова; выбранную стратегию запустить нельзя".into(),
            );
        }
        Ok(())
    }

    /// Только для синтетических офлайн-проверок. Engine остаётся изменяемым и
    /// его публичные низкоуровневые методы сами по себе не защищены guard.
    /// Успех этой функции НЕ означает, что сетевой запуск безопасен.
    pub fn make_offline_engine(&self, auto: Option<AutoHostList>) -> Result<Engine, String> {
        self.check_known_limits()?;
        Ok(Engine::with_autohostlist(
            self.snapshot.strategy.clone(),
            self.domains.clone(),
            IpSet::default(),
            auto,
        ))
    }
}

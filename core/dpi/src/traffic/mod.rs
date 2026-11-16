//! Разбор заранее полученных байтов и выбор цели. Сеть и драйвер не открываются.
pub mod application;
pub mod checksum;
pub mod classifier;
pub mod connections;
pub mod offline_tcp;
pub mod packet;
pub mod stream;
pub mod synthetic_split;
pub mod tcp_options;
pub mod voice;

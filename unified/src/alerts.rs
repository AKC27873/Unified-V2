use serde::{Deserialize, Seralize};
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use log::{info, warn, error};

const MAX_ALERTS: usize = 1000;

#[derive(Debug, Clone, Seralize, Deserialize, PartialEq)]
pub enum AlertLevel {
	Info,
	Warnig,
	Critical,
}

#[derive(Debug, Clone, Seralize, Deserialize)]
pub struct Alert {
	pub level: AlertLevel,
	pub title: String,
	pub message: String,
	pub timestamp: DateTime<Utc>,
}

pub struct AlertManager {
	alerts: VecDeque<Alert>,
}

impl AlertManager {
	pub fn new() -> Self{
		alerts: VecDeque::with_capacity(MAX_ALERTS),
	}
}

pub fn add_alert(&mut self, alert: Alert) {
        match alert.level {
            AlertLevel::Info => info!("ℹ️  {}: {}", alert.title, alert.message),
            AlertLevel::Warning => warn!("⚠️  {}: {}", alert.title, alert.message),
            AlertLevel::Critical => error!("🚨 {}: {}", alert.title, alert.message),
        }

        if self.alerts.len() >= MAX_ALERTS {
            self.alerts.pop_front();
        }
        
        self.alerts.push_back(alert);
    }

    pub fn get_alerts(&self) -> Vec<Alert> {
        self.alerts.iter().cloned().collect()
    }

    pub fn get_recent_alerts(&self, count: usize) -> Vec<Alert> {
        self.alerts.iter().rev().take(count).cloned().collect()
    }

    pub fn clear_alerts(&mut self) {
        self.alerts.clear();
    }

    pub fn count_by_level(&self, level: AlertLevel) -> usize {
        self.alerts.iter().filter(|a| a.level == level).count()
    }
}






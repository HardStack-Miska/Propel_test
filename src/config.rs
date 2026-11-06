//! Local configuration. Secrets are never formatted and environment wins over .env.
use crate::{
    deepseek::{BudgetLimits, DeepSeekConfig},
    model::Analyzer,
};
use anyhow::{Context, Result, bail};
use std::{collections::HashMap, time::Duration};

pub struct Config {
    values: HashMap<String, String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let values = match std::fs::read_to_string(".env") {
            Ok(text) => parse_env(&text)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(_) => bail!("cannot read local .env"),
        };
        Ok(Self { values })
    }

    pub fn get(&self, name: &str, default: &str) -> Result<String> {
        match std::env::var(name) {
            Ok(value) => Ok(value),
            Err(std::env::VarError::NotPresent) => Ok(self
                .values
                .get(name)
                .cloned()
                .unwrap_or_else(|| default.into())),
            Err(_) => bail!("{name} must be valid UTF-8"),
        }
    }

    pub fn positive(&self, name: &str, default: u64) -> Result<u64> {
        self.get(name, &default.to_string())?
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .with_context(|| format!("{name} must be a positive integer"))
    }

    pub fn analyzer(&self) -> Result<Analyzer> {
        self.build_analyzer(false)
    }

    fn build_analyzer(&self, evaluation: bool) -> Result<Analyzer> {
        let concurrency = usize::try_from(self.positive("MODEL_CONCURRENCY", 4)?)
            .context("invalid model concurrency")?;
        let analyzer = match self.get("TRIAGE_MODE", "replay")?.as_str() {
            "replay" => Ok(Analyzer::replay()),
            "ollama" => Analyzer::ollama(
                &self.get("OLLAMA_URL", "http://127.0.0.1:11434")?,
                &self.get("OLLAMA_MODEL", "qwen2.5:3b")?,
                concurrency,
                Duration::from_millis(self.positive("MODEL_TIMEOUT_MS", 8000)?),
            ),
            "deepseek" => {
                let model = self.get("DEEPSEEK_MODEL", "deepseek-flash")?;
                // Default estimates apply only to the documented Flash price.
                if model != "deepseek-flash" {
                    for name in [
                        "DEEPSEEK_INPUT_MISS_NANO",
                        "DEEPSEEK_INPUT_HIT_NANO",
                        "DEEPSEEK_OUTPUT_NANO",
                    ] {
                        if self.get(name, "")?.is_empty() {
                            bail!("custom DeepSeek models require explicit token prices");
                        }
                    }
                }
                Analyzer::deepseek(DeepSeekConfig {
                    api_key: self.get("DEEPSEEK_API_KEY", "")?,
                    model,
                    max_tokens: u32::try_from(self.positive("DEEPSEEK_MAX_TOKENS", 512)?)
                        .context("invalid output limit")?,
                    timeout: Duration::from_millis(self.positive("MODEL_TIMEOUT_MS", 15000)?),
                    max_in_flight: concurrency,
                    budget: BudgetLimits {
                        max_calls: u32::try_from(
                            self.positive("DEEPSEEK_MAX_CALLS", 100)?
                                .min(if evaluation { 100 } else { u32::MAX as u64 }),
                        )
                        .context("invalid call limit")?,
                        max_cost_nano_usd: self
                            .positive("DEEPSEEK_MAX_COST_NANO_USD", 1_000_000_000)?
                            .min(if evaluation { 1_000_000_000 } else { u64::MAX }),
                        input_miss_nano_per_token: self
                            .positive("DEEPSEEK_INPUT_MISS_NANO", 300)?,
                        input_hit_nano_per_token: self.positive("DEEPSEEK_INPUT_HIT_NANO", 6)?,
                        output_nano_per_token: self.positive("DEEPSEEK_OUTPUT_NANO", 1200)?,
                    },
                })
            }
            _ => bail!("TRIAGE_MODE must be replay, ollama or deepseek"),
        }?;
        analyzer.with_cache(
            &self.get("ANALYSIS_CACHE_NAMESPACE", "singletenant")?,
            crate::cache::CacheConfig {
                capacity: usize::try_from(self.positive("ANALYSIS_CACHE_CAPACITY", 256)?)
                    .context("invalid cache capacity")?,
                ttl: Duration::from_secs(self.positive("ANALYSIS_CACHE_TTL_SECS", 300)?),
                max_in_flight: 256,
            },
        )
    }
}

pub fn analyzer_from_env() -> Result<Analyzer> {
    Config::load()?.analyzer()
}

pub fn evaluation_analyzer_from_env() -> Result<Analyzer> {
    let config = Config::load()?;
    if config.get("TRIAGE_MODE", "replay")? != "deepseek" {
        bail!("live evaluation requires TRIAGE_MODE=deepseek");
    }
    config.build_analyzer(true)
}

fn parse_env(text: &str) -> Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, raw) = line
            .split_once('=')
            .context("invalid .env entry; expected KEY=VALUE")?;
        let name = name.trim();
        if name.is_empty()
            || !name
                .bytes()
                .enumerate()
                .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
        {
            bail!("invalid .env variable name");
        }
        let raw = raw.trim();
        let value = if raw.starts_with(['\'', '"']) {
            if raw.len() < 2 || raw.as_bytes().first() != raw.as_bytes().last() {
                bail!("invalid .env quotation");
            }
            &raw[1..raw.len() - 1]
        } else {
            raw
        };
        values.insert(name.to_owned(), value.to_owned());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dotenv_is_literal_and_errors_do_not_echo_secrets() {
        let vars = parse_env("# comment\nKEY='literal$VALUE#suffix'\nEMPTY=\n").unwrap();
        assert_eq!(vars["KEY"], "literal$VALUE#suffix");
        assert_eq!(vars["EMPTY"], "");
        for invalid in ["secret-no-equals", "7SECRET=value", "KEY='secret"] {
            assert!(
                !parse_env(invalid)
                    .unwrap_err()
                    .to_string()
                    .contains("secret")
            );
        }
    }
}

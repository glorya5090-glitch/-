use anyhow::{anyhow, bail, Result};

const MAX_U128_DECIMALS: u8 = 38;

pub(super) fn format_token_amount(raw: u128, decimals: u8) -> Result<String> {
    if decimals > MAX_U128_DECIMALS {
        bail!("token decimals must be <= {MAX_U128_DECIMALS} for u128 formatting");
    }
    if decimals == 0 {
        return Ok(raw.to_string());
    }

    let scale = pow10(decimals)?;
    let whole = raw / scale;
    let fractional = raw % scale;
    if fractional == 0 {
        return Ok(whole.to_string());
    }

    let mut fractional_text = format!("{fractional:0width$}", width = decimals as usize);
    while fractional_text.ends_with('0') {
        fractional_text.pop();
    }
    Ok(format!("{whole}.{fractional_text}"))
}

pub(super) fn format_gwei_amount(raw_wei: u128) -> Result<String> {
    format_token_amount(raw_wei, 9)
}

pub(super) fn parse_required_token_amount(label: &str, value: &str, decimals: u8) -> Result<u128> {
    parse_token_amount(label, value, decimals, false)
}

pub(super) fn parse_optional_token_amount(
    label: &str,
    value: Option<&str>,
    decimals: u8,
) -> Result<u128> {
    match value {
        Some(value) if !value.trim().is_empty() => parse_token_amount(label, value, decimals, true),
        _ => Ok(0),
    }
}

pub(super) fn parse_optional_gwei_amount(label: &str, value: Option<&str>) -> Result<u128> {
    parse_optional_token_amount(label, value, 9)
}

pub(super) fn parse_legacy_amount(label: &str, value: f64, decimals: u8) -> Result<u128> {
    if !value.is_finite() || value <= 0.0 {
        bail!("{label} must be a positive finite number");
    }
    parse_required_token_amount(label, &value.to_string(), decimals)
}

fn parse_token_amount(label: &str, value: &str, decimals: u8, allow_zero: bool) -> Result<u128> {
    if decimals > MAX_U128_DECIMALS {
        bail!("{label} token decimals must be <= {MAX_U128_DECIMALS}");
    }

    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} is required");
    }
    if trimmed.starts_with('-') {
        bail!("{label} must not be negative");
    }

    let mut parts = trimmed.split('.');
    let whole_part = parts.next().unwrap_or_default();
    let fractional_part = parts.next();
    if parts.next().is_some() {
        bail!("{label} must be a decimal number");
    }

    let whole_digits = if whole_part.is_empty() {
        "0"
    } else {
        whole_part
    };
    if !whole_digits.chars().all(|ch| ch.is_ascii_digit()) {
        bail!("{label} must be a decimal number");
    }

    let fractional_digits = fractional_part.unwrap_or_default();
    if !fractional_digits.chars().all(|ch| ch.is_ascii_digit()) {
        bail!("{label} must be a decimal number");
    }
    if fractional_digits.len() > decimals as usize {
        bail!("{label} must use at most {} decimal places", decimals);
    }

    let scale = pow10(decimals)?;
    let whole = whole_digits
        .parse::<u128>()
        .map_err(|_| anyhow!("{label} is too large"))?;
    let whole_scaled = whole
        .checked_mul(scale)
        .ok_or_else(|| anyhow!("{label} is too large"))?;

    let mut fractional_text = fractional_digits.to_string();
    while fractional_text.len() < decimals as usize {
        fractional_text.push('0');
    }
    let fractional = if fractional_text.is_empty() {
        0
    } else {
        fractional_text
            .parse::<u128>()
            .map_err(|_| anyhow!("{label} is too large"))?
    };

    let value = whole_scaled
        .checked_add(fractional)
        .ok_or_else(|| anyhow!("{label} is too large"))?;
    if !allow_zero && value == 0 {
        bail!("{label} must be greater than zero");
    }
    Ok(value)
}

fn pow10(decimals: u8) -> Result<u128> {
    let mut value = 1_u128;
    for _ in 0..decimals {
        value = value
            .checked_mul(10)
            .ok_or_else(|| anyhow!("10^{} overflows u128", decimals))?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{
        format_gwei_amount, format_token_amount, parse_optional_gwei_amount,
        parse_optional_token_amount, parse_required_token_amount,
    };

    #[test]
    fn parse_required_token_amount_accepts_decimal_strings() {
        assert_eq!(
            parse_required_token_amount("amount", "1.25", 6).expect("amount"),
            1_250_000
        );
    }

    #[test]
    fn parse_required_token_amount_rejects_excess_precision() {
        let err = parse_required_token_amount("amount", "1.0000001", 6).expect_err("must reject");
        assert!(err
            .to_string()
            .contains("must use at most 6 decimal places"));
    }

    #[test]
    fn parse_optional_token_amount_defaults_blank_to_zero() {
        assert_eq!(
            parse_optional_token_amount("amount", Some(""), 18).expect("blank"),
            0
        );
        assert_eq!(
            parse_optional_token_amount("amount", None, 18).expect("none"),
            0
        );
    }

    #[test]
    fn format_token_amount_trims_trailing_zeroes() {
        assert_eq!(format_token_amount(1_250_000, 6).expect("format"), "1.25");
        assert_eq!(format_token_amount(1_000_000, 6).expect("format"), "1");
    }

    #[test]
    fn gwei_helpers_round_trip() {
        let raw = parse_optional_gwei_amount("fee", Some("2.5")).expect("parse");
        assert_eq!(raw, 2_500_000_000);
        assert_eq!(format_gwei_amount(raw).expect("format"), "2.5");
    }
}

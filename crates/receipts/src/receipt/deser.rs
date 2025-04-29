//! Serialization and deserialization for receipt types.

use super::{BLINDING_FACTOR_SIZE, TokenAmount};

use crate::alloc::string::String;
use crate::alloc::string::ToString;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum U32OrString {
    // TODO: actually, as we are using mostly "JSON", the greatest number we can use is 2^53 - 1.
    // That's u32 is used here for back-compatability.
    Number(u32),
    String(String),
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TokenAmountView {
    amount: U32OrString,

    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "is_default_blinding_factor")
    )]
    blinding_factor: [u8; BLINDING_FACTOR_SIZE],
}

fn is_default_blinding_factor(blinding_factor: &[u8; BLINDING_FACTOR_SIZE]) -> bool {
    *blinding_factor == [0; BLINDING_FACTOR_SIZE]
}

impl serde::Serialize for TokenAmount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let amount = u32::try_from(self.amount)
            .map(U32OrString::Number)
            .unwrap_or_else(|_| U32OrString::String(self.amount.to_string()));

        TokenAmountView {
            amount,
            blinding_factor: self.blinding_factor,
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for TokenAmount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let view = TokenAmountView::deserialize(deserializer)?;

        let amount = match view.amount {
            U32OrString::Number(num) => num as u128,
            U32OrString::String(string) => string
                .parse()
                .map_err(|_| serde::de::Error::custom("invalid u128 amount"))?,
        };

        Ok(Self {
            amount,
            blinding_factor: view.blinding_factor,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::TokenAmount;

    #[test]
    fn test_sanity_check() {
        let token_amount = TokenAmount::new(100, [1; super::BLINDING_FACTOR_SIZE]);
        let serialized = serde_json::to_string(&token_amount).unwrap();
        let deserialized: TokenAmount = serde_json::from_str(&serialized).unwrap();
        assert_eq!(token_amount, deserialized);
    }

    #[test]
    fn test_back_compatabilty() {
        let jsons = [
            json!({
                "amount": 100_000,
            }),
            json!({
                "amount": 10_000_000,
            }),
        ];

        for json in jsons {
            let _token_amount: TokenAmount = serde_json::from_value(json).unwrap();
        }
    }

    #[test]
    fn test_serializes_bigger_amounts_to_string() {
        let token_amount = TokenAmount::new(u32::MAX as u128 + 1, Default::default());
        let serialized = serde_json::to_value(token_amount).unwrap();

        assert_eq!(
            serialized,
            json!({
                "amount": (u32::MAX as u128 + 1).to_string(),
            })
        );
    }

    #[test]
    fn test_serializes_smaller_amounts_to_u32() {
        let token_amount = TokenAmount::new(u32::MAX as u128 - 1, Default::default());
        let serialized = serde_json::to_value(token_amount).unwrap();

        assert_eq!(
            serialized,
            json!({
                "amount": u32::MAX - 1,
            })
        );
    }

    #[test]
    fn test_must_deserializes_from_number_and_string() {
        let jsons = [
            json!({
                "amount": u32::MAX - 1,
            }),
            json!({
                "amount": "100000000000000",
            }),
        ];

        for json in jsons {
            let _: TokenAmount = serde_json::from_value(json).unwrap();
        }
    }
}

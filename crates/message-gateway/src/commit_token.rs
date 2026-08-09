use anyhow::{Result, bail};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use wattswarm_network_transport_core::{DeliveryClass, OpaqueCommitToken};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitClaims {
    pub page_id: String,
    pub network_id: String,
    pub principal_id: String,
    pub delivery_class: DeliveryClass,
    pub owner_instance_id: String,
    pub consumer_epoch: Uuid,
    pub expires_at: u64,
}

pub fn issue(secret: &[u8], claims: &CommitClaims) -> Result<OpaqueCommitToken> {
    let payload = serde_json::to_vec(claims)?;
    let mut mac = HmacSha256::new_from_slice(secret)?;
    mac.update(&payload);
    let signature = mac.finalize().into_bytes();
    OpaqueCommitToken::new(format!(
        "{}.{}",
        hex::encode(payload),
        hex::encode(signature)
    ))
}

pub fn verify(secret: &[u8], token: &OpaqueCommitToken, now_ms: u64) -> Result<CommitClaims> {
    let (payload, signature) = token
        .expose()
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("malformed commit token"))?;
    let payload = hex::decode(payload)?;
    let signature = hex::decode(signature)?;
    let mut mac = HmacSha256::new_from_slice(secret)?;
    mac.update(&payload);
    mac.verify_slice(&signature)?;
    let claims: CommitClaims = serde_json::from_slice(&payload)?;
    if claims.expires_at <= now_ms {
        bail!("commit token expired");
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_binds_class_principal_and_epoch() {
        let claims = CommitClaims {
            page_id: "page".to_owned(),
            network_id: "network".to_owned(),
            principal_id: "principal".to_owned(),
            delivery_class: DeliveryClass::Interactive,
            owner_instance_id: "gateway-a".to_owned(),
            consumer_epoch: Uuid::new_v4(),
            expires_at: 100,
        };
        let token = issue(&[7; 32], &claims).unwrap();
        assert_eq!(verify(&[7; 32], &token, 99).unwrap(), claims);
        assert!(verify(&[8; 32], &token, 99).is_err());
        assert!(verify(&[7; 32], &token, 100).is_err());
    }
}

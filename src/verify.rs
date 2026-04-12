use crate::contracts::SignedNodeEvent;
use crate::models::{SignedGatewayManifest, SignedPublicClientSnapshot};
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use watt_did::{Did, DidKey, DidKeyPublicKey};

pub fn canonical_bytes(payload: &impl serde::Serialize) -> Result<Vec<u8>> {
    let json = serde_jcs::to_string(payload).context("canonicalize payload")?;
    Ok(json.into_bytes())
}

pub fn verify_signed_snapshot(
    snapshot: &SignedPublicClientSnapshot,
    expected_signer_agent_did: Option<&str>,
) -> Result<()> {
    let payload = &snapshot.payload;
    let signer_public_key_b64 = public_key_b64_from_ref(&snapshot.signer_agent_did)
        .context("resolve signer_agent_did public key")?;
    if payload.node_id.trim().is_empty() {
        bail!("snapshot node_id is empty");
    }
    if payload.public_key.trim().is_empty() {
        bail!("snapshot public_key is empty");
    }
    if let Some(expected) = expected_signer_agent_did {
        let expected_public_key_b64 = public_key_b64_from_ref(expected)
            .context("resolve expected_signer_agent_did public key")?;
        if snapshot.signer_agent_did != expected && signer_public_key_b64 != expected_public_key_b64
        {
            bail!(
                "unexpected signer_agent_did: expected {expected}, got {}",
                snapshot.signer_agent_did
            );
        }
    }
    if signer_public_key_b64 != payload.public_key {
        bail!("signer_agent_did does not resolve to payload public_key");
    }
    verify_canonical_signature(
        payload,
        &snapshot.signature,
        &payload.public_key,
        "snapshot signature",
    )?;
    Ok(())
}

pub fn verify_signed_gateway_manifest(manifest: &SignedGatewayManifest) -> Result<()> {
    let payload = &manifest.payload;
    if payload.gateway_id.trim().is_empty() {
        bail!("manifest gateway_id is empty");
    }
    if payload.display_name.trim().is_empty() {
        bail!("manifest display_name is empty");
    }
    if payload.base_url.trim().is_empty() {
        bail!("manifest base_url is empty");
    }
    if payload.public_key.trim().is_empty() {
        bail!("manifest public_key is empty");
    }
    if payload.roles.is_empty() {
        bail!("manifest roles must not be empty");
    }
    verify_canonical_signature(
        payload,
        &manifest.signature,
        &payload.public_key,
        "gateway manifest signature",
    )?;
    Ok(())
}

pub fn verify_signed_node_event(
    event: &SignedNodeEvent,
    expected_signer_agent_did: Option<&str>,
) -> Result<()> {
    let payload = &event.payload;
    let signer_public_key_b64 = public_key_b64_from_ref(&payload.signer_agent_did)
        .context("resolve node event signer_agent_did public key")?;
    if payload.event_id.trim().is_empty() {
        bail!("node event event_id is empty");
    }
    if payload.node_id.trim().is_empty() {
        bail!("node event node_id is empty");
    }
    if payload.public_key.trim().is_empty() {
        bail!("node event public_key is empty");
    }
    if payload.event_kind.trim().is_empty() {
        bail!("node event event_kind is empty");
    }
    if let Some(expected) = expected_signer_agent_did {
        let expected_public_key_b64 = public_key_b64_from_ref(expected)
            .context("resolve expected_signer_agent_did public key for node event")?;
        if payload.signer_agent_did != expected && signer_public_key_b64 != expected_public_key_b64
        {
            bail!(
                "unexpected node event signer_agent_did: expected {expected}, got {}",
                payload.signer_agent_did
            );
        }
    }
    if signer_public_key_b64 != payload.public_key {
        bail!("node event signer_agent_did does not resolve to payload public_key");
    }
    verify_canonical_signature(
        payload,
        &event.signature,
        &payload.public_key,
        "node event signature",
    )?;
    Ok(())
}

pub fn verify_canonical_signature(
    payload: &impl serde::Serialize,
    signature_b64: &str,
    public_key_b64: &str,
    context_label: &str,
) -> Result<()> {
    let public = STANDARD
        .decode(public_key_b64)
        .context("decode public key base64")?;
    let signature = STANDARD
        .decode(signature_b64)
        .context("decode signature base64")?;
    let verifying = VerifyingKey::from_bytes(
        public
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid public key length"))?,
    )
    .context("decode ed25519 verifying key")?;
    let sig = Signature::from_bytes(
        signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signature length"))?,
    );
    verifying
        .verify(&canonical_bytes(payload)?, &sig)
        .with_context(|| format!("verify {context_label}"))?;
    Ok(())
}

fn public_key_b64_from_ref(public_key_ref: &str) -> Result<String> {
    if public_key_ref.starts_with("did:") {
        return public_key_b64_from_did_key(public_key_ref);
    }
    Ok(public_key_ref.to_string())
}

fn public_key_b64_from_did_key(agent_did: &str) -> Result<String> {
    let did = Did::parse(agent_did).context("parse did:key")?;
    let did_key = DidKey::from_did(did).context("build did:key helper")?;
    let public_key = match did_key
        .decode_public_key()
        .context("decode did:key public key")?
    {
        DidKeyPublicKey::Ed25519(bytes) => bytes,
        _ => bail!("did:key is not an Ed25519 verification key"),
    };
    Ok(STANDARD.encode(public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{
        DataKind, EventScope, NodeEventPayload, ProvisionalExportPolicy, SignedNodeEvent,
        Visibility,
    };
    use crate::models::{GatewayManifest, PublicClientSnapshot};
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    const DID_KEY_PREFIX: &str = "did:key:";
    const DID_KEY_BASE58BTC_PREFIX: &str = "z";
    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

    #[test]
    fn signed_snapshot_verifies() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_key = STANDARD.encode(verifying_key.as_bytes());
        let payload = PublicClientSnapshot {
            generated_at: 1_710_000_000,
            node_id: "node-alpha".to_string(),
            public_key: public_key.clone(),
            network_name: None,
            network_org_name: None,
            network_status: json!({"total_nodes": 2, "active_nodes": 2, "health_percent": 100, "avg_latency_ms": 0}),
            peers: vec![json!({"id":"peer-1"})],
            operator: json!({"id":"agent-root","display_name":"Agent Root"}),
            rpc_logs: vec![],
            friend_relationships: vec![],
            pending_friend_requests: vec![],
            public_blocks: vec![],
            dm_threads: vec![],
            dm_messages: vec![],
            public_topics: vec![],
            public_topic_messages: vec![],
            swarm_task_activity: json!({}),
            tasks: vec![],
            organizations: vec![],
            leaderboard: vec![],
        };
        let signature = STANDARD.encode(
            signing_key
                .sign(&canonical_bytes(&payload).unwrap())
                .to_bytes(),
        );
        let snapshot = SignedPublicClientSnapshot {
            payload,
            signature,
            signer_agent_did: did_key_from_public_key_b64(&public_key),
        };

        verify_signed_snapshot(&snapshot, Some(&snapshot.signer_agent_did)).unwrap();
        verify_signed_snapshot(&snapshot, Some(&public_key)).unwrap();
    }

    #[test]
    fn signed_gateway_manifest_verifies() {
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let public_key = STANDARD.encode(signing_key.verifying_key().as_bytes());
        let payload = GatewayManifest {
            generated_at: 1_710_000_000,
            gateway_id: "gw-ap-1".to_string(),
            display_name: "AP Gateway".to_string(),
            base_url: "https://gw-ap.example".to_string(),
            public_key: public_key.clone(),
            region: Some("ap-southeast".to_string()),
            operator_did: Some("did:key:operator-ap".to_string()),
            roles: vec!["ingest".to_string(), "query".to_string()],
            supported_endpoints: vec!["/api/network/status".to_string()],
            federation_peers: vec!["https://gw-us.example".to_string()],
            allows_public_ingest: true,
        };
        let signature = STANDARD.encode(
            signing_key
                .sign(&canonical_bytes(&payload).unwrap())
                .to_bytes(),
        );
        let manifest = SignedGatewayManifest { payload, signature };

        verify_signed_gateway_manifest(&manifest).unwrap();
    }

    #[test]
    fn signed_node_event_verifies() {
        let signing_key = SigningKey::from_bytes(&[3_u8; 32]);
        let public_key = STANDARD.encode(signing_key.verifying_key().as_bytes());
        let payload = NodeEventPayload {
            event_id: "evt-1".to_string(),
            node_id: "node-alpha".to_string(),
            public_key: public_key.clone(),
            signer_agent_did: did_key_from_public_key_b64(&public_key),
            seq: 7,
            timestamp: 1_710_000_123,
            data_kind: DataKind::TaskRoundUpdate,
            event_kind: "task.round.updated".to_string(),
            visibility: Visibility::Public,
            provisional_policy: ProvisionalExportPolicy::ProvisionalWithDowngrade,
            scope: EventScope {
                node_id: Some("node-alpha".to_string()),
                topic_id: None,
                organization_id: Some("org-1".to_string()),
                task_id: Some("task-1".to_string()),
            },
            identity_key: Some("task-1".to_string()),
            payload: json!({"task_id":"task-1","round":2}),
        };
        let signature = STANDARD.encode(
            signing_key
                .sign(&canonical_bytes(&payload).unwrap())
                .to_bytes(),
        );
        let event = SignedNodeEvent { payload, signature };

        verify_signed_node_event(&event, Some(&event.payload.signer_agent_did)).unwrap();
    }

    fn did_key_from_public_key_b64(public_key_b64: &str) -> String {
        let public_key = STANDARD.decode(public_key_b64).unwrap();
        let mut multicodec = Vec::with_capacity(ED25519_MULTICODEC_PREFIX.len() + public_key.len());
        multicodec.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
        multicodec.extend_from_slice(&public_key);
        format!(
            "{DID_KEY_PREFIX}{DID_KEY_BASE58BTC_PREFIX}{}",
            bs58::encode(multicodec).into_string()
        )
    }
}

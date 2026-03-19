#[tokio::test]
async fn broadcast_unknown_selector_is_allowed_when_policies_allow_it() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x1000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 1,
                data_hex: "0xdeadbeef".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: false,
            },
        },
    );
    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let signature = daemon.sign_for_agent(request).await.expect("must sign");
    assert!(!signature.bytes.is_empty(), "signature should be non-empty");
}

#[tokio::test]
async fn eip1559_broadcast_signature_artifacts_are_consistent() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 7,
        to: "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("to"),
        value_wei: 123,
        data_hex: "0x".to_string(),
        gas_limit: 21_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 100_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };
    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx { tx: tx.clone() },
    );
    reserve_nonce_for_agent(&daemon, &agent_credentials, tx.chain_id, tx.nonce).await;

    let signature = daemon.sign_for_agent(request).await.expect("must sign");
    let r_hex = signature.r_hex.expect("eip1559 r must be present");
    let s_hex = signature.s_hex.expect("eip1559 s must be present");
    let v = signature.v.expect("eip1559 v must be present");
    let raw_tx_hex = signature
        .raw_tx_hex
        .expect("eip1559 raw tx bytes must be present");
    let tx_hash_hex = signature
        .tx_hash_hex
        .expect("eip1559 tx hash must be present");
    assert!(v <= 1, "typed tx y-parity must be 0 or 1");

    let parsed_der = K256Signature::from_der(&signature.bytes).expect("DER signature");
    let compact = parsed_der.to_bytes();
    assert_eq!(r_hex, format!("0x{}", hex::encode(&compact[..32])));
    assert_eq!(s_hex, format!("0x{}", hex::encode(&compact[32..])));

    let raw_tx = hex::decode(
        raw_tx_hex
            .strip_prefix("0x")
            .expect("raw tx must be 0x-prefixed"),
    )
    .expect("raw tx hex");
    assert_eq!(raw_tx.first().copied(), Some(0x02));
    assert_eq!(
        tx_hash_hex,
        format!("0x{}", hex::encode(keccak256(&raw_tx).0))
    );

    let signing_message = tx.eip1559_signing_message().expect("signing message");
    let digest = keccak256(&signing_message).0;
    let recovery_id = RecoveryId::from_byte(v as u8).expect("valid recovery id");
    let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed_der, recovery_id)
        .expect("recover verifying key");
    let expected_verifying_key =
        VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("public key hex"))
            .expect("public key bytes");
    assert_eq!(recovered, expected_verifying_key);
}

#[tokio::test]
async fn non_eip1559_broadcast_is_rejected_for_signing() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x4000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x04,
                delegation_enabled: false,
            },
        },
    );
    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("non-eip1559 broadcast tx must be rejected");
    assert!(matches!(
        err,
        DaemonError::Signer(vault_signer::SignerError::Unsupported(message))
            if message.contains("unsupported for signing")
    ));
}

#[tokio::test]
async fn broadcast_signer_failure_preserves_request_id_and_nonce_reservation() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        FlakySignerBackend::fail_first_digest(SignerError::Internal(
            "simulated signer timeout".to_string(),
        )),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x4100000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: false,
            },
        },
    );

    let err = daemon
        .sign_for_agent(request.clone())
        .await
        .expect_err("first broadcast signing attempt should fail");
    assert!(matches!(
        err,
        DaemonError::Signer(SignerError::Internal(message))
            if message == "simulated signer timeout"
    ));

    let signature = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("same request id and reservation should remain retryable after signer failure");
    assert!(!signature.bytes.is_empty(), "signature should be non-empty");

    let replay = daemon
        .sign_for_agent(request)
        .await
        .expect("successful broadcast retries should remain idempotent");
    assert_eq!(replay, signature);
}

#[tokio::test]
async fn non_eip1559_broadcast_rejection_preserves_nonce_reservation() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let rejected = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x4000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x04,
                delegation_enabled: false,
            },
        },
    );
    let err = daemon
        .sign_for_agent(rejected)
        .await
        .expect_err("non-eip1559 broadcast tx must be rejected");
    assert!(matches!(
        err,
        DaemonError::Signer(vault_signer::SignerError::Unsupported(message))
            if message.contains("unsupported for signing")
    ));

    let recovered = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x4000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: false,
            },
        },
    );
    let signature = daemon
        .sign_for_agent(recovered)
        .await
        .expect("reserved nonce should remain usable after signing rejection");
    assert!(!signature.bytes.is_empty(), "signature should be non-empty");
}

#[tokio::test]
async fn signer_backend_failure_preserves_broadcast_nonce_reservation() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let detached_backend_key_id = Uuid::new_v4();
    let mut detached_backend_key = key.clone();
    detached_backend_key.id = detached_backend_key_id;
    daemon
        .vault_keys
        .write()
        .expect("vault keys")
        .insert(detached_backend_key_id, detached_backend_key);
    daemon
        .agent_keys
        .write()
        .expect("agent keys")
        .entry(agent_credentials.agent_key.id)
        .and_modify(|agent_key| agent_key.vault_key_id = detached_backend_key_id);

    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x4100000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 1_000_000_000,
                    max_priority_fee_per_gas_wei: 1_000_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect_err("backend signing failure must reject the request");
    assert!(matches!(
        err,
        DaemonError::Signer(vault_signer::SignerError::UnknownKey(id))
            if id == detached_backend_key_id
    ));

    let reservations = daemon
        .nonce_reservations
        .read()
        .expect("nonce reservations");
    let reservation = reservations
        .values()
        .next()
        .expect("nonce reservation must be preserved after signer failure");
    assert_eq!(reservations.len(), 1);
    assert_eq!(reservation.agent_key_id, agent_credentials.agent_key.id);
    assert_eq!(reservation.vault_key_id, detached_backend_key_id);
    assert_eq!(reservation.chain_id, 1);
    assert_eq!(reservation.nonce, 0);
}

#[tokio::test]
async fn broadcast_with_delegation_is_rejected_even_for_eip7702() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x2000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: true,
            },
        },
    );
    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("must reject delegation even for eip-7702");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));
}

#[tokio::test]
async fn per_chain_gas_policy_rejects_over_limit_broadcast() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 500_000_000_000_000))
        .await
        .expect("add gas policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x3000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0xdeadbeef".to_string(),
                gas_limit: 1_000_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: false,
            },
        },
    );

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("gas policy must reject oversized tx");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::GasLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn broadcast_fee_and_calldata_policies_are_enforced() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx spend policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::PerTxMaxFeePerGas,
                1_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("policy"),
        )
        .await
        .expect("add max-fee policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                2,
                PolicyType::PerTxMaxPriorityFeePerGas,
                500_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("policy"),
        )
        .await
        .expect("add priority-fee policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_calldata_limit(
                3,
                3,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("policy"),
        )
        .await
        .expect("add calldata policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let fee_err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x3000000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 2_000_000_000,
                    max_priority_fee_per_gas_wei: 100_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect_err("max fee per gas must reject request");
    assert!(matches!(
        fee_err,
        DaemonError::Policy(PolicyError::MaxFeePerGasLimitExceeded { .. })
    ));

    let priority_err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x3000000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 1_000_000_000,
                    max_priority_fee_per_gas_wei: 600_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect_err("max priority fee per gas must reject request");
    assert!(matches!(
        priority_err,
        DaemonError::Policy(PolicyError::PriorityFeePerGasLimitExceeded { .. })
    ));

    let calldata_err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x3000000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0xdeadbeef".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 1_000_000_000,
                    max_priority_fee_per_gas_wei: 100_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect_err("calldata bytes limit must reject request");
    assert!(matches!(
        calldata_err,
        DaemonError::Policy(PolicyError::CalldataBytesLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn daily_tx_count_policy_is_enforced() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx spend policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::DailyMaxTxCount,
                1,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("policy"),
        )
        .await
        .expect("add tx count policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x1000000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x2000000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 1,
            },
        ))
        .await
        .expect("first tx should pass");

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x1000000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x2000000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 1,
            },
        ))
        .await
        .expect_err("daily tx count must reject second tx");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::TxCountLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn fee_policy_allows_non_broadcast_actions_without_tx_metadata() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add spend policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::PerTxMaxFeePerGas,
                1_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("policy"),
        )
        .await
        .expect("add fee policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x1000000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x2000000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 1,
            },
        ))
        .await
        .expect("non-broadcast action should skip fee metadata policy");
}

#[tokio::test]
async fn gas_policy_allows_non_broadcast_actions_without_tx_metadata() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add spend policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::PerChainMaxGasSpend,
                1_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("policy"),
        )
        .await
        .expect("add gas policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x1000000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x2000000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 1,
            },
        ))
        .await
        .expect("non-broadcast action should skip gas metadata policy");
}

#[tokio::test]
async fn permit2_signature_artifacts_are_recoverable() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    let expiration = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::hours(2)).unix_timestamp(),
    )
    .expect("future unix timestamp");
    let sig_deadline = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp(),
    )
    .expect("future unix timestamp");

    let action = AgentAction::Permit2Permit {
        permit: vault_domain::Permit2Permit {
            chain_id: 1,
            permit2_contract: "0x000000000022d473030f116ddee9f6b43ac78ba3"
                .parse()
                .expect("permit2"),
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            spender: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("spender"),
            amount_wei: 42,
            expiration,
            nonce: 1,
            sig_deadline,
        },
    };

    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
        .expect("must sign permit2");
    let parsed_der = K256Signature::from_der(&signature.bytes).expect("DER signature");
    let digest = action
        .signing_hash()
        .expect("typed hash")
        .expect("typed action");
    let recovery_id = RecoveryId::from_byte(signature.v.expect("v") as u8).expect("recovery id");
    let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed_der, recovery_id)
        .expect("recover verifying key");
    let expected_verifying_key =
        VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("public key hex"))
            .expect("public key bytes");
    assert_eq!(recovered, expected_verifying_key);
    assert!(signature.raw_tx_hex.is_none());
    assert!(signature.tx_hash_hex.is_none());
    assert!(signature.r_hex.is_some());
    assert!(signature.s_hex.is_some());
}

#[tokio::test]
async fn expired_permit2_signature_deadline_is_rejected() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    let expiration = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::hours(2)).unix_timestamp(),
    )
    .expect("future unix timestamp");

    let action = AgentAction::Permit2Permit {
        permit: vault_domain::Permit2Permit {
            chain_id: 1,
            permit2_contract: "0x000000000022d473030f116ddee9f6b43ac78ba3"
                .parse()
                .expect("permit2"),
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            spender: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("spender"),
            amount_wei: 42,
            expiration,
            nonce: 1,
            sig_deadline: u64::try_from(
                (time::OffsetDateTime::now_utc() - time::Duration::seconds(1)).unix_timestamp(),
            )
            .expect("past unix timestamp"),
        },
    };

    let err = daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect_err("expired permit2 deadline must be rejected");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));
}

#[tokio::test]
async fn expired_permit2_expiration_is_rejected() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let action = AgentAction::Permit2Permit {
        permit: vault_domain::Permit2Permit {
            chain_id: 1,
            permit2_contract: "0x000000000022d473030f116ddee9f6b43ac78ba3"
                .parse()
                .expect("permit2"),
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            spender: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("spender"),
            amount_wei: 42,
            expiration: u64::try_from(
                (time::OffsetDateTime::now_utc() - time::Duration::seconds(1)).unix_timestamp(),
            )
            .expect("past unix timestamp"),
            nonce: 1,
            sig_deadline: u64::try_from(
                (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp(),
            )
            .expect("future unix timestamp"),
        },
    };

    let err = daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect_err("expired permit2 expiration must be rejected");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));
}

#[tokio::test]
async fn eip3009_signature_artifacts_are_recoverable() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    let valid_after = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::minutes(5)).unix_timestamp(),
    )
    .expect("future unix timestamp");
    let valid_before = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::minutes(10)).unix_timestamp(),
    )
    .expect("future unix timestamp");

    let action = AgentAction::Eip3009TransferWithAuthorization {
        authorization: vault_domain::Eip3009Transfer {
            chain_id: 1,
            token: "0x3000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            token_name: "USD Coin".to_string(),
            token_version: Some("2".to_string()),
            from: "0x4000000000000000000000000000000000000000"
                .parse()
                .expect("from"),
            to: "0x5000000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            amount_wei: 77,
            valid_after,
            valid_before,
            nonce_hex: format!("0x{}", hex::encode([0x11u8; 32])),
        },
    };

    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
        .expect("must sign eip3009");
    let parsed_der = K256Signature::from_der(&signature.bytes).expect("DER signature");
    let digest = action
        .signing_hash()
        .expect("typed hash")
        .expect("typed action");
    let recovery_id = RecoveryId::from_byte(signature.v.expect("v") as u8).expect("recovery id");
    let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed_der, recovery_id)
        .expect("recover verifying key");
    let expected_verifying_key = VerifyingKey::from_sec1_bytes(
        &hex::decode(&key.public_key_hex).expect("public key hex"),
    )
    .expect("public key bytes");
    assert_eq!(recovered, expected_verifying_key);
    assert!(signature.raw_tx_hex.is_none());
    assert!(signature.tx_hash_hex.is_none());
    assert!(signature.r_hex.is_some());
    assert!(signature.s_hex.is_some());
}

#[tokio::test]
async fn expired_eip3009_valid_before_is_rejected() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let action = AgentAction::Eip3009TransferWithAuthorization {
        authorization: vault_domain::Eip3009Transfer {
            chain_id: 1,
            token: "0x3000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            token_name: "USD Coin".to_string(),
            token_version: Some("2".to_string()),
            from: "0x4000000000000000000000000000000000000000"
                .parse()
                .expect("from"),
            to: "0x5000000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            amount_wei: 77,
            valid_after: u64::try_from(
                (time::OffsetDateTime::now_utc() - time::Duration::minutes(2)).unix_timestamp(),
            )
            .expect("past unix timestamp"),
            valid_before: u64::try_from(
                (time::OffsetDateTime::now_utc() - time::Duration::seconds(1)).unix_timestamp(),
            )
            .expect("past unix timestamp"),
            nonce_hex: format!("0x{}", hex::encode([0x11u8; 32])),
        },
    };

    let err = daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect_err("expired eip3009 authorization must be rejected");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));
}

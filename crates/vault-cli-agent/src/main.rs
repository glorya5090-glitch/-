use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use uuid::Uuid;
use vault_daemon::{DaemonError, KeyManagerDaemonApi};
use vault_domain::{AgentAction, BroadcastTx, EvmAddress};
use vault_sdk_agent::{AgentOperations, AgentSdk, AgentSdkError};
use vault_transport_unix::{assert_root_owned_daemon_socket_path, UnixDaemonClient};

mod io_utils;

use io_utils::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandRunOutcome {
    Completed,
    ManualApprovalRequired,
}

#[derive(Debug, Parser)]
#[command(name = "agentpay-agent")]
#[command(about = "Agent CLI for sending signing requests through daemon policy checks")]
struct Cli {
    #[arg(
        long,
        default_value_t = false,
        help = "Do not prompt for missing secrets; require AGENTPAY_AGENT_AUTH_TOKEN or --agent-auth-token-stdin"
    )]
    non_interactive: bool,
    #[arg(
        long,
        env = "AGENTPAY_AGENT_KEY_ID",
        value_name = "UUID",
        help = "Provisioned agent key id"
    )]
    agent_key_id: Uuid,
    #[arg(
        long,
        value_name = "TOKEN",
        conflicts_with = "agent_auth_token_stdin",
        help = "Legacy insecure agent auth token flag (disabled by default); use --agent-auth-token-stdin or AGENTPAY_AGENT_AUTH_TOKEN"
    )]
    agent_auth_token: Option<String>,
    #[arg(
        long,
        default_value_t = false,
        help = "Read agent auth token from stdin (trailing newlines are trimmed)"
    )]
    agent_auth_token_stdin: bool,
    #[arg(
        long,
        env = "AGENTPAY_DAEMON_SOCKET",
        value_name = "PATH",
        help = "Always-on daemon unix socket path (default: $AGENTPAY_HOME/daemon.sock or ~/.agentpay/daemon.sock)"
    )]
    daemon_socket: Option<PathBuf>,
    #[arg(
        long,
        short = 'f',
        value_enum,
        value_name = "text|json",
        help = "Output format"
    )]
    format: Option<OutputFormat>,
    #[arg(
        long,
        short = 'j',
        default_value_t = false,
        help = "Shortcut for --format json"
    )]
    json: bool,
    #[arg(
        long,
        short = 'q',
        default_value_t = false,
        help = "Suppress non-essential status messages in text mode"
    )]
    quiet: bool,
    #[arg(
        long,
        short = 'o',
        value_name = "PATH",
        help = "Write final command output to PATH (use '-' for stdout)"
    )]
    output: Option<PathBuf>,
    #[arg(
        long,
        default_value_t = false,
        requires = "output",
        help = "Allow replacing an existing output file"
    )]
    overwrite: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug)]
enum OutputTarget {
    Stdout,
    File { path: PathBuf, overwrite: bool },
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Submit an ERC-20 transfer request through policy checks")]
    Transfer {
        #[arg(long, value_parser = parse_positive_u64)]
        network: u64,
        #[arg(long)]
        token: EvmAddress,
        #[arg(long)]
        to: EvmAddress,
        #[arg(long, value_parser = parse_positive_u128)]
        amount_wei: u128,
    },
    #[command(about = "Submit a native ETH transfer request through policy checks")]
    TransferNative {
        #[arg(long, value_parser = parse_positive_u64)]
        network: u64,
        #[arg(long)]
        to: EvmAddress,
        #[arg(long, value_parser = parse_positive_u128)]
        amount_wei: u128,
    },
    #[command(about = "Submit an ERC-20 approve request through policy checks")]
    Approve {
        #[arg(long, value_parser = parse_positive_u64)]
        network: u64,
        #[arg(long)]
        token: EvmAddress,
        #[arg(long)]
        spender: EvmAddress,
        #[arg(long, value_parser = parse_positive_u128)]
        amount_wei: u128,
    },
    #[command(about = "Submit a raw transaction broadcast request through policy checks")]
    Broadcast {
        #[arg(long, value_parser = parse_positive_u64)]
        network: u64,
        #[arg(long, default_value_t = 0u64, value_parser = parse_non_negative_u64)]
        nonce: u64,
        #[arg(long)]
        to: EvmAddress,
        #[arg(long, default_value_t = 0u128, value_parser = parse_non_negative_u128)]
        value_wei: u128,
        #[arg(long, default_value = "0x")]
        data_hex: String,
        #[arg(long, value_parser = parse_positive_u64)]
        gas_limit: u64,
        #[arg(long, value_parser = parse_positive_u128)]
        max_fee_per_gas_wei: u128,
        #[arg(
            long,
            default_value_t = 0u128,
            value_parser = parse_non_negative_u128
        )]
        max_priority_fee_per_gas_wei: u128,
        #[arg(long, default_value_t = 0x02u8, value_parser = parse_tx_type_u8)]
        tx_type: u8,
        #[arg(long, default_value_t = false)]
        delegation_enabled: bool,
    },
}

#[derive(Debug, Serialize)]
struct AgentCommandOutput {
    command: String,
    network: String,
    asset: String,
    counterparty: String,
    amount_wei: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    estimated_max_gas_spend_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegation_enabled: Option<bool>,
    signature_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    r_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    s_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    v: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_tx_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct ManualApprovalRequiredOutput {
    command: String,
    approval_request_id: String,
    cli_approval_command: String,
}

#[tokio::main]
async fn main() {
    match run_main().await {
        Ok(CommandRunOutcome::Completed) => {}
        Ok(CommandRunOutcome::ManualApprovalRequired) => std::process::exit(2),
        Err(err) => {
            eprintln!("{}", render_cli_error(&err));
            std::process::exit(1);
        }
    }
}

async fn run_main() -> Result<CommandRunOutcome> {
    let cli = Cli::parse();
    let output_format = resolve_output_format(cli.format, cli.json)?;
    let output_target = resolve_output_target(cli.output, cli.overwrite)?;
    let daemon_socket = resolve_daemon_socket_path(cli.daemon_socket)?;
    let agent_auth_token = resolve_agent_auth_token(
        cli.agent_auth_token,
        std::env::var("AGENTPAY_AGENT_AUTH_TOKEN").ok(),
        cli.agent_auth_token_stdin,
        cli.non_interactive,
    )?;
    print_status("connecting to daemon socket", output_format, cli.quiet);
    let daemon: Arc<dyn KeyManagerDaemonApi> =
        Arc::new(UnixDaemonClient::new_with_expected_server_euid(
            daemon_socket.clone(),
            std::time::Duration::from_secs(10),
            0,
        ));

    let sdk = AgentSdk::new_with_key_id_and_token(daemon, cli.agent_key_id, agent_auth_token);

    run_command(
        cli.command,
        cli.quiet,
        &daemon_socket,
        output_format,
        &output_target,
        &sdk,
    )
    .await
}

fn render_cli_error(error: &anyhow::Error) -> String {
    error.to_string()
}

async fn run_command<A>(
    command: Commands,
    quiet: bool,
    daemon_socket: &Path,
    output_format: OutputFormat,
    output_target: &OutputTarget,
    sdk: &A,
) -> Result<CommandRunOutcome>
where
    A: AgentOperations + ?Sized,
{
    match command {
        Commands::Transfer {
            network,
            token,
            to,
            amount_wei,
        } => {
            let token_str = token.to_string();
            let to_str = to.to_string();
            print_status("submitting transfer request", output_format, quiet);
            let signature = match await_signature_or_handle_manual_approval(
                "transfer",
                daemon_socket,
                output_format,
                output_target,
                sdk.transfer(network, token, to, amount_wei),
            )
            .await?
            {
                Some(signature) => signature,
                None => return Ok(CommandRunOutcome::ManualApprovalRequired),
            };
            let output = AgentCommandOutput {
                command: "transfer".to_string(),
                network: network.to_string(),
                asset: format!("erc20:{token_str}"),
                counterparty: to_str,
                amount_wei: amount_wei.to_string(),
                estimated_max_gas_spend_wei: None,
                tx_type: None,
                delegation_enabled: None,
                signature_hex: format!("0x{}", hex::encode(signature.bytes)),
                r_hex: None,
                s_hex: None,
                v: None,
                raw_tx_hex: None,
                tx_hash_hex: None,
            };
            print_status("transfer request signed", output_format, quiet);
            print_agent_output(&output, output_format, output_target)?;
        }
        Commands::TransferNative {
            network,
            to,
            amount_wei,
        } => {
            let to_str = to.to_string();
            print_status("submitting native transfer request", output_format, quiet);
            let signature = match await_signature_or_handle_manual_approval(
                "transfer-native",
                daemon_socket,
                output_format,
                output_target,
                sdk.transfer_native(network, to, amount_wei),
            )
            .await?
            {
                Some(signature) => signature,
                None => return Ok(CommandRunOutcome::ManualApprovalRequired),
            };
            let output = AgentCommandOutput {
                command: "transfer-native".to_string(),
                network: network.to_string(),
                asset: "native_eth".to_string(),
                counterparty: to_str,
                amount_wei: amount_wei.to_string(),
                estimated_max_gas_spend_wei: None,
                tx_type: None,
                delegation_enabled: None,
                signature_hex: format!("0x{}", hex::encode(signature.bytes)),
                r_hex: None,
                s_hex: None,
                v: None,
                raw_tx_hex: None,
                tx_hash_hex: None,
            };
            print_status("native transfer request signed", output_format, quiet);
            print_agent_output(&output, output_format, output_target)?;
        }
        Commands::Approve {
            network,
            token,
            spender,
            amount_wei,
        } => {
            let token_str = token.to_string();
            let spender_str = spender.to_string();
            print_status("submitting approve request", output_format, quiet);
            let signature = match await_signature_or_handle_manual_approval(
                "approve",
                daemon_socket,
                output_format,
                output_target,
                sdk.approve(network, token, spender, amount_wei),
            )
            .await?
            {
                Some(signature) => signature,
                None => return Ok(CommandRunOutcome::ManualApprovalRequired),
            };
            let output = AgentCommandOutput {
                command: "approve".to_string(),
                network: network.to_string(),
                asset: format!("erc20:{token_str}"),
                counterparty: spender_str,
                amount_wei: amount_wei.to_string(),
                estimated_max_gas_spend_wei: None,
                tx_type: None,
                delegation_enabled: None,
                signature_hex: format!("0x{}", hex::encode(signature.bytes)),
                r_hex: None,
                s_hex: None,
                v: None,
                raw_tx_hex: None,
                tx_hash_hex: None,
            };
            print_status("approve request signed", output_format, quiet);
            print_agent_output(&output, output_format, output_target)?;
        }
        Commands::Broadcast {
            network,
            nonce,
            to,
            value_wei,
            data_hex,
            gas_limit,
            max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei,
            tx_type,
            delegation_enabled,
        } => {
            let tx = BroadcastTx {
                chain_id: network,
                nonce,
                to,
                value_wei,
                data_hex,
                gas_limit,
                max_fee_per_gas_wei,
                max_priority_fee_per_gas_wei,
                tx_type,
                delegation_enabled,
            };
            let action = AgentAction::BroadcastTx { tx: tx.clone() };
            action
                .validate()
                .context("invalid broadcast transaction payload")?;
            let estimated_max_gas_spend_wei = tx.max_gas_spend_wei()?;
            let asset = action.asset();
            let counterparty = action.recipient();

            print_status("submitting broadcast request", output_format, quiet);
            let signature = match await_signature_or_handle_manual_approval(
                "broadcast",
                daemon_socket,
                output_format,
                output_target,
                sdk.broadcast_tx(tx),
            )
            .await?
            {
                Some(signature) => signature,
                None => return Ok(CommandRunOutcome::ManualApprovalRequired),
            };
            let output = AgentCommandOutput {
                command: "broadcast".to_string(),
                network: network.to_string(),
                asset: asset.to_string(),
                counterparty: counterparty.to_string(),
                amount_wei: action.amount_wei().to_string(),
                estimated_max_gas_spend_wei: Some(estimated_max_gas_spend_wei.to_string()),
                tx_type: Some(format!("0x{tx_type:02x}")),
                delegation_enabled: Some(delegation_enabled),
                signature_hex: format!("0x{}", hex::encode(&signature.bytes)),
                r_hex: signature.r_hex,
                s_hex: signature.s_hex,
                v: signature.v,
                raw_tx_hex: signature.raw_tx_hex,
                tx_hash_hex: signature.tx_hash_hex,
            };
            print_status("broadcast request signed", output_format, quiet);
            print_agent_output(&output, output_format, output_target)?;
        }
    }

    Ok(CommandRunOutcome::Completed)
}

async fn await_signature_or_handle_manual_approval(
    command: &str,
    daemon_socket: &Path,
    format: OutputFormat,
    target: &OutputTarget,
    future: impl std::future::Future<Output = Result<vault_domain::Signature, AgentSdkError>>,
) -> Result<Option<vault_domain::Signature>> {
    match future.await {
        Ok(signature) => Ok(Some(signature)),
        Err(AgentSdkError::Daemon(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        })) => {
            let output = ManualApprovalRequiredOutput {
                command: command.to_string(),
                approval_request_id: approval_request_id.to_string(),
                cli_approval_command: format!(
                    "agentpay admin --daemon-socket {} approve-manual-approval-request --approval-request-id {}",
                    daemon_socket.display(),
                    approval_request_id
                ),
            };
            print_manual_approval_required_output(&output, format, target)?;
            Ok(None)
        }
        Err(err) => Err(err.into()),
    }
}

fn print_manual_approval_required_output(
    output: &ManualApprovalRequiredOutput,
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => {
            let mut lines = vec![
                format!("Command: {}", output.command),
                format!("Approval Request ID: {}", output.approval_request_id),
            ];
            lines.push(format!(
                "CLI Approval Command: {}",
                output.cli_approval_command
            ));
            lines.join(
                "
",
            )
        }
    };
    emit_output(&rendered, target)
}

fn resolve_daemon_socket_path(cli_value: Option<PathBuf>) -> Result<PathBuf> {
    let path = match cli_value {
        Some(path) => path,
        None => agentpay_home_dir()?.join("daemon.sock"),
    };

    assert_root_owned_daemon_socket_path(&path).map_err(anyhow::Error::msg)
}

fn agentpay_home_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("AGENTPAY_HOME") {
        let candidate = PathBuf::from(path);
        if candidate.as_os_str().is_empty() {
            return Err(anyhow::anyhow!("AGENTPAY_HOME must not be empty").into());
        }
        return Ok(candidate);
    }

    let Some(home) = std::env::var_os("HOME") else {
        return Err(
            anyhow::anyhow!("HOME is not set; use AGENTPAY_HOME to choose config directory").into(),
        );
    };
    Ok(PathBuf::from(home).join(".agentpay"))
}

fn parse_positive_u128(input: &str) -> Result<u128, String> {
    let parsed = input
        .parse::<u128>()
        .map_err(|_| "must be a valid unsigned integer".to_string())?;
    if parsed == 0 {
        return Err("must be greater than zero".to_string());
    }
    Ok(parsed)
}

fn parse_non_negative_u128(input: &str) -> Result<u128, String> {
    input
        .parse::<u128>()
        .map_err(|_| "must be a valid unsigned integer".to_string())
}

fn parse_tx_type_u8(input: &str) -> Result<u8, String> {
    let trimmed = input.trim();
    let parsed = if let Some(hex_value) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u8::from_str_radix(hex_value, 16)
    } else {
        trimmed.parse::<u8>()
    };
    parsed.map_err(|_| "must be a valid u8 (decimal or 0x-prefixed hex)".to_string())
}

fn parse_positive_u64(input: &str) -> Result<u64, String> {
    let parsed = input
        .parse::<u64>()
        .map_err(|_| "must be a valid unsigned integer".to_string())?;
    if parsed == 0 {
        return Err("must be greater than zero".to_string());
    }
    Ok(parsed)
}

fn parse_non_negative_u64(input: &str) -> Result<u64, String> {
    input
        .parse::<u64>()
        .map_err(|_| "must be a valid unsigned integer".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        await_signature_or_handle_manual_approval, ensure_output_parent,
        print_manual_approval_required_output, render_cli_error, resolve_agent_auth_token,
        resolve_output_format, resolve_output_target, run_command, should_print_status,
        write_output_file, Cli, CommandRunOutcome, Commands, ManualApprovalRequiredOutput,
        OutputFormat, OutputTarget,
    };
    use async_trait::async_trait;
    use clap::Parser;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::runtime::Builder;
    use uuid::Uuid;
    use vault_daemon::DaemonError;
    use vault_domain::{BroadcastTx, EvmAddress, Signature};
    use vault_policy::PolicyError;
    use vault_sdk_agent::{AgentOperations, AgentSdkError};

    const TEST_AGENT_KEY_ID: &str = "11111111-1111-1111-1111-111111111111";

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeCall {
        Transfer {
            chain_id: u64,
            token: EvmAddress,
            to: EvmAddress,
            amount_wei: u128,
        },
        TransferNative {
            chain_id: u64,
            to: EvmAddress,
            amount_wei: u128,
        },
        Approve {
            chain_id: u64,
            token: EvmAddress,
            spender: EvmAddress,
            amount_wei: u128,
        },
        Broadcast(BroadcastTx),
    }

    #[derive(Clone)]
    enum FakeOutcome {
        Signature(Signature),
        ManualApprovalRequired {
            approval_request_id: Uuid,
            relay_url: Option<String>,
            frontend_url: Option<String>,
        },
        Serialization(String),
    }

    struct FakeAgentOps {
        calls: Mutex<Vec<FakeCall>>,
        outcome: FakeOutcome,
    }

    impl FakeAgentOps {
        fn result(&self) -> Result<Signature, AgentSdkError> {
            match &self.outcome {
                FakeOutcome::Signature(signature) => Ok(signature.clone()),
                FakeOutcome::ManualApprovalRequired {
                    approval_request_id,
                    relay_url,
                    frontend_url,
                } => Err(AgentSdkError::Daemon(DaemonError::ManualApprovalRequired {
                    approval_request_id: *approval_request_id,
                    relay_url: relay_url.clone(),
                    frontend_url: frontend_url.clone(),
                })),
                FakeOutcome::Serialization(err) => Err(AgentSdkError::Serialization(err.clone())),
            }
        }
    }

    #[async_trait]
    impl AgentOperations for FakeAgentOps {
        async fn approve(
            &self,
            chain_id: u64,
            token: EvmAddress,
            spender: EvmAddress,
            amount_wei: u128,
        ) -> Result<Signature, AgentSdkError> {
            self.calls.lock().expect("lock").push(FakeCall::Approve {
                chain_id,
                token,
                spender,
                amount_wei,
            });
            self.result()
        }

        async fn transfer(
            &self,
            chain_id: u64,
            token: EvmAddress,
            to: EvmAddress,
            amount_wei: u128,
        ) -> Result<Signature, AgentSdkError> {
            self.calls.lock().expect("lock").push(FakeCall::Transfer {
                chain_id,
                token,
                to,
                amount_wei,
            });
            self.result()
        }

        async fn transfer_native(
            &self,
            chain_id: u64,
            to: EvmAddress,
            amount_wei: u128,
        ) -> Result<Signature, AgentSdkError> {
            self.calls
                .lock()
                .expect("lock")
                .push(FakeCall::TransferNative {
                    chain_id,
                    to,
                    amount_wei,
                });
            self.result()
        }

        async fn permit2_permit(
            &self,
            _permit: vault_domain::Permit2Permit,
        ) -> Result<Signature, AgentSdkError> {
            panic!("unused in test");
        }

        async fn eip3009_transfer_with_authorization(
            &self,
            _authorization: vault_domain::Eip3009Transfer,
        ) -> Result<Signature, AgentSdkError> {
            panic!("unused in test");
        }

        async fn eip3009_receive_with_authorization(
            &self,
            _authorization: vault_domain::Eip3009Transfer,
        ) -> Result<Signature, AgentSdkError> {
            panic!("unused in test");
        }

        async fn sign_erc20_calldata(
            &self,
            _chain_id: u64,
            _token: EvmAddress,
            _calldata: Vec<u8>,
        ) -> Result<Signature, AgentSdkError> {
            panic!("unused in test");
        }

        async fn broadcast_tx(&self, tx: BroadcastTx) -> Result<Signature, AgentSdkError> {
            self.calls
                .lock()
                .expect("lock")
                .push(FakeCall::Broadcast(tx));
            self.result()
        }

        async fn reserve_broadcast_nonce(
            &self,
            _chain_id: u64,
            _min_nonce: u64,
        ) -> Result<vault_domain::NonceReservation, AgentSdkError> {
            panic!("unused in test");
        }

        async fn release_broadcast_nonce(
            &self,
            _reservation_id: Uuid,
        ) -> Result<(), AgentSdkError> {
            panic!("unused in test");
        }
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    fn sample_signature() -> Signature {
        Signature {
            bytes: vec![0xaa, 0xbb, 0xcc],
            r_hex: Some("0x01".to_string()),
            s_hex: Some("0x02".to_string()),
            v: Some(1),
            raw_tx_hex: Some("0x1234".to_string()),
            tx_hash_hex: Some("0xabcd".to_string()),
        }
    }

    fn temp_path(prefix: &str, ext: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}.{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos(),
            ext
        ))
    }

    fn socket_path() -> PathBuf {
        temp_path("agentpay-cli-socket", "sock")
    }

    fn read_file(path: &Path) -> String {
        fs::read_to_string(path).expect("read output")
    }

    #[test]
    fn resolve_output_format_defaults_to_text() {
        let format = resolve_output_format(None, false).expect("format");
        assert!(matches!(format, OutputFormat::Text));
    }

    #[test]
    fn resolve_output_format_json_shortcut() {
        let format = resolve_output_format(None, true).expect("format");
        assert!(matches!(format, OutputFormat::Json));
    }

    #[test]
    fn resolve_output_format_rejects_text_conflict_with_json_shortcut() {
        let err = resolve_output_format(Some(OutputFormat::Text), true).expect_err("must fail");
        assert!(err.to_string().contains("--format text"));
    }

    #[test]
    fn resolve_output_format_allows_json_redundancy() {
        let format = resolve_output_format(Some(OutputFormat::Json), true).expect("format");
        assert!(matches!(format, OutputFormat::Json));
    }

    #[test]
    fn resolve_agent_auth_token_rejects_whitespace_only() {
        let err = resolve_agent_auth_token(Some(" \t ".to_string()), None, false, false)
            .expect_err("must fail");
        assert!(err.to_string().contains("must not be empty or whitespace"));
    }

    #[test]
    fn resolve_agent_auth_token_rejects_cli_argument_source() {
        let err = resolve_agent_auth_token(Some("secret".to_string()), None, false, false)
            .expect_err("must fail");
        assert!(err
            .to_string()
            .contains("--agent-auth-token is disabled for security"));
    }

    #[test]
    fn resolve_agent_auth_token_accepts_environment_source() {
        let token = resolve_agent_auth_token(None, Some("secret".to_string()), false, false)
            .expect("environment token");
        assert_eq!(token.as_str(), "secret");
    }

    #[test]
    fn status_printing_only_in_text_when_not_quiet() {
        assert!(should_print_status(OutputFormat::Text, false));
        assert!(!should_print_status(OutputFormat::Text, true));
        assert!(!should_print_status(OutputFormat::Json, false));
    }

    #[test]
    fn resolve_output_target_maps_dash_to_stdout() {
        let target = resolve_output_target(Some("-".into()), false).expect("target");
        assert!(matches!(target, OutputTarget::Stdout));
    }

    #[test]
    fn resolve_output_target_rejects_overwrite_with_stdout() {
        let err = resolve_output_target(Some("-".into()), true).expect_err("must fail");
        assert!(err.to_string().contains("--overwrite cannot be used"));
    }

    #[test]
    fn output_file_write_respects_overwrite_flag() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "agentpay-cli-output-{}-{}.txt",
            std::process::id(),
            unique
        ));
        std::fs::write(&path, "existing\n").expect("seed");

        let err = write_output_file(&path, "next", false).expect_err("must fail");
        assert!(err.to_string().contains("already exists"));

        write_output_file(&path, "next", true).expect("overwrite");
        let updated = std::fs::read_to_string(&path).expect("read");
        assert_eq!(updated, "next\n");

        std::fs::remove_file(&path).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn output_file_write_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let target = std::env::temp_dir().join(format!(
            "agentpay-cli-symlink-target-{}-{}.txt",
            std::process::id(),
            unique
        ));
        let link = std::env::temp_dir().join(format!(
            "agentpay-cli-symlink-link-{}-{}.txt",
            std::process::id(),
            unique
        ));
        std::fs::write(&target, "seed\n").expect("seed");
        symlink(&target, &link).expect("symlink");

        let err = ensure_output_parent(&link).expect_err("must fail");
        assert!(err.to_string().contains("must not be a symlink"));

        std::fs::remove_file(&link).expect("cleanup link");
        std::fs::remove_file(&target).expect("cleanup target");
    }

    #[test]
    fn render_cli_error_uses_single_display_message() {
        let error = anyhow::Error::from(AgentSdkError::Daemon(DaemonError::Policy(
            PolicyError::PerTxLimitExceeded {
                policy_id: Uuid::nil(),
                max_amount_wei: 1,
                requested_amount_wei: 2,
            },
        )));

        let rendered = render_cli_error(&error);

        assert_eq!(
            rendered,
            "daemon call failed: policy check failed: policy 00000000-0000-0000-0000-000000000000 rejected request: per transaction max 1 < requested 2"
        );
        assert!(!rendered.contains('\n'));
    }

    #[test]
    #[cfg(unix)]
    fn resolve_daemon_socket_path_rejects_non_socket_files() {
        use std::os::unix::fs::PermissionsExt;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("wg-{unique:x}"));
        fs::create_dir_all(&root).expect("create root directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure root directory permissions");

        let socket_path = root.join("daemon.sock");
        fs::write(&socket_path, "not a socket").expect("write file");

        let err = super::resolve_daemon_socket_path(Some(socket_path)).expect_err("must reject");
        assert!(err.to_string().contains("must be a unix socket"));

        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }

    #[test]
    fn canonical_transfer_command_is_accepted() {
        let cli = Cli::try_parse_from([
            "agentpay-agent",
            "--agent-key-id",
            TEST_AGENT_KEY_ID,
            "--agent-auth-token",
            "test-auth-token",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "transfer",
            "--network",
            "1",
            "--token",
            "0x1000000000000000000000000000000000000000",
            "--to",
            "0x2000000000000000000000000000000000000000",
            "--amount-wei",
            "1",
        ])
        .expect("parse");
        assert!(matches!(cli.command, Commands::Transfer { .. }));
    }

    #[test]
    fn canonical_transfer_native_command_is_accepted() {
        let cli = Cli::try_parse_from([
            "agentpay-agent",
            "--agent-key-id",
            TEST_AGENT_KEY_ID,
            "--agent-auth-token",
            "test-auth-token",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "transfer-native",
            "--network",
            "1",
            "--to",
            "0x2000000000000000000000000000000000000000",
            "--amount-wei",
            "1",
        ])
        .expect("parse");
        assert!(matches!(cli.command, Commands::TransferNative { .. }));
    }

    #[test]
    fn canonical_approve_command_is_accepted() {
        let cli = Cli::try_parse_from([
            "agentpay-agent",
            "--agent-key-id",
            TEST_AGENT_KEY_ID,
            "--agent-auth-token",
            "test-auth-token",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "approve",
            "--network",
            "1",
            "--token",
            "0x1000000000000000000000000000000000000000",
            "--spender",
            "0x3000000000000000000000000000000000000000",
            "--amount-wei",
            "1",
        ])
        .expect("parse");
        assert!(matches!(cli.command, Commands::Approve { .. }));
    }

    #[test]
    fn canonical_broadcast_command_is_accepted() {
        let cli = Cli::try_parse_from([
            "agentpay-agent",
            "--agent-key-id",
            TEST_AGENT_KEY_ID,
            "--agent-auth-token",
            "test-auth-token",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "broadcast",
            "--network",
            "1",
            "--to",
            "0x3000000000000000000000000000000000000000",
            "--value-wei",
            "0",
            "--data-hex",
            "0xdeadbeef",
            "--gas-limit",
            "21000",
            "--max-fee-per-gas-wei",
            "1000000000",
            "--tx-type",
            "0x02",
        ])
        .expect("parse");
        assert!(matches!(cli.command, Commands::Broadcast { .. }));
    }

    #[test]
    fn agent_auth_token_flag_conflicts_with_stdin_flag() {
        let err = Cli::try_parse_from([
            "agentpay-agent",
            "--agent-key-id",
            TEST_AGENT_KEY_ID,
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "--agent-auth-token",
            "test-auth-token",
            "--agent-auth-token-stdin",
            "transfer-native",
            "--network",
            "1",
            "--to",
            "0x2000000000000000000000000000000000000000",
            "--amount-wei",
            "1",
        ])
        .expect_err("must fail");
        let rendered = err.to_string();
        assert!(rendered.contains("--agent-auth-token"));
        assert!(rendered.contains("--agent-auth-token-stdin"));
    }

    #[test]
    fn manual_approval_output_renders_text_and_json() {
        let text_path = temp_path("manual-approval-output", "txt");
        let json_path = temp_path("manual-approval-output", "json");
        let output = ManualApprovalRequiredOutput {
            command: "transfer".to_string(),
            approval_request_id: Uuid::nil().to_string(),
            cli_approval_command: "agentpay admin approve".to_string(),
        };

        print_manual_approval_required_output(
            &output,
            OutputFormat::Text,
            &OutputTarget::File {
                path: text_path.clone(),
                overwrite: false,
            },
        )
        .expect("text output");
        let text = read_file(&text_path);
        assert!(text.contains("Command: transfer"));
        assert!(text.contains("Approval Request ID: 00000000-0000-0000-0000-000000000000"));
        assert!(text.contains("CLI Approval Command: agentpay admin approve"));
        assert!(!text.contains("Frontend Approval URL:"));
        assert!(!text.contains("Relay URL:"));

        print_manual_approval_required_output(
            &output,
            OutputFormat::Json,
            &OutputTarget::File {
                path: json_path.clone(),
                overwrite: false,
            },
        )
        .expect("json output");
        let json = read_file(&json_path);
        assert!(json.contains("\"command\": \"transfer\""));
        assert!(!json.contains("\"relay_url\":"));
        assert!(!json.contains("\"frontend_url\":"));

        fs::remove_file(&text_path).expect("cleanup text");
        fs::remove_file(&json_path).expect("cleanup json");
    }

    #[test]
    fn await_signature_handles_success_manual_approval_and_error_paths() {
        let runtime = test_runtime();
        let output_path = temp_path("manual-approval-await", "json");
        let output_target = OutputTarget::File {
            path: output_path.clone(),
            overwrite: false,
        };
        let daemon_socket = socket_path();

        let signature = runtime
            .block_on(await_signature_or_handle_manual_approval(
                "transfer",
                &daemon_socket,
                OutputFormat::Json,
                &output_target,
                std::future::ready(Ok(sample_signature())),
            ))
            .expect("success path");
        assert_eq!(signature, Some(sample_signature()));
        assert!(!output_path.exists());

        let manual = runtime
            .block_on(await_signature_or_handle_manual_approval(
                "approve",
                &daemon_socket,
                OutputFormat::Json,
                &output_target,
                std::future::ready(Err(AgentSdkError::Daemon(
                    DaemonError::ManualApprovalRequired {
                        approval_request_id: Uuid::nil(),
                        relay_url: Some("https://relay.example".to_string()),
                        frontend_url: None,
                    },
                ))),
            ))
            .expect("manual approval path");
        assert_eq!(manual, None);
        let rendered = read_file(&output_path);
        assert!(
            rendered.contains("\"approval_request_id\": \"00000000-0000-0000-0000-000000000000\"")
        );
        assert!(rendered.contains(&format!(
            "agentpay admin --daemon-socket {} approve-manual-approval-request --approval-request-id 00000000-0000-0000-0000-000000000000",
            daemon_socket.display()
        )));

        let err = runtime
            .block_on(await_signature_or_handle_manual_approval(
                "approve",
                &daemon_socket,
                OutputFormat::Json,
                &output_target,
                std::future::ready(Err(AgentSdkError::Daemon(DaemonError::Transport(
                    "boom".to_string(),
                )))),
            ))
            .expect_err("transport error must bubble");
        assert!(err.to_string().contains("daemon call failed"));

        fs::remove_file(&output_path).expect("cleanup");
    }

    #[test]
    fn run_command_covers_success_and_manual_approval_flows() {
        let runtime = test_runtime();
        let daemon_socket = socket_path();
        let token: EvmAddress = "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("token");
        let to: EvmAddress = "0x2000000000000000000000000000000000000000"
            .parse()
            .expect("recipient");
        let spender: EvmAddress = "0x3000000000000000000000000000000000000000"
            .parse()
            .expect("spender");

        let transfer_output = temp_path("transfer-output", "json");
        let transfer_ops = FakeAgentOps {
            calls: Mutex::new(Vec::new()),
            outcome: FakeOutcome::Signature(sample_signature()),
        };
        let outcome = runtime
            .block_on(run_command(
                Commands::Transfer {
                    network: 1,
                    token: token.clone(),
                    to: to.clone(),
                    amount_wei: 7,
                },
                true,
                &daemon_socket,
                OutputFormat::Json,
                &OutputTarget::File {
                    path: transfer_output.clone(),
                    overwrite: false,
                },
                &transfer_ops,
            ))
            .expect("transfer run");
        assert_eq!(outcome, CommandRunOutcome::Completed);
        assert_eq!(
            transfer_ops.calls.lock().expect("lock").as_slice(),
            &[FakeCall::Transfer {
                chain_id: 1,
                token: token.clone(),
                to: to.clone(),
                amount_wei: 7,
            }]
        );
        let transfer_json = read_file(&transfer_output);
        assert!(transfer_json.contains("\"command\": \"transfer\""));
        assert!(transfer_json
            .contains("\"asset\": \"erc20:0x1000000000000000000000000000000000000000\""));
        fs::remove_file(&transfer_output).expect("cleanup transfer");

        let native_output = temp_path("native-output", "json");
        let native_ops = FakeAgentOps {
            calls: Mutex::new(Vec::new()),
            outcome: FakeOutcome::Signature(sample_signature()),
        };
        let outcome = runtime
            .block_on(run_command(
                Commands::TransferNative {
                    network: 10,
                    to: to.clone(),
                    amount_wei: 9,
                },
                true,
                &daemon_socket,
                OutputFormat::Json,
                &OutputTarget::File {
                    path: native_output.clone(),
                    overwrite: false,
                },
                &native_ops,
            ))
            .expect("native run");
        assert_eq!(outcome, CommandRunOutcome::Completed);
        assert_eq!(
            native_ops.calls.lock().expect("lock").as_slice(),
            &[FakeCall::TransferNative {
                chain_id: 10,
                to: to.clone(),
                amount_wei: 9,
            }]
        );
        let native_json = read_file(&native_output);
        assert!(native_json.contains("\"command\": \"transfer-native\""));
        assert!(native_json.contains("\"asset\": \"native_eth\""));
        fs::remove_file(&native_output).expect("cleanup native");

        let approve_output = temp_path("approve-output", "json");
        let approve_ops = FakeAgentOps {
            calls: Mutex::new(Vec::new()),
            outcome: FakeOutcome::Signature(sample_signature()),
        };
        let outcome = runtime
            .block_on(run_command(
                Commands::Approve {
                    network: 137,
                    token: token.clone(),
                    spender: spender.clone(),
                    amount_wei: 11,
                },
                true,
                &daemon_socket,
                OutputFormat::Json,
                &OutputTarget::File {
                    path: approve_output.clone(),
                    overwrite: false,
                },
                &approve_ops,
            ))
            .expect("approve run");
        assert_eq!(outcome, CommandRunOutcome::Completed);
        assert_eq!(
            approve_ops.calls.lock().expect("lock").as_slice(),
            &[FakeCall::Approve {
                chain_id: 137,
                token: token.clone(),
                spender: spender.clone(),
                amount_wei: 11,
            }]
        );
        let approve_json = read_file(&approve_output);
        assert!(approve_json.contains("\"command\": \"approve\""));
        assert!(approve_json
            .contains("\"counterparty\": \"0x3000000000000000000000000000000000000000\""));
        fs::remove_file(&approve_output).expect("cleanup approve");

        let broadcast_output = temp_path("broadcast-output", "json");
        let broadcast_ops = FakeAgentOps {
            calls: Mutex::new(Vec::new()),
            outcome: FakeOutcome::Signature(sample_signature()),
        };
        let broadcast_command = Commands::Broadcast {
            network: 8453,
            nonce: 2,
            to: to.clone(),
            value_wei: 13,
            data_hex: "0xdeadbeef".to_string(),
            gas_limit: 21000,
            max_fee_per_gas_wei: 100,
            max_priority_fee_per_gas_wei: 3,
            tx_type: 0x02,
            delegation_enabled: false,
        };
        let outcome = runtime
            .block_on(run_command(
                broadcast_command,
                true,
                &daemon_socket,
                OutputFormat::Json,
                &OutputTarget::File {
                    path: broadcast_output.clone(),
                    overwrite: false,
                },
                &broadcast_ops,
            ))
            .expect("broadcast run");
        assert_eq!(outcome, CommandRunOutcome::Completed);
        assert_eq!(broadcast_ops.calls.lock().expect("lock").len(), 1);
        let broadcast_json = read_file(&broadcast_output);
        assert!(broadcast_json.contains("\"command\": \"broadcast\""));
        assert!(broadcast_json.contains("\"estimated_max_gas_spend_wei\":"));
        assert!(broadcast_json.contains("\"delegation_enabled\": false"));
        fs::remove_file(&broadcast_output).expect("cleanup broadcast");

        let manual_output = temp_path("manual-output", "json");
        let manual_ops = FakeAgentOps {
            calls: Mutex::new(Vec::new()),
            outcome: FakeOutcome::ManualApprovalRequired {
                approval_request_id: Uuid::nil(),
                relay_url: Some("https://relay.example".to_string()),
                frontend_url: Some("https://frontend.example/approval".to_string()),
            },
        };
        let outcome = runtime
            .block_on(run_command(
                Commands::Transfer {
                    network: 1,
                    token: token.clone(),
                    to: to.clone(),
                    amount_wei: 1,
                },
                true,
                &daemon_socket,
                OutputFormat::Json,
                &OutputTarget::File {
                    path: manual_output.clone(),
                    overwrite: false,
                },
                &manual_ops,
            ))
            .expect("manual approval run");
        assert_eq!(outcome, CommandRunOutcome::ManualApprovalRequired);
        let manual_json = read_file(&manual_output);
        assert!(manual_json.contains("\"approval_request_id\":"));
        assert!(!manual_json.contains("\"relay_url\":"));
        assert!(!manual_json.contains("\"frontend_url\":"));
        fs::remove_file(&manual_output).expect("cleanup manual");
    }

    #[test]
    fn run_command_bubbles_sdk_errors() {
        let runtime = test_runtime();
        let output_path = temp_path("agent-run-error", "json");
        let ops = FakeAgentOps {
            calls: Mutex::new(Vec::new()),
            outcome: FakeOutcome::Serialization("bad payload".to_string()),
        };

        let err = runtime
            .block_on(run_command(
                Commands::TransferNative {
                    network: 1,
                    to: "0x2000000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    amount_wei: 3,
                },
                true,
                Path::new("/tmp/agentpay.sock"),
                OutputFormat::Json,
                &OutputTarget::File {
                    path: output_path,
                    overwrite: false,
                },
                &ops,
            ))
            .expect_err("sdk error must bubble");
        assert!(err
            .to_string()
            .contains("failed to serialize action payload"));
    }

    #[test]
    fn run_command_rejects_invalid_broadcast_payloads_before_sdk_call() {
        let runtime = test_runtime();
        let output_path = temp_path("agent-run-invalid-broadcast", "json");
        let ops = FakeAgentOps {
            calls: Mutex::new(Vec::new()),
            outcome: FakeOutcome::Signature(sample_signature()),
        };

        let err = runtime
            .block_on(run_command(
                Commands::Broadcast {
                    network: 1,
                    nonce: 0,
                    to: "0x2000000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 1,
                    max_priority_fee_per_gas_wei: 0,
                    tx_type: 0x02,
                    delegation_enabled: true,
                },
                true,
                Path::new("/tmp/agentpay.sock"),
                OutputFormat::Json,
                &OutputTarget::File {
                    path: output_path,
                    overwrite: false,
                },
                &ops,
            ))
            .expect_err("invalid broadcast must fail before sdk call");
        assert!(err
            .to_string()
            .contains("invalid broadcast transaction payload"));
        assert!(ops.calls.lock().expect("lock").is_empty());
    }
}

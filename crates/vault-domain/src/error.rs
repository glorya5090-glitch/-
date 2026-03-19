use thiserror::Error;

/// Errors returned by domain constructors and parsers.
#[derive(Debug, Error)]
pub enum DomainError {
    /// Provided address was malformed.
    #[error(
        "address must start with 0x, contain exactly 40 hex characters, and use a valid EIP-55 checksum when mixed-case"
    )]
    InvalidAddress,
    /// Spending amount was zero.
    #[error("amount must be greater than zero")]
    InvalidAmount,
    /// Numeric value could not fit target type.
    #[error("numeric value exceeds supported range")]
    AmountOutOfRange,
    /// Permit2 `uint48` field exceeded the supported range.
    #[error("permit2 {field} exceeds uint48 range")]
    Permit2FieldOutOfRange { field: &'static str },
    /// Chain ID must be greater than zero.
    #[error("chain_id must be greater than zero")]
    InvalidChainId,
    /// ERC-20 calldata was invalid or unsupported.
    #[error("invalid erc20 calldata: {0}")]
    InvalidErc20Calldata(String),
    /// Transaction data hex was malformed.
    #[error("invalid transaction data hex")]
    InvalidTransactionDataHex,
    /// Gas fields were invalid.
    #[error("invalid gas configuration")]
    InvalidGasConfiguration,
    /// Delegation is not permitted for broadcast transactions.
    #[error("delegation is not allowed for broadcast transactions")]
    DelegationNotAllowed,
    /// ERC-20 approve/transfer calldata must not include native value.
    #[error("erc20 approve/transfer transactions must set value_wei to 0")]
    Erc20CallWithNativeValue,
    /// A policy attachment set was empty.
    #[error("policy set cannot be empty")]
    EmptyPolicySet,
    /// An entity scope that requires explicit members was empty.
    #[error("{scope} scope must not be empty")]
    EmptyScope { scope: &'static str },
    /// Transaction type is unsupported for a requested operation.
    #[error("unsupported transaction type for operation: 0x{0:02x}")]
    UnsupportedTransactionType(u8),
    /// Invalid ECDSA recovery parity.
    #[error("invalid signature parity; must be 0 or 1")]
    InvalidSignatureParity,
    /// Authorization time window is malformed.
    #[error("authorization window is invalid")]
    InvalidAuthorizationWindow,
    /// Permit expiration is malformed or expired.
    #[error("permit expiration must be a future unix timestamp")]
    InvalidPermitExpiration,
    /// Permit signature deadline is malformed or expired.
    #[error("signature deadline must be a future unix timestamp")]
    InvalidSignatureDeadline,
    /// Typed-data domain or nonce field is malformed.
    #[error("invalid typed-data domain: {0}")]
    InvalidTypedDataDomain(String),
    /// Relay capability secret could not derive a secure approval token.
    #[error("invalid relay approval capability secret")]
    InvalidRelayCapabilitySecret,
    /// Relay capability token was missing or malformed.
    #[error("invalid relay approval capability token")]
    InvalidRelayCapabilityToken,
}

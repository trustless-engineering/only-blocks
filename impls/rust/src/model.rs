//! The internal data model shared by the protobuf and bincode decoders (WIRE_FORMATS.md §12).

pub type Pubkey = [u8; 32];

/// `InstructionError` (54 variants, `25 = Custom(u32)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionError {
    Unit(u32),
    Custom(u32),
}

/// `TransactionError` (39 variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionError {
    Unit(u32),
    InstructionError(u8, InstructionError),
    DuplicateInstruction(u8),
    InsufficientFundsForRent(u8),
    ProgramExecutionTemporarilyRestricted(u8),
}

pub const INSTRUCTION_ERROR_NAMES: [&str; 54] = [
    "GenericError",
    "InvalidArgument",
    "InvalidInstructionData",
    "InvalidAccountData",
    "AccountDataTooSmall",
    "InsufficientFunds",
    "IncorrectProgramId",
    "MissingRequiredSignature",
    "AccountAlreadyInitialized",
    "UninitializedAccount",
    "UnbalancedInstruction",
    "ModifiedProgramId",
    "ExternalAccountLamportSpend",
    "ExternalAccountDataModified",
    "ReadonlyLamportChange",
    "ReadonlyDataModified",
    "DuplicateAccountIndex",
    "ExecutableModified",
    "RentEpochModified",
    "NotEnoughAccountKeys",
    "AccountDataSizeChanged",
    "AccountNotExecutable",
    "AccountBorrowFailed",
    "AccountBorrowOutstanding",
    "DuplicateAccountOutOfSync",
    "Custom",
    "InvalidError",
    "ExecutableDataModified",
    "ExecutableLamportChange",
    "ExecutableAccountNotRentExempt",
    "UnsupportedProgramId",
    "CallDepth",
    "MissingAccount",
    "ReentrancyNotAllowed",
    "MaxSeedLengthExceeded",
    "InvalidSeeds",
    "InvalidRealloc",
    "ComputationalBudgetExceeded",
    "PrivilegeEscalation",
    "ProgramEnvironmentSetupFailure",
    "ProgramFailedToComplete",
    "ProgramFailedToCompile",
    "Immutable",
    "IncorrectAuthority",
    "BorshIoError",
    "AccountNotRentExempt",
    "InvalidAccountOwner",
    "ArithmeticOverflow",
    "UnsupportedSysvar",
    "IllegalOwner",
    "MaxAccountsDataAllocationsExceeded",
    "MaxAccountsExceeded",
    "MaxInstructionTraceLengthExceeded",
    "BuiltinProgramsMustConsumeComputeUnits",
];

pub const TRANSACTION_ERROR_NAMES: [&str; 39] = [
    "AccountInUse",
    "AccountLoadedTwice",
    "AccountNotFound",
    "ProgramAccountNotFound",
    "InsufficientFundsForFee",
    "InvalidAccountForFee",
    "AlreadyProcessed",
    "BlockhashNotFound",
    "InstructionError",
    "CallChainTooDeep",
    "MissingSignatureForFee",
    "InvalidAccountIndex",
    "SignatureFailure",
    "InvalidProgramForExecution",
    "SanitizeFailure",
    "ClusterMaintenance",
    "AccountBorrowOutstanding",
    "WouldExceedMaxBlockCostLimit",
    "UnsupportedVersion",
    "InvalidWritableAccount",
    "WouldExceedMaxAccountCostLimit",
    "WouldExceedAccountDataBlockLimit",
    "TooManyAccountLocks",
    "AddressLookupTableNotFound",
    "InvalidAddressLookupTableOwner",
    "InvalidAddressLookupTableData",
    "InvalidAddressLookupTableIndex",
    "InvalidRentPayingAccount",
    "WouldExceedMaxVoteCostLimit",
    "WouldExceedAccountDataTotalLimit",
    "DuplicateInstruction",
    "InsufficientFundsForRent",
    "MaxLoadedAccountsDataSizeExceeded",
    "InvalidLoadedAccountsDataSizeLimit",
    "ResanitizationNeeded",
    "ProgramExecutionTemporarilyRestricted",
    "UnbalancedTransaction",
    "ProgramCacheHitMaxLimit",
    "CommitCancelled",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
    pub stack_height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerInstructions {
    pub index: u8,
    pub instructions: Vec<InnerInstruction>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenBalance {
    pub account_index: u8,
    pub mint: String,
    pub owner: String,
    pub program_id: String,
    pub ui_amount: Option<f64>,
    pub decimals: u8,
    pub amount: String,
    pub ui_amount_string: String,
}

/// Reward types are stored 1-based like the protobuf enum: 1 Fee, 2 Rent, 3 Staking, 4 Voting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reward {
    pub pubkey: String,
    pub lamports: i64,
    pub post_balance: u64,
    pub reward_type: Option<u8>,
    pub commission: Option<u8>,
}

pub fn reward_type_name(t: u8) -> Option<&'static str> {
    match t {
        1 => Some("Fee"),
        2 => Some("Rent"),
        3 => Some("Staking"),
        4 => Some("Voting"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnData {
    pub program_id: Pubkey,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Meta {
    pub status: Option<TransactionError>,
    pub fee: u64,
    pub pre_balances: Vec<u64>,
    pub post_balances: Vec<u64>,
    pub inner_instructions: Option<Vec<InnerInstructions>>,
    pub log_messages: Option<Vec<String>>,
    pub pre_token_balances: Option<Vec<TokenBalance>>,
    pub post_token_balances: Option<Vec<TokenBalance>>,
    pub rewards: Option<Vec<Reward>>,
    pub loaded_writable: Vec<Pubkey>,
    pub loaded_readonly: Vec<Pubkey>,
    pub return_data: Option<ReturnData>,
    pub compute_units_consumed: Option<u64>,
    pub cost_units: Option<u64>,
}

/// Block rewards and the optional partition count.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockRewards {
    pub rewards: Vec<Reward>,
    pub num_partitions: Option<u64>,
}

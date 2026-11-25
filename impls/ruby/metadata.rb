# Protobuf and historical bincode metadata and rewards.
require_relative 'wire'
require_relative 'zstd'

module Metadata
  include Wire

  INSTRUCTION_ERRORS = %w[
    GenericError InvalidArgument InvalidInstructionData InvalidAccountData AccountDataTooSmall
    InsufficientFunds IncorrectProgramId MissingRequiredSignature AccountAlreadyInitialized
    UninitializedAccount UnbalancedInstruction ModifiedProgramId ExternalAccountLamportSpend
    ExternalAccountDataModified ReadonlyLamportChange ReadonlyDataModified DuplicateAccountIndex
    ExecutableModified RentEpochModified NotEnoughAccountKeys AccountDataSizeChanged
    AccountNotExecutable AccountBorrowFailed AccountBorrowOutstanding DuplicateAccountOutOfSync
    Custom InvalidError ExecutableDataModified ExecutableLamportChange ExecutableAccountNotRentExempt
    UnsupportedProgramId CallDepth MissingAccount ReentrancyNotAllowed MaxSeedLengthExceeded
    InvalidSeeds InvalidRealloc ComputationalBudgetExceeded PrivilegeEscalation
    ProgramEnvironmentSetupFailure ProgramFailedToComplete ProgramFailedToCompile Immutable
    IncorrectAuthority BorshIoError AccountNotRentExempt InvalidAccountOwner ArithmeticOverflow
    UnsupportedSysvar IllegalOwner MaxAccountsDataAllocationsExceeded MaxAccountsExceeded
    MaxInstructionTraceLengthExceeded BuiltinProgramsMustConsumeComputeUnits
  ].freeze

  TRANSACTION_ERRORS = %w[
    AccountInUse AccountLoadedTwice AccountNotFound ProgramAccountNotFound InsufficientFundsForFee
    InvalidAccountForFee AlreadyProcessed BlockhashNotFound InstructionError CallChainTooDeep
    MissingSignatureForFee InvalidAccountIndex SignatureFailure InvalidProgramForExecution
    SanitizeFailure ClusterMaintenance AccountBorrowOutstanding WouldExceedMaxBlockCostLimit
    UnsupportedVersion InvalidWritableAccount WouldExceedMaxAccountCostLimit
    WouldExceedAccountDataBlockLimit TooManyAccountLocks AddressLookupTableNotFound
    InvalidAddressLookupTableOwner InvalidAddressLookupTableData InvalidAddressLookupTableIndex
    InvalidRentPayingAccount WouldExceedMaxVoteCostLimit WouldExceedAccountDataTotalLimit
    DuplicateInstruction InsufficientFundsForRent MaxLoadedAccountsDataSizeExceeded
    InvalidLoadedAccountsDataSizeLimit ResanitizationNeeded ProgramExecutionTemporarilyRestricted
    UnbalancedTransaction ProgramCacheHitMaxLimit CommitCancelled
  ].freeze

  REWARD_TYPES = %w[Fee Rent Staking Voting].freeze
  CUTOFF = 157 * 432000

  def transaction_error(reader)
    variant = reader.u32
    name = TRANSACTION_ERRORS[variant]
    require_valid(name, 'Unknown TransactionError variant')
    case variant
    when 8
      index, kind = reader.u8, reader.u32
      instruction = INSTRUCTION_ERRORS[kind]
      require_valid(instruction, 'Unknown InstructionError variant')
      { name => [index, kind == 25 ? { Custom: reader.u32 } : instruction] }
    when 30 then { name => reader.u8 }
    when 31, 35 then { name => { account_index: reader.u8 } }
    else name
    end
  end

  def unsigned_text(value, maximum = U64_MAX)
    return unless /\A\+?[0-9]+\z/.match?(value)

    digits = value.sub(/\A\+?0*/, '')
    return if digits.bytesize > 20

    number = digits.to_i
    number if number <= maximum
  end

  def token_balance(index, mint, ui, decimals, amount, owner = '', program = '', display = '')
    if display.empty?
      digits = (unsigned_text(amount) || 0).to_s.rjust(decimals + 1, '0')
      display = if decimals.zero?
                  digits
                else
                  "#{digits[0...-decimals]}.#{digits[-decimals..-1]}".sub(/0+\z/, '').sub(/\.\z/, '')
                end
    end
    balance = { accountIndex: index, mint: mint,
                uiTokenAmount: { uiAmount: ui && ui.finite? ? ui : nil, decimals: decimals,
                                 amount: amount, uiAmountString: display } }
    balance[:owner] = owner unless owner.empty?
    balance[:programId] = program unless program.empty?
    balance
  end

  def empty_meta
    { err: nil, fee: 0, preBalances: [], postBalances: [], innerInstructions: nil, logMessages: nil,
      preTokenBalances: nil, postTokenBalances: nil, rewards: nil, loadedAddresses: { writable: [], readonly: [] } }
  end

  # Each field is [name, scalar type or nested schema, optional repeated flag].
  INSTRUCTION = { 1 => [:programIdIndex, :varint], 2 => [:accounts, :bytes], 3 => [:data, :bytes],
                  4 => [:stackHeight, :varint] }.freeze
  INNER = { 1 => [:index, :varint], 2 => [:instructions, INSTRUCTION, true] }.freeze
  AMOUNT = { 1 => [:uiAmount, :double], 2 => [:decimals, :varint], 3 => [:amount, :string],
             4 => [:uiAmountString, :string] }.freeze
  TOKEN = { 1 => [:accountIndex, :varint], 2 => [:mint, :string], 3 => [:uiTokenAmount, AMOUNT],
            4 => [:owner, :string], 5 => [:programId, :string] }.freeze
  REWARD = { 1 => [:pubkey, :string], 2 => [:lamports, :varint], 3 => [:postBalance, :varint],
             4 => [:rewardType, :varint], 5 => [:commission, :string], 6 => [:commissionBps, :string] }.freeze
  REWARDS = { 1 => [:rewards, REWARD, true], 2 => [:partitions, { 1 => [:count, :varint] }] }.freeze
  META = {
    1 => [:error, { 1 => [:bytes, :bytes] }], 2 => [:fee, :varint], 3 => [:preBalances, :varint, true],
    4 => [:postBalances, :varint, true], 5 => [:innerInstructions, INNER, true],
    6 => [:logMessages, :string, true], 7 => [:preTokenBalances, TOKEN, true],
    8 => [:postTokenBalances, TOKEN, true], 9 => [:rewards, REWARD, true],
    10 => [:innerInstructionsNone, :varint], 11 => [:logMessagesNone, :varint],
    12 => [:loadedWritable, :bytes, true], 13 => [:loadedReadonly, :bytes, true],
    14 => [:returnData, { 1 => [:programId, :bytes], 2 => [:data, :bytes] }],
    15 => [:returnDataNone, :varint], 16 => [:computeUnitsConsumed, :varint], 17 => [:costUnits, :varint]
  }.freeze

  def proto_key(reader)
    key = reader.varint
    require_valid(key.between?(8, 0xffffffff), 'Invalid protobuf key')
    [key >> 3, key & 7]
  end

  def skip_proto(reader, field, wire, depth = 0)
    case wire
    when 0 then reader.varint
    when 1 then reader.take(8)
    when 2 then reader.take(reader.varint)
    when 3
      require_valid(depth < 100, 'Protobuf group nesting limit')
      loop do
        tag, mode = proto_key(reader)
        if mode == 4
          require_valid(tag == field, 'Mismatched protobuf group')
          break
        end
        skip_proto(reader, tag, mode, depth + 1)
      end
    when 5 then reader.take(4)
    else raise Wire::Error, 'Invalid protobuf wire type'
    end
  end

  def protobuf(data, schema, target = nil)
    target ||= {}
    reader = Reader.new(data)
    while reader.left.positive?
      field, wire = proto_key(reader)
      descriptor = schema[field]
      unless descriptor
        skip_proto(reader, field, wire)
        next
      end
      name, type, repeated = descriptor
      if repeated && type == :varint && wire == 2
        packed = Reader.new(reader.take(reader.varint))
        values = (target[name] ||= [])
        values << packed.varint while packed.left.positive?
        next
      end
      expected = { varint: 0, double: 1 }.fetch(type, 2)
      require_valid(wire == expected, 'Wrong protobuf wire type')
      value = case wire
              when 0 then reader.varint
              when 1 then reader.f64
              else
                payload = reader.take(reader.varint)
                if type.is_a?(Hash)
                  protobuf(payload, type, repeated ? nil : target[name])
                else
                  type == :string ? utf8(payload) : payload
                end
              end
      if repeated
        (target[name] ||= []) << value
      else
        target[name] = value
      end
    end
    target
  end

  def proto_reward(value)
    commission = unsigned_text(value.fetch(:commission, ''), 255)
    bps = unsigned_text(value.fetch(:commissionBps, ''), 65535)
    commission ||= bps / 100 if bps && bps / 100 <= 255
    kind = value.fetch(:rewardType, 0) & 0xffffffff
    lamports = value.fetch(:lamports, 0)
    lamports -= 1 << 64 if lamports >= (1 << 63)
    { pubkey: value.fetch(:pubkey, ''), lamports: lamports, postBalance: value.fetch(:postBalance, 0),
      rewardType: kind.between?(1, 4) ? REWARD_TYPES[kind - 1] : nil, commission: commission }
  end

  def proto_token(value)
    amount = value.fetch(:uiTokenAmount, {})
    ui = amount.fetch(:uiAmount, 0.0)
    token_balance(value.fetch(:accountIndex, 0) & 255, value.fetch(:mint, ''),
                  ui.abs > Float::EPSILON ? ui : nil, amount.fetch(:decimals, 0) & 255,
                  amount.fetch(:amount, ''), value.fetch(:owner, ''), value.fetch(:programId, ''),
                  amount.fetch(:uiAmountString, ''))
  end

  def proto_instruction(value)
    height = value[:stackHeight]
    { programIdIndex: value.fetch(:programIdIndex, 0) & 255, accounts: value.fetch(:accounts, EMPTY),
      data: value.fetch(:data, EMPTY), stackHeight: height && (height & 0xffffffff) }
  end

  def proto_meta(value)
    result = empty_meta
    error = value[:error]
    result[:err] = transaction_error(Reader.new(error.fetch(:bytes, EMPTY))) if error
    result[:fee] = value.fetch(:fee, 0)
    [:preBalances, :postBalances].each { |key| result[key] = value.fetch(key, []) }
    if value.fetch(:innerInstructionsNone, 0).zero?
      result[:innerInstructions] = value.fetch(:innerInstructions, []).map do |group|
        { index: group.fetch(:index, 0) & 255, instructions: group.fetch(:instructions, []).map { |ix| proto_instruction(ix) } }
      end
    end
    result[:logMessages] = value.fetch(:logMessages, []) if value.fetch(:logMessagesNone, 0).zero?
    [:preTokenBalances, :postTokenBalances].each do |key|
      result[key] = value.fetch(key, []).map { |balance| proto_token(balance) }
    end
    result[:rewards] = value.fetch(:rewards, []).map { |reward| proto_reward(reward) }
    result[:loadedAddresses] = {
      writable: value.fetch(:loadedWritable, []).map { |bytes| pubkey(bytes) },
      readonly: value.fetch(:loadedReadonly, []).map { |bytes| pubkey(bytes) }
    }
    if value[:returnData] && value.fetch(:returnDataNone, 0).zero?
      data = value[:returnData]
      result[:returnData] = { programId: pubkey(data[:programId]), data: [b64(data.fetch(:data, EMPTY)), 'base64'] }
    end
    [:computeUnitsConsumed, :costUnits].each { |key| result[key] = value[key] if value.key?(key) }
    result
  end

  def proto_rewards(value)
    result = { rewards: value.fetch(:rewards, []).map { |item| proto_reward(item) } }
    result[:numRewardPartitions] = value[:partitions].fetch(:count, 0) if value[:partitions]
    result
  end

  def stored_reward(reader, extended = true)
    key, lamports = reader.string, reader.i64
    post = reader.left.positive? || !extended ? reader.u64 : 0
    if reader.left.positive? || !extended
      kind = reader.option do
        name = REWARD_TYPES[reader.u32]
        require_valid(name, 'Unknown RewardType')
        name
      end
    end
    commission = reader.option { reader.u8 } if extended && reader.left.positive?
    { pubkey: key, lamports: lamports, postBalance: post, rewardType: kind, commission: commission }
  end

  def stored_token(reader, layout)
    index, mint, ui, decimals, amount = reader.u8, reader.string, reader.f64, reader.u8, reader.string
    owner = layout >= 2 && reader.left.positive? ? reader.string : ''
    program = layout >= 3 && reader.left.positive? ? reader.string : ''
    token_balance(index, mint, ui, decimals, amount, owner, program)
  end

  def stored_meta(reader, legacy = false, layout = 3)
    status = reader.u32
    require_valid(status <= 1, 'Invalid bincode result tag')
    result = empty_meta
    result[:err] = transaction_error(reader) if status == 1
    result[:fee] = reader.u64
    [:preBalances, :postBalances].each { |key| result[key] = reader.vec(8) { reader.u64 } }
    inner = lambda do
      reader.vec(9) do
        index = reader.u8
        instructions = reader.vec(legacy ? 3 : 4) do
          ix = instruction(reader)
          ix[:stackHeight] = reader.option { reader.u32 } unless legacy
          ix
        end
        { index: index, instructions: instructions }
      end
    end
    fields = {
      innerInstructions: inner,
      logMessages: -> { reader.vec(8) { reader.string } },
      preTokenBalances: -> { reader.vec(26) { stored_token(reader, layout) } },
      postTokenBalances: -> { reader.vec(26) { stored_token(reader, layout) } },
      rewards: -> { reader.vec(16) { stored_reward(reader) } },
      returnData: -> { { programId: pubkey(reader.take(32)), data: [b64(reader.take(reader.u64)), 'base64'] } },
      computeUnitsConsumed: -> { reader.u64 },
      costUnits: -> { reader.u64 }
    }
    fields.each do |key, read|
      break if reader.left.zero?

      value = reader.option(&read)
      result[key] = value unless value.nil?
    end
    result
  end

  def bincode(data, layouts)
    layouts.each do |layout|
      reader = Reader.new(data)
      begin
        value = layout.call(reader)
        return value if reader.left.zero?
      rescue Wire::Error
        # Historical records can use different field layouts.
      end
    end
    layouts.first.call(Reader.new(data))
  end

  def bincode_meta(data)
    layouts = [method(:stored_meta)] + [1, 2, 3].map { |layout| ->(r) { stored_meta(r, true, layout) } }
    bincode(data, layouts)
  end

  def bincode_rewards(data)
    current = ->(r) { r.vec(16) { stored_reward(r) } }
    legacy = ->(r) { r.vec(25) { stored_reward(r, false) } }
    { rewards: bincode(data, [current, legacy]) }
  end

  def decode_payload(slot, data, schema, convert, stored)
    if slot < CUTOFF
      begin
        return stored.call(data)
      rescue Wire::Error
        # Fall through to protobuf for pre-157 records carrying newer metadata.
      end
    end
    begin
      parsed = protobuf(data, schema)
    rescue Wire::Error
      raise if slot < CUTOFF

      return stored.call(data)
    end
    convert.call(parsed)
  end

  def unwrap(slot, data, schema, convert, stored)
    decode = ->(payload) { decode_payload(slot, payload, schema, method(convert), method(stored)) }
    if data.start_with?("\x28\xb5\x2f\xfd".b)
      begin
        data = Zstd.decompress(data)
      rescue Zstd::Error
        # Try the original bytes when Zstandard framing fails.
      end
      return decode.call(data)
    end
    begin
      decode.call(data)
    rescue Wire::Error => original
      begin
        plain = Zstd.decompress(data)
      rescue Zstd::Error
        raise original
      end
      decode.call(plain)
    end
  end

  def metadata(slot, data)
    unwrap(slot, data, META, :proto_meta, :bincode_meta) unless data.empty?
  end

  def rewards(slot, data)
    data.empty? ? { rewards: [] } : unwrap(slot, data, REWARDS, :proto_rewards, :bincode_rewards)
  end
end

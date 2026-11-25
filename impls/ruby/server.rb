# OnlyBlocks JSON-RPC server and Old Faithful range transport.
require 'json'
require 'net/http'
require 'openssl'
require 'optparse'
require 'set'
require 'time'
require 'timeout'
require 'uri'
require 'webrick'
require_relative 'metadata'

module OnlyBlocks
  MAX_BODY = 1 << 20
  MAX_SLICE = 128 << 20
  EPOCH_SLOTS = 432000
  UPGRADEABLE = 'BPFLoaderUpgradeab1e11111111111111111111111'
  RESERVED = Set.new(%w[
    AddressLookupTab1e1111111111111111111111111 BPFLoader2111111111111111111111111111111111
    BPFLoader1111111111111111111111111111111111 BPFLoaderUpgradeab1e11111111111111111111111
    ComputeBudget111111111111111111111111111111 Config1111111111111111111111111111111111111
    Ed25519SigVerify111111111111111111111111111 Feature111111111111111111111111111111111111
    LoaderV411111111111111111111111111111111111 KeccakSecp256k11111111111111111111111111111
    Secp256r1SigVerify1111111111111111111111111 StakeConfig11111111111111111111111111111111
    Stake11111111111111111111111111111111111111 11111111111111111111111111111111
    Vote111111111111111111111111111111111111111 ZkE1Gama1Proof11111111111111111111111111111
    ZkTokenProof1111111111111111111111111111111 SysvarC1ock11111111111111111111111111111111
    SysvarEpochRewards1111111111111111111111111 SysvarEpochSchedu1e111111111111111111111111
    SysvarFees111111111111111111111111111111111 Sysvar1nstructions1111111111111111111111111
    SysvarLastRestartS1ot1111111111111111111111 SysvarRecentB1ockHashes11111111111111111111
    SysvarRent111111111111111111111111111111111 SysvarRewards111111111111111111111111111111
    SysvarS1otHashes111111111111111111111111111 SysvarS1otHistory11111111111111111111111111
    SysvarStakeHistory1111111111111111111111111 NativeLoader1111111111111111111111111111111
    Sysvar1111111111111111111111111111111111111
  ]).freeze

  class RpcError < StandardError
    attr_reader :code

    def initialize(code, message)
      super(message)
      @code = code
    end
  end

  module Encoding
    include Metadata

    def account_objects(version, message, loaded)
      static = message[:accountKeys]
      writable = version == 0 ? loaded[:writable] : []
      readonly = version == 0 ? loaded[:readonly] : []
      keys = static + writable + readonly
      header = message[:header]
      signers = header[:numRequiredSignatures]
      programs = message[:instructions].map { |ix| ix[:programIdIndex] }.to_set
      upgradeable = keys.include?(UPGRADEABLE)
      keys.each_with_index.map do |key, index|
        lookup = index >= static.length
        can_write = if lookup
                      index - static.length < writable.length
                    elsif index < signers
                      index < signers - header[:numReadonlySignedAccounts]
                    else
                      index < static.length - header[:numReadonlyUnsignedAccounts]
                    end
        { pubkey: key, signer: index < signers,
          writable: can_write && !RESERVED.include?(key) && (upgradeable || !programs.include?(index)),
          source: lookup ? 'lookupTable' : 'transaction' }
      end
    end

    def instruction_json(ix, keys)
      result = { data: base58(ix[:data]), stackHeight: ix[:stackHeight] }
      if keys
        address = lambda do |index|
          require_valid(index < keys.length, 'Instruction account index out of range')
          keys[index]
        end
        result.merge(programId: address.call(ix[:programIdIndex]), accounts: ix[:accounts].bytes.map(&address))
      else
        result.merge(programIdIndex: ix[:programIdIndex], accounts: ix[:accounts].bytes)
      end
    end

    def transaction_json(tx, meta, encoding, details, include_rewards, max_version)
      version, signatures, message, raw = tx
      if version == 0
        raise RpcError.new(-32015, 'Transaction version (0) requires "maxSupportedTransactionVersion": 0') if max_version.nil?

        meta ||= empty_meta
      end
      parsed = encoding == 'jsonParsed'
      accounts_only = details == 'accounts'
      keys = nil
      if %w[base64 base58].include?(encoding)
        output = [encoding == 'base64' ? b64(raw) : base58(raw), encoding]
      else
        accounts = message[:accountKeys]
        if parsed || accounts_only
          loaded = meta ? meta[:loadedAddresses] : { writable: [], readonly: [] }
          accounts = account_objects(version, message, loaded)
        end
        keys = accounts.map { |account| account[:pubkey] } if parsed
        output = { signatures: signatures.map { |sig| base58(sig) } }
        if accounts_only
          output[:accountKeys] = accounts
        else
          output[:message] = message.merge(accountKeys: accounts,
                                           instructions: message[:instructions].map { |ix| instruction_json(ix, keys) })
          output[:message].delete(:header) if parsed
        end
      end

      if meta
        meta = meta.dup
        error = meta[:err]
        meta[:status] = error.nil? ? { Ok: nil } : { Err: error }
        meta[:rewards] = nil unless include_rewards
        if accounts_only
          [:innerInstructions, :logMessages, :loadedAddresses, :returnData,
           :computeUnitsConsumed, :costUnits].each { |field| meta.delete(field) }
          meta.delete(:rewards) unless include_rewards
        else
          meta.delete(:loadedAddresses) if parsed
          if meta[:innerInstructions]
            meta[:innerInstructions] = meta[:innerInstructions].map do |group|
              { index: group[:index], instructions: group[:instructions].map { |ix| instruction_json(ix, keys) } }
            end
          end
        end
      end
      result = { transaction: output, meta: meta }
      result[:version] = version if meta && !max_version.nil?
      result
    end
  end

  class Lru
    def initialize(capacity = 100_000)
      @capacity = capacity
      @entries = {}
      @lock = Mutex.new
    end

    def get(key)
      @lock.synchronize do
        return unless @entries.key?(key)

        @entries[key] = @entries.delete(key)
      end
    end

    def put(key, value)
      @lock.synchronize do
        @entries.delete(key)
        @entries[key] = value
        @entries.shift if @entries.length > @capacity
      end
    end
  end

  class Archive
    include Encoding

    def initialize(base)
      @base = base
      @ranges = Lru.new
      @hashes = Lru.new
      @permits = SizedQueue.new(32)
      32.times { @permits.push(nil) }
    end

    def retry_delay(header, attempt)
      if header
        if /\A[0-9]+\z/.match?(header)
          digits = header.sub(/\A0+/, '')
          return digits.bytesize > 2 ? 10 : [10, digits.to_i].min
        end
        begin
          return (Time.httpdate(header) - Time.now).clamp(0, 10)
        rescue ArgumentError
          # Invalid Retry-After uses the normal jittered backoff.
        end
      end
      [10, 0.2 * 2**attempt].min * (0.5 + rand * 0.5)
    end

    def range_attempt(path, start, finish, size, cap)
      @permits.pop
      begin
        Timeout.timeout(60) do
          http = Net::HTTP.new(@base.hostname, @base.port, nil)
          http.use_ssl = @base.scheme == 'https'
          http.open_timeout = 10
          http.read_timeout = 60
          http.max_retries = 0
          request = Net::HTTP::Get.new(path, {
            'Range' => "bytes=#{start}-#{finish}", 'User-Agent' => 'onlyblocks/ruby',
            'Connection' => 'close', 'Accept-Encoding' => 'identity'
          })
          http.request(request) do |response|
            status = response.code.to_i
            return [status, response['retry-after']] unless status == 206

            lengths = response.get_fields('content-length')
            if lengths
              require_valid(lengths.length == 1 && /\A[0-9]+\z/.match?(lengths.first),
                            'Invalid archive Content-Length')
              digits = lengths.first.sub(/\A0+/, '')
              require_valid(digits.bytesize <= 9 && digits.to_i <= cap,
                            'Archive Content-Length exceeds range cap')
              length = digits.to_i unless response.chunked?
            end
            body = ''.b
            received = 0
            response.read_body do |chunk|
              received += chunk.bytesize
              require_valid(received <= cap, 'Archive body exceeds range cap')
              body << chunk if received <= size
            end
            if length && received < length
              raise EOFError, 'Incomplete archive range response'
            end
            require_valid(received == size, 'Archive range body has wrong length')
            return [206, body]
          end
        end
      ensure
        @permits.push(nil)
      end
    end

    def read_range(slot, suffix, start, size, cap)
      finish = start + size - 1
      require_valid(finish <= Wire::U64_MAX, 'Archive range end overflows u64')
      epoch = slot / EPOCH_SLOTS
      path = "#{@base.path}/#{epoch}/epoch-#{epoch}#{suffix}"
      5.times do |attempt|
        begin
          status, value = range_attempt(path, start, finish, size, cap)
        rescue IOError, SystemCallError, SocketError, Timeout::Error, OpenSSL::SSL::SSLError, Net::HTTPBadResponse
          status, value = nil, nil
        end
        return value if status == 206
        raise RpcError.new(-32004, "Block not available for slot #{slot}") if status == 404

        require_valid(status.nil? || status == 429 || status.between?(500, 599),
                      "Unexpected archive HTTP status #{status}")
        sleep(retry_delay(value, attempt)) if attempt < 4
      end
      raise Wire::Error, 'Archive range retries exhausted'
    end

    def load_block(slot)
      record = @ranges.get(slot)
      unless record
        raw = read_range(slot, '-slot-ranges.raw', (slot % EPOCH_SLOTS) * 12, 12, 12)
        record = raw.unpack('Q<V')
        @ranges.put(slot, record)
      end
      offset, size = record
      raise RpcError.new(-32007, "Slot #{slot} was skipped, or missing in long-term storage") if size.zero?

      require_valid(size <= MAX_SLICE, 'Archive slice exceeds 128 MiB')
      index_car(read_range(slot, '.car', offset, size, MAX_SLICE))
    end

    def blockhash(slot, index, entries)
      hash = entries.empty? ? Wire::ZERO_HASH : pubkey(indexed(index, entries.last, 1)[2])
      @hashes.put(slot, hash)
      hash
    end

    def previous_hash(slot, parent)
      return Wire::ZERO_HASH if slot.zero?

      cached = @hashes.get(parent)
      return cached if cached

      index, block = load_block(parent)
      require_valid(unsigned(block[1]), 'Missing parent Block slot')
      blockhash(parent, index, links(block[3]))
    end

    def get_block(slot, encoding, details, include_rewards, max_version)
      index, block = load_block(slot)
      require_valid(unsigned(block[1]) == slot, 'Block slot differs from requested slot')
      entries = links(block[3])
      info = block[4].is_a?(Array) ? block[4] : []
      parent = unsigned(info[0]) || 0
      time = signed(info[1])
      hash = blockhash(slot, index, entries)
      result = { previousBlockhash: previous_hash(slot, parent), blockhash: hash,
                 parentSlot: parent, blockTime: time == 0 ? nil : time, blockHeight: unsigned(info[2]) }
      if details != 'none'
        items = []
        entries.each do |key|
          entry = indexed(index, key, 1)
          require_valid(bytes?(entry[2]) && entry[2].bytesize == 32, 'Invalid Entry hash')
          links(entry[3]).each do |tx_key|
            node = indexed(index, tx_key, 0)
            tx = transaction(frame_payload(index, node[1]))
            if details == 'signatures'
              require_valid(!tx[1].empty?, 'Transaction has no signature')
              items << base58(tx[1][0])
            else
              meta = metadata(slot, frame_payload(index, node[2])) if node[2].is_a?(Array)
              items << transaction_json(tx, meta, encoding, details, include_rewards, max_version)
            end
          end
        end
        result[details == 'signatures' ? :signatures : :transactions] = items
      end
      if include_rewards
        data = Wire::EMPTY
        if bytes?(block[5])
          key, absent = link(block[5])
          if !absent && index.key?(key)
            node = indexed(index, key, 5)
            data = frame_payload(index, node[2]) if node.length > 2
          end
        end
        result.merge!(rewards(slot, data))
      end
      result
    end
  end

  class Rpc
    Number = Struct.new(:text)

    # The parser calls decimal_class for decimal tokens only. Replace numbers
    # outside strings with decimal surrogates, retaining the original spelling
    # for validation and ID echo. JSON.parse still checks the full grammar.
    TOKEN = /"(?:[^"\\\x00-\x1f]|\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4}))*"|(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)|["\/]/.freeze

    def initialize(archive)
      @archive = archive
    end

    def parse(raw)
      raw = raw.force_encoding(::Encoding::UTF_8)
      raise JSON::ParserError, 'Invalid UTF-8' unless raw.valid_encoding?

      numbers = []
      normalized = raw.gsub(TOKEN) do |token|
        if Regexp.last_match(1)
          numbers << Number.new(token)
          "#{numbers.length - 1}.0"
        else
          raise JSON::ParserError, 'Invalid JSON token' if token.bytesize == 1

          token
        end
      end
      decimals = Object.new
      decimals.define_singleton_method(:new) { |value| numbers.fetch(value.to_i) }
      value = JSON.parse(normalized, decimal_class: decimals, max_nesting: 128)
      check_strings(value) if /\\u[dD]/.match?(normalized)
      value
    end

    # Ruby 2.6 JSON can decode a lone low surrogate as malformed UTF-8.
    def check_strings(value)
      case value
      when Hash
        value.each do |key, item|
          check_strings(key)
          check_strings(item)
        end
      when Array
        value.each { |item| check_strings(item) }
      when String
        raise JSON::ParserError, 'Invalid Unicode escape' unless value.valid_encoding?
      end
    end

    def response(id, **fields)
      id_json = id.is_a?(Number) ? id.text : JSON.generate(id)
      value = JSON.generate({ jsonrpc: '2.0' }.merge(fields))
      value[0...-1] + ',"id":' + id_json + '}'
    end

    def error(id, code, message)
      response(id, error: { code: code, message: message })
    end

    def uint_parameter(value, maximum)
      if value.is_a?(Number) && /\A(?:0|[1-9][0-9]{0,19})\z/.match?(value.text)
        number = value.text.to_i
        return number if number <= maximum
      end
      raise RpcError.new(-32602, 'Invalid unsigned integer parameter')
    end

    def block_params(params)
      invalid = RpcError.new(-32602, 'Invalid getBlock params')
      raise invalid unless params.is_a?(Array) && params.length.between?(1, 2)

      slot = uint_parameter(params[0], Wire::U64_MAX)
      config = params[1]
      config = {} if config.nil?
      config = { 'encoding' => config } if config.is_a?(String)
      raise invalid unless config.is_a?(Hash)

      encoding = config['encoding'].nil? ? 'json' : config['encoding']
      details = config['transactionDetails'].nil? ? 'full' : config['transactionDetails']
      include_rewards = config['rewards'].nil? ? true : config['rewards']
      max_version = config['maxSupportedTransactionVersion']
      commitment = config['commitment']
      unless %w[json jsonParsed base64 base58].include?(encoding) &&
             %w[full accounts signatures none].include?(details) &&
             (details != 'accounts' || encoding == 'json') &&
             [true, false].include?(include_rewards) && [nil, 'finalized', 'confirmed'].include?(commitment)
        raise invalid
      end
      [slot, encoding, details, include_rewards, max_version.nil? ? nil : uint_parameter(max_version, 255)]
    end

    def dispatch(request)
      return error(nil, -32600, 'Invalid Request') unless request.is_a?(Hash)

      version, name, id = request.values_at('jsonrpc', 'method', 'id')
      unless (version.nil? || version.is_a?(String)) && (name.nil? || name.is_a?(String)) &&
             (id.nil? || id.is_a?(String) || id.is_a?(Number))
        return error(nil, -32600, 'Invalid Request')
      end
      return error(id, -32600, 'Invalid Request') if version != '2.0' || name.nil?

      params = request['params']
      result = case name
               when 'getHealth'
                 raise RpcError.new(-32602, 'Invalid getHealth params') unless params.nil? || params == []

                 'ok'
               when 'getBlock'
                 @archive.get_block(*block_params(params))
               else
                 raise RpcError.new(-32601, "Method not found: #{name}")
               end
      response(id, result: result)
    rescue RpcError => ex
      error(id, ex.code, ex.message)
    rescue StandardError => ex
      error(id, -32603, ex.message.empty? ? 'Internal error' : ex.message)
    end

    def call(raw)
      request = parse(raw)
      if request.is_a?(Array)
        return error(nil, -32600, 'Invalid batch size') unless request.length.between?(1, 100)

        '[' + request.map { |item| dispatch(item) }.join(',') + ']'
      else
        dispatch(request)
      end
    rescue JSON::ParserError, JSON::NestingError
      error(nil, -32700, 'Parse error')
    end
  end

  def self.serve(rpc, request, response)
    response.keep_alive = false
    response['Connection'] = 'close'
    response.body = ''
    unless request.request_method == 'POST' && request.unparsed_uri == '/'
      response.status = 404
      return
    end

    lengths = request.header['content-length']
    transfer = request.header['transfer-encoding']
    if lengths.length > 1 || (!lengths.empty? && !/\A[0-9]+\z/.match?(lengths.first)) ||
       (!transfer.empty? && (!lengths.empty? || transfer.map(&:downcase) != ['chunked']))
      raise WEBrick::HTTPStatus::BadRequest
    end
    unless lengths.empty?
      digits = lengths.first.sub(/\A0+/, '')
      raise WEBrick::HTTPStatus::RequestEntityTooLarge if digits.bytesize > 7 || digits.to_i > MAX_BODY
    end

    raw = ''.b
    unless lengths.empty? && transfer.empty?
      request.body do |chunk|
        raise WEBrick::HTTPStatus::RequestEntityTooLarge if raw.bytesize + chunk.bytesize > MAX_BODY

        raw << chunk
      end
    end
    response['Content-Type'] = 'application/json'
    response.body = rpc.call(raw)
  rescue WEBrick::HTTPStatus::Status => ex
    response.status = ex.code
  end

  def self.run
    bind = ENV.fetch('ONLYBLOCKS_BIND', '127.0.0.1:8899')
    base = ENV.fetch('OLD_FAITHFUL_BASE_URL', 'https://files.old-faithful.net')
    parser = OptionParser.new do |options|
      options.on('--bind HOST:PORT') { |value| bind = value }
      options.on('--base-url URL') { |value| base = value }
    end
    parser.parse!
    raise ArgumentError, 'Unexpected positional arguments' unless ARGV.empty?

    uri = URI.parse(base.strip.sub(%r{/+\z}, ''))
    unless uri.is_a?(URI::HTTP) && uri.host && !uri.host.empty?
      raise ArgumentError, '--base-url requires an HTTP or HTTPS origin'
    end
    host, separator, port = bind.rpartition(':')
    raise ArgumentError, '--bind requires HOST:PORT' if host.empty? || separator.empty?

    server = WEBrick::HTTPServer.new(BindAddress: host, Port: Integer(port, 10), RequestTimeout: 10,
                                    AccessLog: [], Logger: WEBrick::Log.new($stderr, WEBrick::Log::FATAL),
                                    DoNotReverseLookup: true)
    rpc = Rpc.new(Archive.new(uri))
    server.mount_proc('/') { |request, response| serve(rpc, request, response) }
    # Aborting active threads on shutdown also bounds exit time during a slow
    # upstream request. The process owns no durable state to flush.
    %w[INT TERM].each { |name| Signal.trap(name) { exit!(0) } }
    server.start
  rescue ArgumentError, URI::InvalidURIError, OptionParser::ParseError => ex
    warn ex.message
    exit 1
  end
end

OnlyBlocks.run if $PROGRAM_NAME == __FILE__

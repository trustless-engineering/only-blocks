# CARv1, DAG-CBOR, DataFrame and Solana transaction decoding.
require 'base64'

module Wire
  class Error < StandardError; end

  U64_MAX = (1 << 64) - 1
  EMPTY = ''.b.freeze
  ZERO_HASH = '1' * 32
  BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

  def require_valid(condition, message)
    raise Error, message unless condition
  end

  def utf8(data)
    text = data.dup.force_encoding(Encoding::UTF_8)
    require_valid(text.valid_encoding?, 'Invalid UTF-8')
    text
  end

  class Reader
    include Wire

    attr_reader :data, :pos

    def initialize(data)
      @data, @pos = data, 0
    end

    def left
      @data.bytesize - @pos
    end

    def peek
      @data.getbyte(@pos)
    end

    def take(size)
      require_valid(size.between?(0, left), 'Truncated binary value')
      value = @data.byteslice(@pos, size)
      @pos += size
      value
    end

    def fixed(size, format)
      take(size).unpack1(format)
    end

    def u8
      require_valid(left.positive?, 'Truncated byte')
      byte = peek
      @pos += 1
      byte
    end

    def u32
      fixed(4, 'V')
    end

    def u64
      fixed(8, 'Q<')
    end

    def i64
      fixed(8, 'q<')
    end

    def f64
      fixed(8, 'E')
    end

    def varint
      value = 0
      10.times do |index|
        byte = u8
        require_valid(index < 9 || byte <= 1, 'Varint overflow')
        value |= (byte & 127) << (index * 7)
        return value if byte < 128
      end
    end

    def compact
      value = 0
      3.times do |index|
        byte = u8
        require_valid(index.zero? || byte != 0, 'Noncanonical compact-u16')
        require_valid(index < 2 || byte <= 3, 'Compact-u16 overflow')
        value |= (byte & 127) << (index * 7)
        return value if byte < 128
      end
    end

    def items(count, minimum = 1)
      require_valid(count <= left / minimum, 'Count exceeds enclosing field')
      # Grow as fields are consumed so a corrupt count alone cannot allocate
      # a large array before the first field is checked.
      values = []
      count.times { values << yield }
      values
    end

    def vec(minimum = 1, &read)
      items(u64, minimum, &read)
    end

    def string
      utf8(take(u64))
    end

    def option
      tag = u8
      require_valid(tag <= 1, 'Invalid bincode option')
      yield if tag == 1
    end
  end

  def unsigned(value)
    value if value.is_a?(Integer) && value.between?(0, U64_MAX)
  end

  def signed(value)
    value if value.is_a?(Integer) && value.between?(-(1 << 63), (1 << 63) - 1)
  end

  def base58(data)
    zeroes = 0
    zeroes += 1 while zeroes < data.bytesize && data.getbyte(zeroes).zero?
    number = data.unpack1('H*').to_i(16)
    digits = +''
    until number.zero?
      number, digit = number.divmod(58)
      digits << BASE58.getbyte(digit)
    end
    '1' * zeroes + digits.reverse
  end

  def b64(data)
    Base64.strict_encode64(data)
  end

  def bytes?(data)
    data.is_a?(String) && data.encoding == Encoding::BINARY
  end

  def pubkey(data)
    require_valid(bytes?(data) && data.bytesize == 32, 'Expected 32-byte hash or public key')
    base58(data)
  end

  def cbor_argument(reader, info)
    return info if info < 24
    return nil if info == 31

    require_valid(info <= 27, 'Reserved CBOR argument')
    reader.fixed(1 << (info - 24), ['C', 'n', 'N', 'Q>'][info - 24])
  end

  def cbor_simple(reader, info)
    case info
    when 20 then false
    when 21 then true
    when 22, 23 then nil
    when 25
      half = reader.fixed(2, 'n')
      exponent, fraction = (half >> 10) & 31, half & 1023
      value = case exponent
              when 0 then Math.ldexp(fraction, -24)
              when 31 then fraction.zero? ? Float::INFINITY : Float::NAN
              else Math.ldexp(1024 + fraction, exponent - 25)
              end
      half >= 32768 ? -value : value
    when 26 then reader.fixed(4, 'g')
    when 27 then reader.fixed(8, 'G')
    else raise Error, 'Unsupported CBOR simple value'
    end
  end

  def cbor_string(reader, argument, major)
    convert = ->(data) { major == 2 ? data : utf8(data) }
    return convert.call(reader.take(argument)) if argument

    result = major == 2 ? ''.b : +''
    until reader.peek == 255
      head = reader.u8
      require_valid(head >> 5 == major && (head & 31) != 31, 'Invalid CBOR string chunk')
      result << convert.call(reader.take(cbor_argument(reader, head & 31)))
    end
    reader.u8
    result
  end

  def cbor_item(reader, depth = 0)
    require_valid(depth <= 128, 'CBOR nesting limit')
    head = reader.u8
    major, info = head >> 5, head & 31
    return cbor_simple(reader, info) if major == 7

    arg = cbor_argument(reader, info)
    require_valid(arg || major.between?(2, 5), 'Invalid indefinite CBOR item')
    case major
    when 0 then arg
    when 1 then -1 - arg
    when 2, 3 then cbor_string(reader, arg, major)
    when 6 then cbor_item(reader, depth + 1)
    when 4, 5
      array = major == 4
      result = array ? [] : {}
      require_valid(arg.nil? || arg <= reader.left / (array ? 1 : 2), 'CBOR count exceeds enclosing field')
      while arg ? arg.positive? : reader.peek != 255
        item = cbor_item(reader, depth + 1)
        if array
          result << item
        else
          value = cbor_item(reader, depth + 1)
          result[item] = value if item.is_a?(String) && !bytes?(item)
        end
        arg -= 1 if arg
      end
      reader.u8 if arg.nil?
      result
    end
  end

  def cbor(data)
    reader = Reader.new(data)
    item = cbor_item(reader)
    require_valid(reader.left.zero?, 'Trailing CBOR bytes')
    item
  end

  def cid(reader)
    start = reader.pos
    version, codec = reader.varint, reader.varint
    absent = false
    if version == 0x12 && codec == 0x20
      reader.take(32)
    else
      require_valid(version == 1, 'Unsupported CID version')
      code, size = reader.varint, reader.varint
      require_valid(size <= 64, 'CID digest too long')
      reader.take(size)
      absent = code.zero? && size.zero?
    end
    [reader.data.byteslice(start, reader.pos - start), absent]
  end

  def link(value)
    require_valid(bytes?(value) && value.getbyte(0) == 0, 'Invalid CID link')
    cid(Reader.new(value.byteslice(1..-1)))
  end

  def links(value)
    value.is_a?(Array) ? value.map { |item| link(item).first } : []
  end

  def kind(node, number)
    require_valid(node.is_a?(Array) && unsigned(node[0]) == number, "Expected IPLD node kind #{number}")
    node
  end

  def indexed(index, key, number)
    bytes = index[key]
    require_valid(bytes, 'CID missing from CAR slice')
    kind(cbor(bytes), number)
  end

  def car_header?(data)
    return false unless data.getbyte(0) >> 5 == 5

    value = cbor(data)
    value.is_a?(Hash) && value.key?('version')
  rescue Error
    false
  end

  def block_section?(data)
    head = data.getbyte(0)
    return false unless head && head >> 5 == 4

    info = head & 31
    return false if info.between?(28, 30)

    width = info < 24 || info == 31 ? 1 : 1 + (1 << (info - 24))
    data.getbyte(width) == 2
  end

  def index_car(data)
    reader = Reader.new(data)
    index = {}
    block = nil
    first = true
    while reader.left.positive?
      size = reader.varint
      next if size.zero?

      require_valid(size <= (32 << 20), 'Oversize CAR section')
      section = Reader.new(reader.take(size))
      header = first && car_header?(section.data)
      first = false
      next if header

      key, = cid(section)
      node = section.take(section.left)
      index[key] = node
      block = node if block_section?(node)
    end
    require_valid(block, 'No Block node in CAR slice')
    [index, kind(cbor(block), 2)]
  end

  CRC_TABLE = Array.new(256) do |byte|
    8.times { byte = (byte >> 1) ^ (byte.odd? ? 0xd800000000000000 : 0) }
    byte
  end.freeze

  def crc64(data)
    value = U64_MAX
    data.each_byte { |byte| value = (value >> 8) ^ CRC_TABLE[(value & 255) ^ byte] }
    value ^ U64_MAX
  end

  def fnv1a(data)
    value = 0xcbf29ce484222325
    data.each_byte { |byte| value = ((value ^ byte) * 0x100000001b3) & U64_MAX }
    value
  end

  def frame_payload(index, root)
    kind(root, 6)
    payload = bytes?(root[4]) ? root[4].dup : ''.b
    stack = links(root[5]).reverse
    seen = {}
    until stack.empty?
      key = stack.pop
      require_valid(!seen.key?(key), 'Repeated DataFrame CID')
      seen[key] = true
      frame = indexed(index, key, 6)
      if bytes?(frame[4])
        require_valid(payload.bytesize + frame[4].bytesize <= (128 << 20), 'Oversize reassembled DataFrame')
        payload << frame[4]
      end
      stack.concat(links(frame[5]).reverse)
    end
    expected = unsigned(root[1])
    require_valid(expected.nil? || crc64(payload) == expected || fnv1a(payload) == expected, 'DataFrame hash mismatch')
    payload
  end

  def instruction(reader, height = nil)
    { programIdIndex: reader.u8, accounts: reader.take(reader.compact),
      data: reader.take(reader.compact), stackHeight: height }
  end

  def transaction_v1(reader)
    header = { numRequiredSignatures: reader.u8, numReadonlySignedAccounts: reader.u8,
               numReadonlyUnsignedAccounts: reader.u8 }
    mask = reader.u32
    priority_bits = mask & 0x03
    require_valid(mask <= 0x1f && [0, 0x03].include?(priority_bits), 'Invalid v1 transaction config mask')
    recent = pubkey(reader.take(32))
    instruction_count = reader.u8
    keys = reader.items(reader.u8, 32) { pubkey(reader.take(32)) }
    config = {
      priorityFee: priority_bits == 0x03 ? reader.u64 : nil,
      computeUnitLimit: (mask & 0x04).zero? ? nil : reader.u32,
      loadedAccountsDataSizeLimit: (mask & 0x08).zero? ? nil : reader.u32,
      heapSize: (mask & 0x10).zero? ? nil : reader.u32
    }
    # All headers precede the payloads, which are laid out in instruction order.
    headers = reader.items(instruction_count, 4) { [reader.u8, reader.u8, reader.fixed(2, 'v')] }
    instructions = headers.map do |program, account_count, data_length|
      { programIdIndex: program, accounts: reader.take(account_count),
        data: reader.take(data_length), stackHeight: 1 }
    end
    signatures = reader.items(header[:numRequiredSignatures], 64) { reader.take(64) }
    message = { header: header, accountKeys: keys, recentBlockhash: recent,
                instructions: instructions, transactionConfig: config }
    [1, signatures, message, reader.data.byteslice(0, reader.pos)]
  end

  def transaction(data)
    reader = Reader.new(data)
    discriminator = reader.u8
    return transaction_v1(reader) if discriminator == 0x81

    require_valid(discriminator < 0x80, 'Invalid transaction discriminator')
    signatures = reader.items(discriminator, 64) { reader.take(64) }
    prefix = reader.u8
    require_valid(prefix <= 128, 'Unsupported wire transaction version')
    version = prefix == 128 ? 0 : 'legacy'
    header = { numRequiredSignatures: version == 0 ? reader.u8 : prefix,
               numReadonlySignedAccounts: reader.u8, numReadonlyUnsignedAccounts: reader.u8 }
    keys = reader.items(reader.compact, 32) { pubkey(reader.take(32)) }
    recent = pubkey(reader.take(32))
    instructions = reader.items(reader.compact, 3) { instruction(reader, 1) }
    message = { header: header, accountKeys: keys, recentBlockhash: recent, instructions: instructions }
    if version == 0
      message[:addressTableLookups] = reader.items(reader.compact, 34) do
        { accountKey: pubkey(reader.take(32)), writableIndexes: reader.take(reader.compact).bytes,
          readonlyIndexes: reader.take(reader.compact).bytes }
      end
    end
    [version, signatures, message, data.byteslice(0, reader.pos)]
  end
end

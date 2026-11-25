# RFC 8878 decoding, based on docs/ZSTD_MINI_SPEC.md.
module Zstd
  class Error < StandardError; end

  CAP = 512 << 20
  BLOCK_MAX = 128 << 10
  MAGIC = 0xfd2fb528
  SKIPPABLE = 0x184d2a50
  M64 = (1 << 64) - 1

  LL_BASE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
             16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
             8192, 16384, 32768, 65536].freeze
  LL_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
             13, 14, 15, 16].freeze
  ML_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
             19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
             35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
             4099, 8195, 16387, 32771, 65539].freeze
  ML_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
             12, 13, 14, 15, 16].freeze
  LL_DEFAULT = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1]
  ML_DEFAULT = [1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1]
  OF_DEFAULT = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1]
  SEQ_KINDS = [[LL_DEFAULT, 6, 35, 9], [OF_DEFAULT, 5, 31, 8], [ML_DEFAULT, 6, 52, 9]]
  Frame = Struct.new(:offsets, :huffman, :tables)

  def self.le(data, pos, size, limit = data.bytesize)
    raise Error, 'Truncated input' if pos < 0 || pos + size > limit

    value = 0
    size.times { |i| value |= data.getbyte(pos + i) << (8 * i) }
    value
  end

  class BackwardBits
    attr_accessor :bits

    def initialize(data, start, finish)
      raise Error, 'Empty or out-of-range bitstream' unless start >= 0 && start < finish && finish <= data.bytesize

      last = data.getbyte(finish - 1)
      raise Error, 'Missing bitstream end marker' if last.zero?

      @data = data
      @start = start
      @bits = 8 * (finish - start - 1) + last.bit_length - 1
    end

    def peek(count)
      return 0 if count.zero? || @bits <= 0

      low = [0, @bits - count].max
      first = low >> 3
      size = ((@bits - 1) >> 3) - first + 1
      word = Zstd.le(@data, @start + first, size)
      value = (word >> (low & 7)) & ((1 << (@bits - low)) - 1)
      value << [0, count - @bits].max
    end

    def read(count)
      value = peek(count)
      @bits -= count
      value
    end
  end

  class ForwardBits
    def initialize(data, start, limit)
      @data, @position, @limit = data, start * 8, limit * 8
    end

    def peek(count)
      value = 0
      count.times do |i|
        bit = @position + i
        break if bit >= @limit

        value |= ((@data.getbyte(bit >> 3) >> (bit & 7)) & 1) << i
      end
      value
    end

    def read(count)
      raise Error, 'Truncated FSE description' if @position + count > @limit

      value = peek(count)
      @position += count
      value
    end

    def end_byte
      (@position + 7) >> 3
    end
  end

  def self.fse_description(data, pos, limit, max_symbol, max_log)
    bits = ForwardBits.new(data, pos, limit)
    log = bits.read(4) + 5
    raise Error, 'FSE accuracy log too large' if log > max_log

    threshold = 1 << log
    remaining = threshold + 1
    width = log + 1
    weights = []
    while remaining > 1
      raise Error, 'Too many FSE symbols' if weights.length > max_symbol

      maximum = 2 * threshold - 1 - remaining
      low = bits.peek(width - 1)
      if low < maximum
        value = bits.read(width - 1)
      else
        value = bits.read(width)
        value -= maximum if value >= threshold
      end
      weight = value - 1
      weights << weight
      remaining -= weight.abs
      if weight.zero?
        loop do
          repeat = bits.read(2)
          weights.concat([0] * repeat)
          raise Error, 'Too many FSE symbols' if weights.length > max_symbol + 1

          break if repeat != 3
        end
      end
      raise Error, 'Invalid FSE probability' if remaining < 1

      while remaining < threshold
        width -= 1
        threshold >>= 1
      end
    end
    [weights, log, bits.end_byte]
  end

  def self.fse_table(weights, log)
    size = 1 << log
    raise Error, 'Invalid FSE distribution' unless weights.sum(&:abs) == size

    cells = Array.new(size)
    high = size - 1
    counters = weights.map(&:abs)
    weights.each_with_index do |weight, symbol|
      if weight == -1
        cells[high] = symbol
        high -= 1
      end
    end
    step = (size >> 1) + (size >> 3) + 3
    mask = size - 1
    pos = 0
    weights.each_with_index do |weight, symbol|
      weight.times do
        cells[pos] = symbol
        begin
          pos = (pos + step) & mask
        end while pos > high
      end
    end
    raise Error, 'Invalid FSE spread' unless pos.zero?

    cells.map do |symbol|
      count = counters[symbol]
      counters[symbol] += 1
      width = log - count.bit_length + 1
      [symbol, width, (count << width) - size]
    end
  end

  PREDEFINED = SEQ_KINDS.map { |weights, log, _symbol, _max| [fse_table(weights, log), log] }.freeze

  def self.huffman_table(weights)
    raise Error, 'Invalid Huffman weights' if weights.size > 255 || weights.any? { |weight| weight > 11 }

    total = weights.sum { |weight| weight.zero? ? 0 : 1 << (weight - 1) }
    width = total.bit_length
    raise Error, 'Invalid Huffman code width' unless width.between?(1, 11)

    rest = (1 << width) - total
    raise Error, 'Invalid implied Huffman weight' unless (rest & (rest - 1)).zero?

    weights << rest.bit_length
    table = []
    (1..width).each do |weight|
      weights.each_with_index do |w, symbol|
        table.concat([[symbol, width + 1 - w]] * (1 << (w - 1))) if w == weight
      end
    end
    [table, width]
  end

  def self.huffman_description(data, pos, limit)
    header = le(data, pos, 1, limit)
    pos += 1
    weights = []
    if header < 128
      finish = pos + header
      raise Error, 'Huffman description overruns literals' if finish > limit

      probabilities, log, bits_start = fse_description(data, pos, finish, 255, 6)
      table = fse_table(probabilities, log)
      bits = BackwardBits.new(data, bits_start, finish)
      states = [bits.read(log), bits.read(log)]
      raise Error, 'Truncated Huffman initial states' if bits.bits < 0

      turn = 0
      loop do
        raise Error, 'Too many Huffman weights' if weights.length >= 255

        symbol, width, baseline = table[states[turn]]
        weights << symbol
        states[turn] = baseline + bits.read(width)
        turn ^= 1
        if bits.bits < 0
          weights << table[states[turn]][0]
          break
        end
      end
    else
      count = header - 127
      finish = pos + (count + 1) / 2
      raise Error, 'Huffman description overruns literals' if finish > limit

      weights = Array.new(count) do |i|
        value = data.getbyte(pos + i / 2)
        i.even? ? value >> 4 : value & 15
      end
    end
    [huffman_table(weights), finish]
  end

  def self.huffman_stream(data, start, finish, huffman, count, out)
    table, width = huffman
    bits = BackwardBits.new(data, start, finish)
    count.times do
      symbol, length = table[bits.peek(width)]
      out << symbol
      bits.bits -= length
    end
    raise Error, 'Huffman bitstream not fully consumed' unless bits.bits.zero?
  end

  LITERAL_HEADERS = [[1, 3, 10], [4, 3, 10], [4, 4, 14], [4, 5, 18]].freeze

  def self.literals(data, pos, finish, frame, maximum)
    first = le(data, pos, 1, finish)
    type, format = first & 3, (first >> 2) & 3
    if type < 2
      width = [1, 2, 1, 3][format]
      size = le(data, pos, width, finish) >> (width == 1 ? 3 : 4)
      pos += width
      raise Error, 'Literal output exceeds block limit' if size > maximum

      if type.zero?
        raise Error, 'Raw literals overrun block' if pos + size > finish

        return [data.byteslice(pos, size), pos + size]
      end
      return [le(data, pos, 1, finish).chr(Encoding::BINARY) * size, pos + 1]
    end

    streams, length, width = LITERAL_HEADERS[format]
    header = le(data, pos, length, finish)
    mask = (1 << width) - 1
    count = (header >> 4) & mask
    pos += length
    end_literal = pos + ((header >> (4 + width)) & mask)
    raise Error, 'Compressed literals overrun block' if end_literal > finish
    raise Error, 'Literal output exceeds block limit' if count > maximum

    if type == 2
      frame.huffman, pos = huffman_description(data, pos, end_literal)
    end
    raise Error, 'Missing previous Huffman table' unless frame.huffman

    out = ''.b
    if streams == 1
      huffman_stream(data, pos, end_literal, frame.huffman, count, out)
    else
      sizes = [0, 2, 4].map { |i| le(data, pos + i, 2, end_literal) }
      pos += 6
      sizes << end_literal - pos - sizes.sum
      quarter = (count + 3) / 4
      counts = [quarter, quarter, quarter, count - 3 * quarter]
      raise Error, 'Invalid 4-stream literals' unless sizes.all?(&:positive?) && counts.last >= 0

      sizes.zip(counts).each do |size, symbols|
        huffman_stream(data, pos, pos + size, frame.huffman, symbols, out)
        pos += size
      end
    end
    [out, end_literal]
  end

  def self.sequence_table(data, pos, finish, mode, index, frame)
    _default, _log, max_symbol, max_log = SEQ_KINDS[index]
    case mode
    when 0
      table = PREDEFINED[index]
    when 1
      symbol = le(data, pos, 1, finish)
      raise Error, 'Invalid RLE sequence symbol' if symbol > max_symbol

      table = [[[symbol, 0, 0]], 0]
      pos += 1
    when 2
      probabilities, log, pos = fse_description(data, pos, finish, max_symbol, max_log)
      table = [fse_table(probabilities, log), log]
    when 3
      table = frame.tables[index]
      raise Error, 'Missing previous FSE table' unless table
    end
    frame.tables[index] = table
    [table, pos]
  end

  def self.sequences(data, pos, finish, frame, maximum)
    first = le(data, pos, 1, finish)
    pos += 1
    if first.zero?
      raise Error, 'Trailing bytes after empty sequence section' unless pos == finish

      return
    end
    count = first
    if first == 255
      count = le(data, pos, 2, finish) + 0x7f00
      pos += 2
    elsif first >= 128
      count = ((first - 128) << 8) + le(data, pos, 1, finish)
      pos += 1
    end
    raise Error, 'Invalid sequence count' if count.zero? || count * 3 > maximum

    modes = le(data, pos, 1, finish)
    pos += 1
    raise Error, 'Reserved sequence mode bits set' unless (modes & 3).zero?

    tables = [6, 4, 2].each_with_index.map do |shift, index|
      table, pos = sequence_table(data, pos, finish, (modes >> shift) & 3, index, frame)
      table
    end
    bits = BackwardBits.new(data, pos, finish)
    states = tables.map { |_table, log| bits.read(log) }
    count.times do |i|
      ll, of, ml = tables.each_with_index.map { |(table, _log), index| table[states[index]] }
      value = (1 << of[0]) + bits.read(of[0])
      match_length = ML_BASE[ml[0]] + bits.read(ML_BITS[ml[0]])
      literal_length = LL_BASE[ll[0]] + bits.read(LL_BITS[ll[0]])
      raise Error, 'Truncated sequence bits' if bits.bits < 0

      yield literal_length, value, match_length
      if i + 1 < count
        states[0] = ll[2] + bits.read(ll[1])
        states[2] = ml[2] + bits.read(ml[1])
        states[1] = of[2] + bits.read(of[1])
      end
    end
    raise Error, 'Sequence bitstream not fully consumed' unless bits.bits.zero?
  end

  def self.offset(value, literal_length, offsets)
    if value > 3
      result = value - 3
      offsets.replace([result, offsets[0], offsets[1]])
      return result
    end
    index = value - 1 + (literal_length.zero? ? 1 : 0)
    if index == 3
      result = offsets[0] - 1
      offsets.replace([result, offsets[0], offsets[1]])
      return result
    end
    result = offsets.delete_at(index)
    offsets.unshift(result)
    result
  end

  def self.compressed_block(data, pos, finish, frame, out, frame_start, window, maximum)
    literals, pos = literals(data, pos, finish, frame, maximum)
    block_end = out.bytesize + maximum
    lit = 0
    sequences(data, pos, finish, frame, maximum) do |ll, value, ml|
      raise Error, 'Sequence consumes unavailable literals' if lit + ll > literals.bytesize
      raise Error, 'Block output exceeds limit' if out.bytesize + ll + ml > block_end

      out << literals.byteslice(lit, ll)
      lit += ll
      distance = offset(value, ll, frame.offsets)
      unless distance.positive? && distance <= window && distance <= out.bytesize - frame_start
        raise Error, 'Match offset out of range'
      end

      # An overlapping match repeats the first distance bytes.
      if ml <= distance
        out << out.byteslice(-distance, ml)
      else
        pattern = out.byteslice(-distance, distance)
        repeats, remainder = ml.divmod(distance)
        out << pattern * repeats << pattern.byteslice(0, remainder)
      end
    end
    remainder = literals.bytesize - lit
    raise Error, 'Block output exceeds limit' if out.bytesize + remainder > block_end

    out << literals.byteslice(lit, remainder)
  end

  def self.decode_frame(data, pos, out)
    descriptor = le(data, pos, 1)
    pos += 1
    raise Error, 'Reserved frame header bit set' unless (descriptor & 8).zero?

    single = (descriptor & 32) != 0
    unless single
      wd = le(data, pos, 1)
      pos += 1
      base = 1 << (10 + (wd >> 3))
      window = base + (base >> 3) * (wd & 7)
    end

    dict_length = [0, 1, 2, 4][descriptor & 3]
    raise Error, 'Zstd dictionaries are unsupported' unless le(data, pos, dict_length).zero?

    pos += dict_length
    fcs_length = [single ? 1 : 0, 2, 4, 8][descriptor >> 6]
    if fcs_length.positive?
      content_size = le(data, pos, fcs_length) + (fcs_length == 2 ? 256 : 0)
      pos += fcs_length
      raise Error, 'Decompressed size limit exceeded' if content_size > CAP - out.bytesize
    end
    window = content_size if single
    block_max = [window, BLOCK_MAX].min
    frame_start = out.bytesize
    frame = Frame.new([1, 4, 8], nil, [nil, nil, nil])
    loop do
      header = le(data, pos, 3)
      pos += 3
      type, size = (header >> 1) & 3, header >> 3
      raise Error, 'Invalid block size' if size > block_max

      encoded = type == 1 ? 1 : size
      finish = pos + encoded
      raise Error, 'Truncated block' if finish > data.bytesize

      maximum = [block_max, CAP - out.bytesize].min
      maximum = [maximum, content_size - (out.bytesize - frame_start)].min if content_size
      case type
      when 0, 1
        raise Error, 'Block output exceeds limit' if size > maximum

        out << (type.zero? ? data.byteslice(pos, size) : data.byteslice(pos, 1) * size)
      when 2
        compressed_block(data, pos, finish, frame, out, frame_start, window, maximum)
      else
        raise Error, 'Reserved block type'
      end
      pos = finish
      break unless (header & 1).zero?
    end
    if content_size && out.bytesize - frame_start != content_size
      raise Error, 'Frame content size mismatch'
    end
    if (descriptor & 4) != 0
      checksum = le(data, pos, 4)
      raise Error, 'Content checksum mismatch' unless (xxh64(out, frame_start) & 0xffffffff) == checksum

      pos += 4
    end
    pos
  end

  def self.decompress(data)
    out = ''.b
    pos = 0
    while pos < data.bytesize
      magic = le(data, pos, 4)
      pos += 4
      if magic == MAGIC
        pos = decode_frame(data, pos, out)
      elsif (magic & 0xfffffff0) == SKIPPABLE
        count = le(data, pos, 4)
        pos += 4 + count
        raise Error, 'Truncated skippable frame' if pos > data.bytesize
      else
        raise Error, 'Unknown frame magic'
      end
    end
    out
  end

  P1 = 0x9e3779b185ebca87
  P2 = 0xc2b2ae3d27d4eb4f
  P3 = 0x165667b19e3779f9
  P4 = 0x85ebca77c2b2ae63
  P5 = 0x27d4eb2f165667c5

  def self.rotl(value, count)
    ((value << count) | (value >> (64 - count))) & M64
  end

  def self.xxh_round(acc, lane)
    (rotl((acc + lane * P2) & M64, 31) * P1) & M64
  end

  def self.xxh64(data, start = 0)
    finish = data.bytesize
    pos = start
    if finish - start >= 32
      accumulators = [(P1 + P2) & M64, P2, 0, (-P1) & M64]
      while pos + 32 <= finish
        4.times { |i| accumulators[i] = xxh_round(accumulators[i], le(data, pos + 8 * i, 8)) }
        pos += 32
      end
      hash = accumulators.zip([1, 7, 12, 18]).sum { |acc, shift| rotl(acc, shift) } & M64
      accumulators.each { |acc| hash = ((hash ^ xxh_round(0, acc)) * P1 + P4) & M64 }
    else
      hash = P5
    end
    hash = (hash + finish - start) & M64
    while pos + 8 <= finish
      hash = (rotl(hash ^ xxh_round(0, le(data, pos, 8)), 27) * P1 + P4) & M64
      pos += 8
    end
    if pos + 4 <= finish
      hash = (rotl(hash ^ ((le(data, pos, 4) * P1) & M64), 23) * P2 + P3) & M64
      pos += 4
    end
    while pos < finish
      hash = (rotl(hash ^ ((data.getbyte(pos) * P5) & M64), 11) * P1) & M64
      pos += 1
    end
    hash = ((hash ^ (hash >> 33)) * P2) & M64
    hash = ((hash ^ (hash >> 29)) * P3) & M64
    hash ^ (hash >> 32)
  end
end

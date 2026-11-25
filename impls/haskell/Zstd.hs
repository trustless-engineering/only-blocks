{-# LANGUAGE BangPatterns, ScopedTypeVariables #-}
-- | RFC 8878 Zstandard decoder, ported from docs/ZSTD_MINI_SPEC.md.
--   Internally imperative (unboxed arrays, one growable output buffer), but
--   exposed as the pure function 'decompress'.
module Zstd (decompress, isZstd, xxh64) where

import Control.Exception
import Control.Monad
import Data.Array.Base (unsafeAt, unsafeFreeze, unsafeRead, unsafeWrite)
import Data.Array.IO (IOUArray, newArray)
import Data.Array.Unboxed (UArray, listArray)
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.IORef
import Data.Word
import Foreign.ForeignPtr
import Foreign.Marshal.Utils (copyBytes, fillBytes)
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe (unsafePerformIO)

newtype ZstdError = ZstdError String deriving Show
instance Exception ZstdError

zfail :: String -> IO a
zfail = throwIO . ZstdError

maxOutput, blockMax :: Int
maxOutput = 512 * 1024 * 1024
blockMax = 128 * 1024

isZstd :: B.ByteString -> Bool
isZstd = B.isPrefixOf (B.pack [0x28, 0xb5, 0x2f, 0xfd])

-- | Decompress every frame of the input (skippable frames skipped).
decompress :: B.ByteString -> Either String B.ByteString
decompress d = unsafePerformIO $
  (Right <$> (run d >>= evaluate)) `catch` \(e :: SomeException) -> case fromException e of
    Just (ZstdError m) -> pure (Left m)
    Nothing -> pure (Left (show e))
{-# NOINLINE decompress #-}

byte :: B.ByteString -> Int -> IO Int
byte d i
  | i < 0 || i >= B.length d = zfail "truncated input"
  | otherwise = pure (fromIntegral (BU.unsafeIndex d i))

le :: B.ByteString -> Int -> Int -> IO Int
le d pos n
  | pos < 0 || pos + n > B.length d = zfail "truncated input"
  | otherwise = pure $! go (n - 1) 0
  where go i !acc | i < 0 = acc
                  | otherwise = go (i - 1) ((acc `shiftL` 8) .|. fromIntegral (BU.unsafeIndex d (pos + i)))

highbit :: Int -> Int
highbit x = finiteBitSize x - 1 - countLeadingZeros x

-- ---- output buffer --------------------------------------------------------

data Out = Out { oBuf :: !(IORef (ForeignPtr Word8)), oCap :: !(IORef Int), oLen :: !(IORef Int) }

ensure :: Out -> Int -> IO ()
ensure o need = do
  cap <- readIORef (oCap o)
  when (need > cap) $ do
    len <- readIORef (oLen o)
    let newCap = max need (min (cap * 2) (maxOutput + 1))
    old <- readIORef (oBuf o)
    new <- mallocForeignPtrBytes newCap
    withForeignPtr old $ \src -> withForeignPtr new $ \dst -> copyBytes dst src len
    writeIORef (oBuf o) new
    writeIORef (oCap o) newCap

-- ---- backward bitstreams (state = remaining bit count) ----------------------

backward :: B.ByteString -> Int -> Int -> IO Int
backward d start end
  | start < 0 || end > B.length d || end <= start = zfail "empty or out-of-range bitstream"
  | otherwise = do
      let lastB = fromIntegral (BU.unsafeIndex d (end - 1))
      when (lastB == 0) $ zfail "bitstream end marker missing"
      pure (8 * (end - start - 1) + highbit lastB)

-- Bits [lo, hi) of the little-endian stream starting at byte @start@.
window :: B.ByteString -> Int -> Int -> Int -> Int
window d start lo hi = (go lst 0 `shiftR` (lo .&. 7)) .&. ((1 `shiftL` (hi - lo)) - 1)
  where
    first = lo `shiftR` 3
    lst = (hi - 1) `shiftR` 3
    go !i !acc | i < first = acc
               | otherwise = go (i - 1) ((acc `shiftL` 8) .|. fromIntegral (BU.unsafeIndex d (start + i)))

peekBits :: B.ByteString -> Int -> Int -> Int -> Int
peekBits d start bits n
  | n == 0 || hi <= 0 = 0
  | lo < 0 = window d start 0 hi `shiftL` negate lo
  | otherwise = window d start lo hi
  where hi = bits
        lo = bits - n
{-# INLINE peekBits #-}

-- ---- FSE ----------------------------------------------------------------

data Fse = Fse { fSym :: !(UArray Int Int), fNb :: !(UArray Int Int), fBase :: !(UArray Int Int), fLog :: !Int }

readFseDescription :: B.ByteString -> Int -> Int -> Int -> Int -> IO ([Int], Int, Int)
readFseDescription d pos limit maxSymbol maxLog = do
  let al = peekF (pos * 8) 4 + 5
  when (al > maxLog) $ zfail "FSE accuracy log too large"
  loop (pos * 8 + 4) al ((1 `shiftL` al) + 1) (1 `shiftL` al) (al + 1) [] 0
  where
    peekF bp n = go 0 0
      where go i !v | i >= n = v
                    | otherwise =
                        let p = bp + i
                            bit = if p `shiftR` 3 < limit
                                    then (fromIntegral (BU.unsafeIndex d (p `shiftR` 3)) `shiftR` (p .&. 7)) .&. 1
                                    else 0
                        in go (i + 1) (v .|. (bit `shiftL` i))
    loop !bp al !rem' !threshold !nbits probs !count
      | rem' <= 1 = do
          when (rem' /= 1 || count > maxSymbol + 1) $ zfail "corrupt FSE description"
          let end = (bp + 7) `shiftR` 3
          when (end > limit) $ zfail "FSE description overruns its section"
          pure (reverse probs, al, end)
      | otherwise = do
          when (count > maxSymbol) $ zfail "FSE description has too many symbols"
          let biggest = 2 * threshold - 1 - rem'
              low = peekF bp (nbits - 1)
              (value, bp1)
                | low < biggest = (low, bp + nbits - 1)
                | otherwise = let v = peekF bp nbits in (if v >= threshold then v - biggest else v, bp + nbits)
              prob = value - 1
              rem2 = rem' - abs prob
              repeats b ps c
                | c > 4096 = zfail "corrupt FSE description"
                | otherwise = let r = peekF b 2; ps' = replicate r 0 ++ ps
                              in if r == 3 then repeats (b + 2) ps' (c + r) else pure (ps', c + r, b + 2)
          (probs', count', bp2) <- if prob == 0 then repeats bp1 (prob : probs) (count + 1)
                                   else pure (prob : probs, count + 1, bp1)
          let shrink t nb | rem2 < t && t > 0 = shrink (t `shiftR` 1) (nb - 1)
                          | otherwise = (t, nb)
              (threshold', nbits') = shrink threshold nbits
          loop bp2 al rem2 threshold' nbits' probs' count'

buildFse :: [Int] -> Int -> IO Fse
buildFse probs al = do
  let size = 1 `shiftL` al
      n = length probs
      indexed = zip [0 ..] probs
      negs = [s | (s, p) <- indexed, p == -1]
      high = size - 1 - length negs
  when (high < -1) $ zfail "corrupt FSE distribution"
  cell <- newArray (0, size - 1) 0 :: IO (IOUArray Int Int)
  counter <- newArray (0, max 0 (n - 1)) 0 :: IO (IOUArray Int Int)
  forM_ (zip [size - 1, size - 2 ..] negs) $ \(c, s) -> unsafeWrite cell c s >> unsafeWrite counter s 1
  forM_ indexed $ \(s, p) -> when (p /= -1) $ unsafeWrite counter s p
  let step = (size `shiftR` 1) + (size `shiftR` 3) + 3
      mask = size - 1
      skipTaken q = if q > high then skipTaken ((q + step) .&. mask) else q
      place _ 0 q = pure q
      place s k q = unsafeWrite cell q s >> place s (k - 1 :: Int) (skipTaken ((q + step) .&. mask))
  final <- foldM (\q (s, p) -> if p > 0 then place s p q else pure q) 0 indexed
  when (final /= 0) $ zfail "corrupt FSE distribution"
  sym <- newArray (0, size - 1) 0 :: IO (IOUArray Int Int)
  nb <- newArray (0, size - 1) 0 :: IO (IOUArray Int Int)
  base <- newArray (0, size - 1) 0 :: IO (IOUArray Int Int)
  forM_ [0 .. size - 1] $ \c -> do
    s <- unsafeRead cell c
    x <- unsafeRead counter s
    unsafeWrite counter s (x + 1)
    when (x <= 0) $ zfail "corrupt FSE distribution"
    let k = al - highbit x
    unsafeWrite sym c s
    unsafeWrite nb c k
    unsafeWrite base c ((x `shiftL` k) - size)
  Fse <$> unsafeFreeze sym <*> unsafeFreeze nb <*> unsafeFreeze base <*> pure al

-- ---- Huffman ------------------------------------------------------------

data Huff = Huff { hSym :: !(UArray Int Word8), hNb :: !(UArray Int Int), hMax :: !Int }

buildHuffman :: [Int] -> IO Huff
buildHuffman ws = do
  when (length ws > 255) $ zfail "too many Huffman weights"
  when (any (> 11) ws) $ zfail "Huffman weight too large"
  let total = sum [1 `shiftL` (w - 1) | w <- ws, w > 0]
  when (total == 0) $ zfail "empty Huffman table"
  let maxBits = highbit total + 1
  when (maxBits > 11) $ zfail "Huffman code too long"
  let rest = (1 `shiftL` maxBits) - total
  when (rest .&. (rest - 1) /= 0) $ zfail "corrupt Huffman weights"
  let weights = ws ++ [highbit rest + 1]
      size = 1 `shiftL` maxBits
      starts = scanl (\acc w -> acc + (length (filter (== w) weights) `shiftL` (w - 1))) 0 [1 .. maxBits]
  next <- newArray (0, maxBits + 1) 0 :: IO (IOUArray Int Int)
  forM_ (zip [1 .. maxBits] starts) $ \(w, st) -> unsafeWrite next w st
  sym <- newArray (0, size - 1) 0 :: IO (IOUArray Int Word8)
  nb <- newArray (0, size - 1) 0 :: IO (IOUArray Int Int)
  forM_ (zip [0 :: Int ..] weights) $ \(s, w) -> when (w > 0) $ do
    st <- unsafeRead next w
    forM_ [st .. st + (1 `shiftL` (w - 1)) - 1] $ \i -> do
      unsafeWrite sym i (fromIntegral s)
      unsafeWrite nb i (maxBits + 1 - w)
    unsafeWrite next w (st + (1 `shiftL` (w - 1)))
  Huff <$> unsafeFreeze sym <*> unsafeFreeze nb <*> pure maxBits

readHuffmanDescription :: B.ByteString -> Int -> Int -> IO (Huff, Int)
readHuffmanDescription d pos0 limit = do
  when (pos0 >= limit) $ zfail "missing Huffman description"
  h <- byte d pos0
  let pos = pos0 + 1
  if h < 128
    then do
      let end = pos + h
      when (end > limit) $ zfail "Huffman description overruns literals"
      (probs, al, p) <- readFseDescription d pos end 255 6
      t <- buildFse probs al
      bits0 <- backward d p end
      let rd bits n = (peekBits d p bits n, bits - n)
          (s1, b1) = rd bits0 al
          (s2, b2) = rd b1 al
          sy s = unsafeAt (fSym t) s
          go !st1 !st2 !bits acc count
            | count > 255 = zfail "too many Huffman weights"
            | otherwise = do
                let (x, bits1) = rd bits (unsafeAt (fNb t) st1)
                    st1' = unsafeAt (fBase t) st1 + x
                if bits1 < 0 then pure (reverse (sy st2 : sy st1 : acc)) else do
                  let (y, bits2) = rd bits1 (unsafeAt (fNb t) st2)
                      st2' = unsafeAt (fBase t) st2 + y
                  if bits2 < 0 then pure (reverse (sy st1' : sy st2 : sy st1 : acc))
                    else go st1' st2' bits2 (sy st2 : sy st1 : acc) (count + 2 :: Int)
      ws <- go s1 s2 b2 [] 0
      hf <- buildHuffman ws
      pure (hf, end)
    else do
      let n = h - 127
          end = pos + (n + 1) `div` 2
      when (end > limit) $ zfail "Huffman description overruns literals"
      ws <- forM [0 .. n - 1] $ \i -> do
        b <- byte d (pos + i `div` 2)
        pure (if even i then b `shiftR` 4 else b .&. 15)
      hf <- buildHuffman ws
      pure (hf, end)

huffmanStream :: B.ByteString -> Int -> Int -> Huff -> Int -> Ptr Word8 -> IO ()
huffmanStream d start end h count out = do
  bits0 <- backward d start end
  let go !k !bits
        | k == count = unless (bits == 0) $ zfail "Huffman stream not fully consumed"
        | otherwise = do
            let i = peekBits d start bits (hMax h)
            pokeByteOff out k (unsafeAt (hSym h) i)
            go (k + 1) (bits - unsafeAt (hNb h) i)
  go 0 bits0

-- ---- literals -----------------------------------------------------------

decodeLiterals :: B.ByteString -> Int -> Int -> Maybe Huff -> IO (B.ByteString, Int, Maybe Huff)
decodeLiterals d pos end huff = do
  when (pos >= end) $ zfail "missing literals section"
  b0 <- byte d pos
  let ltype = b0 .&. 3
      sizeFormat = (b0 `shiftR` 2) .&. 3
  if ltype < 2
    then do
      (size, p) <- case sizeFormat of
        1 -> do { b1 <- byte d (pos + 1); pure ((b0 `shiftR` 4) + (b1 `shiftL` 4), pos + 2) }
        3 -> do { b1 <- byte d (pos + 1); b2 <- byte d (pos + 2)
                ; pure ((b0 `shiftR` 4) + (b1 `shiftL` 4) + (b2 `shiftL` 12), pos + 3) }
        _ -> pure (b0 `shiftR` 3, pos + 1)
      if ltype == 0
        then do
          when (p + size > end) $ zfail "raw literals overrun block"
          pure (B.take size (B.drop p d), p + size, huff)
        else do
          when (p >= end) $ zfail "RLE literals overrun block"
          c <- byte d p
          pure (B.replicate size (fromIntegral c), p + 1, huff)
    else do
      let (streams, headerLen, width) = case sizeFormat of
            0 -> (1, 3, 10)
            1 -> (4, 3, 10)
            2 -> (4, 4, 14)
            _ -> (4 :: Int, 5, 18)
      h <- le d pos headerLen
      let regenerated = (h `shiftR` 4) .&. ((1 `shiftL` width) - 1)
          compressed = (h `shiftR` (4 + width)) .&. ((1 `shiftL` width) - 1)
          p0 = pos + headerLen
          litEnd = p0 + compressed
      when (litEnd > end) $ zfail "compressed literals overrun block"
      when (regenerated > blockMax) $ zfail "literals exceed the block size"
      (table, p1) <- if ltype == 2
        then do { (t, q) <- readHuffmanDescription d p0 litEnd; pure (t, q) }
        else maybe (zfail "treeless literals without a previous Huffman table") (\t -> pure (t, p0)) huff
      lits <- BI.create regenerated $ \out ->
        if streams == 1 then huffmanStream d p1 litEnd table regenerated out
        else do
          s1 <- le d p1 2
          s2 <- le d (p1 + 2) 2
          s3 <- le d (p1 + 4) 2
          let p = p1 + 6
              s4 = litEnd - p - s1 - s2 - s3
              quarter = (regenerated + 3) `div` 4
              c4 = regenerated - 3 * quarter
          when (s4 < 1 || c4 < 0) $ zfail "corrupt 4-stream literals"
          huffmanStream d p (p + s1) table quarter out
          huffmanStream d (p + s1) (p + s1 + s2) table quarter (out `plusPtr` quarter)
          huffmanStream d (p + s1 + s2) (p + s1 + s2 + s3) table quarter (out `plusPtr` (2 * quarter))
          huffmanStream d (p + s1 + s2 + s3) litEnd table c4 (out `plusPtr` (3 * quarter))
      pure (lits, litEnd, Just table)

-- ---- sequences ------------------------------------------------------------

data Kind = LL | OF | ML

llBase, llBits, mlBase, mlBits :: UArray Int Int
llBase = listArray (0, 35) [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
llBits = listArray (0, 35) [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
mlBase = listArray (0, 52) [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539]
mlBits = listArray (0, 52) [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

-- default distribution, default accuracy log, max symbol, max accuracy log
seqKind :: Kind -> ([Int], Int, Int, Int)
seqKind LL = ([4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1], 6, 35, 9)
seqKind OF = ([1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1], 5, 31, 8)
seqKind ML = ([1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1], 6, 52, 9)

sequenceTable :: B.ByteString -> Int -> Int -> Int -> Kind -> Maybe Fse -> IO (Fse, Int)
sequenceTable d pos end mode kind prev = do
  let (dflt, dlog, maxSymbol, maxLog) = seqKind kind
  case mode of
    0 -> do { t <- buildFse dflt dlog; pure (t, pos) }
    1 -> do
      when (pos >= end) $ zfail "bad RLE sequence symbol"
      s <- byte d pos
      when (s > maxSymbol) $ zfail "bad RLE sequence symbol"
      let one v = listArray (0, 0) [v]
      pure (Fse (one s) (one 0) (one 0) 0, pos + 1)
    2 -> do
      (probs, al, p) <- readFseDescription d pos end maxSymbol maxLog
      t <- buildFse probs al
      pure (t, p)
    _ -> maybe (zfail "repeat mode without a previous table") (\t -> pure (t, pos)) prev

data Frame = Frame
  { frHuff :: !(Maybe Huff), frLL :: !(Maybe Fse), frOF :: !(Maybe Fse), frML :: !(Maybe Fse)
  , frR0 :: !Int, frR1 :: !Int, frR2 :: !Int }

-- | Decode the sequences of one compressed block and execute them straight
--   into the output buffer (whose capacity already covers @limit@).
sequences :: B.ByteString -> Int -> Int -> B.ByteString -> Out -> Int -> Int -> Frame -> IO Frame
sequences d pos end lits o frameStart limit fr = do
  b0 <- byte d pos
  if b0 == 0
    then do
      when (pos + 1 /= end) $ zfail "data after empty sequences section"
      len <- readIORef (oLen o)
      appendLiterals len 0 (B.length lits)
      pure fr
    else do
      (count, p1) <-
        if b0 < 128 then pure (b0, pos + 1)
        else if b0 < 255 then do { b1 <- byte d (pos + 1); pure (((b0 - 128) `shiftL` 8) + b1, pos + 2) }
        else do { v <- le d (pos + 1) 2; pure (v + 0x7F00, pos + 3) }
      when (p1 >= end) $ zfail "missing compression modes"
      modes <- byte d p1
      when (modes .&. 3 /= 0) $ zfail "reserved compression-mode bits set"
      (llt, p2) <- sequenceTable d (p1 + 1) end ((modes `shiftR` 6) .&. 3) LL (frLL fr)
      (oft, p3) <- sequenceTable d p2 end ((modes `shiftR` 4) .&. 3) OF (frOF fr)
      (mlt, p4) <- sequenceTable d p3 end ((modes `shiftR` 2) .&. 3) ML (frML fr)
      bits0 <- backward d p4 end
      len0 <- readIORef (oLen o)
      fp <- readIORef (oBuf o)
      let rd bits n = (peekBits d p4 bits n, bits - n)
          (ll0, b1) = rd bits0 (fLog llt)
          (of0, b2) = rd b1 (fLog oft)
          (ml0, b3) = rd b2 (fLog mlt)
          nlit = B.length lits
      (r0', r1', r2') <- withForeignPtr fp $ \out -> BU.unsafeUseAsCString lits $ \litp -> do
        let go !i !llS !ofS !mlS !bits !r0 !r1 !r2 !lit !olen
              | i == count = do
                  unless (bits == 0) $ zfail "sequence bitstream not fully consumed"
                  let rest = nlit - lit
                  when (olen + rest > limit) $ zfail "block output too large"
                  copyBytes (out `plusPtr` olen) (litp `plusPtr` lit) rest
                  writeIORef (oLen o) (olen + rest)
                  pure (r0, r1, r2)
              | otherwise = do
                  let ofCode = unsafeAt (fSym oft) ofS
                      mlCode = unsafeAt (fSym mlt) mlS
                      llCode = unsafeAt (fSym llt) llS
                  when (ofCode > 31 || mlCode > 52 || llCode > 35) $ zfail "bad sequence code"
                  let (ofX, c1) = rd bits ofCode
                      offsetValue = (1 `shiftL` ofCode) + ofX
                      (mlX, c2) = rd c1 (unsafeAt mlBits mlCode)
                      ml = unsafeAt mlBase mlCode + mlX
                      (llX, c3) = rd c2 (unsafeAt llBits llCode)
                      ll = unsafeAt llBase llCode + llX
                      (llS', mlS', ofS', c6)
                        | i == count - 1 = (llS, mlS, ofS, c3)
                        | otherwise =
                            let (a, c4) = rd c3 (unsafeAt (fNb llt) llS)
                                (m, c5) = rd c4 (unsafeAt (fNb mlt) mlS)
                                (f, c7) = rd c5 (unsafeAt (fNb oft) ofS)
                            in (unsafeAt (fBase llt) llS + a, unsafeAt (fBase mlt) mlS + m, unsafeAt (fBase oft) ofS + f, c7)
                  when (lit + ll > nlit) $ zfail "sequence consumes more literals than available"
                  when (olen + ll + ml > limit) $ zfail "block output too large"
                  copyBytes (out `plusPtr` olen) (litp `plusPtr` lit) ll
                  let olen1 = olen + ll
                      (offset, n0, n1, n2)
                        | offsetValue > 3 = let v = offsetValue - 3 in (v, v, r0, r1)
                        | otherwise = case offsetValue - 1 + (if ll == 0 then 1 else 0) of
                            0 -> (r0, r0, r1, r2)
                            1 -> (r1, r1, r0, r2)
                            2 -> (r2, r2, r0, r1)
                            _ -> let v = r0 - 1 in (v, v, r0, r1)
                  when (offset <= 0 || offset > olen1 - frameStart) $ zfail "match offset out of range"
                  if offset >= ml
                    then copyBytes (out `plusPtr` olen1) (out `plusPtr` (olen1 - offset)) ml
                    else forM_ [0 .. ml - 1] $ \k ->
                      peekByteOff out (olen1 - offset + k) >>= (pokeByteOff out (olen1 + k) :: Word8 -> IO ())
                  go (i + 1) llS' ofS' mlS' c6 n0 n1 n2 (lit + ll) (olen1 + ml)
        go (0 :: Int) ll0 of0 ml0 b3 (frR0 fr) (frR1 fr) (frR2 fr) 0 len0
      pure fr { frLL = Just llt, frOF = Just oft, frML = Just mlt, frR0 = r0', frR1 = r1', frR2 = r2' }
  where
    appendLiterals len from n = do
      when (len + n > limit) $ zfail "block output too large"
      fp <- readIORef (oBuf o)
      withForeignPtr fp $ \out -> BU.unsafeUseAsCString lits $ \litp ->
        copyBytes (out `plusPtr` len) (litp `plusPtr` from) n
      writeIORef (oLen o) (len + n)

-- ---- XXH64 ----------------------------------------------------------------

xxh64 :: B.ByteString -> Word64
xxh64 s = finish (tailLanes h1 i1)
  where
    n = B.length s
    p1, p2, p3, p4, p5 :: Word64
    p1 = 0x9E3779B185EBCA87
    p2 = 0xC2B2AE3D27D4EB4F
    p3 = 0x165667B19E3779F9
    p4 = 0x85EBCA77C2B2AE63
    p5 = 0x27D4EB2F165667C5
    w64 i = foldr (\k acc -> (acc `shiftL` 8) .|. fromIntegral (BU.unsafeIndex s (i + k))) 0 [0 .. 7]
    w32 i = foldr (\k acc -> (acc `shiftL` 8) .|. fromIntegral (BU.unsafeIndex s (i + k))) 0 [0 .. 3]
    rnd acc lane = rotateL (acc + lane * p2) 31 * p1
    (h0, i1)
      | n >= 32 =
          let stripes !v1 !v2 !v3 !v4 !i
                | i + 32 <= n = stripes (rnd v1 (w64 i)) (rnd v2 (w64 (i + 8))) (rnd v3 (w64 (i + 16))) (rnd v4 (w64 (i + 24))) (i + 32)
                | otherwise = (v1, v2, v3, v4, i)
              (a, b, c, e, j) = stripes (p1 + p2) p2 0 (negate p1) 0
              h = rotateL a 1 + rotateL b 7 + rotateL c 12 + rotateL e 18
              merge acc v = (acc `xor` rnd 0 v) * p1 + p4
          in (foldl merge h [a, b, c, e], j)
      | otherwise = (p5, 0)
    h1 = h0 + fromIntegral n
    tailLanes !h !i
      | i + 8 <= n = tailLanes (rotateL (h `xor` rnd 0 (w64 i)) 27 * p1 + p4) (i + 8)
      | i + 4 <= n = tailBytes (rotateL (h `xor` (w32 i * p1)) 23 * p2 + p3) (i + 4)
      | otherwise = tailBytes h i
    tailBytes !h !i
      | i < n = tailBytes (rotateL (h `xor` (fromIntegral (BU.unsafeIndex s i) * p5)) 11 * p1) (i + 1)
      | otherwise = h
    finish h = let a = (h `xor` (h `shiftR` 33)) * p2
                   b = (a `xor` (a `shiftR` 29)) * p3
               in b `xor` (b `shiftR` 32)

-- ---- frames -------------------------------------------------------------

decodeFrame :: B.ByteString -> Int -> Out -> IO Int
decodeFrame d pos0 o = do
  fhd <- byte d pos0
  let fcsFlag = fhd `shiftR` 6
      single = (fhd `shiftR` 5) .&. 1 == 1
      hasChecksum = (fhd `shiftR` 2) .&. 1 == 1
      didFlag = fhd .&. 3
  when (fhd .&. 0x08 /= 0) $ zfail "reserved frame header bit set"
  p1 <- if single then pure (pos0 + 1) else byte d (pos0 + 1) >> pure (pos0 + 2)
  let didSize = [0, 1, 2, 4] !! didFlag
  when (didSize > 0) $ do
    did <- le d p1 didSize
    when (did /= 0) $ zfail "zstd dictionaries are not supported"
  let p2 = p1 + didSize
      fcsSize = [if single then 1 else 0, 2, 4, 8] !! fcsFlag
  (contentSize, p3) <- case fcsSize of
    0 -> pure (Nothing, p2)
    8 -> do
      when (p2 + 8 > B.length d) $ zfail "truncated input"
      let v = B.foldr' (\b acc -> (acc `shiftL` 8) .|. fromIntegral b) (0 :: Word64) (B.take 8 (B.drop p2 d))
      when (v > fromIntegral maxOutput) $ zfail "frame content size too large"
      pure (Just (fromIntegral v), p2 + 8)
    k -> do { v <- le d p2 k; pure (Just (v + if k == 2 then 256 else 0), p2 + k) }
  frameStart <- readIORef (oLen o)
  let blocks pos fr = do
        header <- le d pos 3
        let lastBlock = header .&. 1 == 1
            blockType = (header `shiftR` 1) .&. 3
            blockSize = header `shiftR` 3
            start = pos + 3
        when (blockSize > blockMax) $ zfail "block too large"
        len <- readIORef (oLen o)
        let limit = min (len + blockMax) maxOutput
        ensure o limit
        (next, fr') <- case blockType of
          0 -> do
            when (start + blockSize > B.length d) $ zfail "truncated raw block"
            when (len + blockSize > limit) $ zfail "decompressed size limit exceeded"
            fp <- readIORef (oBuf o)
            withForeignPtr fp $ \out -> BU.unsafeUseAsCString (B.drop start d) $ \src ->
              copyBytes (out `plusPtr` len) (castPtr src) blockSize
            writeIORef (oLen o) (len + blockSize)
            pure (start + blockSize, fr)
          1 -> do
            c <- byte d start
            when (len + blockSize > limit) $ zfail "decompressed size limit exceeded"
            fp <- readIORef (oBuf o)
            withForeignPtr fp $ \out -> fillBytes (out `plusPtr` len) (fromIntegral c) blockSize
            writeIORef (oLen o) (len + blockSize)
            pure (start + 1, fr)
          2 -> do
            let end = start + blockSize
            when (end > B.length d) $ zfail "truncated compressed block"
            (lits, p, huff) <- decodeLiterals d start end (frHuff fr)
            fr' <- sequences d p end lits o frameStart limit fr { frHuff = huff }
            pure (end, fr')
          _ -> zfail "reserved block type"
        if lastBlock then pure next else blocks next fr'
  pos <- blocks p3 (Frame Nothing Nothing Nothing Nothing 1 4 8)
  len <- readIORef (oLen o)
  case contentSize of
    Just n | len - frameStart /= n -> zfail "frame content size mismatch"
    _ -> pure ()
  if hasChecksum
    then do
      expected <- le d pos 4
      fp <- readIORef (oBuf o)
      let produced = BI.fromForeignPtr fp frameStart (len - frameStart)
      when (fromIntegral (xxh64 produced .&. 0xFFFFFFFF) /= expected) $ zfail "content checksum mismatch"
      pure (pos + 4)
    else pure pos

run :: B.ByteString -> IO B.ByteString
run d = do
  let initial = min (16 * 1024 * 1024) (max 4096 (3 * B.length d))
  fp <- mallocForeignPtrBytes initial
  o <- Out <$> newIORef fp <*> newIORef initial <*> newIORef 0
  let loop pos
        | pos >= B.length d = pure ()
        | otherwise = do
            magic <- le d pos 4
            if magic .&. 0xFFFFFFF0 == 0x184D2A50
              then do
                size <- le d (pos + 4) 4
                when (pos + 8 + size > B.length d) $ zfail "truncated skippable frame"
                loop (pos + 8 + size)
              else if magic == 0xFD2FB528
                then decodeFrame d (pos + 4) o >>= loop
                else zfail "unknown frame magic"
  loop 0
  len <- readIORef (oLen o)
  final <- readIORef (oBuf o)
  pure (B.copy (BI.fromForeignPtr final 0 len))

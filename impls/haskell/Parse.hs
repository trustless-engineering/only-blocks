{-# LANGUAGE BangPatterns #-}
-- | A tiny, strict, pure parser-combinator monad over a strict 'ByteString'.
--   Every OnlyBlocks wire format (CARv1, DAG-CBOR, protobuf, bincode,
--   Solana transactions, even JSON-RPC bodies) is a 'P' value.
module Parse
  ( P, runP, runPrefix, failP, orElse, attempt
  , position, remaining, atEnd, peekByte, peekMaybe, slice, takeWhileP
  , u8, u16be, u32be, u64be, u16le, u32le, u64le, f64le, takeBytes, skipBytes
  , uvarint, compactU16, countOf, sub, word64ToInt
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as BU
import Data.Bits
import Data.Word
import GHC.Float (castWord64ToDouble)

data R a = Ok a {-# UNPACK #-} !Int | Err String

-- | A parser sees the whole input and its current offset.
newtype P a = P { unP :: B.ByteString -> Int -> R a }

instance Functor P where
  fmap f (P g) = P $ \s i -> case g s i of
    Ok a j -> Ok (f a) j
    Err e -> Err e

instance Applicative P where
  pure a = P $ \_ i -> Ok a i
  P pf <*> P pa = P $ \s i -> case pf s i of
    Err e -> Err e
    Ok f j -> case pa s j of
      Err e -> Err e
      Ok a k -> Ok (f a) k

instance Monad P where
  P g >>= k = P $ \s i -> case g s i of
    Ok a j -> unP (k a) s j
    Err e -> Err e

instance MonadFail P where
  fail = failP

failP :: String -> P a
failP m = P $ \_ _ -> Err m

-- | Run a parser that must consume the whole input.
runP :: P a -> B.ByteString -> Either String a
runP p s = case unP p s 0 of
  Ok a j | j == B.length s -> Right a
         | otherwise -> Left "trailing bytes"
  Err e -> Left e

-- | Run a parser, returning the value and the number of bytes consumed.
runPrefix :: P a -> B.ByteString -> Either String (a, Int)
runPrefix p s = case unP p s 0 of
  Ok a j -> Right (a, j)
  Err e -> Left e

-- | Backtracking choice: try the first parser, else rewind and run the second.
orElse :: P a -> P a -> P a
orElse (P a) (P b) = P $ \s i -> case a s i of
  Err _ -> b s i
  ok -> ok

-- | Run a parser for its outcome without failing the enclosing parse.
attempt :: P a -> P (Either String a)
attempt (P a) = P $ \s i -> case a s i of
  Ok v j -> Ok (Right v) j
  Err e -> Ok (Left e) i

position :: P Int
position = P $ \_ i -> Ok i i

remaining :: P Int
remaining = P $ \s i -> Ok (B.length s - i) i

atEnd :: P Bool
atEnd = (== 0) <$> remaining

peekByte :: P Word8
peekByte = P $ \s i -> if i < B.length s then Ok (BU.unsafeIndex s i) i else Err "truncated input"

peekMaybe :: P (Maybe Word8)
peekMaybe = P $ \s i -> Ok (if i < B.length s then Just (BU.unsafeIndex s i) else Nothing) i

-- | The longest run of bytes satisfying the predicate.
takeWhileP :: (Word8 -> Bool) -> P B.ByteString
takeWhileP f = P $ \s i -> let run = B.takeWhile f (BU.unsafeDrop i s) in Ok run (i + B.length run)

-- | The input bytes between two absolute offsets.
slice :: Int -> Int -> P B.ByteString
slice a b = P $ \s i -> Ok (B.take (b - a) (B.drop a s)) i

takeBytes :: Int -> P B.ByteString
takeBytes n = P $ \s i ->
  if n < 0 || n > B.length s - i then Err "truncated binary value"
  else Ok (BU.unsafeTake n (BU.unsafeDrop i s)) (i + n)

skipBytes :: Int -> P ()
skipBytes n = P $ \s i ->
  if n < 0 || n > B.length s - i then Err "truncated binary value" else Ok () (i + n)

u8 :: P Word8
u8 = P $ \s i -> if i < B.length s then Ok (BU.unsafeIndex s i) (i + 1) else Err "truncated binary value"

fixed :: Int -> (B.ByteString -> Word64) -> P Word64
fixed n f = f <$> takeBytes n

beN, leN :: B.ByteString -> Word64
beN = B.foldl' (\acc b -> (acc `shiftL` 8) .|. fromIntegral b) 0
leN = B.foldr' (\b acc -> (acc `shiftL` 8) .|. fromIntegral b) 0

u16be, u32be, u64be, u16le, u32le, u64le :: P Word64
u16be = fixed 2 beN
u32be = fixed 4 beN
u64be = fixed 8 beN
u16le = fixed 2 leN
u32le = fixed 4 leN
u64le = fixed 8 leN

f64le :: P Double
f64le = castWord64ToDouble <$> u64le

-- | Unsigned LEB128: at most 10 bytes, the 10th at most 1.
uvarint :: P Word64
uvarint = go 0 0 0
  where
    go :: Int -> Int -> Word64 -> P Word64
    go !i !sh !acc = do
      b <- u8
      if b < 0x80
        then if i == 9 && b > 1 then failP "varint overflow" else pure (acc .|. (fromIntegral b `shiftL` sh))
        else if i == 9 then failP "varint overflow"
        else go (i + 1) (sh + 7) (acc .|. (fromIntegral (b .&. 0x7f) `shiftL` sh))

-- | Solana's strictly canonical compact-u16 (short_vec length).
compactU16 :: P Int
compactU16 = do
  b0 <- fromIntegral <$> u8
  if b0 < 0x80 then pure b0 else do
    b1 <- fromIntegral <$> u8
    if b1 == 0 then failP "noncanonical compact-u16" else if b1 < 0x80
      then pure ((b0 .&. 0x7f) .|. (b1 `shiftL` 7)) else do
        b2 <- fromIntegral <$> u8
        if b2 == 0 then failP "noncanonical compact-u16"
        else if b2 > 3 then failP "compact-u16 overflow"
        else pure ((b0 .&. 0x7f) .|. ((b1 .&. 0x7f) `shiftL` 7) .|. (b2 `shiftL` 14))

-- | @countOf n minimum p@: n items of at least @minimum@ bytes each.  The
--   count is checked against the remaining input before anything is built.
countOf :: Word64 -> Int -> P a -> P [a]
countOf n minimum p = do
  left <- remaining
  if n > fromIntegral (left `div` minimum) then failP "count exceeds enclosing field" else go (fromIntegral n)
  where
    go 0 = pure []
    go k = do { x <- p; xs <- go (k - 1); pure (x : xs) }

-- | Run a parser over a length-prefixed region; it must consume exactly that region.
sub :: Int -> P a -> P a
sub n p = do
  bytes <- takeBytes n
  either failP pure (runP p bytes)

word64ToInt :: Word64 -> P Int
word64ToInt w
  | w > fromIntegral (maxBound :: Int) = failP "length too large"
  | otherwise = pure (fromIntegral w)

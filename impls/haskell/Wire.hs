{-# LANGUAGE BangPatterns, OverloadedStrings #-}
-- | CARv1 sections, DAG-CBOR, CIDs, DataFrame reassembly (CRC-64/GO-ISO and
--   FNV-1a), Base58/Base64 and the Solana VersionedTransaction wire format.
module Wire
  ( Cbor (..), cbor, at, asU64, asI64
  , Car (..), indexCar, node, member, link, links
  , framePayload, crc64, fnv1a
  , base58, base64, zeroHash, pubkey
  , Instruction (..), Lookup (..), Tx (..), transaction, compiled
  ) where

import Control.Monad
import Control.Monad.ST (ST, runST)
import Data.Array.Base (unsafeRead, unsafeWrite)
import Data.Array.ST (STUArray, newArray)
import Data.Array.Unboxed (UArray, listArray, (!))
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Int
import qualified Data.Map.Strict as M
import qualified Data.Set as S
import Data.Word
import Foreign.Storable (pokeByteOff)
import GHC.Float (castWord32ToFloat, castWord64ToDouble, float2Double)
import Parse

-- ---- DAG-CBOR ---------------------------------------------------------------

data Cbor
  = CU !Word64            -- ^ unsigned integer
  | CN !Word64            -- ^ negative integer @-1 - n@
  | CB !B.ByteString      -- ^ byte string
  | CT !B.ByteString      -- ^ UTF-8 text
  | CA [Cbor]
  | CM [(Cbor, Cbor)]
  | CBool !Bool
  | CNull
  | CF !Double
  deriving (Eq, Show)

halfToDouble :: Word64 -> Double
halfToDouble h
  | e == 0 = sign * encodeFloat (fromIntegral m) (-24)
  | e == 31 = if m == 0 then sign / 0 else 0 / 0
  | otherwise = sign * encodeFloat (fromIntegral (m + 1024)) (fromIntegral e - 25)
  where sign = if testBit h 15 then -1 else 1
        e = (h `shiftR` 10) .&. 0x1f
        m = h .&. 0x3ff

argument :: Int -> P (Maybe Word64)
argument info
  | info < 24 = pure (Just (fromIntegral info))
  | info == 24 = Just . fromIntegral <$> u8
  | info == 25 = Just <$> u16be
  | info == 26 = Just <$> u32be
  | info == 27 = Just <$> u64be
  | info == 31 = pure Nothing
  | otherwise = failP "reserved CBOR argument"

item :: Int -> P Cbor
item depth = do
  when (depth > 128) $ failP "CBOR nesting limit"
  hd <- u8
  let major = hd `shiftR` 5
      info = fromIntegral (hd .&. 31)
  if major == 7
    then case info of
      20 -> pure (CBool False)
      21 -> pure (CBool True)
      22 -> pure CNull
      23 -> pure CNull
      25 -> CF . halfToDouble <$> u16be
      26 -> CF . float2Double . castWord32ToFloat . fromIntegral <$> u32be
      27 -> CF . castWord64ToDouble <$> u64be
      _ -> failP "unsupported CBOR simple value"
    else do
      arg <- argument info
      let definite = maybe (failP "invalid indefinite CBOR item") pure arg
          more = (/= 0xff) <$> peekByte
          breakByte = void u8
      case major of
        0 -> CU <$> definite
        1 -> CN <$> definite
        6 -> definite >> item (depth + 1)
        _ | major == 2 || major == 3 -> do
              bytes <- case arg of
                Just n -> word64ToInt n >>= takeBytes
                Nothing -> B.concat <$> chunks major
              if major == 2 then pure (CB bytes)
                else if B.isValidUtf8 bytes then pure (CT bytes)
                else failP "invalid UTF-8 in CBOR text"
        4 -> case arg of
          Just n -> CA <$> countOf n 1 (item (depth + 1))
          Nothing -> CA <$> untilBreak more breakByte (item (depth + 1))
        _ -> case arg of
          Just n -> CM <$> countOf n 2 ((,) <$> item (depth + 1) <*> item (depth + 1))
          Nothing -> CM <$> untilBreak more breakByte ((,) <$> item (depth + 1) <*> item (depth + 1))
  where
    chunks major = do
      b <- peekByte
      if b == 0xff then u8 >> pure [] else do
        h <- u8
        when (h `shiftR` 5 /= major || h .&. 31 == 31) $ failP "invalid CBOR string chunk"
        n <- argument (fromIntegral (h .&. 31)) >>= maybe (failP "invalid CBOR string chunk") pure
        c <- word64ToInt n >>= takeBytes
        (c :) <$> chunks major
    untilBreak more breakByte p = do
      m <- more
      if m then (:) <$> p <*> untilBreak more breakByte p else breakByte >> pure []

-- | Exactly one CBOR item, nothing after it.
cbor :: B.ByteString -> Either String Cbor
cbor = runP (item 0)

at :: [Cbor] -> Int -> Maybe Cbor
at xs i = case drop i xs of
  (x : _) | i >= 0 -> Just x
  _ -> Nothing

asU64 :: Maybe Cbor -> Maybe Word64
asU64 (Just (CU n)) = Just n
asU64 _ = Nothing

asI64 :: Maybe Cbor -> Maybe Int64
asI64 (Just (CU n)) | n <= fromIntegral (maxBound :: Int64) = Just (fromIntegral n)
asI64 (Just (CN n)) | n <= fromIntegral (maxBound :: Int64) = Just (-1 - fromIntegral n)
asI64 _ = Nothing

-- ---- CIDs and links -----------------------------------------------------------

-- | A CID at the cursor: its raw bytes and whether it is the empty identity CID.
cid :: P (B.ByteString, Bool)
cid = do
  start <- position
  a <- uvarint
  b <- uvarint
  absent <-
    if a == 0x12 && b == 0x20 then skipBytes 32 >> pure False
    else do
      when (a /= 1) $ failP "unsupported CID version"
      code <- uvarint
      len <- uvarint
      when (len > 64) $ failP "CID digest too long"
      skipBytes (fromIntegral len)
      pure (code == 0 && len == 0)
  end <- position
  bytes <- slice start end
  pure (bytes, absent)

link :: Cbor -> Either String (B.ByteString, Bool)
link (CB s) | not (B.null s) && B.head s == 0 = fst <$> runPrefix cid (B.drop 1 s)
link _ = Left "invalid CID link"

links :: Maybe Cbor -> Either String [B.ByteString]
links (Just (CA xs)) = mapM (fmap fst . link) xs
links _ = Right []

-- ---- CARv1 section index ------------------------------------------------------

data Car = Car { carIndex :: !(M.Map B.ByteString B.ByteString), carBlock :: [Cbor] }

kind :: Int -> Cbor -> Either String [Cbor]
kind n (CA xs@(CU k : _)) | k == fromIntegral n = Right xs
kind n _ = Left ("expected IPLD node kind " ++ show n)

member :: Car -> B.ByteString -> Bool
member car k = M.member k (carIndex car)

node :: Car -> B.ByteString -> Int -> Either String [Cbor]
node car k n = maybe (Left "CID missing from CAR slice") (\bytes -> cbor bytes >>= kind n) (M.lookup k (carIndex car))

isVersionHeader :: B.ByteString -> Bool
isVersionHeader s = case cbor s of
  Right (CM kvs) -> any ((== CT "version") . fst) kvs
  _ -> False

-- | Is this node a Block (an array whose first element is the small uint 2)?
looksLikeBlock :: B.ByteString -> Bool
looksLikeBlock n
  | B.null n = False
  | otherwise =
      let b = B.head n
          info = fromIntegral (b .&. 31) :: Int
          hd = if info < 24 || info == 31 then 1 else 1 + (1 `shiftL` (info - 24))
      in b `shiftR` 5 == 4 && (info < 28 || info == 31) && hd < B.length n && B.index n hd == 2

indexCar :: B.ByteString -> Either String Car
indexCar slice0 = go slice0 True M.empty Nothing
  where
    go s first !idx block
      | B.null s = case block of
          Nothing -> Left "no Block node in CAR slice"
          Just b -> Car idx <$> (cbor b >>= kind 2)
      | otherwise = do
          (size, used) <- runPrefix uvarint s
          let rest = B.drop used s
          if size == 0 then go rest first idx block else do
            when (size > 33554432) $ Left "oversize CAR section"
            let n = fromIntegral size
            when (n > B.length rest) $ Left "truncated CAR section"
            let section = B.take n rest
                after = B.drop n rest
            if first && B.head section `shiftR` 5 == 5 && isVersionHeader section
              then go after False idx block
              else do
                ((key, _), klen) <- runPrefix cid section
                let nodeBytes = B.drop klen section
                go after False (M.insert key nodeBytes idx)
                   (if looksLikeBlock nodeBytes then Just nodeBytes else block)

-- ---- DataFrames -----------------------------------------------------------------

crcTable :: UArray Int Word64
crcTable = listArray (0, 255) [entry (fromIntegral i) | i <- [0 .. 255 :: Int]]
  where entry v = iterate step v !! 8
        step v = if v .&. 1 == 1 then (v `shiftR` 1) `xor` 0xD800000000000000 else v `shiftR` 1

crc64 :: B.ByteString -> Word64
crc64 = complement . B.foldl' f maxBound
  where f c b = (c `shiftR` 8) `xor` (crcTable ! fromIntegral ((c .&. 0xff) `xor` fromIntegral b))

fnv1a :: B.ByteString -> Word64
fnv1a = B.foldl' (\h b -> (h `xor` fromIntegral b) * 0x100000001B3) 0xCBF29CE484222325

frameData :: [Cbor] -> B.ByteString
frameData f = case at f 4 of
  Just (CB s) -> s
  _ -> B.empty

-- | Iterative DFS over the DataFrame chain; only the first frame's hash is checked.
framePayload :: Car -> Cbor -> Either String B.ByteString
framePayload car root0 = do
  root <- kind 6 root0
  start <- links (at root 5)
  parts <- walk start S.empty [frameData root] (B.length (frameData root))
  let payload = B.concat (reverse parts)
  case asU64 (at root 1) of
    Just h | crc64 payload /= h && fnv1a payload /= h -> Left "DataFrame hash mismatch"
    _ -> Right payload
  where
    walk [] _ acc _ = Right acc
    walk (k : stack) seen acc !size
      | S.member k seen = Left "repeated DataFrame CID"
      | otherwise = do
          f <- node car k 6
          next <- links (at f 5)
          let chunk = frameData f
              size' = size + B.length chunk
          when (size' > 128 * 1024 * 1024) $ Left "oversize reassembled DataFrame"
          walk (next ++ stack) (S.insert k seen) (chunk : acc) size'

-- ---- Base58 / Base64 ------------------------------------------------------------

base58 :: B.ByteString -> B.ByteString
base58 s = runST $ do
  let n = B.length s
      zeros = B.length (B.takeWhile (== 0) s)
  digits <- newArray (0, n * 138 `div` 100 + 1) 0 :: ST st (STUArray st Int Int)
  -- little-endian base-58 digits, multiplied up one input byte at a time
  let outer i len
        | i >= n = pure len
        | otherwise = do
            let inner j carry
                  | j >= len = pure carry
                  | otherwise = do
                      d <- unsafeRead digits j
                      let v = d * 256 + carry
                      unsafeWrite digits j (v `rem` 58)
                      inner (j + 1) (v `quot` 58)
                spill l c
                  | c == 0 = pure l
                  | otherwise = unsafeWrite digits l (c `rem` 58) >> spill (l + 1) (c `quot` 58)
            carry <- inner 0 (fromIntegral (BU.unsafeIndex s i))
            spill len carry >>= outer (i + 1)
  len <- outer zeros 0
  ds <- mapM (unsafeRead digits) [len - 1, len - 2 .. 0]
  pure (BC.replicate zeros '1' <> B.pack (map (BU.unsafeIndex alphabet) ds))
  where alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" :: B.ByteString

base64 :: B.ByteString -> B.ByteString
base64 s = BI.unsafeCreate outLen $ \p -> mapM_ (emit p) [0 .. groups - 1]
  where
    n = B.length s
    groups = (n + 2) `div` 3
    outLen = groups * 4
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" :: B.ByteString
    byteAt i = if i < n then fromIntegral (BU.unsafeIndex s i) else 0 :: Int
    emit p g = do
      let i = 3 * g
          v = (byteAt i `shiftL` 16) .|. (byteAt (i + 1) `shiftL` 8) .|. byteAt (i + 2)
          ch k = BU.unsafeIndex table ((v `shiftR` (18 - 6 * k)) .&. 63)
          avail = n - i
      pokeByteOff p (4 * g) (ch 0)
      pokeByteOff p (4 * g + 1) (ch 1)
      pokeByteOff p (4 * g + 2) (if avail > 1 then ch 2 else 61 :: Word8)
      pokeByteOff p (4 * g + 3) (if avail > 2 then ch 3 else 61 :: Word8)

zeroHash :: B.ByteString
zeroHash = BC.replicate 32 '1'

pubkey :: B.ByteString -> Either String B.ByteString
pubkey s | B.length s == 32 = Right (base58 s)
         | otherwise = Left "expected a 32-byte hash or public key"

-- ---- Solana VersionedTransaction ------------------------------------------------

data Instruction = Instruction
  { ixProgram :: !Int, ixAccounts :: !B.ByteString, ixData :: !B.ByteString, ixHeight :: !(Maybe Int) }

data Lookup = Lookup { lkTable :: !B.ByteString, lkWritable :: !B.ByteString, lkReadonly :: !B.ByteString }

data Tx = Tx
  { txV0 :: !Bool
  , txSignatures :: [B.ByteString]
  , txNrs, txNros, txNrou :: !Int
  , txKeys :: [B.ByteString]              -- ^ Base58 static account keys
  , txRecent :: !B.ByteString             -- ^ Base58 recent blockhash
  , txInstructions :: [Instruction]
  , txLookups :: [Lookup]
  , txRaw :: !B.ByteString                -- ^ the consumed wire prefix
  }

compiled :: Maybe Int -> P Instruction
compiled height = do
  program <- fromIntegral <$> u8
  accounts <- compactU16 >>= takeBytes
  dat <- compactU16 >>= takeBytes
  pure (Instruction program accounts dat height)

-- | Trailing bytes are ignored (bincode's default), so this runs as a prefix parser.
transaction :: B.ByteString -> Either String Tx
transaction bytes = do
  (tx, used) <- runPrefix parser bytes
  pure tx { txRaw = B.take used bytes }
  where
    vec minimum p = compactU16 >>= \n -> countOf (fromIntegral n) minimum p
    parser = do
      sigs <- vec 64 (takeBytes 64)
      prefix <- u8
      (v0, nrs) <-
        if prefix .&. 0x80 == 0 then pure (False, fromIntegral prefix)
        else case prefix .&. 0x7f of
          0 -> (,) True . fromIntegral <$> u8
          127 -> failP "off-chain messages are not accepted"
          _ -> failP "unsupported transaction version"
      nros <- fromIntegral <$> u8
      nrou <- fromIntegral <$> u8
      keys <- vec 32 (base58 <$> takeBytes 32)
      recent <- base58 <$> takeBytes 32
      ixs <- vec 3 (compiled (Just 1))
      lookups <- if v0
        then vec 34 (Lookup <$> takeBytes 32 <*> (compactU16 >>= takeBytes) <*> (compactU16 >>= takeBytes))
        else pure []
      pure (Tx v0 sigs nrs nros nrou keys recent ixs lookups B.empty)

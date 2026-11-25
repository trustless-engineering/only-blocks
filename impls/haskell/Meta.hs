{-# LANGUAGE OverloadedStrings #-}
-- | Transaction metadata and block rewards: protobuf (modern slots), bincode
--   (pre-epoch-157), TransactionError, and the zstd / epoch-157 fallbacks.
module Meta
  ( Reward (..), TokenBalance (..), TxErr (..), Meta (..), emptyMeta
  , metadata, rewards, unsignedText
  ) where

import Control.Monad
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Int
import Data.Maybe (fromMaybe)
import Data.Word
import GHC.Float (castWord64ToDouble)
import Parse
import Wire
import qualified Zstd

-- ---- internal model (WIRE_FORMATS.md section 12) ------------------------------

data Reward = Reward
  { rwPubkey :: !B.ByteString, rwLamports :: !Int64, rwPost :: !Word64
  , rwType :: !(Maybe B.ByteString), rwCommission :: !(Maybe Int) }

data TokenBalance = TokenBalance
  { tbIndex :: !Int, tbMint :: !B.ByteString, tbOwner :: !B.ByteString, tbProgram :: !B.ByteString
  , tbUi :: !(Maybe Double), tbDecimals :: !Int, tbAmount :: !B.ByteString, tbUiString :: !B.ByteString }

-- | A TransactionError, shaped like its JSON.
data TxErr = EStr B.ByteString | EObj B.ByteString TxErr | EArr [TxErr] | EInt Int

data Meta = Meta
  { mErr :: Maybe TxErr, mFee :: !Word64, mPre :: [Word64], mPost :: [Word64]
  , mInner :: Maybe [(Int, [Instruction])], mLogs :: Maybe [B.ByteString]
  , mPreTok :: Maybe [TokenBalance], mPostTok :: Maybe [TokenBalance], mRewards :: Maybe [Reward]
  , mLoadedW :: [B.ByteString], mLoadedR :: [B.ByteString]
  , mReturn :: Maybe (B.ByteString, B.ByteString), mCu :: Maybe Word64, mCost :: Maybe Word64 }

emptyMeta :: Meta
emptyMeta = Meta Nothing 0 [] [] Nothing Nothing Nothing Nothing Nothing [] [] Nothing Nothing Nothing

cutoff :: Word64
cutoff = 157 * 432000

-- ---- TransactionError (bincode enum) ------------------------------------------

instructionErrors, transactionErrors, rewardTypes :: [B.ByteString]
instructionErrors = BC.words
  "GenericError InvalidArgument InvalidInstructionData InvalidAccountData AccountDataTooSmall \
  \InsufficientFunds IncorrectProgramId MissingRequiredSignature AccountAlreadyInitialized \
  \UninitializedAccount UnbalancedInstruction ModifiedProgramId ExternalAccountLamportSpend \
  \ExternalAccountDataModified ReadonlyLamportChange ReadonlyDataModified DuplicateAccountIndex \
  \ExecutableModified RentEpochModified NotEnoughAccountKeys AccountDataSizeChanged \
  \AccountNotExecutable AccountBorrowFailed AccountBorrowOutstanding DuplicateAccountOutOfSync \
  \Custom InvalidError ExecutableDataModified ExecutableLamportChange ExecutableAccountNotRentExempt \
  \UnsupportedProgramId CallDepth MissingAccount ReentrancyNotAllowed MaxSeedLengthExceeded \
  \InvalidSeeds InvalidRealloc ComputationalBudgetExceeded PrivilegeEscalation \
  \ProgramEnvironmentSetupFailure ProgramFailedToComplete ProgramFailedToCompile Immutable \
  \IncorrectAuthority BorshIoError AccountNotRentExempt InvalidAccountOwner ArithmeticOverflow \
  \UnsupportedSysvar IllegalOwner MaxAccountsDataAllocationsExceeded MaxAccountsExceeded \
  \MaxInstructionTraceLengthExceeded BuiltinProgramsMustConsumeComputeUnits"
transactionErrors = BC.words
  "AccountInUse AccountLoadedTwice AccountNotFound ProgramAccountNotFound InsufficientFundsForFee \
  \InvalidAccountForFee AlreadyProcessed BlockhashNotFound InstructionError CallChainTooDeep \
  \MissingSignatureForFee InvalidAccountIndex SignatureFailure InvalidProgramForExecution \
  \SanitizeFailure ClusterMaintenance AccountBorrowOutstanding WouldExceedMaxBlockCostLimit \
  \UnsupportedVersion InvalidWritableAccount WouldExceedMaxAccountCostLimit \
  \WouldExceedAccountDataBlockLimit TooManyAccountLocks AddressLookupTableNotFound \
  \InvalidAddressLookupTableOwner InvalidAddressLookupTableData InvalidAddressLookupTableIndex \
  \InvalidRentPayingAccount WouldExceedMaxVoteCostLimit WouldExceedAccountDataTotalLimit \
  \DuplicateInstruction InsufficientFundsForRent MaxLoadedAccountsDataSizeExceeded \
  \InvalidLoadedAccountsDataSizeLimit ResanitizationNeeded ProgramExecutionTemporarilyRestricted \
  \UnbalancedTransaction ProgramCacheHitMaxLimit CommitCancelled"
rewardTypes = ["Fee", "Rent", "Staking", "Voting"]

pick :: [B.ByteString] -> Word64 -> String -> P B.ByteString
pick names i what = case drop (fromIntegral i) names of
  (x : _) | i < fromIntegral (length names) -> pure x
  _ -> failP ("unknown " ++ what ++ " variant")

transactionError :: P TxErr
transactionError = do
  v <- u32le
  name <- pick transactionErrors v "TransactionError"
  case v of
    8 -> do
      index <- fromIntegral <$> u8
      k <- u32le
      inner <- if k == 25 then EObj "Custom" . EInt . fromIntegral <$> u32le
               else EStr <$> pick instructionErrors k "InstructionError"
      pure (EObj name (EArr [EInt index, inner]))
    30 -> EObj name . EInt . fromIntegral <$> u8
    _ | v == 31 || v == 35 -> EObj name . EObj "account_index" . EInt . fromIntegral <$> u8
      | otherwise -> pure (EStr name)

-- ---- shared helpers ------------------------------------------------------------

-- | Rust @from_str@ for unsigned integers: optional '+', ASCII digits, fits @maxV@.
unsignedText :: Word64 -> B.ByteString -> Maybe Word64
unsignedText maxV t0 = do
  let t = fromMaybe t0 (B.stripPrefix "+" t0)
  guard (not (B.null t) && BC.all (\c -> c >= '0' && c <= '9') t)
  let digits = BC.dropWhile (== '0') t
  guard (B.length digits <= 20)
  let v = BC.foldl' (\acc c -> acc * 10 + toInteger (fromEnum c - 48)) (0 :: Integer) digits
  guard (v <= toInteger maxV)
  pure (fromInteger v)

-- | real_number_string_trimmed
uiAmountString :: B.ByteString -> Int -> B.ByteString
uiAmountString amount decimals
  | decimals == 0 = digits
  | otherwise = trim (whole <> "." <> frac)
  where
    digits = BC.pack (show (fromMaybe 0 (unsignedText maxBound amount)))
    padded = BC.replicate (decimals + 1 - B.length digits) '0' <> digits
    (whole, frac) = B.splitAt (B.length padded - decimals) padded
    trim s = let s' = BC.dropWhileEnd (== '0') s in fromMaybe s' (B.stripSuffix "." s')

tokenBalance :: Int -> B.ByteString -> Maybe Double -> Int -> B.ByteString -> B.ByteString -> B.ByteString -> B.ByteString -> TokenBalance
tokenBalance idx mint ui decimals amount owner program display =
  TokenBalance idx mint owner program ui decimals amount
    (if B.null display then uiAmountString amount decimals else display)

-- ---- protobuf wire level --------------------------------------------------------

data WV = WVar !Word64 | WF64 !Word64 | WLen !B.ByteString

-- | Field kinds: varint, double, length-delimited, repeated varint (packed or not).
data FK = KV | KD | KL | KP

protoKey :: P (Int, Int)
protoKey = do
  k <- uvarint
  when (k < 8 || k > 0xFFFFFFFF) $ failP "invalid protobuf key"
  pure (fromIntegral (k `shiftR` 3), fromIntegral (k .&. 7))

skipValue :: Int -> Int -> Int -> P ()
skipValue field wire depth = case wire of
  0 -> void uvarint
  1 -> skipBytes 8
  2 -> uvarint >>= word64ToInt >>= skipBytes
  3 -> do
    when (depth > 100) $ failP "protobuf group nesting limit"
    let loop = do
          (tag, w) <- protoKey
          if w == 4 then when (tag /= field) (failP "mismatched protobuf group")
            else skipValue tag w (depth + 1) >> loop
    loop
  5 -> skipBytes 4
  _ -> failP "invalid protobuf wire type"

-- | Parse one message: unknown fields skipped, known fields type-checked.
fields :: [(Int, FK)] -> B.ByteString -> Either String [(Int, WV)]
fields schema = runP (go [])
  where
    go acc = do
      done <- atEnd
      if done then pure (reverse acc) else do
        (f, w) <- protoKey
        case lookup f schema of
          Nothing -> skipValue f w 0 >> go acc
          Just k -> do
            v <- case (k, w) of
              (KV, 0) -> WVar <$> uvarint
              (KP, 0) -> WVar <$> uvarint
              (KD, 1) -> WF64 <$> u64le
              (KL, 2) -> WLen <$> (uvarint >>= word64ToInt >>= takeBytes)
              (KP, 2) -> WLen <$> (uvarint >>= word64ToInt >>= takeBytes)
              _ -> failP "wrong protobuf wire type"
            go ((f, v) : acc)

lastVar :: [(Int, WV)] -> Int -> Maybe Word64
lastVar fs n = foldl (\acc (f, v) -> case v of { WVar x | f == n -> Just x; _ -> acc }) Nothing fs

lastDouble :: [(Int, WV)] -> Int -> Maybe Double
lastDouble fs n = foldl (\acc (f, v) -> case v of { WF64 x | f == n -> Just (castWord64ToDouble x); _ -> acc }) Nothing fs

allLen :: [(Int, WV)] -> Int -> [B.ByteString]
allLen fs n = [s | (f, WLen s) <- fs, f == n]

lastLen :: [(Int, WV)] -> Int -> Maybe B.ByteString
lastLen fs n = case allLen fs n of { [] -> Nothing; xs -> Just (last xs) }

utf8 :: B.ByteString -> Either String B.ByteString
utf8 s = if B.isValidUtf8 s then Right s else Left "invalid UTF-8 in protobuf string"

strings :: [(Int, WV)] -> Int -> Either String [B.ByteString]
strings fs n = mapM utf8 (allLen fs n)

lastString :: [(Int, WV)] -> Int -> Either String B.ByteString
lastString fs n = (\xs -> if null xs then B.empty else last xs) <$> strings fs n

-- | A non-repeated message seen several times is merged; concatenating its
--   encodings and parsing once is exactly protobuf's merge.
message :: [(Int, WV)] -> Int -> Maybe B.ByteString
message fs n = case allLen fs n of { [] -> Nothing; xs -> Just (B.concat xs) }

packed :: [(Int, WV)] -> Int -> Either String [Word64]
packed fs n = concat <$> mapM one [v | (f, v) <- fs, f == n]
  where one (WVar x) = Right [x]
        one (WLen s) = runP (many' uvarint) s
        one _ = Right []
        many' p = atEnd >>= \e -> if e then pure [] else (:) <$> p <*> many' p

flag :: [(Int, WV)] -> Int -> Bool
flag fs n = maybe False (/= 0) (lastVar fs n)

low :: Word64 -> Word64 -> Int
low mask v = fromIntegral (v .&. mask)

-- ---- protobuf messages: parse (Left = wire-level failure), then convert --------

data PReward = PReward B.ByteString Word64 Word64 Word64 B.ByteString B.ByteString

pReward :: B.ByteString -> Either String PReward
pReward bytes = do
  fs <- fields [(1, KL), (2, KV), (3, KV), (4, KV), (5, KL), (6, KL)] bytes
  PReward <$> lastString fs 1 <*> pure (fromMaybe 0 (lastVar fs 2)) <*> pure (fromMaybe 0 (lastVar fs 3))
          <*> pure (fromMaybe 0 (lastVar fs 4)) <*> lastString fs 5 <*> lastString fs 6

convertReward :: PReward -> Reward
convertReward (PReward pk lam post rt comm bps) = Reward pk (fromIntegral lam) post kind commission
  where
    k = low 0xFFFFFFFF rt
    kind = if k >= 1 && k <= 4 then Just (rewardTypes !! (k - 1)) else Nothing
    commission = case unsignedText 255 comm of
      Just c -> Just (fromIntegral c)
      Nothing -> case unsignedText 65535 bps of
        Just b | b `div` 100 <= 255 -> Just (fromIntegral (b `div` 100))
        _ -> Nothing

pToken :: B.ByteString -> Either String TokenBalance
pToken bytes = do
  fs <- fields [(1, KV), (2, KL), (3, KL), (4, KL), (5, KL)] bytes
  amt <- maybe (Right []) (fields [(1, KD), (2, KV), (3, KL), (4, KL)]) (message fs 3)
  mint <- lastString fs 2
  owner <- lastString fs 4
  program <- lastString fs 5
  amount <- lastString amt 3
  display <- lastString amt 4
  let ui = fromMaybe 0 (lastDouble amt 1)
  pure (tokenBalance (low 0xFF (fromMaybe 0 (lastVar fs 1))) mint
          (if abs ui > 2.220446049250313e-16 then Just ui else Nothing)
          (low 0xFF (fromMaybe 0 (lastVar amt 2))) amount owner program display)

pInnerInstruction :: B.ByteString -> Either String Instruction
pInnerInstruction bytes = do
  fs <- fields [(1, KV), (2, KL), (3, KL), (4, KV)] bytes
  pure (Instruction (low 0xFF (fromMaybe 0 (lastVar fs 1))) (fromMaybe B.empty (lastLen fs 2))
          (fromMaybe B.empty (lastLen fs 3)) (low 0xFFFFFFFF <$> lastVar fs 4))

pInner :: B.ByteString -> Either String (Int, [Instruction])
pInner bytes = do
  fs <- fields [(1, KV), (2, KL)] bytes
  ixs <- mapM pInnerInstruction (allLen fs 2)
  pure (low 0xFF (fromMaybe 0 (lastVar fs 1)), ixs)

metaSchema :: [(Int, FK)]
metaSchema = [ (1, KL), (2, KV), (3, KP), (4, KP), (5, KL), (6, KL), (7, KL), (8, KL), (9, KL)
             , (10, KV), (11, KV), (12, KL), (13, KL), (14, KL), (15, KV), (16, KV), (17, KV) ]

-- | Outer 'Either': does it parse?  Inner 'Either': does it convert (final)?
protoMeta :: B.ByteString -> Either String (Either String Meta)
protoMeta bytes = do
  fs <- fields metaSchema bytes
  errBytes <- traverse (\m -> fromMaybe B.empty . (`lastLen` 1) <$> fields [(1, KL)] m) (message fs 1)
  pre <- packed fs 3
  post <- packed fs 4
  inner <- mapM pInner (allLen fs 5)
  logs <- strings fs 6
  preTok <- mapM pToken (allLen fs 7)
  postTok <- mapM pToken (allLen fs 8)
  rws <- mapM pReward (allLen fs 9)
  ret <- traverse (\m -> (\f -> (fromMaybe B.empty (lastLen f 1), fromMaybe B.empty (lastLen f 2))) <$> fields [(1, KL), (2, KL)] m) (message fs 14)
  pure $ do
    err <- traverse (fmap fst . runPrefix transactionError) errBytes
    loadedW <- mapM pubkey (allLen fs 12)
    loadedR <- mapM pubkey (allLen fs 13)
    returnData <- if flag fs 15 then Right Nothing
                  else traverse (\(p, d) -> (\k -> (k, d)) <$> pubkey p) ret
    pure Meta
      { mErr = err, mFee = fromMaybe 0 (lastVar fs 2), mPre = pre, mPost = post
      , mInner = if flag fs 10 then Nothing else Just inner
      , mLogs = if flag fs 11 then Nothing else Just logs
      , mPreTok = Just preTok, mPostTok = Just postTok, mRewards = Just (map convertReward rws)
      , mLoadedW = loadedW, mLoadedR = loadedR, mReturn = returnData
      , mCu = lastVar fs 16, mCost = lastVar fs 17 }

protoRewards :: B.ByteString -> Either String (Either String ([Reward], Maybe Word64))
protoRewards bytes = do
  fs <- fields [(1, KL), (2, KL)] bytes
  rws <- mapM pReward (allLen fs 1)
  parts <- traverse (\m -> fromMaybe 0 . (`lastVar` 1) <$> fields [(1, KV)] m) (message fs 2)
  pure (Right (map convertReward rws, parts))

-- ---- bincode (pre-epoch-157) ------------------------------------------------------

bString :: P B.ByteString
bString = do
  s <- u64le >>= word64ToInt >>= takeBytes
  if B.isValidUtf8 s then pure s else failP "invalid UTF-8"

bVec :: Int -> P a -> P [a]
bVec minimum p = u64le >>= \n -> countOf n minimum p

bOption :: P a -> P (Maybe a)
bOption p = u8 >>= \t -> case t of
  0 -> pure Nothing
  1 -> Just <$> p
  _ -> failP "invalid bincode option"

-- | An EOF-default field: an exhausted input means None.
eofOpt :: P a -> P (Maybe a)
eofOpt p = atEnd >>= \e -> if e then pure Nothing else bOption p

-- | Run @p@ only while input remains (otherwise the default).
whenLeft :: a -> P a -> P a
whenLeft dflt p = atEnd >>= \e -> if e then pure dflt else p

bReward :: Bool -> P Reward
bReward extended = do
  pk <- bString
  lam <- fromIntegral <$> u64le
  let eofField dflt p = if extended then whenLeft dflt p else p
  post <- eofField 0 u64le
  kind <- eofField Nothing (bOption (u32le >>= \i -> pick rewardTypes i "RewardType"))
  commission <- if extended then whenLeft Nothing (bOption (fromIntegral <$> u8)) else pure Nothing
  pure (Reward pk lam post kind commission)

-- | layout 1 = V1 (no owner / program), 2 = V2 (owner), 3 = StoredTokenBalance.
bToken :: Int -> P TokenBalance
bToken layout = do
  idx <- fromIntegral <$> u8
  mint <- bString
  ui <- f64le
  decimals <- fromIntegral <$> u8
  amount <- bString
  owner <- if layout >= 2 then whenLeft B.empty bString else pure B.empty
  program <- if layout >= 3 then whenLeft B.empty bString else pure B.empty
  pure (tokenBalance idx mint (Just ui) decimals amount owner program B.empty)

bMeta :: Bool -> Int -> P Meta
bMeta legacy layout = do
  status <- u32le
  when (status > 1) $ failP "invalid bincode result tag"
  err <- if status == 1 then Just <$> transactionError else pure Nothing
  fee <- u64le
  pre <- bVec 8 u64le
  post <- bVec 8 u64le
  let innerIx = do
        ix <- compiled Nothing
        if legacy then pure ix else (\h -> ix { ixHeight = fromIntegral <$> h }) <$> bOption u32le
  inner <- eofOpt (bVec 9 ((,) <$> (fromIntegral <$> u8) <*> bVec (if legacy then 3 else 4) innerIx))
  logs <- eofOpt (bVec 8 bString)
  preTok <- eofOpt (bVec 26 (bToken layout))
  postTok <- eofOpt (bVec 26 (bToken layout))
  rws <- eofOpt (bVec 16 (bReward True))
  ret <- eofOpt $ do
    p <- takeBytes 32
    d <- u64le >>= word64ToInt >>= takeBytes
    pure (base58 p, d)
  cu <- eofOpt u64le
  cost <- eofOpt u64le
  pure (Meta err fee pre post inner logs preTok postTok rws [] [] ret cu cost)

-- | Strict layouts in order, then the first layout leniently (trailing bytes ok).
bincode :: [P a] -> B.ByteString -> Either String a
bincode layouts bytes = case [v | p <- layouts, Right v <- [runP p bytes]] of
  (v : _) -> Right v
  [] -> case layouts of
    (p : _) -> fst <$> runPrefix p bytes
    [] -> Left "no bincode layout"

bincodeMeta :: B.ByteString -> Either String Meta
bincodeMeta = bincode [bMeta False 3, bMeta True 1, bMeta True 2, bMeta True 3]

bincodeRewards :: B.ByteString -> Either String ([Reward], Maybe Word64)
bincodeRewards bytes = (\r -> (r, Nothing)) <$> bincode [bVec 16 (bReward True), bVec 25 (bReward False)] bytes

-- ---- frame unwrapping (WIRE_FORMATS.md section 9) ------------------------------------

decodePayload :: Word64 -> (B.ByteString -> Either String (Either String a)) -> (B.ByteString -> Either String a)
              -> B.ByteString -> Either String a
decodePayload slot proto stored bytes
  | slot < cutoff, Right v <- stored bytes = Right v
  | otherwise = case proto bytes of
      Right converted -> converted
      Left e | slot < cutoff -> Left e
             | otherwise -> stored bytes

unwrap :: Word64 -> (B.ByteString -> Either String (Either String a)) -> (B.ByteString -> Either String a)
       -> B.ByteString -> Either String a
unwrap slot proto stored bytes
  | Zstd.isZstd bytes = decode (either (const bytes) id (Zstd.decompress bytes))
  | otherwise = case decode bytes of
      Right v -> Right v
      Left original -> either (const (Left original)) decode (Zstd.decompress bytes)
  where decode = decodePayload slot proto stored

metadata :: Word64 -> B.ByteString -> Either String (Maybe Meta)
metadata slot bytes
  | B.null bytes = Right Nothing
  | otherwise = Just <$> unwrap slot protoMeta bincodeMeta bytes

rewards :: Word64 -> B.ByteString -> Either String ([Reward], Maybe Word64)
rewards slot bytes
  | B.null bytes = Right ([], Nothing)
  | otherwise = unwrap slot protoRewards bincodeRewards bytes

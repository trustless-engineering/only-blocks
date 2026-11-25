{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
-- | OnlyBlocks in Haskell: a zero-dependency historical Solana getBlock
--   JSON-RPC server over Old Faithful HTTP Range reads.  GHC boot libraries only.
module Main (main) where

import Control.Concurrent
import Control.Concurrent.QSem
import Control.Exception
import Control.Monad
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BC
import Data.IORef
import Data.Int
import Data.List (isPrefixOf)
import qualified Data.Map.Strict as M
import Data.Maybe (fromMaybe, isNothing)
import qualified Data.Set as S
import Data.Word
import GHC.Clock (getMonotonicTimeNSec)
import System.Environment (getArgs, lookupEnv)
import System.Exit
import System.IO
import System.Posix.Signals

import Json hiding (member)
import Meta
import Net
import Wire

-- ---- errors -------------------------------------------------------------------

data RpcError = RpcError !Int !B.ByteString deriving Show
instance Exception RpcError

internal :: String -> IO a
internal m = throwIO (RpcError (-32603) (BC.pack m))

orFail :: Either String a -> IO a
orFail = either internal pure

-- ---- bounded LRU ------------------------------------------------------------------

data LruState v = LruState !(M.Map Word64 (Int, v)) !(M.Map Int Word64) !Int
data Lru v = Lru !Int !(MVar (LruState v))

newLru :: Int -> IO (Lru v)
newLru cap = Lru cap <$> newMVar (LruState M.empty M.empty 0)

lruGet :: Lru v -> Word64 -> IO (Maybe v)
lruGet (Lru _ mv) k = modifyMVar mv $ \st@(LruState items order tick) -> case M.lookup k items of
  Nothing -> pure (st, Nothing)
  Just (t, v) -> pure (LruState (M.insert k (tick, v) items) (M.insert tick k (M.delete t order)) (tick + 1), Just v)

lruPut :: Lru v -> Word64 -> v -> IO ()
lruPut (Lru cap mv) k v = modifyMVar_ mv $ \(LruState items order tick) -> do
  let order0 = maybe order (\(t, _) -> M.delete t order) (M.lookup k items)
      items1 = M.insert k (tick, v) items
      order1 = M.insert tick k order0
  pure $! case M.minViewWithKey order1 of
    Just ((_, oldest), order2) | M.size items1 > cap -> LruState (M.delete oldest items1) order2 (tick + 1)
    _ -> LruState items1 order1 (tick + 1)

-- ---- Old Faithful: the 2-range-read protocol -----------------------------------------

data SlotRange = Present !Word64 !Int | Skipped

data Env = Env
  { eBase :: Base, eRanges :: Lru SlotRange, eHashes :: Lru B.ByteString
  , eSem :: QSem, eRng :: IORef Word64 }

epochSlots :: Word64
epochSlots = 432000

maxSlice :: Int
maxSlice = 128 * 1024 * 1024

-- | xorshift64* in [0, 1), for retry jitter.
jitter :: Env -> IO Double
jitter env = atomicModifyIORef' (eRng env) $ \x ->
  let a = x `xor` (x `shiftR` 12)
      b = a `xor` (a `shiftL` 25)
      c = b `xor` (b `shiftR` 27)
  in (c, fromIntegral ((c * 2685821657736338717) `shiftR` 11) / 9007199254740992)

notArchived :: Word64 -> RpcError
notArchived slot = RpcError (-32004) $ BC.pack $
  "Block not available for slot " ++ show slot ++ ": epoch " ++ show (slot `div` epochSlots)
  ++ " is not archived in Old Faithful (historical-only server)"

readRange :: Env -> Word64 -> String -> Word64 -> Int -> Int -> IO B.ByteString
readRange env slot suffix start size cap = do
  let stop = start + fromIntegral size - 1
  when (stop < start) $ internal "archive range end overflows u64"
  let epoch = slot `div` epochSlots
      path = bPrefix (eBase env) ++ "/" ++ show epoch ++ "/epoch-" ++ show epoch ++ suffix
      range = "bytes=" ++ show start ++ "-" ++ show stop
      go n = do
        outcome <- bracket_ (waitQSem (eSem env)) (signalQSem (eSem env)) $
          try (try (attempt (eBase env) path range size cap))
        case outcome of
          Right (Right (Partial body)) -> pure body
          Right (Right (Status 404 _)) -> throwIO (notArchived slot)
          Right (Right (Status s ra))
            | s == 429 || (s >= 500 && s < 600) -> retry n ra
            | otherwise -> internal ("unexpected archive HTTP status " ++ show s)
          Right (Left (Fatal m)) -> internal m
          Right (Left (Transport _)) -> retry n Nothing
          Left (_ :: IOException) -> retry n Nothing
      retry n ra = do
        when (n >= 4) $ internal "archive range retries exhausted"
        d <- jitter env >>= retryDelay ra n
        threadDelay (round (d * 1000000))
        go (n + 1)
  go (0 :: Int)

leWord :: B.ByteString -> Word64
leWord = B.foldr' (\b acc -> (acc `shiftL` 8) .|. fromIntegral b) 0

loadBlock :: Env -> Word64 -> IO Car
loadBlock env slot = do
  cached <- lruGet (eRanges env) slot
  record <- case cached of
    Just r -> pure r
    Nothing -> do
      raw <- readRange env slot "-slot-ranges.raw" ((slot `mod` epochSlots) * 12) 12 12
      let offset = leWord (B.take 8 raw)
          len = leWord (B.drop 8 raw)
          r = if len == 0 then Skipped else Present offset (fromIntegral len)
      lruPut (eRanges env) slot r
      pure r
  case record of
    Skipped -> throwIO (RpcError (-32007) (BC.pack ("Slot " ++ show slot ++ " was skipped, or missing in long-term storage")))
    Present offset len -> do
      when (len > maxSlice) $ internal "archive slice exceeds 128 MiB"
      readRange env slot ".car" offset len maxSlice >>= orFail . indexCar

entryHash :: Car -> B.ByteString -> Either String B.ByteString
entryHash car k = node car k 1 >>= \e -> case at e 2 of
  Just (CB h) | B.length h == 32 -> Right h
  _ -> Left "invalid Entry hash"

blockHash :: Env -> Word64 -> Car -> [B.ByteString] -> IO B.ByteString
blockHash env slot car entries = do
  h <- if null entries then pure zeroHash else base58 <$> orFail (entryHash car (last entries))
  lruPut (eHashes env) slot h
  pure h

previousHash :: Env -> Word64 -> Word64 -> IO B.ByteString
previousHash env slot parent
  | slot == 0 = pure zeroHash
  | otherwise = lruGet (eHashes env) parent >>= \cached -> case cached of
      Just h -> pure h
      Nothing -> do
        car <- loadBlock env parent
        when (isNothing (asU64 (at (carBlock car) 1))) $ internal "missing parent Block slot"
        orFail (links (at (carBlock car) 3)) >>= blockHash env parent car

-- ---- JSON rendering (WIRE_FORMATS.md section 13) ------------------------------------

data Opts = Opts { oEncoding :: B.ByteString, oDetails :: B.ByteString, oRewards :: Bool, oMaxVersion :: Maybe Int }

upgradeable :: B.ByteString
upgradeable = "BPFLoaderUpgradeab1e11111111111111111111111"

reserved :: S.Set B.ByteString
reserved = S.fromList $ BC.words
  "AddressLookupTab1e1111111111111111111111111 BPFLoader2111111111111111111111111111111111 \
  \BPFLoader1111111111111111111111111111111111 BPFLoaderUpgradeab1e11111111111111111111111 \
  \ComputeBudget111111111111111111111111111111 Config1111111111111111111111111111111111111 \
  \Ed25519SigVerify111111111111111111111111111 Feature111111111111111111111111111111111111 \
  \LoaderV411111111111111111111111111111111111 KeccakSecp256k11111111111111111111111111111 \
  \Secp256r1SigVerify1111111111111111111111111 StakeConfig11111111111111111111111111111111 \
  \Stake11111111111111111111111111111111111111 11111111111111111111111111111111 \
  \Vote111111111111111111111111111111111111111 ZkE1Gama1Proof11111111111111111111111111111 \
  \ZkTokenProof1111111111111111111111111111111 SysvarC1ock11111111111111111111111111111111 \
  \SysvarEpochRewards1111111111111111111111111 SysvarEpochSchedu1e111111111111111111111111 \
  \SysvarFees111111111111111111111111111111111 Sysvar1nstructions1111111111111111111111111 \
  \SysvarLastRestartS1ot1111111111111111111111 SysvarRecentB1ockHashes11111111111111111111 \
  \SysvarRent111111111111111111111111111111111 SysvarRewards111111111111111111111111111111 \
  \SysvarS1otHashes111111111111111111111111111 SysvarS1otHistory11111111111111111111111111 \
  \SysvarStakeHistory1111111111111111111111111 NativeLoader1111111111111111111111111111111 \
  \Sysvar1111111111111111111111111111111111111"

opt :: (a -> J) -> Maybe a -> J
opt = maybe JNull'

byteList :: B.ByteString -> J
byteList = JArr' . map (int . fromIntegral) . B.unpack

errJson :: TxErr -> J
errJson (EStr s) = str s
errJson (EInt n) = int n
errJson (EArr xs) = JArr' (map errJson xs)
errJson (EObj k v) = JObj' [(k, errJson v)]

rewardJson :: Reward -> J
rewardJson r = JObj'
  [ ("pubkey", str (rwPubkey r)), ("lamports", int64 (rwLamports r)), ("postBalance", word (rwPost r))
  , ("rewardType", opt str (rwType r)), ("commission", opt int (rwCommission r)) ]

tokenJson :: TokenBalance -> J
tokenJson t = JObj' $
  [ ("accountIndex", int (tbIndex t)), ("mint", str (tbMint t))
  , ("uiTokenAmount", JObj' [ ("uiAmount", opt JDouble (tbUi t)), ("decimals", int (tbDecimals t))
                            , ("amount", str (tbAmount t)), ("uiAmountString", str (tbUiString t)) ]) ]
  ++ [("owner", str (tbOwner t)) | not (B.null (tbOwner t))]
  ++ [("programId", str (tbProgram t)) | not (B.null (tbProgram t))]

-- | Compiled form without keys; partially decoded (jsonParsed) with them.
instructionJson :: Maybe [B.ByteString] -> Instruction -> Either String J
instructionJson keys ix = case keys of
  Nothing -> Right $ JObj' (("programIdIndex", int (ixProgram ix)) : ("accounts", byteList (ixAccounts ix)) : common)
  Just ks -> do
    let table = M.fromList (zip [0 ..] ks)
        addr i = maybe (Left "instruction account index out of range") (Right . str) (M.lookup i table)
    program <- addr (ixProgram ix)
    accounts <- mapM (addr . fromIntegral) (B.unpack (ixAccounts ix))
    Right $ JObj' (("programId", program) : ("accounts", JArr' accounts) : common)
  where common = [("data", str (base58 (ixData ix))), ("stackHeight", opt int (ixHeight ix))]

accountObjects :: Tx -> ([B.ByteString], [B.ByteString]) -> [(B.ByteString, J)]
accountObjects tx (lw, lr) = zipWith object [0 ..] keys
  where
    (w, r) = case txVersion tx of
      V0 -> (lw, lr)
      _ -> ([], [])
    keys = txKeys tx ++ w ++ r
    ns = length (txKeys tx)
    programs = S.fromList (map ixProgram (txInstructions tx))
    upg = upgradeable `elem` keys
    object i key =
      let lookupKey = i >= ns
          canWrite | lookupKey = i - ns < length w
                   | i < txNrs tx = i < txNrs tx - txNros tx
                   | otherwise = i < ns - txNrou tx
          writable = canWrite && not (S.member key reserved) && (upg || not (S.member i programs))
      in (key, JObj' [ ("pubkey", str key), ("writable", JBool' writable), ("signer", JBool' (i < txNrs tx))
                     , ("source", str (if lookupKey then "lookupTable" else "transaction")) ])

metaJson :: Opts -> Maybe [B.ByteString] -> Meta -> Either String J
metaJson o keys m = do
  inner <- traverse (mapM (\(idx, ixs) -> (\js -> JObj' [("index", int idx), ("instructions", JArr' js)]) <$> mapM (instructionJson keys) ixs)) (mInner m)
  let parsed = oEncoding o == "jsonParsed"
      accountsOnly = oDetails o == "accounts"
      tokens = opt (JArr' . map tokenJson)
      base =
        [ ("err", opt errJson (mErr m))
        , ("status", maybe (JObj' [("Ok", JNull')]) (\e -> JObj' [("Err", errJson e)]) (mErr m))
        , ("fee", word (mFee m)), ("preBalances", JArr' (map word (mPre m))), ("postBalances", JArr' (map word (mPost m)))
        , ("preTokenBalances", tokens (mPreTok m)), ("postTokenBalances", tokens (mPostTok m)) ]
      rewardsField
        | oRewards o = [("rewards", opt (JArr' . map rewardJson) (mRewards m))]
        | accountsOnly = []
        | otherwise = [("rewards", JNull')]
      extra
        | accountsOnly = []
        | otherwise =
            [ ("innerInstructions", opt JArr' inner), ("logMessages", opt (JArr' . map str) (mLogs m)) ]
            ++ [ ("loadedAddresses", JObj' [("writable", JArr' (map str (mLoadedW m))), ("readonly", JArr' (map str (mLoadedR m)))])
               | not parsed ]
            ++ [ ("returnData", JObj' [("programId", str p), ("data", JArr' [str (base64 d), str "base64"])]) | Just (p, d) <- [mReturn m] ]
            ++ [ ("computeUnitsConsumed", word v) | Just v <- [mCu m] ]
            ++ [ ("costUnits", word v) | Just v <- [mCost m] ]
  pure (JObj' (base ++ rewardsField ++ extra))

unsupportedVersion :: Int -> RpcError
unsupportedVersion version = RpcError (-32015) $
  "Transaction version (" <> v <> ") is not supported by the requesting client. Please try the request again with the following configuration parameter: \"maxSupportedTransactionVersion\": " <> v
  where v = BC.pack (show version)

transactionJson :: Opts -> Tx -> Maybe Meta -> IO J
transactionJson o tx meta0 = do
  let numericVersion = case txVersion tx of
        Legacy -> Nothing
        V0 -> Just 0
        V1 _ -> Just 1
  meta <- case numericVersion of
    Nothing -> pure meta0
    Just v -> do
      when (fromMaybe (-1) (oMaxVersion o) < v) $ throwIO (unsupportedVersion v)
      pure (Just (fromMaybe emptyMeta meta0))
  let parsed = oEncoding o == "jsonParsed"
      accountsOnly = oDetails o == "accounts"
      loaded = maybe ([], []) (\m -> (mLoadedW m, mLoadedR m)) meta
      objects = if parsed || accountsOnly then Just (accountObjects tx loaded) else Nothing
      keys = if parsed then map fst <$> objects else Nothing
      accountKeys = maybe (JArr' (map str (txKeys tx))) (JArr' . map snd) objects
      signatures = ("signatures", JArr' (map (str . base58) (txSignatures tx)))
  transactionOut <- case oEncoding o of
    "base64" -> pure (JArr' [str (base64 (txRaw tx)), str "base64"])
    "base58" -> pure (JArr' [str (base58 (txRaw tx)), str "base58"])
    _ | accountsOnly -> pure (JObj' [signatures, ("accountKeys", accountKeys)])
      | otherwise -> do
          ixs <- orFail (mapM (instructionJson keys) (txInstructions tx))
          let header = [ ("header", JObj' [ ("numRequiredSignatures", int (txNrs tx))
                                          , ("numReadonlySignedAccounts", int (txNros tx))
                                          , ("numReadonlyUnsignedAccounts", int (txNrou tx)) ]) | not parsed ]
              versionFields = case txVersion tx of
                V0 -> [ ("addressTableLookups", JArr' [ JObj' [ ("accountKey", str (base58 (lkTable l)))
                                                             , ("writableIndexes", byteList (lkWritable l))
                                                             , ("readonlyIndexes", byteList (lkReadonly l)) ]
                                                     | l <- txLookups tx ]) ]
                V1 config -> [ ("transactionConfig", JObj'
                                 [ ("priorityFee", opt word (priorityFee config))
                                 , ("computeUnitLimit", opt word (computeUnitLimit config))
                                 , ("loadedAccountsDataSizeLimit", opt word (loadedAccountsDataSizeLimit config))
                                 , ("heapSize", opt word (heapSize config)) ]) ]
                Legacy -> []
          pure (JObj' [ signatures, ("message", JObj' (header ++ [ ("accountKeys", accountKeys)
                                                               , ("recentBlockhash", str (txRecent tx))
                                                               , ("instructions", JArr' ixs) ] ++ versionFields)) ])
  metaOut <- maybe (pure JNull') (orFail . metaJson o keys) meta
  let version = [ ("version", maybe (str "legacy") int numericVersion) | Just _ <- [meta], Just _ <- [oMaxVersion o] ]
  pure (JObj' ([("transaction", transactionOut), ("meta", metaOut)] ++ version))

getBlock :: Env -> Word64 -> Opts -> IO J
getBlock env slot o = do
  car <- loadBlock env slot
  let block = carBlock car
  when (asU64 (at block 1) /= Just slot) $ internal "Block slot differs from requested slot"
  entries <- orFail (links (at block 3))
  let info = case at block 4 of { Just (CA xs) -> xs; _ -> [] }
      parent = fromMaybe 0 (asU64 (at info 0))
  blockhash <- blockHash env slot car entries
  previous <- previousHash env slot parent
  details <- if oDetails o == "none" then pure [] else do
    items <- fmap concat $ forM entries $ \k -> do
      entry <- orFail (node car k 1)
      case at entry 2 of
        Just (CB h) | B.length h == 32 -> pure ()
        _ -> internal "invalid Entry hash"
      txKeys' <- orFail (links (at entry 3))
      forM txKeys' $ \tk -> do
        n <- orFail (node car tk 0)
        dataFrame <- maybe (internal "transaction node has no data frame") pure (at n 1)
        tx <- orFail (framePayload car dataFrame >>= transaction)
        if oDetails o == "signatures"
          then case txSignatures tx of
            (s : _) -> pure (str (base58 s))
            [] -> internal "transaction has no signature"
          else do
            meta <- case at n 2 of
              Just frame@(CA _) -> orFail (framePayload car frame >>= metadata slot)
              _ -> pure Nothing
            transactionJson o tx meta
    pure [(if oDetails o == "signatures" then "signatures" else "transactions", JArr' items)]
  rewardsOut <- if not (oRewards o) then pure [] else do
    payload <- case at block 5 of
      Just v@(CB _) -> do
        (k, absent) <- orFail (link v)
        if absent || not (member car k) then pure B.empty else do
          rn <- orFail (node car k 5)
          maybe (pure B.empty) (orFail . framePayload car) (at rn 2)
      _ -> pure B.empty
    (list, partitions) <- orFail (rewards slot payload)
    pure (("rewards", JArr' (map rewardJson list)) : [("numRewardPartitions", word p) | Just p <- [partitions]])
  let blockTime = case asI64 (at info 1) of
        Just t | t /= 0 -> int64 t
        _ -> JNull'
  pure $ JObj' $ [("previousBlockhash", str previous), ("blockhash", str blockhash), ("parentSlot", word parent)]
    ++ details ++ rewardsOut
    ++ [("blockTime", blockTime), ("blockHeight", opt word (asU64 (at info 2)))]

-- ---- JSON-RPC 2.0 -----------------------------------------------------------------

invalidParams :: IO a
invalidParams = throwIO (RpcError (-32602) "Invalid params")

-- | A JSON integer literal (0|[1-9][0-9]*) within 0..maxV, judged on its source text.
uintParam :: Word64 -> JV -> IO Word64
uintParam maxV (JNum t)
  | t == "0" || (not (B.null t) && BC.head t >= '1' && BC.head t <= '9' && BC.all (\c -> c >= '0' && c <= '9') t)
  , Just v <- unsignedText maxV t = pure v
uintParam _ _ = invalidParams

blockParams :: Maybe JV -> IO (Word64, Opts)
blockParams params = do
  (first, second) <- case params of
    Just (JArr [a]) -> pure (a, Nothing)
    Just (JArr [a, b]) -> pure (a, Just b)
    _ -> invalidParams
  slot <- uintParam maxBound first
  config <- case second of
    Nothing -> pure []
    Just JNull -> pure []
    Just (JStr s) -> pure [("encoding", JStr s)]
    Just (JObj kvs) -> pure kvs
    _ -> invalidParams
  let field k = case lookup k config of { Nothing -> Nothing; Just JNull -> Nothing; v -> v }
      choice k dflt allowed = case field k of
        Nothing -> pure dflt
        Just (JStr s) | s `elem` allowed -> pure s
        _ -> invalidParams
  encoding <- choice "encoding" "json" ["json", "jsonParsed", "base64", "base58"]
  details <- choice "transactionDetails" "full" ["full", "accounts", "signatures", "none"]
  rewardsOn <- case field "rewards" of
    Nothing -> pure True
    Just (JBool b) -> pure b
    _ -> invalidParams
  _ <- choice "commitment" "finalized" ["finalized", "confirmed"]
  maxVersion <- traverse (fmap fromIntegral . uintParam 255) (field "maxSupportedTransactionVersion")
  when (encoding == "base58" && fromMaybe 0 maxVersion >= 1) $
    throwIO (RpcError (-32602) "base58 encoding is not supported with maxSupportedTransactionVersion >= 1")
  when (details == "accounts" && encoding /= "json") invalidParams
  pure (slot, Opts encoding details rewardsOn maxVersion)

idJson :: Maybe JV -> J
idJson (Just (JNum t)) = JRaw (BB.byteString t)
idJson (Just (JStr s)) = str s
idJson _ = JNull'

envelope :: Maybe JV -> B.ByteString -> J -> B.ByteString
envelope rid field v = B.toStrict (BB.toLazyByteString (render (JObj' [("jsonrpc", str "2.0"), (field, v), ("id", idJson rid)])))

errorReply :: Maybe JV -> Int -> B.ByteString -> B.ByteString
errorReply rid code message = envelope rid "error" (JObj' [("code", int code), ("message", str message)])

dispatch :: Env -> JV -> IO B.ByteString
dispatch env (JObj kvs) =
  let get k = lookup k kvs
      textOrNull v = case v of { Nothing -> True; Just JNull -> True; Just (JStr _) -> True; _ -> False }
      validId = case get "id" of { Nothing -> True; Just JNull -> True; Just (JStr _) -> True; Just (JNum _) -> True; _ -> False }
      rid = get "id"
  in if not (textOrNull (get "jsonrpc") && textOrNull (get "method") && validId) then pure (errorReply Nothing (-32600) "Invalid Request")
     else if get "jsonrpc" /= Just (JStr "2.0") then pure (errorReply rid (-32600) "Invalid Request")
     else case get "method" of
       Just (JStr m) -> run rid m (get "params")
       _ -> pure (errorReply rid (-32600) "Invalid Request")
  where
    run rid m params = (call >>= evaluate) `catches`
      [ Handler (\(RpcError code msg) -> pure (errorReply rid code msg))
      , Handler (\(e :: SomeException) -> case fromException e of
          Just (async :: SomeAsyncException) -> throwIO async
          Nothing -> pure (errorReply rid (-32603) (BC.pack ("Internal error: " ++ take 200 (show e))))) ]
      where
        call = case m of
          "getHealth" -> case params of
            Nothing -> pure (envelope rid "result" (str "ok"))
            Just JNull -> pure (envelope rid "result" (str "ok"))
            Just (JArr []) -> pure (envelope rid "result" (str "ok"))
            _ -> throwIO (RpcError (-32602) "Invalid params: getHealth takes no parameters")
          "getBlock" -> do
            (slot, o) <- blockParams params
            envelope rid "result" <$> getBlock env slot o
          _ -> throwIO (RpcError (-32601) ("Method not found: " <> m))
dispatch _ _ = pure (errorReply Nothing (-32600) "Invalid Request")

rpc :: Env -> B.ByteString -> IO B.ByteString
rpc env body = case parseJson body of
  Nothing -> pure (errorReply Nothing (-32700) "Parse error")
  Just (JArr items)
    | null items || length items > 100 -> pure (errorReply Nothing (-32600) "Invalid Request: batch must hold 1 to 100 requests")
    | otherwise -> do
        replies <- mapM (dispatch env) items
        pure (B.concat ["[", B.intercalate "," replies, "]"])
  Just v -> dispatch env v

-- ---- server --------------------------------------------------------------------------

handleConn :: Env -> Sock -> IO ()
handleConn env fd = do
  r <- try (readRequest fd)
  case r of
    Right (Request "POST" "/" body) -> rpc env body >>= respond fd 200 "OK" True
    Right (Request "POST" _ _) -> respond fd 404 "Not Found" False ""
    Right _ -> respond fd 405 "Method Not Allowed" False ""
    Left (e :: SomeException)
      | Just TooLarge <- fromException e -> respond fd 413 "Payload Too Large" False "" >> drain fd
      | Just BadRequest <- fromException e -> respond fd 400 "Bad Request" False ""
      | otherwise -> pure ()
  `catch` \(_ :: SomeException) -> pure ()

usage :: String -> IO a
usage msg = do
  hPutStrLn stderr (msg ++ "\nusage: onlyblocks [--bind HOST:PORT] [--base-url URL]")
  exitWith (ExitFailure 2)

parseArgs :: [String] -> (String, String) -> IO (String, String)
parseArgs [] acc = pure acc
parseArgs ("--bind" : v : rest) (_, u) = parseArgs rest (v, u)
parseArgs ("--base-url" : v : rest) (b, _) = parseArgs rest (b, v)
parseArgs (a : rest) (b, u)
  | "--bind=" `isPrefixOf` a = parseArgs rest (drop 7 a, u)
  | "--base-url=" `isPrefixOf` a = parseArgs rest (b, drop 11 a)
  | otherwise = usage ("unknown or incomplete argument: " ++ a)

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  envBind <- lookupEnv "ONLYBLOCKS_BIND"
  envUrl <- lookupEnv "OLD_FAITHFUL_BASE_URL"
  args <- getArgs
  (bind, url) <- parseArgs args (fromMaybe "127.0.0.1:8899" envBind, fromMaybe "https://files.old-faithful.net" envUrl)
  base <- either (\e -> usage ("invalid --base-url " ++ show url ++ ": " ++ e)) pure (parseBaseUrl url)
  (host, port) <- case break (== ':') (reverse bind) of
    (p, ':' : h) | not (null p) -> pure (unbracket (reverse h), reverse p)
    _ -> usage ("invalid --bind " ++ show bind)
  lfd <- listenOn host port `catch` \(e :: SomeException) -> do
    hPutStrLn stderr ("cannot listen on " ++ bind ++ ": " ++ show e)
    exitWith (ExitFailure 1)
  seed <- getMonotonicTimeNSec
  env <- Env base <$> newLru 100000 <*> newLru 100000 <*> newQSem 32 <*> newIORef (seed .|. 1)
  mainThread <- myThreadId
  forM_ [sigTERM, sigINT] $ \s -> installHandler s (CatchOnce (throwTo mainThread ExitSuccess)) Nothing
  putStrLn ("onlyblocks/haskell listening on " ++ bind ++ " (archive " ++ bUrl base ++ ")")
  acceptLoop lfd (handleConn env)
  where unbracket h = case h of
          ('[' : rest) | not (null rest), last rest == ']' -> init rest
          _ -> h

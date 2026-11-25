{-# LANGUAGE ForeignFunctionInterface, OverloadedStrings, ScopedTypeVariables #-}
-- | Networking without the @network@ package: a minimal POSIX socket FFI on
--   non-blocking descriptors (GHC's IO manager does the waiting), HTTP/1.1
--   framing for the inbound server, and the outbound Range client.
module Net
  ( Sock, listenOn, acceptLoop, closeSock
  , Request (..), readRequest, respond, drain, maxBody, TooLarge (..), BadRequest (..)
  , Base (..), parseBaseUrl, Reply (..), NetError (..), attempt, retryDelay
  ) where

import Control.Concurrent (forkIO, threadDelay, threadWaitRead, threadWaitWrite)
import Control.Exception
import Control.Monad
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Char (isDigit, toLower)
import Data.IORef
import Data.Maybe (fromMaybe, mapMaybe)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word
import Foreign.C.Error
import Foreign.C.String (withCString)
import Foreign.C.Types
import Foreign.Marshal.Alloc (allocaBytes, callocBytes, free)
import Foreign.Ptr
import Foreign.Storable
import GHC.Conc (closeFdWith)
import System.Info (os)
import System.IO (hClose)
import System.Posix.IO (FdOption (..), closeFd, setFdOption)
import System.Posix.Types (CSsize (..), Fd (..))
import System.Process
import System.Timeout (timeout)

-- ---- POSIX socket FFI ------------------------------------------------------------

foreign import ccall unsafe "socket" c_socket :: CInt -> CInt -> CInt -> IO CInt
foreign import ccall unsafe "bind" c_bind :: CInt -> Ptr () -> CUInt -> IO CInt
foreign import ccall unsafe "listen" c_listen :: CInt -> CInt -> IO CInt
foreign import ccall unsafe "accept" c_accept :: CInt -> Ptr () -> Ptr CUInt -> IO CInt
foreign import ccall unsafe "connect" c_connect :: CInt -> Ptr () -> CUInt -> IO CInt
foreign import ccall unsafe "recv" c_recv :: CInt -> Ptr Word8 -> CSize -> CInt -> IO CSsize
foreign import ccall unsafe "send" c_send :: CInt -> Ptr Word8 -> CSize -> CInt -> IO CSsize
foreign import ccall unsafe "shutdown" c_shutdown :: CInt -> CInt -> IO CInt
foreign import ccall unsafe "setsockopt" c_setsockopt :: CInt -> CInt -> CInt -> Ptr CInt -> CUInt -> IO CInt
foreign import ccall unsafe "getsockopt" c_getsockopt :: CInt -> CInt -> CInt -> Ptr CInt -> Ptr CUInt -> IO CInt
foreign import ccall safe "getaddrinfo" c_getaddrinfo :: Ptr CChar -> Ptr CChar -> Ptr () -> Ptr (Ptr ()) -> IO CInt
foreign import ccall unsafe "freeaddrinfo" c_freeaddrinfo :: Ptr () -> IO ()

type Sock = CInt

darwin :: Bool
darwin = os == "darwin"

solSocket, soReuseAddr, soError :: CInt
solSocket = if darwin then 0xffff else 1
soReuseAddr = if darwin then 0x0004 else 2
soError = if darwin then 0x1007 else 4

-- | Resolve with getaddrinfo; returns (family, raw sockaddr bytes), IPv4 first.
resolve :: String -> String -> Bool -> IO (CInt, B.ByteString)
resolve host port passive = do
  hints <- callocBytes 64
  (pokeByteOff hints 0 (if passive then 1 else 0 :: CInt) >> pokeByteOff hints 8 (1 :: CInt))
    `onException` free hints
  found <- withCString host $ \h -> withCString port $ \p -> alloca' $ \res -> do
    rc <- c_getaddrinfo h p hints res
    free hints
    if rc /= 0 then pure [] else do
      first <- peek res
      let walk q | q == nullPtr = pure []
                 | otherwise = do
                     fam <- peekByteOff q 4 :: IO CInt
                     len <- peekByteOff q 16 :: IO CUInt
                     addr <- peekByteOff q (if darwin then 32 else 24) :: IO (Ptr Word8)
                     bytes <- B.packCStringLen (castPtr addr, fromIntegral len)
                     next <- peekByteOff q 40
                     ((fam, bytes) :) <$> walk next
      xs <- walk first
      c_freeaddrinfo first
      pure xs
  case [x | x@(2, _) <- found] ++ found of
    (x : _) -> pure x
    [] -> throwIO (Transport ("cannot resolve " ++ host))
  where alloca' f = allocaBytes 8 $ \p -> poke p nullPtr >> f p

nonBlocking :: CInt -> IO ()
nonBlocking fd = setFdOption (Fd fd) NonBlockingRead True >> setFdOption (Fd fd) CloseOnExec True

closeSock :: Sock -> IO ()
closeSock fd = closeFdWith closeFd (Fd fd) `catch` \(_ :: IOException) -> pure ()

newSocket :: CInt -> IO Sock
newSocket family = do
  fd <- throwErrnoIfMinus1 "socket" (c_socket family 1 0)
  nonBlocking fd
  pure fd

listenOn :: String -> String -> IO Sock
listenOn host port = do
  (family, addr) <- resolve host port True
  fd <- newSocket family
  with1 $ \one -> void (c_setsockopt fd solSocket soReuseAddr one 4)
  BU.unsafeUseAsCStringLen addr $ \(p, n) ->
    throwErrnoIfMinus1_ "bind" (c_bind fd (castPtr p) (fromIntegral n))
  throwErrnoIfMinus1_ "listen" (c_listen fd 1024)
  pure fd
  where with1 f = allocaBytes 4 $ \p -> poke p (1 :: CInt) >> f p

acceptLoop :: Sock -> (Sock -> IO ()) -> IO ()
acceptLoop lfd handler = forever $ do
  r <- c_accept lfd nullPtr nullPtr
  if r >= 0
    then do
      (nonBlocking r >> void (forkIO (handler r `finally` closeSock r))) `onException` closeSock r
    else do
      e <- getErrno
      if e == eAGAIN || e == eWOULDBLOCK then threadWaitRead (Fd lfd)
      else unless (e == eINTR || e == eCONNABORTED) (threadDelay 50000)

recvSome :: Sock -> Int -> IO B.ByteString
recvSome fd n = do
  r <- BI.createAndTrim n $ \p -> loop p
  pure r
  where
    loop p = do
      k <- c_recv fd p (fromIntegral n) 0
      if k >= 0 then pure (fromIntegral k) else do
        e <- getErrno
        if e == eAGAIN || e == eWOULDBLOCK then threadWaitRead (Fd fd) >> loop p
        else if e == eINTR then loop p
        else throwIO (Transport ("recv: errno " ++ show (let Errno c = e in c)))

sendAll :: Sock -> B.ByteString -> IO ()
sendAll fd bs
  | B.null bs = pure ()
  | otherwise = do
      k <- BU.unsafeUseAsCStringLen bs $ \(p, n) -> c_send fd (castPtr p) (fromIntegral n) 0
      if k >= 0 then sendAll fd (B.drop (fromIntegral k) bs) else do
        e <- getErrno
        if e == eAGAIN || e == eWOULDBLOCK then threadWaitWrite (Fd fd) >> sendAll fd bs
        else if e == eINTR then sendAll fd bs
        else throwIO (Transport ("send: errno " ++ show (let Errno c = e in c)))

connectTo :: String -> Int -> IO Sock
connectTo host port = do
  (family, addr) <- resolve host (show port) False
  fd <- newSocket family
  let go = do
        r <- BU.unsafeUseAsCStringLen addr $ \(p, n) -> c_connect fd (castPtr p) (fromIntegral n)
        when (r < 0) $ do
          e <- getErrno
          if e == eINPROGRESS || e == eAGAIN || e == eINTR then do
            threadWaitWrite (Fd fd)
            err <- allocaBytes 4 $ \v -> allocaBytes 4 $ \l -> do
              poke l (4 :: CUInt)
              _ <- c_getsockopt fd solSocket soError v l
              peek v
            when (err /= 0) $ throwIO (Transport ("connect: errno " ++ show err))
          else throwIO (Transport ("connect: errno " ++ show (let Errno c = e in c)))
  r <- timeout 10000000 go `onException` closeSock fd
  case r of
    Just () -> pure fd
    Nothing -> closeSock fd >> throwIO (Transport "connect timed out")

-- ---- buffered connection reader --------------------------------------------------

data Conn = Conn { cRecv :: IO B.ByteString, cBuf :: IORef B.ByteString }

newConn :: IO B.ByteString -> IO Conn
newConn r = Conn r <$> newIORef B.empty

-- | Next chunk of input (empty at EOF).
chunk :: Conn -> IO B.ByteString
chunk c = do
  b <- readIORef (cBuf c)
  if B.null b then cRecv c else writeIORef (cBuf c) B.empty >> pure b

unread :: Conn -> B.ByteString -> IO ()
unread c b = unless (B.null b) $ modifyIORef' (cBuf c) (b <>)

-- | The header block up to the blank line, or Nothing at EOF / when too large.
readHead :: Conn -> Int -> IO (Maybe B.ByteString)
readHead c limit = go B.empty
  where
    go acc = case B.breakSubstring "\r\n\r\n" acc of
      (h, rest) | not (B.null rest) -> unread c (B.drop 4 rest) >> pure (Just h)
      _ | B.length acc > limit -> pure Nothing
        | otherwise -> chunk c >>= \b -> if B.null b then pure Nothing else go (acc <> b)

-- | Exactly n bytes, or Nothing if the stream ends first.
readExactly :: Conn -> Int -> IO (Maybe B.ByteString)
readExactly c n = go [] 0
  where
    go acc got
      | got >= n = pure (Just (B.concat (reverse acc)))
      | otherwise = do
          b <- chunk c
          if B.null b then pure Nothing else do
            let (mine, extra) = B.splitAt (n - got) b
            unread c extra
            go (mine : acc) (got + B.length mine)

readLine :: Conn -> Int -> IO (Maybe B.ByteString)
readLine c limit = go B.empty
  where
    go acc = case BC.elemIndex '\n' acc of
      Just i -> unread c (B.drop (i + 1) acc) >> pure (Just (stripCR (B.take i acc)))
      Nothing | B.length acc > limit -> pure Nothing
              | otherwise -> chunk c >>= \b -> if B.null b then pure Nothing else go (acc <> b)
    stripCR s = fromMaybe s (B.stripSuffix "\r" s)

-- | First line and lower-cased headers.
parseHead :: B.ByteString -> (B.ByteString, [(B.ByteString, B.ByteString)])
parseHead h = case map (\l -> fromMaybe l (B.stripSuffix "\r" l)) (BC.lines h) of
  [] -> ("", [])
  (first : rest) -> (first, mapMaybe header rest)
  where header l = case BC.elemIndex ':' l of
          Nothing -> Nothing
          Just i -> Just (BC.map toLower (trim (B.take i l)), trim (B.drop (i + 1) l))

trim :: B.ByteString -> B.ByteString
trim = BC.dropWhile (`elem` (" \t" :: String)) . BC.dropWhileEnd (`elem` (" \t" :: String))

headers :: [(B.ByteString, B.ByteString)] -> B.ByteString -> [B.ByteString]
headers hs k = [v | (n, v) <- hs, n == k]

-- | Decimal length, saturating far above any cap; Nothing unless all digits.
decimal :: B.ByteString -> Maybe Int
decimal s
  | B.null s || not (BC.all isDigit s) = Nothing
  | otherwise = Just (BC.foldl' (\acc ch -> if acc > 1 `shiftL` 40 then acc else acc * 10 + fromEnum ch - 48) 0 s)

hexadecimal :: B.ByteString -> Maybe Int
hexadecimal s0
  | B.null s || B.length s > 12 || not (BC.all (`elem` ("0123456789abcdefABCDEF" :: String)) s) = Nothing
  | otherwise = Just (BC.foldl' (\acc ch -> acc * 16 + hexValue ch) 0 s)
  where s = trim (BC.takeWhile (/= ';') s0)
        hexValue ch | isDigit ch = fromEnum ch - 48
                    | otherwise = fromEnum (toLower ch) - 87

-- | A chunked body.  @tooBig@ is thrown as soon as more than @cap@ bytes arrive.
readChunked :: Exception e => Conn -> Int -> e -> IO B.ByteString
readChunked c cap tooBig = go [] 0
  where
    bad = throwIO (Transport "malformed chunked body")
    go acc total = do
      line <- readLine c 4096 >>= maybe bad pure
      case hexadecimal line of
        Nothing -> bad
        Just 0 -> trailers (0 :: Int) >> pure (B.concat (reverse acc))
        Just n -> do
          when (total + n > cap) $ throwIO tooBig
          body <- readExactly c n >>= maybe bad pure
          end <- readLine c 2 >>= maybe bad pure
          unless (B.null end) bad
          go (body : acc) (total + n)
    trailers k = do
      line <- readLine c 4096 >>= maybe bad pure
      when (k > 100) bad
      unless (B.null line) (trailers (k + 1))

-- ---- inbound ----------------------------------------------------------------------

data Request = Request { reqMethod :: B.ByteString, reqTarget :: B.ByteString, reqBody :: B.ByteString }

data TooLarge = TooLarge deriving Show
instance Exception TooLarge
data BadRequest = BadRequest deriving Show
instance Exception BadRequest

maxBody :: Int
maxBody = 1024 * 1024

readRequest :: Sock -> IO Request
readRequest fd = do
  c <- newConn (recvSome fd 65536)
  r <- timeout 10000000 $ do
    h <- readHead c 65536 >>= maybe (throwIO BadRequest) pure
    let (first, hs) = parseHead h
    (meth, target) <- case BC.words first of
      (m : t : _) -> pure (m, t)
      _ -> throwIO BadRequest
    body <-
      if meth /= "POST" then pure B.empty
      else case headers hs "transfer-encoding" of
        (te : _) -> do
          when (BC.map toLower te /= "chunked" || not (null (headers hs "content-length"))) $ throwIO BadRequest
          readChunked c maxBody TooLarge `catch` \(_ :: NetError) -> throwIO BadRequest
        [] -> case headers hs "content-length" of
          [] -> pure B.empty
          [cl] -> case decimal cl of
            Nothing -> throwIO BadRequest
            Just n | n > maxBody -> throwIO TooLarge
                   | otherwise -> readExactly c n >>= maybe (throwIO BadRequest) pure
          _ -> throwIO BadRequest
    pure (Request meth target body)
  maybe (throwIO BadRequest) pure r

respond :: Sock -> Int -> B.ByteString -> Bool -> B.ByteString -> IO ()
respond fd status reason json body = sendAll fd $ B.concat
  [ "HTTP/1.1 ", BC.pack (show status), " ", reason, "\r\n"
  , if json then "Content-Type: application/json\r\n" else ""
  , "Content-Length: ", BC.pack (show (B.length body)), "\r\nConnection: close\r\n\r\n", body ]

-- | After an early error reply, discard what the client is still sending so
--   closing does not reset the reply away.
drain :: Sock -> IO ()
drain fd = do
  _ <- c_shutdown fd 1
  let go n = when (n < 4 * maxBody) $ do
        b <- recvSome fd 65536
        unless (B.null b) (go (n + B.length b))
  void (timeout 1000000 (go 0)) `catch` \(_ :: SomeException) -> pure ()

-- ---- outbound ------------------------------------------------------------------------

data NetError = Transport String | Fatal String deriving Show
instance Exception NetError

data Base = Base { bScheme :: String, bHost :: String, bPort :: Int, bPrefix :: String, bUrl :: String }

parseBaseUrl :: String -> Either String Base
parseBaseUrl raw = do
  let s = reverse (dropWhile (== '/') (reverse (strip raw)))
      strip = reverse . dropWhile (`elem` (" \t\r\n" :: String)) . reverse . dropWhile (`elem` (" \t\r\n" :: String))
  (scheme, rest) <- case break (== ':') s of
    (sc, ':' : '/' : '/' : r) -> Right (map toLower sc, r)
    _ -> Left "base URL needs an http:// or https:// scheme"
  unless (scheme == "http" || scheme == "https") $ Left "base URL scheme must be http or https"
  let (authority0, prefix) = break (== '/') rest
      authority = case break (== '@') (reverse authority0) of
        (h, '@' : _) -> reverse h
        _ -> authority0
      dflt = if scheme == "https" then 443 else 80
  (host, port) <- case authority of
    ('[' : v6) -> case break (== ']') v6 of
      (h, "]") -> Right (h, dflt)
      (h, ']' : ':' : p) | not (null p), all isDigit p -> Right (h, read p)
      _ -> Left "bad IPv6 authority"
    _ -> case break (== ':') (reverse authority) of
      (p, ':' : h) | not (null p), all isDigit (reverse p) -> Right (reverse h, read (reverse p))
                   | otherwise -> Left "bad port"
      _ -> Right (authority, dflt)
  when (null host) $ Left "base URL has no host"
  when (port <= 0 || port > 65535) $ Left "bad port"
  pure (Base scheme host port prefix s)

data Reply = Partial B.ByteString | Status Int (Maybe B.ByteString)

userAgent :: B.ByteString
userAgent = "onlyblocks/haskell"

-- | Parse an upstream response: a status, then a 206 body bounded by @cap@.
readResponse :: Conn -> Int -> Int -> IO Reply
readResponse c size cap = do
  h <- readHead c 65536 >>= maybe (throwIO (Transport "connection closed in headers")) pure
  let (first, hs) = parseHead h
  status <- case BC.words first of
    (v : code : _) | "HTTP/" `B.isPrefixOf` v, Just n <- decimal code -> pure n
    _ -> throwIO (Transport "bad status line")
  if status /= 206 then pure (Status status (case headers hs "retry-after" of { (v : _) -> Just v; _ -> Nothing })) else do
    let tooBig = Fatal "archive body exceeds range cap"
        chunked = any (\te -> "chunked" `elem` map (trim . BC.map toLower) (BC.split ',' te)) (headers hs "transfer-encoding")
    body <-
      if chunked then readChunked c cap tooBig
      else case headers hs "content-length" of
        [] -> let go acc got = do
                    b <- chunk c
                    let got' = got + B.length b
                    when (got' > cap) $ throwIO tooBig
                    if B.null b then pure (B.concat (reverse acc)) else go (b : acc) got'
              in go [] 0
        [cl] -> case decimal cl of
          Nothing -> throwIO (Fatal "invalid Content-Length")
          Just n | n > cap -> throwIO tooBig
                 | otherwise -> readExactly c n >>= maybe (throwIO (Transport "connection closed before body complete")) pure
        _ -> throwIO (Fatal "duplicate Content-Length")
    when (B.length body /= size) $ throwIO (Fatal "archive range body has wrong length")
    pure (Partial body)

-- | One Range GET attempt, bounded by the 60 s per-attempt timeout.
attempt :: Base -> String -> String -> Int -> Int -> IO Reply
attempt base path range size cap = do
  r <- timeout 60000000 (if bScheme base == "https" then viaCurl else viaSocket)
  maybe (throwIO (Transport "attempt timed out")) pure r
  where
    hostHeader = (if ':' `elem` bHost base then "[" ++ bHost base ++ "]" else bHost base)
                 ++ (if bPort base == 80 || bPort base == 443 then "" else ':' : show (bPort base))
    viaSocket = bracket (connectTo (bHost base) (bPort base)) closeSock $ \fd -> do
      sendAll fd $ BC.pack $ concat
        [ "GET ", path, " HTTP/1.1\r\nHost: ", hostHeader, "\r\nRange: ", range
        , "\r\nUser-Agent: ", BC.unpack userAgent, "\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n" ]
      c <- newConn (recvSome fd 65536)
      readResponse c size cap
    -- HTTPS: the OS curl binary does only the TLS transport.  --raw -i makes
    -- its stdout the raw HTTP/1.1 response, parsed exactly like a socket's.
    viaCurl = do
      let url = "https://" ++ hostHeader ++ path
          args = [ "-sS", "--http1.1", "--raw", "-i", "--suppress-connect-headers"
                 , "--connect-timeout", "10", "--max-time", "60"
                 , "-H", "Range: " ++ range, "-H", "User-Agent: " ++ BC.unpack userAgent
                 , "-H", "Accept-Encoding: identity", "-H", "Connection: close", "--", url ]
          spec = (proc "curl" args) { std_in = NoStream, std_out = CreatePipe, std_err = Inherit }
          start = createProcess spec `catch` \(e :: IOException) -> throwIO (Transport (show e))
          stop (_, out, _, ph) = do
            mapM_ hClose out `catch` \(_ :: IOException) -> pure ()
            terminateProcess ph
            void (waitForProcess ph) `catch` \(_ :: IOException) -> pure ()
      bracket start stop $ \(_, out, _, _) -> case out of
        Nothing -> throwIO (Transport "curl has no stdout")
        Just h -> do
          c <- newConn (B.hGetSome h 65536 `catch` \(e :: IOException) -> throwIO (Transport (show e)))
          readResponse c size cap

-- ---- Retry-After --------------------------------------------------------------------

daysFromCivil :: Int -> Int -> Int -> Int
daysFromCivil y0 m d = era * 146097 + doe - 719468
  where
    y = if m <= 2 then y0 - 1 else y0
    era = (if y >= 0 then y else y - 399) `div` 400
    yoe = y - era * 400
    mp = (m + 9) `mod` 12
    doy = (153 * mp + 2) `div` 5 + d - 1
    doe = yoe * 365 + yoe `div` 4 - yoe `div` 100 + doy

-- | IMF-fixdate (e.g. "Sun, 06 Nov 1994 08:49:37 GMT") to Unix seconds.
httpDate :: B.ByteString -> Maybe Double
httpDate s = case BC.words s of
  [_, d, mon, y, hms, _] -> do
    m <- lookup (BC.map toLower mon) (zip ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"] [1 ..])
    [dd, yy] <- mapM decimal [d, y]
    [hh, mi, ss] <- mapM decimal (BC.split ':' hms)
    pure (fromIntegral (daysFromCivil yy m dd * 86400 + hh * 3600 + mi * 60 + ss))
  _ -> Nothing

-- | Seconds to wait before retry number @n@ (0-based).
retryDelay :: Maybe B.ByteString -> Int -> Double -> IO Double
retryDelay retryAfter n jitter = case trim <$> retryAfter of
  Just v | Just secs <- decimal v -> pure (min 10 (fromIntegral secs))
         | Just t <- httpDate v -> do
             now <- realToFrac <$> getPOSIXTime
             pure (max 0 (min 10 (t - now)))
  _ -> pure (min 10 (0.2 * 2 ^^ min n 30) * (0.5 + 0.5 * jitter))

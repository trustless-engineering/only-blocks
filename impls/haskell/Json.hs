{-# LANGUAGE OverloadedStrings #-}
-- | RFC 8259 JSON: a depth-limited parser (number tokens keep their source
--   text) built from the same 'P' combinators as the wire decoders, and a
--   'Builder'-based printer.
module Json
  ( JV (..), parseJson, member
  , J (..), render, int, word, int64, str
  ) where

import Control.Monad
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as BB
import Data.Char (chr)
import Data.Int
import Data.Word
import Parse

-- | Parsed request JSON.  Object members are kept last-first, so 'lookup'
--   finds the final duplicate key, as the reference does.
data JV = JNull | JBool !Bool | JNum !B.ByteString | JStr !B.ByteString | JArr [JV] | JObj [(B.ByteString, JV)]
  deriving (Eq)

member :: B.ByteString -> JV -> Maybe JV
member k (JObj kvs) = lookup k kvs
member _ _ = Nothing

maxDepth :: Int
maxDepth = 128

parseJson :: B.ByteString -> Maybe JV
parseJson s
  | not (B.isValidUtf8 s) = Nothing
  | otherwise = either (const Nothing) Just (runP (value 1 <* ws) s)

ws :: P ()
ws = void (takeWhileP (\c -> c == 32 || c == 9 || c == 10 || c == 13))

expect :: Word8 -> P ()
expect c = u8 >>= \b -> unless (b == c) (failP "unexpected character")

literal :: B.ByteString -> JV -> P JV
literal word v = takeBytes (B.length word) >>= \w -> if w == word then pure v else failP "bad literal"

value :: Int -> P JV
value depth = do
  when (depth > maxDepth) $ failP "nesting too deep"
  ws
  c <- peekByte
  case c of
    123 -> u8 >> ws >> peekByte >>= \c' -> if c' == 125 then u8 >> pure (JObj []) else JObj <$> members []
    91 -> u8 >> ws >> peekByte >>= \c' -> if c' == 93 then u8 >> pure (JArr []) else JArr . reverse <$> elements []
    34 -> JStr <$> string
    116 -> literal "true" (JBool True)
    102 -> literal "false" (JBool False)
    110 -> literal "null" JNull
    _ | c == 45 || (c >= 48 && c <= 57) -> JNum <$> number
      | otherwise -> failP "unexpected character"
  where
    members acc = do
      ws
      k <- string
      ws >> expect 58
      v <- value (depth + 1)
      ws
      sep <- u8
      case sep of
        44 -> members ((k, v) : acc)
        125 -> pure ((k, v) : acc)
        _ -> failP "expected , or }"
    elements acc = do
      v <- value (depth + 1)
      ws
      sep <- u8
      case sep of
        44 -> elements (v : acc)
        93 -> pure (v : acc)
        _ -> failP "expected , or ]"

isDigit :: Word8 -> Bool
isDigit c = c >= 48 && c <= 57

number :: P B.ByteString
number = do
  start <- position
  peekMaybe >>= \c -> when (c == Just 45) (void u8)
  first <- u8
  unless (isDigit first) $ failP "bad number"
  when (first /= 48) $ void (takeWhileP isDigit)
  peekMaybe >>= \c -> when (c == Just 46) (u8 >> digits)
  peekMaybe >>= \c -> when (c == Just 101 || c == Just 69) $ do
    void u8
    peekMaybe >>= \s -> when (s == Just 43 || s == Just 45) (void u8)
    digits
  end <- position
  slice start end
  where digits = takeWhileP isDigit >>= \d -> when (B.null d) (failP "bad number")

string :: P B.ByteString
string = expect 34 >> (B.concat <$> go [])
  where
    plain c = c /= 34 && c /= 92 && c >= 0x20
    go acc = do
      run <- takeWhileP plain
      c <- u8
      case c of
        34 -> pure (reverse (run : acc))
        92 -> do
          e <- u8
          piece <- case e of
            34 -> pure "\""
            92 -> pure "\\"
            47 -> pure "/"
            98 -> pure "\b"
            102 -> pure "\f"
            110 -> pure "\n"
            114 -> pure "\r"
            116 -> pure "\t"
            117 -> unicode
            _ -> failP "bad escape"
          go (piece : run : acc)
        _ -> failP "control character in string"
    hex4 = do
      h <- takeBytes 4
      foldM (\acc d -> (\v -> acc * 16 + v) <$> hexDigit d) 0 (B.unpack h)
    hexDigit d
      | d >= 48 && d <= 57 = pure (fromIntegral d - 48)
      | d >= 97 && d <= 102 = pure (fromIntegral d - 87)
      | d >= 65 && d <= 70 = pure (fromIntegral d - 55)
      | otherwise = failP "bad hex digit"
    unicode = do
      u <- hex4 :: P Int
      cp <- if u >= 0xD800 && u <= 0xDBFF
        then do
          expect 92 >> expect 117
          lo <- hex4
          unless (lo >= 0xDC00 && lo <= 0xDFFF) $ failP "lone surrogate"
          pure (0x10000 + ((u - 0xD800) `shiftL` 10) + (lo - 0xDC00))
        else if u >= 0xDC00 && u <= 0xDFFF then failP "lone surrogate" else pure u
      pure (B.toStrict (BB.toLazyByteString (BB.charUtf8 (chr cp))))

-- ---- output ------------------------------------------------------------------

data J = JNull' | JBool' !Bool | JRaw !BB.Builder | JDouble !Double | JStr' !B.ByteString | JArr' [J] | JObj' [(B.ByteString, J)]

int :: Int -> J
int = JRaw . BB.intDec

word :: Word64 -> J
word = JRaw . BB.word64Dec

int64 :: Int64 -> J
int64 = JRaw . BB.int64Dec

str :: B.ByteString -> J
str = JStr'

escape :: B.ByteString -> BB.Builder
escape s = BB.char7 '"' <> go s <> BB.char7 '"'
  where
    safe c = c >= 0x20 && c /= 34 && c /= 92
    go t = let (run, rest) = B.span safe t
           in BB.byteString run <> case B.uncons rest of
                Nothing -> mempty
                Just (c, more) -> esc c <> go more
    esc 34 = "\\\""
    esc 92 = "\\\\"
    esc 10 = "\\n"
    esc 13 = "\\r"
    esc 9 = "\\t"
    esc c = "\\u00" <> BB.word8HexFixed c

render :: J -> BB.Builder
render JNull' = "null"
render (JBool' b) = if b then "true" else "false"
render (JRaw b) = b
render (JDouble d)
  | isNaN d || isInfinite d = "null"
  | otherwise = BB.string7 (show d)          -- shortest round-trip digits
render (JStr' s) = escape s
render (JArr' xs) = BB.char7 '[' <> commas (map render xs) <> BB.char7 ']'
render (JObj' kvs) = BB.char7 '{' <> commas [escape k <> BB.char7 ':' <> render v | (k, v) <- kvs] <> BB.char7 '}'

commas :: [BB.Builder] -> BB.Builder
commas [] = mempty
commas (x : xs) = x <> mconcat [BB.char7 ',' <> y | y <- xs]

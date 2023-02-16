{-# LANGUAGE TemplateHaskell, FlexibleInstances #-}

import System.IO.Unsafe (unsafePerformIO)

import Test.QuickCheck
import Test.QuickCheck.Monadic
-- import Test.Framework
-- import Test.Framework.TH
-- import Test.Framework.Providers.QuickCheck2

import Crypto.Paillier
import qualified Crypto.PaillierRealNum as CPRN


instance Show (IO (PubKey, PrvKey)) where
    show a = show (unsafePerformIO a)

instance Arbitrary (IO (PubKey, PrvKey)) where
    arbitrary = do
        nBits <- frequency [(2,return 512), (1,return 1024)]
        return $ genKey nBits


-- prop_fixed_plaintext :: IO (PubKey, PrvKey) -> Property 
-- prop_fixed_plaintext keys = monadicIO $ do 
--     (pub, prv) <- run keys
--     let plaintext = 37
--     ciphertext <- run $ encrypt pub plaintext
--     let plaintext' = decrypt prv pub ciphertext
--     assert $ plaintext == plaintext'

doubleEq :: Double -> Double -> Double -> Bool
doubleEq eps op1 op2 = abs (op1 - op2) <= eps

prop_realnum_test :: IO (PubKey, PrvKey) -> Double -> Property
prop_realnum_test keys num = monadicIO $ do
    (pub, prv) <- run keys
    ct <- run $ CPRN.encrypt pub num
    let pt = CPRN.decrypt prv pub ct

    monitor $ whenFail $ do
        putStrLn $ concat ["plaintext:  ", show num]
        putStrLn $ concat ["ciphertext: ", show ct]
        putStrLn $ concat ["plaintext2: ", show pt]

    assert $ doubleEq 0.001 pt num

prop_realnum_test_mul :: IO (PubKey, PrvKey) -> Double -> Double -> Property
prop_realnum_test_mul keys op1 op2 = monadicIO $ do
    (pub, prv) <- run keys
    ct <- run $ CPRN.encrypt pub op1
    let ct2 = CPRN.homoMul pub ct op2
        pt  = CPRN.decrypt prv pub ct2

    monitor $ whenFail $ do
        putStrLn $ concat ["op1:         ", show op1]
        putStrLn $ concat ["op2:         ", show op2]
        putStrLn $ concat ["op1 * op2:   ", show (op1 * op2)]
        putStrLn $ concat ["ciphertext:  ", show ct]
        putStrLn $ concat ["ciphertext2: ", show ct2]
        putStrLn $ concat ["plaintext2:  ", show pt]

    assert $ doubleEq 0.1 pt (op1 * op2)

prop_realnum_test_sub :: IO (PubKey, PrvKey) -> Double -> Double -> Property
prop_realnum_test_sub keys op1 op2 = monadicIO $ do
    (pub, prv) <- run keys
    ct1 <- run $ CPRN.encrypt pub op1
    ct2 <- run $ CPRN.encrypt pub op2
    let ct3 = CPRN.homoSub pub ct1 ct2
        pt  = CPRN.decrypt prv pub ct3

    monitor $ whenFail $ do
        putStrLn $ concat ["op1:         ", show op1]
        putStrLn $ concat ["op2:         ", show op2]
        putStrLn $ concat ["op1 - op2:   ", show (op1 - op2)]
        putStrLn $ concat ["ciphertext:  ", show ct1]
        putStrLn $ concat ["ciphertext2: ", show ct2]
        putStrLn $ concat ["plaintext2:  ", show pt]

    assert $ doubleEq 0.001 pt (op1 - op2)

prop_realnum_test_add :: IO (PubKey, PrvKey) -> Double -> Double -> Property
prop_realnum_test_add keys op1 op2 = monadicIO $ do
    (pub, prv) <- run keys
    ct1 <- run $ CPRN.encrypt pub op1
    ct2 <- run $ CPRN.encrypt pub op2
    let ct3 = CPRN.homoAdd pub ct1 ct2
        pt  = CPRN.decrypt prv pub ct3

    monitor $ whenFail $ do
        putStrLn $ concat ["op1:         ", show op1]
        putStrLn $ concat ["op2:         ", show op2]
        putStrLn $ concat ["op1 + op2:   ", show (op1 + op2)]
        putStrLn $ concat ["ciphertext:  ", show ct1]
        putStrLn $ concat ["ciphertext2: ", show ct2]
        putStrLn $ concat ["plaintext2:  ", show pt]

    assert $ doubleEq 0.002 pt (op1 + op2)

main :: IO ()
main = do
    quickCheck $ withMaxSuccess 10000 prop_realnum_test
    quickCheck $ withMaxSuccess 10000 prop_realnum_test_add
    quickCheck $ withMaxSuccess 10000 prop_realnum_test_mul
    quickCheck $ withMaxSuccess 10000 prop_realnum_test_sub

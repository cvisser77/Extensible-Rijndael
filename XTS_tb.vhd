-------------------------------------------------------------------------------
-- Title      : AES/XTS test bench
-- Project    : Extensible Rijndael Block Cipher using VHDL-2008
-------------------------------------------------------------------------------
-- File       : XTS_tb.vhd
-- Author     : Clyde R. Visser  <Clyde.R.Visser@gmail.com>
-- Company    : eXpertroniX
-- Created    : 2023-04-23
-- Last update: 2023-04-29
-- Platform   : Modelsim
-- Standard   : VHDL'08, Math Packages
-------------------------------------------------------------------------------
-- Description: AES/XTS test bench
-------------------------------------------------------------------------------
--
-- Copyright 2023 eXpertroniX
-- SPDX-License-Identifier: Apache-2.0 WITH SHL-2.1
--
-- Licensed under the Solderpad Hardware License v 2.1 (the “License”); you may
-- not use this file except in compliance with the License, or, at your option,
-- the Apache License version 2.0. You may obtain a copy of the License at
-- https://solderpad.org/licenses/SHL-2.1/
--
-- Unless required by applicable law or agreed to in writing, any work
-- distributed under the License is distributed on an “AS IS” BASIS, WITHOUT
-- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
-- License for the specific language governing permissions and limitations
-- under the License.
--
-------------------------------------------------------------------------------
-- Revisions  :
-- Date        Version  Author  Description
-- 2023-04-23  1.0      Clyde   Created
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use work.Rijndael.all;
use work.testbench_utils.all;

entity testbench is
end entity testbench;

architecture behavior of testbench is

  constant WordSize  : natural  := 8;
  constant WordRange : natural  := 2**WordSize;
  subtype WordType is FiniteField(WordSize-1 downto 0);
  constant Word      : WordType := (others => '0');

  constant Sbox    : SboxType(0 to 2**WordSize-1)(Word'range) := InitSbox(WordSize);
  constant InvSbox : SboxType(0 to 2**WordSize-1)(Word'range) := InitInvSbox(Sbox);


  ---------------------------------------------------------------------------
  -- test vectors taken from IEEE Std 1619-2007 Vector 10
  -- XTS-AES-256 applied for a data unit of 512 bytes
  ---------------------------------------------------------------------------
  constant Key1 : FiniteField(255 downto 0) :=
    x"2718281828459045235360287471352662497757247093699959574966967627";
  constant Key2 : FiniteField(255 downto 0) :=
    x"3141592653589793238462643383279502884197169399375105820974944592";
  constant DataUnitSequenceNumber : FiniteField(127 downto 0) :=
    x"ff000000000000000000000000000000";
  type TestVectorType is array (0 to 31, 0 to 1) of FiniteField(127 downto 0);
  constant TestVector : TestVectorType := (
    (x"000102030405060708090a0b0c0d0e0f", x"1c3b3a102f770386e4836c99e370cf9b"),
    (x"101112131415161718191a1b1c1d1e1f", x"ea00803f5e482357a4ae12d414a3e63b"),
    (x"202122232425262728292a2b2c2d2e2f", x"5d31e276f8fe4a8d66b317f9ac683f44"),
    (x"303132333435363738393a3b3c3d3e3f", x"680a86ac35adfc3345befecb4bb188fd"),
    (x"404142434445464748494a4b4c4d4e4f", x"5776926c49a3095eb108fd1098baec70"),
    (x"505152535455565758595a5b5c5d5e5f", x"aaa66999a72a82f27d848b21d4a741b0"),
    (x"606162636465666768696a6b6c6d6e6f", x"c5cd4d5fff9dac89aeba122961d03a75"),
    (x"707172737475767778797a7b7c7d7e7f", x"7123e9870f8acf1000020887891429ca"),
    (x"808182838485868788898a8b8c8d8e8f", x"2a3e7a7d7df7b10355165c8b9a6d0a7d"),
    (x"909192939495969798999a9b9c9d9e9f", x"e8b062c4500dc4cd120c0f7418dae3d0"),
    (x"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", x"b5781c34803fa75421c790dfe1de1834"),
    (x"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", x"f280d7667b327f6c8cd7557e12ac3a0f"),
    (x"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", x"93ec05c52e0493ef31a12d3d9260f79a"),
    (x"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf", x"289d6a379bc70c50841473d1a8cc81ec"),
    (x"e0e1e2e3e4e5e6e7e8e9eaebecedeeef", x"583e9645e07b8d9670655ba5bbcfecc6"),
    (x"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", x"dc3966380ad8fecb17b6ba02469a020a"),
    (x"000102030405060708090a0b0c0d0e0f", x"84e18e8f84252070c13e9f1f289be54f"),
    (x"101112131415161718191a1b1c1d1e1f", x"bc481457778f616015e1327a02b140f1"),
    (x"202122232425262728292a2b2c2d2e2f", x"505eb309326d68378f8374595c849d84"),
    (x"303132333435363738393a3b3c3d3e3f", x"f4c333ec4423885143cb47bd71c5edae"),
    (x"404142434445464748494a4b4c4d4e4f", x"9be69a2ffeceb1bec9de244fbe15992b"),
    (x"505152535455565758595a5b5c5d5e5f", x"11b77c040f12bd8f6a975a44a0f90c29"),
    (x"606162636465666768696a6b6c6d6e6f", x"a9abc3d4d893927284c58754cce29452"),
    (x"707172737475767778797a7b7c7d7e7f", x"9f8614dcd2aba991925fedc4ae74ffac"),
    (x"808182838485868788898a8b8c8d8e8f", x"6e333b93eb4aff0479da9a410e4450e0"),
    (x"909192939495969798999a9b9c9d9e9f", x"dd7ae4c6e2910900575da401fc07059f"),
    (x"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", x"645e8b7e9bfdef33943054ff84011493"),
    (x"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", x"c27b3429eaedb4ed5376441a77ed4385"),
    (x"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", x"1ad77f16f541dfd269d50d6a5f14fb0a"),
    (x"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf", x"ab1cbb4c1550be97f7ab4066193c4caa"),
    (x"e0e1e2e3e4e5e6e7e8e9eaebecedeeef", x"773dad38014bd2092fa755c824bb5e54"),
    (x"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", x"c4f36ffda9fcea70b9c6e693e148c151")
    );

begin

  process is
    variable T, PP, P, CC, C : FiniteField(127 downto 0);
    variable KeySchedule1, KeySchedule2 :
      KeyScheduleType(0 to 15-1)(0 to 4-1)(0 to 4-1)(7 downto 0) :=
      (others => (others => (others => (others => '0'))));
  begin

    KeySchedule1 := KeyExpand(Key1, KeySchedule1);
    KeySchedule2 := KeyExpand(Key2, KeySchedule2);

    -- Encryption test
    T := Encrypt(Sbox, KeySchedule2, DataUnitSequenceNumber);
    for i in TestVector'range(1) loop

      P  := TestVector(i, 0);
      PP := P + T;
      CC := Encrypt(Sbox, KeySchedule1, PP);
      C  := CC + T;

      assert C = TestVector(i, 1)
        report "Vector 10: Encryption fail !!!"
        severity failure;

      T := MultiplyByAlpha(T);

    end loop;  -- i

    -- Decryption test
    T := Encrypt(Sbox, KeySchedule2, DataUnitSequenceNumber);
    for i in TestVector'range(1) loop

      C  := TestVector(i, 1);
      CC := C + T;
      PP := Decrypt(InvSbox, KeySchedule1, CC);
      P  := PP + T;

      assert P = TestVector(i, 0)
        report "Vector 10: Decryption failure !!!"
        severity failure;

      T := MultiplyByAlpha(T);

    end loop;  -- i

    report "Vector 10: Passed XTS-AES-256 Encryption & Decryption tests.";

    wait;

  end process;


end architecture behavior;

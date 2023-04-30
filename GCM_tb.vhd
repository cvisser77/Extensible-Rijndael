-------------------------------------------------------------------------------
-- Title      : AES / GCM, Galois Counter Mode test bench
-- Project    : Extensible Rijndael Block Cipher using VHDL-2008
-------------------------------------------------------------------------------
-- File       : GCM_tb.vhd
-- Author     : Clyde R. Visser  <Clyde.R.Visser@gmail.com>
-- Company    : eXpertroniX
-- Created    : 2023-04-23
-- Last update: 2023-04-29
-- Platform   : Modelsim
-- Standard   : VHDL'08, Math Packages
-------------------------------------------------------------------------------
-- Description: AES / GCM, Galois Counter Mode test bench
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

  -- Len: 00000000000000000000000000000200
  constant Len : StateType(0 to 4-1)(0 to 4-1)(7 downto 0) := (
    0 => (0 => x"00", 1 => x"00", 2 => x"00", 3 => x"00"),  -- 00000000
    1 => (0 => x"00", 1 => x"00", 2 => x"00", 3 => x"00"),  -- 00000000
    2 => (0 => x"00", 1 => x"00", 2 => x"00", 3 => x"00"),  -- 00000000
    3 => (0 => x"00", 1 => x"00", 2 => x"02", 3 => x"00")   -- 00000200
    );

  -- Len: 00000000000000000000000000000000
  constant ZeroState : StateType(0 to 4-1)(0 to 4-1)(7 downto 0) := (others => (others => (others => '0')));

  -- T: b094dac5d93471bdec1a502270e3cc6c
  constant T : StateType(0 to 4-1)(0 to 4-1)(7 downto 0) := (
    0 => (0 => x"b0", 1 => x"94", 2 => x"da", 3 => x"c5"),  -- b094dac5
    1 => (0 => x"d9", 1 => x"34", 2 => x"71", 3 => x"bd"),  -- d93471bd
    2 => (0 => x"ec", 1 => x"1a", 2 => x"50", 3 => x"22"),  -- ec1a5022
    3 => (0 => x"70", 1 => x"e3", 2 => x"cc", 3 => x"6c")   -- 70e3cc6c
    );


  -- Test Case 15

  constant Key : KeyType(0 to 8-1)(0 to 4-1)(7 downto 0) := (
    0 => (0 => x"fe", 1 => x"ff", 2 => x"e9", 3 => x"92"),  -- feffe992
    1 => (0 => x"86", 1 => x"65", 2 => x"73", 3 => x"1c"),  -- 8665731c
    2 => (0 => x"6d", 1 => x"6a", 2 => x"8f", 3 => x"94"),  -- 6d6a8f94
    3 => (0 => x"67", 1 => x"30", 2 => x"83", 3 => x"08"),  -- 67308308
    4 => (0 => x"fe", 1 => x"ff", 2 => x"e9", 3 => x"92"),  -- feffe992
    5 => (0 => x"86", 1 => x"65", 2 => x"73", 3 => x"1c"),  -- 8665731c
    6 => (0 => x"6d", 1 => x"6a", 2 => x"8f", 3 => x"94"),  -- 6d6a8f94
    7 => (0 => x"67", 1 => x"30", 2 => x"83", 3 => x"08")   -- 67308308
    );

  type TestVectorType is array (natural range <>, natural range <>) of StateType;

  constant TestVector : TestVectorType(1 to 4, 0 to 1)(0 to 4-1)(0 to 4-1)(7 downto 0) :=
    (
      1 =>
      (
        0 =>
        -- d9313225f88406e5a55909c5aff5269a
        (0 => (0 => x"d9", 1 => x"31", 2 => x"32", 3 => x"25"),   -- d9313225
         1 => (0 => x"f8", 1 => x"84", 2 => x"06", 3 => x"e5"),   -- f88406e5
         2 => (0 => x"a5", 1 => x"59", 2 => x"09", 3 => x"c5"),   -- a55909c5
         3 => (0 => x"af", 1 => x"f5", 2 => x"26", 3 => x"9a")),  -- aff5269a
        1 =>
        -- 522dc1f099567d07f47f37a32a84427d
        (0 => (0 => x"52", 1 => x"2d", 2 => x"c1", 3 => x"f0"),   -- 522dc1f0
         1 => (0 => x"99", 1 => x"56", 2 => x"7d", 3 => x"07"),   -- 99567d07
         2 => (0 => x"f4", 1 => x"7f", 2 => x"37", 3 => x"a3"),   -- f47f37a3
         3 => (0 => x"2a", 1 => x"84", 2 => x"42", 3 => x"7d"))   -- 2a84427d
        ),
      2 =>
      (
        0 =>
        -- 86a7a9531534f7da2e4c303d8a318a72
        (0 => (0 => x"86", 1 => x"a7", 2 => x"a9", 3 => x"53"),   -- 86a7a953
         1 => (0 => x"15", 1 => x"34", 2 => x"f7", 3 => x"da"),   -- 1534f7da
         2 => (0 => x"2e", 1 => x"4c", 2 => x"30", 3 => x"3d"),   -- 2e4c303d
         3 => (0 => x"8a", 1 => x"31", 2 => x"8a", 3 => x"72")),  -- 8a318a72
        1 =>
        -- 643a8cdcbfe5c0c97598a2bd2555d1aa
        (0 => (0 => x"64", 1 => x"3a", 2 => x"8c", 3 => x"dc"),   -- 643a8cdc
         1 => (0 => x"bf", 1 => x"e5", 2 => x"c0", 3 => x"c9"),   -- bfe5c0c9
         2 => (0 => x"75", 1 => x"98", 2 => x"a2", 3 => x"bd"),   -- 7598a2bd
         3 => (0 => x"25", 1 => x"55", 2 => x"d1", 3 => x"aa"))   -- 2555d1aa
        ),
      3 =>
      (
        0 =>
        -- 1c3c0c95956809532fcf0e2449a6b525
        (0 => (0 => x"1c", 1 => x"3c", 2 => x"0c", 3 => x"95"),   -- 1c3c0c95
         1 => (0 => x"95", 1 => x"68", 2 => x"09", 3 => x"53"),   -- 95680953
         2 => (0 => x"2f", 1 => x"cf", 2 => x"0e", 3 => x"24"),   -- 2fcf0e24
         3 => (0 => x"49", 1 => x"a6", 2 => x"b5", 3 => x"25")),  -- 49a6b525
        1 =>
        -- 8cb08e48590dbb3da7b08b1056828838
        (0 => (0 => x"8c", 1 => x"b0", 2 => x"8e", 3 => x"48"),   -- 8cb08e48
         1 => (0 => x"59", 1 => x"0d", 2 => x"bb", 3 => x"3d"),   -- 590dbb3d
         2 => (0 => x"a7", 1 => x"b0", 2 => x"8b", 3 => x"10"),   -- a7b08b10
         3 => (0 => x"56", 1 => x"82", 2 => x"88", 3 => x"38"))   -- 56828838
        ),
      4 =>
      (
        0 =>
        -- b16aedf5aa0de657ba637b391aafd255
        (0 => (0 => x"b1", 1 => x"6a", 2 => x"ed", 3 => x"f5"),   -- b16aedf5
         1 => (0 => x"aa", 1 => x"0d", 2 => x"e6", 3 => x"57"),   -- aa0de657
         2 => (0 => x"ba", 1 => x"63", 2 => x"7b", 3 => x"39"),   -- ba637b39
         3 => (0 => x"1a", 1 => x"af", 2 => x"d2", 3 => x"55")),  -- 1aafd255
        1 =>
        -- c5f61e6393ba7a0abcc9f662898015ad
        (0 => (0 => x"c5", 1 => x"f6", 2 => x"1e", 3 => x"63"),   -- c5f61e63
         1 => (0 => x"93", 1 => x"ba", 2 => x"7a", 3 => x"0a"),   -- 93ba7a0a
         2 => (0 => x"bc", 1 => x"c9", 2 => x"f6", 3 => x"62"),   -- bcc9f662
         3 => (0 => x"89", 1 => x"80", 2 => x"15", 3 => x"ad"))   -- 898015ad
        )
      );

  constant Sbox : SboxType(0 to 2**WordSize-1)(Word'range) := InitSbox(WordSize);

begin


  -----------------------------------------------------------------------------
  -- Test Case 15
  -----------------------------------------------------------------------------
  process is
    variable KeySchedule : KeyScheduleType(0 to 15-1)(0 to 4-1)(0 to 4-1)(7 downto 0) :=
      (others => (others => (others => (others => '0'))));
    constant InitializationVector : FiniteField :=
      (x"cafebabefacedbaddecaf888");
    variable D0, H                  : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable Y0, Y1, Y2, Y3, Y4     : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable E0, E1, E2, E3, E4     : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable X1, X2, X3, X4, X5, X6 : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
  begin  -- process
    KeySchedule := KeyExpand(Key, KeySchedule);

    H := GenHashSubkey(Sbox, KeySchedule);

    Y0 := InitCounter0(InitializationVector, H);
    Y1 := incr(Y0);
    Y2 := incr(Y1);
    Y3 := incr(Y2);
    Y4 := incr(Y3);

    E0 := Encrypt(Sbox, KeySchedule, Y0);
    E1 := Encrypt(Sbox, KeySchedule, Y1);
    E2 := Encrypt(Sbox, KeySchedule, Y2);
    E3 := Encrypt(Sbox, KeySchedule, Y3);
    E4 := Encrypt(Sbox, KeySchedule, Y4);

    X1 := E1 + TestVector(1, 0);
    assert X1 = TestVector(1, 1) report "Test Case 15: X1 Encrypt failure !!!" severity failure;

    X2 := E2 + TestVector(2, 0);
    assert X2 = TestVector(2, 1) report "Test Case 15: X2 Encrypt failure !!!" severity failure;

    X3 := E3 + TestVector(3, 0);
    assert X3 = TestVector(3, 1) report "Test Case 15: X3 Encrypt failure !!!" severity failure;

    X4 := E4 + TestVector(4, 0);
    assert X4 = TestVector(4, 1) report "Test Case 15: X4 Encrypt failure !!!" severity failure;

    X1 := MultH(X1, H);
    X1 := MultH(X1 + X2, H);
    X1 := MultH(X1 + X3, H);
    X1 := MultH(X1 + X4, H);
    X1 := MultH(X1 + Len, H) + E0;

    assert T = X1 report "Test Case 15: GCM authentication failure !!!" severity failure;

    report "Test Case 15: GCM encryption passed.";

    wait;
  end process;


  -----------------------------------------------------------------------------
  -- Test Case 17 for Y0 (IV'length is 64 bits)
  -----------------------------------------------------------------------------
  process is
    variable KeySchedule : KeyScheduleType(0 to 15-1)(0 to 4-1)(0 to 4-1)(7 downto 0) :=
      (others => (others => (others => (others => '0'))));
    constant InitializationVector : FiniteField(63 downto 0) :=
      (x"cafebabefacedbad");
    variable D0, H                  : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable Y0, Y1, Y2, Y3, Y4     : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable E0, E1, E2, E3, E4     : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable X1, X2, X3, X4, X5, X6 : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
  begin  -- process
    KeySchedule := KeyExpand(Key, KeySchedule);

    H := GenHashSubkey(Sbox, KeySchedule);

    Y0 := InitCounter0(InitializationVector, H);

    assert Y0(0)(0) = x"00" report "Test Case 17 failure !!!" severity failure;

    report "Test Case 17 passed.";

    wait;
  end process;


  -----------------------------------------------------------------------------
  -- Test Case 18 for Y0 (IV'length is 480 bits)
  -----------------------------------------------------------------------------
  process is
    variable KeySchedule : KeyScheduleType(0 to 15-1)(0 to 4-1)(0 to 4-1)(7 downto 0) :=
      (others => (others => (others => (others => '0'))));
    constant InitializationVector : FiniteField(479 downto 0) :=
      (x"9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b");
    variable D0, H                  : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable Y0, Y1, Y2, Y3, Y4     : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable E0, E1, E2, E3, E4     : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable X1, X2, X3, X4, X5, X6 : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
  begin  -- process
    KeySchedule := KeyExpand(Key, KeySchedule);

    H := GenHashSubkey(Sbox, KeySchedule);

    Y0 := InitCounter0(InitializationVector, H);

    assert Y0(0)(0) = x"0c" report "Test Case 18 failure !!!" severity failure;

    report "Test Case 18 passed.";

    wait;
  end process;


  -----------------------------------------------------------------------------
  -- Test Case 18 (IV'length is 480 bits) with authentication checked
  -----------------------------------------------------------------------------
  process is
    variable KeySchedule : KeyScheduleType(0 to 15-1)(0 to 4-1)(0 to 4-1)(7 downto 0) :=
      (others => (others => (others => (others => '0'))));
    constant InitializationVector : FiniteField(479 downto 0) :=
      (x"9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b");
    constant Auth                   : FiniteField(159 downto 0) := (x"feedfacedeadbeeffeedfacedeadbeefabaddad2");
    variable D0, H, Len             : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable Y0, Y1, Y2, Y3, Y4     : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable E0, E1, E2, E3, E4     : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
    variable X1, X2, X3, X4, X5, X6 : StateType(0 to 4-1)(0 to 4-1)(7 downto 0);
  begin  -- process
    KeySchedule := KeyExpand(Key, KeySchedule);

    H := GenHashSubkey(Sbox, KeySchedule);

    Len       := ZeroState;
    Len(3)(2) := x"01";
    Len(3)(3) := x"e0";
    Len(1)(3) := x"a0";

    Y0 := InitCounter0(InitializationVector, H);
    Y1 := incr(Y0);
    Y2 := incr(Y1);
    Y3 := incr(Y2);
    Y4 := incr(Y3);

    E0 := Encrypt(Sbox, KeySchedule, Y0);
    E1 := Encrypt(Sbox, KeySchedule, Y1);
    E2 := Encrypt(Sbox, KeySchedule, Y2);
    E3 := Encrypt(Sbox, KeySchedule, Y3);
    E4 := Encrypt(Sbox, KeySchedule, Y4);

    X1    := E1 + TestVector(1, 0);
    X2    := E2 + TestVector(2, 0);
    X3    := E3 + TestVector(3, 0);
    X4    := E4 + TestVector(4, 0);
    X4(3) := (others => (others => '0'));

    X1 := MultH(X1 + InitAuthData(Auth, H), H);
    X1 := MultH(X1 + X2, H);
    X1 := MultH(X1 + X3, H);
    X1 := MultH(X1 + X4, H);
    X1 := MultH(X1 + Len, H) + E0;

    assert X1(0)(0) = x"a4" report "Test Case 18: GCM authentication failure !!!" severity failure;

    report "Test Case 18: GCM authentication passed.";

    wait;
  end process;

end architecture behavior;

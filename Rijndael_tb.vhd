-------------------------------------------------------------------------------
-- Title      : Extensible Rijndael Package Test Bench
-- Project    : Extensible Rijndael Block Cipher using VHDL-2008
-------------------------------------------------------------------------------
-- File       : Rijndael_tb.vhd
-- Author     : Clyde R. Visser  <Clyde.R.Visser@gmail.com>
-- Company    : eXpertroniX
-- Created    : 2023-04-23
-- Last update: 2023-04-29
-- Platform   : Modelsim
-- Standard   : VHDL'08, Math Packages
-------------------------------------------------------------------------------
-- Description: Test bench for extensible Rijndael while varying number of
-- rows, number of columns, word size, & key size
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
use ieee.math_real.all;
use std.textio.all;
use work.Rijndael.all;
use work.testbench_utils.all;

entity testbench is
end entity testbench;

architecture behavior of testbench is

begin

  WordLoop : for WordSize in 10 downto 8 generate
    NkLoop : for Nk in 24 downto 24 generate
      NumRowsLoop : for NumRows in 24 downto 12 generate
        NumColsLoop : for NumCols in 48 downto 24 generate
          ColSizeChk : if WordSize*NumRows mod 4 = 0 generate
            RowColChk : if NumCols >= NumRows generate
              TrinomialChk : if IsTrinomial(WordSize) and IsTrinomial(WordSize*NumRows/4) generate
                process is
                  constant Nb           : positive := NumCols;
                  constant Nr           : positive := LowerRijndaelRoundLimit(Nk, Nb);
                  subtype WordType is FiniteField(WordSize-1 downto 0);
                  constant Word         : WordType := (others => '0');
                  variable seed1, seed2 : positive;
                  variable rand         : real;
                  variable temp         : std_logic;
                  variable Key          : KeyType
                    (0 to Nk-1)
                    (0 to NumRows-1)
                    (Word'range);
                  constant KeySize     : natural := Nk*NumRows*WordSize;
                  constant BlockSize   : natural := NumRows*NumCols*WordSize;
                  variable KeySchedule : KeyScheduleType
                    (0 to Nr)
                    (0 to NumCols-1)
                    (Key'element'range)
                    (Key'element'element'range);
                  variable State0, State1, State2 : StateType
                    (0 to NumCols-1)
                    (0 to NumRows-1)
                    (Key'element'element'range);

                  constant Sbox    : SboxType(0 to 2**WordSize-1)(Word'range) := InitSbox(WordSize);
                  constant InvSbox : SboxType(0 to 2**WordSize-1)(Word'range) := InitInvSbox(Sbox);

                begin  -- process
                  write(OUTPUT,
                        "WordSize: " & to_string(WordSize) & " / " &
                        "Nk: " & to_string(Nk) & " / " &
                        "NumRows: " & to_string(NumRows) & " / " &
                        "NumCols: " & to_string(NumCols) & " / " &
                        "KeySize: " & to_string(KeySize) & " / " &
                        "BlockSize: " & to_string(BlockSize) &
                        LF);
                  -- Init key & key schedule
                  for i in Key'range loop
                    for j in Key'element'range loop
                      for k in Key'element'element'range loop
                        uniform(seed1, seed2, rand);
                        temp := '0';
                        if rand > 0.5 then
                          temp := '1';
                        end if;
                        Key(i)(j)(k) := temp;
                      end loop;  -- k
                    end loop;  -- j
                  end loop;  -- i
                  KeySchedule := KeyExpand(Key, KeySchedule);
                  -- Init State0
                  for i in State0'range loop
                    for j in State0'element'range loop
                      for k in State0'element'element'range loop
                        uniform(seed1, seed2, rand);
                        temp := '0';
                        if rand > 0.5 then
                          temp := '1';
                        end if;
                        State0(i)(j)(k) := temp;
                      end loop;  -- k
                    end loop;  -- j
                  end loop;  -- i
                  State1 := Encrypt(Sbox, KeySchedule, State0);
                  State2 := Decrypt(InvSbox, KeySchedule, State1);
                  assert State0 = State2
                    report "Rijndael Encrypt/Decrypt failed !!!"
                    severity note;
                  wait;
                end process;
              end generate TrinomialChk;
            end generate RowColChk;
          end generate ColSizeChk;
        end generate NumColsLoop;
      end generate NumRowsLoop;
    end generate NkLoop;
  end generate WordLoop;

end architecture behavior;

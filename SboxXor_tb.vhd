-------------------------------------------------------------------------------
-- Title      : Sbox Xor constant value calculator
-- Project    : Extensible Rijndael Block Cipher using VHDL-2008
-------------------------------------------------------------------------------
-- File       : SboxXor_tb.vhd
-- Author     : Clyde R. Visser  <Clyde.R.Visser@gmail.com>
-- Company    : eXpertroniX
-- Created    : 2023-04-23
-- Last update: 2023-04-29
-- Platform   : Modelsim
-- Standard   : VHDL'08, Math Packages
-------------------------------------------------------------------------------
-- Description: Sbox Xor constant value calculator, supports orders 5 to 16
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

begin

  --
  -- So, if the answer was x"63", what was the question?  The constant is 8
  -- bit, so that's 256 possibilities.  The constant must be chosen in such a
  -- way that that the S-box has no fixed points and no opposite fixed points,
  -- which reduces that count to 192.  Assuming that the constant has the same
  -- number of ones as zeroes to maximize confusion, the count is further
  -- reduced to 6.  Almost there.  Lastly, maximizing the changes of the output
  -- relative to the changes in the input leaves us with one constant: x"63".
  --
  SboxXorGen : for WordSize in 16 downto 5 generate
    SboxChecker : process is
      constant Word          : FiniteField(WordSize-1 downto 0)         := (others => '0');
      variable Sbox, InvSbox : SboxType(0 to 2**WordSize-1)(Word'range) := (others => (others => '0'));
      variable n, m, k       : unsigned(Word'range);
      variable SboxXor1      : FiniteField(Word'range);
      variable flag          : boolean;
      variable OnesCount     : unsigned(63 downto 0)                    := (others => '0');
      variable BestOnes      : unsigned(63 downto 0)                    := (others => '0');
      variable BestSboxXor   : FiniteField(Word'range);
      variable Mat1          : SquareMatrix(Word'range, Word'range);

      function InitInverseTable (
        Size : natural)
        return SboxType is
        variable InvTable : SboxType(0 to 2**Size-1)(Size-1 downto 0);
      begin
        for i in InvTable'range loop
          InvTable(to_integer(unsigned(-(FiniteField(to_unsigned(i, Size)))))) :=
            FiniteField(to_unsigned(i, Size));
        end loop;
        return InvTable;
      end function InitInverseTable;

      variable InverseTable : SboxType(0 to 2**WordSize-1)(Word'range);

      impure function InvGf (
        x : FiniteField)
        return FiniteField is
      begin
        return InverseTable(to_integer(unsigned(x)));
      end function InvGf;

    begin  -- process SboxChecker
      Mat1         := AffineMatrix(WordSize);
      InverseTable := InitInverseTable(WordSize);
      for j in Sbox'range loop
        SboxXor1 := FiniteField(to_unsigned(j, WordSize));  -- X"63";
        flag     := true;
        if BalancedHammingWeight(std_logic_vector(SboxXor1)) then
          for i in Sbox'range loop
            k                      := to_unsigned(i, WordSize);
            Sbox(i)                := (Mat1 * (InvGf(FiniteField(to_unsigned(i, WordSize))))) + SboxXor1;
            n                      := unsigned(Sbox(i));
            InvSbox(to_integer(n)) := FiniteField(k);
          end loop;  -- i
          for i in Sbox'range loop
            k := to_unsigned(i, WordSize);
            n := unsigned(Sbox(i));
            m := unsigned(InvSbox(i));
            if n = not k or m = not k or n = k or m = k then
              flag := false;
              exit;
            end if;
          end loop;  -- i
        else
          flag := false;
        end if;
        if flag = true then
          for i in Sbox'range loop
            if to_integer(unsigned(InvSbox(to_integer(unsigned(Sbox(i)))))) /= i then
              flag := false;
              report "Bad sbox 1" severity note;
              exit;
            end if;
            if to_integer(unsigned(Sbox(to_integer(unsigned(InvSbox(i)))))) /= i then
              flag := false;
              report "Bad sbox 2" severity note;
              exit;
            end if;
          end loop;  -- i
        end if;
        if flag = true then
          OnesCount := to_unsigned(0, 64);
          for i in Sbox'range loop
            m         := unsigned(Sbox(GrayCount(i)));
            n         := unsigned(Sbox(GrayCount((i+1)mod Sbox'length)));
            OnesCount := OnesCount + to_unsigned(HammingWeight(std_logic_vector(m xor n)), 64);
            m         := unsigned(InvSbox(GrayCount(i)));
            n         := unsigned(InvSbox(GrayCount((i+1)mod Sbox'length)));
            OnesCount := OnesCount + to_unsigned(HammingWeight(std_logic_vector(m xor n)), 64);
          end loop;  -- i
          if OnesCount > BestOnes then
            BestOnes    := OnesCount;
            BestSboxXor := SboxXor1;
          end if;
        end if;
      end loop;  -- j
      puts("when " & to_string(WordSize) & " => temp := " & '"' &
           to_string(std_logic_vector(BestSboxXor)) & '"' & ";  -- " &
           to_string(WordSize) &"x" & '"' &
           to_hstring(std_logic_vector(BestSboxXor)) & '"' & LF);
      assert SboxXor(WordSize) = BestSboxXor report "SboxXor error" severity note;
      wait;
    end process SboxChecker;
  end generate SboxXorGen;


end architecture behavior;

-------------------------------------------------------------------------------
-- Title      : Low-Weight Binary Irreducible Polynomial Calculator
-- Project    : Extensible Rijndael Block Cipher using VHDL-2008
-------------------------------------------------------------------------------
-- File       : Irreducible_tb.vhd
-- Author     : Clyde R. Visser  <Clyde.R.Visser@gmail.com>
-- Company    : eXpertroniX
-- Created    : 2023-04-23
-- Last update: 2023-04-29
-- Platform   : Modelsim
-- Standard   : VHDL'08, Math Packages
-------------------------------------------------------------------------------
-- Description: Low-weight binary irreducible polynomial calculator,
-- brute force, order 2 to 64
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


  -----------------------------------------------------------------------------
  -- Hunt for Hairy Trinomials & Pentanomials
  -----------------------------------------------------------------------------
  IrreducibleGen : if true generate
    IrreducibleHunter : for WordSize in 64 downto 2 generate
      process is
        variable temp             : FiniteField(WordSize downto 0);
        variable i                : unsigned(WordSize-1 downto 1);
        variable OnesCount, Count : natural;
      begin  -- process
        temp             := (others => '0');
        temp(temp'left)  := '1';
        temp(temp'right) := '1';
        if WordSize mod 8 /= 0 then
          for j in 1 to integer(ceil(real(temp'left)/2.0)) loop
            temp(WordSize-1 downto 1) := (j => '1', others => '0');
            if IsIrreducible(temp) then
              write(OUTPUT,
                    "     when " &
                    to_string(WordSize) &
                    " => temp := " &
                    to_string(WordSize+1) & "x" & '"' &
                    to_hstring(std_logic_vector(temp)) &
                    '"' & ";" & "  -- Trinomial" & LF);
              assert temp = Irreducible(WordSize)
                report "Mismatch: temp != Irreducible(WordSize)"
                severity warning;
              wait;
            end if;
          end loop;  -- j
        end if;
        i := (others => '0');
        loop
          temp(WordSize-1 downto 1) := FiniteField(i);
          OnesCount                 := HammingWeight(std_logic_vector(temp));
          if OnesCount = 5 then
            if IsIrreducible(temp) then
              write(OUTPUT,
                    "     when " &
                    to_string(WordSize) &
                    " => temp := " &
                    to_string(WordSize+1) & "x" & '"' &
                    to_hstring(std_logic_vector(temp)) &
                    '"' & ";" & "  -- Pentanomial" & LF);
              assert temp = Irreducible(WordSize)
                report "Mismatch: temp != Irreducible(WordSize)"
                severity warning;
              exit;
            end if;
          end if;
          i := i + 1;
          if i = 0 then
            exit;
          end if;
        end loop;
        wait;
      end process;
    end generate IrreducibleHunter;
  end generate IrreducibleGen;


  IsIrreducibleGen : if false generate
    IsIrreducibleChecker : for WordSize in 64 downto 2 generate
      process is
        variable temp : FiniteField(WordSize downto 0);
      begin  -- process
        temp := Irreducible(WordSize);
        assert IsIrreducible(temp)
          report "Bad Irreducible Polynomial !!!"
          severity failure;
        write(OUTPUT,
              "     when " & to_string(WordSize) &
              " => temp := " & to_string(WordSize+1) & "x" & '"' &
              to_hstring(std_logic_vector(temp)) & '"' & ";  --");
        case HammingWeight(std_logic_vector(temp)) is
          when 3      => write(OUTPUT, " Trinomial" & LF);
          when 5      => write(OUTPUT, " Pentanomial" & LF);
          when others => write(OUTPUT, " ???" & LF);
        end case;
        wait;
      end process;
    end generate IsIrreducibleChecker;
  end generate IsIrreducibleGen;


end architecture behavior;

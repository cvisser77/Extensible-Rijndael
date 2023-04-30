-------------------------------------------------------------------------------
-- Title      : MixColumn Research Test Bench
-- Project    : Extensible Rijndael Block Cipher using VHDL-2008
-------------------------------------------------------------------------------
-- File       : MixColumn_tb.vhd
-- Author     : Clyde R. Visser  <Clyde.R.Visser@gmail.com>
-- Company    : eXpertroniX
-- Created    : 2023-04-23
-- Last update: 2023-04-29
-- Platform   : Modelsim
-- Standard   : VHDL'08, Math Packages
-------------------------------------------------------------------------------
-- Description: MixColumn research test bench.  Dead end.
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
use work.Rijndael.all;
use work.testbench_utils.all;

entity testbench is
end entity testbench;

architecture behavior of testbench is

  constant WordSize  : natural                          := 8;
  constant WordRange : natural                          := 2**WordSize;
  subtype WordType is FiniteField(WordSize-1 downto 0);
  constant Word      : FiniteField(WordSize-1 downto 0) := (others => '0');

  constant NumRows : natural := 4;      -- Number of rows

  type SquareGfMatrix is array (natural range <>, natural range <>) of FiniteField;

  function "*" (
    x : SquareGfMatrix;
    y : SquareGfMatrix)
    return SquareGfMatrix is
    variable z : SquareGfMatrix(x'range(1), y'range(2))(x(0, 0)'range);
  begin
    for i in x'range(1) loop
      for j in y'range(2) loop
        z(i, j) := (others => '0');
        for k in x'range(2) loop
          z(i, j) := z(i, j) + (x(i, k) * y(k, j));
        end loop;  -- k
      end loop;  -- j
    end loop;  -- i
    return z;
  end function "*";

  function InitSquareGfMatrix (
    x : ColumnType)
    return SquareGfMatrix is
    variable result : SquareGfMatrix(x'range, x'range)(x'element'range);
  begin
    for i in x'range loop
      for j in x'range loop
        result(i, (i+j)mod x'length) := x(j);
      end loop;  -- j
    end loop;  -- i
    return result;
  end function InitSquareGfMatrix;

  function ReadSquareGfMatrix (
    x : SquareGfMatrix)
    return ColumnType is
    variable result : ColumnType(x'range)(x(0, 0)'range);
  begin
    for i in x'range loop
      result(i) := x(0, i);
    end loop;  -- i
    return result;
  end function ReadSquareGfMatrix;

  function ReduceSquareGfMatrix (
    matrix : SquareGfMatrix;
    row    : natural;
    col    : natural)
    return SquareGfMatrix is
    constant Size   : natural := matrix'length(1)-1;
    variable Result : SquareGfMatrix(0 to Size-1, 0 to Size-1)(matrix(0, 0)'range);
    variable n, m   : natural;
  begin
    for j in Result'range(2) loop
      if j < col then
        m := j;
      else
        m := j+1;
      end if;
      for i in Result'range(1) loop
        if i < row then
          n := i;
        else
          n := i+1;
        end if;
        Result(i, j) := matrix(n, m);
      end loop;  -- i
    end loop;  -- j
    return Result;
  end function ReduceSquareGfMatrix;

  function GfMatrixDeterminant (
    matrix : SquareGfMatrix)
    return FiniteField is
    constant Size         : natural                         := matrix'length(1);
    variable Result       : FiniteField(matrix(0, 0)'range) := (others => '0');
    variable temp1, temp2 : FiniteField(Result'range)       := (others => '0');
  begin
    for i in matrix'range(1) loop
      temp1 := (0 => '1', others => '0');
      temp2 := (0 => '1', others => '0');
      for j in matrix'range(1) loop
        temp1 := temp1 * matrix(j, (i+j) mod Size);
        temp2 := temp2 * matrix(j, (i-j) mod Size);
      end loop;  -- j
      Result := Result + temp1 - temp2;
    end loop;  -- i
    return Result;
  end function GfMatrixDeterminant;

  function GfMatrixInverse (
    matrix : SquareGfMatrix)
    return SquareGfMatrix is
    constant Size            : natural := matrix'length(1)-1;
    variable ReducedGfMatrix : SquareGfMatrix(0 to Size-1, 0 to Size-1)(matrix(0, 0)'range);
    variable Result :
      SquareGfMatrix(matrix'range(1), matrix'range(2))(matrix(0, 0)'range);
    variable InvDet : FiniteField(matrix(0, 0)'range);
  begin
    InvDet := -GfMatrixDeterminant(matrix);
    -- InvDet := (0 => '1', others => '0');  -- ???
    for i in matrix'range(1) loop
      for j in matrix'range(2) loop
        ReducedGfMatrix := ReduceSquareGfMatrix(matrix, j, i);
        Result(i, j)    := GfMatrixDeterminant(ReducedGfMatrix) * InvDet;
      -- if (matrix'left(1) + 1 - i + matrix'left(2) + 1 - j) mod 2 = 1 then
      --   Result(i, j) := -Result(i, j);  -- ugly! and ???
      -- end if;
      end loop;  -- j
    end loop;  -- i
    return Result;
  end function GfMatrixInverse;

  -----------------------------------------------------------------------------
  -- MixColumn
  -----------------------------------------------------------------------------

  signal MixColCoefficients : ColumnType(0 to NumRows-1)(Word'range) :=
    (3      => FiniteField(to_unsigned(3, WordSize)),   -- x"03",
     2      => FiniteField(to_unsigned(1, WordSize)),   -- x"01",
     1      => FiniteField(to_unsigned(1, WordSize)),   -- x"01",
     0      => FiniteField(to_unsigned(2, WordSize)),   -- x"02";
     others => FiniteField(to_unsigned(4, WordSize)));  -- x"00";
  -- (3      => FiniteField(to_unsigned(3, WordSize)),   -- x"03",
  --  2      => FiniteField(to_unsigned(1, WordSize)),   -- x"01",
  --  1      => FiniteField(to_unsigned(1, WordSize)),   -- x"01",
  --  0      => FiniteField(to_unsigned(2, WordSize)),   -- x"02";
  --  others => FiniteField(to_unsigned(0, WordSize)));  -- x"00";

  signal TestSquareGfMatrix1 : SquareGfMatrix
    (MixColCoefficients'range, MixColCoefficients'range)
    (MixColCoefficients'element'range) := InitSquareGfMatrix(MixColCoefficients);

  signal TestSquareGfMatrix2 : SquareGfMatrix
    (MixColCoefficients'range, MixColCoefficients'range)
    (MixColCoefficients'element'range) := GfMatrixInverse(TestSquareGfMatrix1);

  signal TestSquareGfMatrix3 : SquareGfMatrix
    (MixColCoefficients'range, MixColCoefficients'range)
    (MixColCoefficients'element'range);

  signal TestSquareGfMatrix4 : SquareGfMatrix
    (MixColCoefficients'range, MixColCoefficients'range)
    (MixColCoefficients'element'range);

  signal InvMixColCoefficients : ColumnType(0 to NumRows-1)(Word'range) :=
    ReadSquareGfMatrix(TestSquareGfMatrix2);
  -- (3 => FiniteField(to_unsigned(11, WordSize)),   -- x"0b",
  --  2 => FiniteField(to_unsigned(13, WordSize)),   -- x"0d",
  --  1 => FiniteField(to_unsigned(9, WordSize)),    -- x"09",
  --  0 => FiniteField(to_unsigned(14, WordSize)));  -- x"0e";

  impure function MixColumn0 (
    Column : ColumnType)
    return ColumnType is
  begin  -- function MixColumn0
    return Column * MixColCoefficients;
  end function MixColumn0;

  impure function InvMixColumn0 (
    Column : ColumnType)
    return ColumnType is
  begin  -- function InvMixColumn0
    return Column * InvMixColCoefficients;
  end function InvMixColumn0;

  signal TestColumn0 : ColumnType(0 to NumRows-1)(Word'range)
    := (0      => (7 downto 0 => x"db", others => '0'),
        1      => (7 downto 0 => x"13", others => '0'),
        2      => (7 downto 0 => x"53", others => '0'),
        3      => (7 downto 0 => x"45", others => '0'),
        others => (7 downto 0 => x"00", others => '0'));
  signal TestColumn1 : ColumnType(TestColumn0'range)(Word'range);
  signal TestColumn2 : ColumnType(TestColumn0'range)(Word'range);
  signal TestColumn3 : ColumnType(TestColumn0'range)(Word'range);
  signal TestColumn4 : ColumnType(TestColumn0'range)(Word'range);

  signal TestGf : FiniteField(Word'range) := GfMatrixDeterminant(TestSquareGfMatrix1);

begin

  InvMixColCoefficients <= ReadSquareGfMatrix(TestSquareGfMatrix2);

  TestColumn1 <= MixColumn0(TestColumn0);
  TestColumn2 <= InvMixColumn0(TestColumn1);
  TestColumn3 <= MixColCoefficients * InvMixColCoefficients;
  TestColumn4 <= ReadSquareGfMatrix(TestSquareGfMatrix2);

  TestSquareGfMatrix3 <= TestSquareGfMatrix1 * TestSquareGfMatrix2;
  TestSquareGfMatrix4 <= TestSquareGfMatrix2 * TestSquareGfMatrix1;

  process is
    constant UnityColumn : ColumnType(0 to NumRows-1)(Word'range)
      := (0 => (0 => '1', others => '0'), others => (others => '0'));
  begin  -- process
    assert UnityColumn = MixColCoefficients * InvMixColCoefficients
      report "MixColumn coefficients error !!!"
      severity note;
    wait;
  end process;

  MixColumnInvMixColumnGen : if true generate
    MixColumnInvMixColumnChecker : for WordSize in 5 to 64 generate
      process is
        variable seed1, seed2 : positive;
        variable rand         : real;
        variable temp         : std_logic;
        variable Column0, Column1, Column2 :
          ColumnType(0 to 4-1)(WordSize-1 downto 0);
      begin  -- process
        for k in 1 to 1000 loop
          for i in Column0'range loop
            for j in Column0'element'range loop
              uniform(seed1, seed2, rand);
              temp := '0';
              if rand > 0.5 then
                temp := '1';
              end if;
              Column0(i)(j) := temp;
            end loop;  -- j
          end loop;  -- i
          Column1 := MixColumn(Column0);
          Column2 := InvMixColumn(Column1);
          assert Column0 = Column2
            report "Bad MixColumn / InvMixColumn !!!"
            severity failure;
        end loop;  -- k
        wait;
      end process;
    end generate MixColumnInvMixColumnChecker;
  end generate MixColumnInvMixColumnGen;

end architecture behavior;

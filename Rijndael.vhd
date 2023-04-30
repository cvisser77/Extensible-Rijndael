-------------------------------------------------------------------------------
-- Title      : Extensible Rijndael Package
-- Project    : Extensible Rijndael Block Cipher using VHDL-2008
-------------------------------------------------------------------------------
-- File       : Rijndael.vhd
-- Author     : Clyde R. Visser  <Clyde.R.Visser@gmail.com>
-- Company    : eXpertroniX
-- Created    : 2023-04-23
-- Last update: 2023-04-29
-- Platform   : Modelsim
-- Standard   : VHDL'08, Math Packages
-------------------------------------------------------------------------------
-- Description: Provides datatype and function definitions for implementing
-- Rijndael block ciphers.
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


package Rijndael is

  type FiniteField is array (natural range <>) of std_logic;

  type SboxType is array (natural range <>) of FiniteField;

  type ColumnType is array (natural range <>) of FiniteField;

  type StateType is array (natural range <>) of ColumnType;

  type KeyType is array (natural range <>) of ColumnType;

  type KeyScheduleType is array (natural range <>) of StateType;

  type SquareMatrix is array (natural range <>, natural range <>) of std_logic;

  function State2FiniteField (
    x : StateType)
    return FiniteField;

  function FiniteField2State (
    x : FiniteField;
    y : StateType)
    return StateType;

  function "+" (
    x : FiniteField;
    y : FiniteField)
    return FiniteField;

  function "+" (
    x : ColumnType;
    y : ColumnType)
    return ColumnType;

  function "+" (
    x : StateType;
    y : StateType)
    return StateType;

  function "+" (
    x : StateType;
    y : natural)
    return StateType;

  function "-" (
    x : FiniteField;
    y : FiniteField)
    return FiniteField;

  function "*" (
    x : FiniteField;
    y : FiniteField)
    return FiniteField;

  function "*" (
    x : SquareMatrix;
    y : FiniteField)
    return FiniteField;

  function "-" (
    x : FiniteField)
    return FiniteField;

  function AffineMatrix (
    Size : natural)
    return SquareMatrix;

  function InitSbox (
    n : natural)
    return SboxType;

  function InitInvSbox (
    x : SboxType)
    return SboxType;

  function MatrixInverse (
    matrix : SquareMatrix)
    return SquareMatrix;

  function HammingWeight (
    slv : std_logic_vector)
    return natural;

  function BalancedHammingWeight (
    slv : std_logic_vector)
    return boolean;

  function GrayCount (
    i : natural)
    return natural;

  function Irreducible (
    x : natural)
    return FiniteField;

  function IsIrreducible (
    x : FiniteField)
    return boolean;

  function IsTrinomial (
    x : natural)
    return boolean;

  function "*" (
    x : ColumnType;
    y : ColumnType)
    return ColumnType;

  function ShiftRows (
    State : StateType)
    return StateType;

  function InvShiftRows (
    State : StateType)
    return StateType;

  function SboxXor (
    x : natural)
    return FiniteField;

  function SubWord (
    WordIn : FiniteField)
    return FiniteField;

  function InvSubWord (
    WordIn : FiniteField)
    return FiniteField;

  function KeyExpand (
    Key         : KeyType;
    KeySchedule : KeyScheduleType)
    return KeyScheduleType;

  function KeyExpand (
    KeyString   : FiniteField;
    KeySchedule : KeyScheduleType)
    return KeyScheduleType;

  function MixColumn (
    Column : ColumnType)
    return ColumnType;

  function InvMixColumn (
    Column : ColumnType)
    return ColumnType;

  function MixColumns (
    StateIn : StateType)
    return StateType;

  function InvMixColumns (
    StateIn : StateType)
    return StateType;

  function LowerRijndaelRoundLimit (
    Nk : positive;
    Nb : positive)
    return positive;

  function incr (
    x : StateType)
    return StateType;

  function GenHashSubkey (
    Sbox        : SboxType;
    KeySchedule : KeyScheduleType)
    return StateType;

  function ReverseFiniteField
    (a : in FiniteField)
    return FiniteField;

  function InitCounter0 (
    Iv : FiniteField;
    H  : StateType)
    return StateType;

  function InitAuthData (
    Auth : FiniteField;
    H    : StateType)
    return StateType;

  function MultH (
    x : in StateType;
    y : in StateType)
    return StateType;

  function ChangeEndianFiniteField
    (a : in FiniteField)
    return FiniteField;

  function MultiplyByAlpha (
    x : FiniteField)
    return FiniteField;

  function SubState (
    Sbox    : SboxType;
    StateIn : StateType)
    return StateType;

  function InvSubState (
    InvSbox : SboxType;
    StateIn : StateType)
    return StateType;

  function Encrypt (
    Sbox        : SboxType;
    KeySchedule : KeyScheduleType;
    StateIn     : StateType)
    return StateType;

  function Encrypt (
    Sbox        : SboxType;
    KeySchedule : KeyScheduleType;
    StateIn     : FiniteField(127 downto 0))
    return FiniteField;

  function Decrypt (
    InvSbox     : SboxType;
    KeySchedule : KeyScheduleType;
    StateIn     : StateType)
    return StateType;

  function Decrypt (
    InvSbox     : SboxType;
    KeySchedule : KeyScheduleType;
    StateIn     : FiniteField(127 downto 0))
    return FiniteField;

end package Rijndael;



package body Rijndael is

  function max(
    left, right : integer)
    return integer is
  begin
    if left > right then
      return left;
    else
      return right;
    end if;
  end function max;


  function State2FiniteField (
    x : StateType)
    return FiniteField is
    variable y :
      FiniteField(x'length*x'element'length*x'element'element'length-1 downto 0);
  begin
    for i in x'range loop
      for j in x'element'range loop
        for k in x'element'element'range loop
          y(y'left-(x'element'length*x'element'element'length*i+x'element'element'length*j+k)) :=
            x(i)(j)(x'element'element'left-k);
        end loop;  -- k
      end loop;  -- j
    end loop;  -- i
    return y;
  end function State2FiniteField;


  function FiniteField2State (
    x : FiniteField;
    y : StateType)
    return StateType is
    variable z :
      StateType(y'range)(y'element'range)(y'element'element'range);
  begin
    for i in y'range loop
      for j in y'element'range loop
        for k in y'element'element'range loop
          z(i)(j)(y'element'element'left-k) :=
            x(x'left-(y'element'length*y'element'element'length*i+y'element'element'length*j+k));
        end loop;  -- k
      end loop;  -- j
    end loop;  -- i
    return z;
  end function FiniteField2State;


  function "xor" (
    x : FiniteField;
    y : FiniteField)
    return FiniteField is
    constant size   : natural := max(x'length, y'length);
    variable x_temp : unsigned(size-1 downto 0);
    variable y_temp : unsigned(size-1 downto 0);
  begin
    x_temp := to_01(resize(unsigned(x), size), 'X');
    y_temp := to_01(resize(unsigned(y), size), 'X');
    return FiniteField(x_temp xor y_temp);
  end function "xor";


  function "+" (
    x : FiniteField;
    y : FiniteField)
    return FiniteField is
  begin
    return FiniteField(x xor y);
  end function "+";


  function "+" (
    x : ColumnType;
    y : ColumnType)
    return ColumnType is
    variable b : ColumnType(x'range)(x'element'range);
  begin
    for i in x'range loop
      b(i) := x(i) + y(i);
    end loop;  -- i
    return b;
  end function "+";


  function "+" (
    x : StateType;
    y : StateType)
    return StateType is
    variable b : StateType(x'range)(x'element'range) (x'element'element'range);
  begin
    for i in x'range loop
      b(i) := x(i) + y(i);
    end loop;  -- i
    return b;
  end function "+";


  function "+" (
    x : StateType;
    y : natural)
    return StateType is
    variable b :
      unsigned(x'length*x'element'length*x'element'element'length-1 downto 0);
    variable result :
      StateType(x'range)(x'element'range)(x'element'element'range);
  begin
    b      := unsigned(State2FiniteField(x));
    b      := b + y;
    result := FiniteField2State(FiniteField(b), result);
    return result;
  end function "+";


  function "-" (
    x : FiniteField;
    y : FiniteField)
    return FiniteField is
  begin
    return FiniteField(x xor y);
  end function "-";


  -----------------------------------------------------------------------------
  -- low-weight binary irreducible polynomials
  -- https://www.hpl.hp.com/techreports/98/HPL-98-135.pdf
  -----------------------------------------------------------------------------
  -----------------------------------------------------------------------------
  -- Precalculated values from Irreducible_tb.vhd
  -----------------------------------------------------------------------------
  function Irreducible (
    x : natural)
    return FiniteField is
    variable temp :
      FiniteField(x downto 0) := (others => '0');
  begin
    case x is
      when 2 => temp := 3x"7";          -- Trinomial
      when 3 => temp := 4x"B";          -- Trinomial
      when 4 => temp := 5x"13";         -- Trinomial
      when 5 => temp := 6x"25";         -- Trinomial
      when 6 => temp := 7x"43";         -- Trinomial
      when 7 => temp := 8x"83";         -- Trinomial

      when 8  => temp := 9x"11B";       -- Pentanomial
      when 9  => temp := 10x"203";      -- Trinomial
      when 10 => temp := 11x"409";      -- Trinomial
      when 11 => temp := 12x"805";      -- Trinomial
      when 12 => temp := 13x"1009";     -- Trinomial
      when 13 => temp := 14x"201B";     -- Pentanomial
      when 14 => temp := 15x"4021";     -- Trinomial
      when 15 => temp := 16x"8003";     -- Trinomial

      when 16 => temp := 17x"1002B";    -- Pentanomial
      when 17 => temp := 18x"20009";    -- Trinomial
      when 18 => temp := 19x"40009";    -- Trinomial
      when 19 => temp := 20x"80027";    -- Pentanomial
      when 20 => temp := 21x"100009";   -- Trinomial
      when 21 => temp := 22x"200005";   -- Trinomial
      when 22 => temp := 23x"400003";   -- Trinomial
      when 23 => temp := 24x"800021";   -- Trinomial

      when 24 => temp := 25x"100001B";   -- Pentanomial
      when 25 => temp := 26x"2000009";   -- Trinomial
      when 26 => temp := 27x"400001B";   -- Pentanomial
      when 27 => temp := 28x"8000027";   -- Pentanomial
      when 28 => temp := 29x"10000003";  -- Trinomial
      when 29 => temp := 30x"20000005";  -- Trinomial
      when 30 => temp := 31x"40000003";  -- Trinomial
      when 31 => temp := 32x"80000009";  -- Trinomial

      when 32 => temp := 33x"10000008D";   -- Pentanomial
      when 33 => temp := 34x"200000401";   -- Trinomial
      when 34 => temp := 35x"400000081";   -- Trinomial
      when 35 => temp := 36x"800000005";   -- Trinomial
      when 36 => temp := 37x"1000000201";  -- Trinomial
      when 37 => temp := 38x"2000000053";  -- Pentanomial
      when 38 => temp := 39x"4000000063";  -- Pentanomial
      when 39 => temp := 40x"8000000011";  -- Trinomial

      when 40 => temp := 41x"10000000039";   -- Pentanomial
      when 41 => temp := 42x"20000000009";   -- Trinomial
      when 42 => temp := 43x"40000000081";   -- Trinomial
      when 43 => temp := 44x"80000000059";   -- Pentanomial
      when 44 => temp := 45x"100000000021";  -- Trinomial
      when 45 => temp := 46x"20000000001B";  -- Pentanomial
      when 46 => temp := 47x"400000000003";  -- Trinomial
      when 47 => temp := 48x"800000000021";  -- Trinomial

      when 48 => temp := 49x"100000000002D";   -- Pentanomial
      when 49 => temp := 50x"2000000000201";   -- Trinomial
      when 50 => temp := 51x"400000000001D";   -- Pentanomial
      when 51 => temp := 52x"800000000004B";   -- Pentanomial
      when 52 => temp := 53x"10000000000009";  -- Trinomial
      when 53 => temp := 54x"20000000000047";  -- Pentanomial
      when 54 => temp := 55x"40000000000201";  -- Trinomial
      when 55 => temp := 56x"80000000000081";  -- Trinomial

      when 56 => temp := 57x"100000000000095";   -- Pentanomial
      when 57 => temp := 58x"200000000000011";   -- Trinomial
      when 58 => temp := 59x"400000000080001";   -- Trinomial
      when 59 => temp := 60x"800000000000095";   -- Pentanomial
      when 60 => temp := 61x"1000000000000003";  -- Trinomial
      when 61 => temp := 62x"2000000000000027";  -- Pentanomial
      when 62 => temp := 63x"4000000020000001";  -- Trinomial
      when 63 => temp := 64x"8000000000000003";  -- Trinomial

      when 64 => temp := 65x"1000000000000001B";  -- Pentanomial

      when 128 =>                                         -- for GCM & XTS
        temp := 129x"100000000000000000000000000000087";  -- Pentanomial

      when others => report "Unsupported polynomial order" severity failure;
    end case;
    return temp;
  end function Irreducible;


  function IsTrinomial (
    x : natural)
    return boolean is
    variable Weight : natural;
  begin  -- function IsTrinomial
    Weight := HammingWeight(std_logic_vector(Irreducible(x)));
    if weight = 3 then
      return true;
    end if;
    return false;
  end function IsTrinomial;


  function "mod" (
    x : FiniteField;
    y : FiniteField)
    return FiniteField is
    constant size   : natural := max(x'length, y'length);
    variable x_temp : unsigned(size-1 downto 0);
    variable y_temp : unsigned(size-1 downto 0);
    variable j      : integer;
  begin
    assert unsigned(y) /= 0
      report "Mod second operand may not be zero !!!"
      severity failure;
    x_temp := to_01(resize(unsigned(x), size), 'X');
    y_temp := to_01(resize(unsigned(y), size), 'X');

    for i in y_temp'range loop
      if y_temp(i) = '1' then
        j := i;
        exit;
      end if;
    end loop;  -- i

    for i in x_temp'left downto j loop
      if x_temp(i) = '1' then
        x_temp := x_temp xor shift_left(y_temp, i-j);
      end if;
    end loop;  -- i

    return FiniteField(x_temp);
  end function "mod";


  function IsIrreducible (
    x : FiniteField)
    return boolean is
    variable i  : unsigned(x'range);
    constant r  : natural := natural(floor(real(x'high)/2.0))+1;
    constant tc : unsigned(x'range) :=
      (r-1 downto 0 => '1', others => '0');
  begin
    i := to_unsigned(2, x'length);
    loop
      if unsigned(x mod FiniteField(i)) = 0 then
        return false;
      end if;
      if i = tc then
        exit;
      end if;
      i := i + 1;
    end loop;
    return true;
  end function IsIrreducible;


  function "*" (
    x : FiniteField;
    y : FiniteField)
    return FiniteField is
    constant size   : natural := max(x'length, y'length);
    variable x_temp : FiniteField(size downto 0);
    variable result :
      FiniteField(size-1 downto 0) := (others => '0');
    constant IrrPoly : FiniteField(size downto 0) :=
      Irreducible(size);
  begin
    x_temp := FiniteField(to_01(resize(unsigned(x), size+1), 'X'));

    for i in y'reverse_range loop
      if y(i) = '1' then
        result := result + x_temp(size-1 downto 0);
      end if;
      x_temp := FiniteField(shift_left(unsigned(x_temp), 1));
      if x_temp(x_temp'left) = '1' then
        x_temp := x_temp xor IrrPoly;
      end if;
    end loop;  -- i
    return result;
  end function "*";


  function "*" (
    x : SquareMatrix;
    y : FiniteField)
    return FiniteField is
    variable result : FiniteField(y'range) := (others => '0');
  begin
    for i in x'range(1) loop
      for j in x'range(2) loop
        result(i) := result(i) xor (x(i, j) and y(j));
      end loop;  -- j
    end loop;  -- i
    return result;
  end function "*";


  function shift_left (
    x : FiniteField;
    n : natural)
    return FiniteField is
    constant Byx : FiniteField(x'range) := (1 => '1', others => '0');
    variable y   : FiniteField(x'range);
  begin
    y := x;
    for i in 1 to n loop
      y := y * Byx;
    end loop;  -- i
    return y;
  end function shift_left;


  -----------------------------------------------------------------------------
  -- Brute force approach to inversion.  Should use extended Euclidean algo?
  -----------------------------------------------------------------------------
  function "-" (
    x : FiniteField)
    return FiniteField is
    constant size   : natural              := x'length;
    variable y      : FiniteField(x'range) := (others => '0');
    variable result : FiniteField(x'range) := (others => '0');
    constant Unity  : FiniteField(x'range) :=
      (x'right => '1', others => '0');
  begin
    if size > 0 and unsigned(x) > 0 then
      for i in 0 to 2**size-1 loop
        y      := FiniteField(to_unsigned(i, size));
        result := x * y;
        if result = Unity then
          return y;
          exit;
        end if;
      end loop;
      report "Inverse function failed !!!"
        severity note;
    end if;
    return y;
  end function "-";


  -----------------------------------------------------------------------------
  -- Just a note on the Count vector below: the Count (or Size-Count) must be a
  -- prime number.  Also, the Count cannot be half of the Size.
  -----------------------------------------------------------------------------
  function AffineMatrix (
    Size : natural)
    return SquareMatrix is
    variable Matrix :
      SquareMatrix(Size-1 downto 0, Size-1 downto 0) :=
      (others => (others => '0'));
    constant Count : integer_vector(5 to 20) :=
      (3, 5, 5, 5, 5, 7, 7, 7, 7, 9, 7, 9, 11, 11, 11, 11);
  begin
    for j in 0 to Count(Size)-1 loop
      for i in Matrix'range(1) loop
        Matrix(i, (i-j)mod Size) := '1';
      end loop;  -- i
    end loop;  -- j
    return Matrix;
  end function AffineMatrix;


  function InitSbox (
    n : natural)
    return SboxType is
    variable y      : SboxType(0 to 2**n-1)(n-1 downto 0);
    constant AffMat : SquareMatrix(y'element'range, y'element'range) := AffineMatrix(n);
    constant SbXor  : FiniteField(y'element'range)                   := SboxXor(n);
  begin  -- function InitSbox
    for i in y'range loop
      y(i) := (AffMat * (-(FiniteField(to_unsigned(i, y'element'length))))) + SbXor;
    end loop;  -- i
    return y;
  end function InitSbox;


  function InitInvSbox (
    x : SboxType)
    return SboxType is
    variable y : SboxType(x'range)(x'element'range);
  begin  -- function InitInvSbox
    for i in y'range loop
      y(to_integer(unsigned(x(i)))) := FiniteField(to_unsigned(i, x'element'length));
    end loop;  -- i
    return y;
  end function InitInvSbox;


  function ReduceSquareMatrix (
    matrix : SquareMatrix;
    row    : natural;
    col    : natural)
    return SquareMatrix is
    constant Size   : natural := matrix'length(1)-1;
    variable Result : SquareMatrix(Size-1 downto 0, Size-1 downto 0);
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
  end function ReduceSquareMatrix;


  function MatrixDeterminant (
    matrix : SquareMatrix)
    return std_logic is
    constant Size         : natural   := matrix'length(1);
    variable Result       : std_logic := '0';
    variable temp1, temp2 : std_logic;
  begin
    for i in matrix'range(1) loop
      temp1 := '1';
      temp2 := '1';
      for j in matrix'range(1) loop
        temp1 := temp1 and matrix(j, (i+j) mod Size);
        temp2 := temp2 and matrix(j, (i-j) mod Size);
      end loop;  -- j
      Result := Result xor temp1 xor temp2;
    end loop;  -- i
    return Result;
  end function MatrixDeterminant;


  function MatrixInverse (
    matrix : SquareMatrix)
    return SquareMatrix is
    constant Size          : natural := matrix'length(1)-1;
    variable ReducedMatrix : SquareMatrix(Size-1 downto 0, Size-1 downto 0);
    variable Result :
      SquareMatrix(matrix'range(1), matrix'range(2));
  begin
    assert MatrixDeterminant(matrix) = '1'
      report "Matrix Det zero"
      severity note;
    for i in matrix'range(1) loop
      for j in matrix'range(2) loop
        ReducedMatrix := ReduceSquareMatrix(matrix, j, i);
        Result(i, j)  := MatrixDeterminant(ReducedMatrix);
        if (matrix'left(1) + 1 - i + matrix'left(2) + 1 - j) mod 2 = 1 then
          Result(i, j) := not Result(i, j);  -- ugly! and ???
        end if;
      end loop;  -- j
    end loop;  -- i
    return Result;
  end function MatrixInverse;


  function HammingWeight (
    slv : std_logic_vector)
    return natural is
    variable i : natural := 0;
  begin  -- function HammingWeight
    for j in slv'range loop
      if slv(j) = '1' then
        i := i + 1;
      end if;
    end loop;  -- j
    return i;
  end function HammingWeight;


  function BalancedHammingWeight (
    slv : std_logic_vector)
    return boolean is
    variable slv_length : natural := slv'length;
    variable ones_count : natural := HammingWeight(slv);
    variable result     : boolean := false;
  begin  -- function BalancedHammingWeight
    if slv_length mod 2 = 0 then
      result := slv_length/2 = ones_count;
    else
      result :=
        natural(floor(real(slv_length)/2.0)) = ones_count or
        natural(ceil(real(slv_length)/2.0)) = ones_count;
    end if;
    return result;
  end function BalancedHammingWeight;


  function GrayCount (
    i : natural)
    return natural is
    variable x, y   : unsigned(31 downto 0);
    variable result : natural;
  begin  -- function GrayCount
    x      := to_unsigned(i, 32);
    y      := shift_right(x, 1);
    result := to_integer(x xor y);
    return result;
  end function GrayCount;


  function "*" (
    x : ColumnType;
    y : ColumnType)
    return ColumnType is
    constant Size              : natural := x'length;
    variable b, x_temp, y_temp : ColumnType
      (0 to Size-1)
      (x'element'range);
  begin  -- function "*"
    x_temp := x;
    y_temp := y;
    for i in x_temp'range loop
      b(i) := (others => '0');
      for j in y_temp'range loop
        b(i) := b(i) +
                y_temp((-j)mod Size) *
                x_temp((i+j)mod Size);
      end loop;  -- j
    end loop;  -- i
    return b;
  end function "*";


  function ShiftRowsOffsetMultiplier (
    Nb : positive;                      -- number of columns
    Nr : positive)                      -- number of rows
    return real is
    variable m : real := 0.138;
    variable b : real := 0.283;
  begin
    if Nb > Nr then
      return m * real(Nb) + b;
    end if;
    return 1.0;
  end function ShiftRowsOffsetMultiplier;


  function ShiftRows (
    State : StateType)
    return StateType is
    variable b :
      StateType(State'range)
      (State'element'range)
      (State'element'element'range);
    constant m : real := ShiftRowsOffsetMultiplier(State'length, State'element'length);
    variable k : natural;
  begin  -- function ShiftRows
    for i in State'element'range loop   -- row
      k := natural(m*real(i));
      for j in State'range loop         -- column
        b(j)(i) := State((j+k)mod State'length)(i);
      end loop;  -- j
    end loop;  -- i
    return b;
  end function ShiftRows;


  function InvShiftRows (
    State : StateType)
    return StateType is
    variable b :
      StateType(State'range)
      (State'element'range)
      (State'element'element'range);
    constant m : real := ShiftRowsOffsetMultiplier(State'length, State'element'length);
    variable k : natural;
  begin  -- function InvShiftRows
    for i in State'element'range loop   -- row
      k := natural(m*real(i));
      for j in State'range loop         -- column
        b(j)(i) := State((j-k)mod State'length)(i);
      end loop;  -- j
    end loop;  -- i
    return b;
  end function InvShiftRows;


  -----------------------------------------------------------------------------
  -- Precalculated values from SboxXor_tb.vhd
  -----------------------------------------------------------------------------
  function SboxXor (
    x : natural)
    return FiniteField is
    variable temp :
      FiniteField(x-1 downto 0) := (others => '0');
  begin
    case x is
      when 5  => temp := "01011";             -- 5x"0B"
      when 6  => temp := "101100";            -- 6x"2C"
      when 7  => temp := "1110010";           -- 7x"72"
      when 8  => temp := "01100011";          -- 8x"63"
      when 9  => temp := "001100111";         -- 9x"067"
      when 10 => temp := "0011010101";        -- 10x"0D5"
      when 11 => temp := "10100001111";       -- 11x"50F"
      when 12 => temp := "110110001010";      -- 12x"D8A"
      when 13 => temp := "0001011110110";     -- 13x"02F6"
      when 14 => temp := "11111101000000";    -- 14x"3F40"
      when 15 => temp := "111010100000111";   -- 15x"7507"
      when 16 => temp := "1011101011100000";  -- 16x"BAE0"
      when others =>
        report "Unsupported SboxXor order"
          severity failure;
    end case;
    return temp;
  end function SboxXor;


  function SubWord (
    WordIn : FiniteField)
    return FiniteField is
  begin  -- function SubWord
    return (AffineMatrix(WordIn'length) * (-WordIn)) + SboxXor(WordIn'length);
  end function SubWord;


  function InvSboxXor (
    x : natural)
    return FiniteField is
  begin
    return -SboxXor(x);
  end function InvSboxXor;


  function InvSubWord (
    WordIn : FiniteField)
    return FiniteField is
  begin  -- function InvSubWord
    -- return (AffineMatrix(WordIn'length) * (-WordIn)) + InvSboxXor(WordIn'length);
    return -(MatrixInverse(AffineMatrix(WordIn'length)) *
             WordIn + InvSboxXor(WordIn'length));
  end function InvSubWord;


  function SubColumn (
    ColumnIn : ColumnType)
    return ColumnType is
    variable b : ColumnType(ColumnIn'range)(ColumnIn'element'range);
  begin  -- function SubColumn
    for i in ColumnIn'range loop
      b(i) := SubWord(ColumnIn(i));
    end loop;  -- i
    return b;
  end function SubColumn;


  function RotColumn (
    ColumnIn : ColumnType)
    return ColumnType is
    variable b : ColumnType(ColumnIn'range)(ColumnIn'element'range);
  begin  -- function RotColumn
    for i in ColumnIn'range loop
      b((i-1)mod ColumnIn'length) := ColumnIn(i);
    end loop;  -- i
    return b;
  end function RotColumn;


  function KeyExpand (
    Key         : KeyType;
    KeySchedule : KeyScheduleType)
    return KeyScheduleType is
    variable w : KeyType
      (0 to KeySchedule'length*KeySchedule'element'length-1)
      (Key'element'range)
      (Key'element'element'range);
    variable b : KeyScheduleType(KeySchedule'range)
      (KeySchedule'element'range)
      (KeySchedule'element'element'range)
      (KeySchedule'element'element'element'range);
    variable temp : ColumnType (Key'element'range)
      (Key'element'element'range);
    constant Nk   : natural := Key'length;  -- Number of key columns
    variable Rcon : KeyType (1 to w'right/Nk)
      (Key'element'range)
      (Key'element'element'range)
      := (others => (others => (others => '0')));
  begin  -- function KeyExpand

    Rcon(1)(0)(0) := '1';
    for i in 2 to Rcon'right loop
      Rcon(i)(0) := shift_left(Rcon(i-1)(0), 1);
    end loop;  -- i

    for i in Key'range loop
      w(i) := Key(i);
    end loop;  -- i

    for i in Nk to w'right loop
      temp := w(i-1);
      if (i mod Nk) = 0 then
        temp := SubColumn(RotColumn(temp)) + Rcon(i/Nk);
      elsif Nk > 6 and (i mod Nk) = Nk/2 then
        temp := SubColumn(temp);
      end if;
      w(i) := w(i-Nk) + temp;
    end loop;  -- i

    for i in w'range loop
      b(i/KeySchedule'element'length)(i mod KeySchedule'element'length) := w(i);
    end loop;  -- i

    return b;
  end function KeyExpand;


  function KeyExpand (
    KeyString   : FiniteField;
    KeySchedule : KeyScheduleType)
    return KeyScheduleType is
    variable Key : KeyType(0 to 8-1)(0 to 4-1)(7 downto 0);
  begin  -- function KeyExpand
    for i in 7 downto 0 loop
      for j in 3 downto 0 loop
        for k in 7 downto 0 loop
          Key(i)(j)(7-k) := KeyString(255 - (8*4*i + 8*j + k));
        end loop;  -- k
      end loop;  -- j
    end loop;  -- i
    return KeyExpand(Key, KeySchedule);
  end function KeyExpand;


  function MixColumn (
    Column : ColumnType)
    return ColumnType is
    variable Result       : ColumnType(Column'range)(Column'element'range);
    constant ColumnSize   : natural := Column'length*Column'element'length;
    constant WordSize     : natural := ColumnSize/4;
    variable temp         : FiniteField(ColumnSize-1 downto 0);
    constant Coefficients : ColumnType(0 to 4-1)(WordSize-1 downto 0) :=
      (3 => FiniteField(to_unsigned(3, WordSize)),   -- x"03",
       2 => FiniteField(to_unsigned(1, WordSize)),   -- x"01",
       1 => FiniteField(to_unsigned(1, WordSize)),   -- x"01",
       0 => FiniteField(to_unsigned(2, WordSize)));  -- x"02";
    variable Column0 :
      ColumnType(Coefficients'range)(Coefficients'element'range);
  begin  -- function MixColumn
    assert ColumnSize mod 4 = 0
      report "Column size must a multiple of 4"
      severity failure;
    for i in Column'range loop
      for j in Column'element'range loop
        temp(Column'element'length*i+j) := Column(i)(j);
      end loop;  -- j
    end loop;  -- i
    for i in Column0'range loop
      for j in Column0'element'range loop
        Column0(i)(j) := temp(Column0'element'length*i+j);
      end loop;  -- j
    end loop;  -- i
    Column0 := Column0 * Coefficients;
    for i in Column0'range loop
      for j in Column0'element'range loop
        temp(Column0'element'length*i+j) := Column0(i)(j);
      end loop;  -- j
    end loop;  -- i
    for i in Column'range loop
      for j in Column'element'range loop
        Result(i)(j) := temp(Column'element'length*i+j);
      end loop;  -- j
    end loop;  -- i
    return Result;
  end function MixColumn;


  function InvMixColumn (
    Column : ColumnType)
    return ColumnType is
    variable Result       : ColumnType(Column'range)(Column'element'range);
    constant ColumnSize   : natural := Column'length*Column'element'length;
    constant WordSize     : natural := ColumnSize/4;
    variable temp         : FiniteField(ColumnSize-1 downto 0);
    constant Coefficients : ColumnType(0 to 4-1)(WordSize-1 downto 0) :=
      (3 => FiniteField(to_unsigned(11, WordSize)),   -- x"0b",
       2 => FiniteField(to_unsigned(13, WordSize)),   -- x"0d",
       1 => FiniteField(to_unsigned(9, WordSize)),    -- x"09",
       0 => FiniteField(to_unsigned(14, WordSize)));  -- x"0e";
    variable Column0 :
      ColumnType(Coefficients'range)(Coefficients'element'range);
  begin  -- function InvMixColumn
    assert ColumnSize mod 4 = 0
      report "Column size must a multiple of 4"
      severity failure;
    for i in Column'range loop
      for j in Column'element'range loop
        temp(Column'element'length*i+j) := Column(i)(j);
      end loop;  -- j
    end loop;  -- i
    for i in Column0'range loop
      for j in Column0'element'range loop
        Column0(i)(j) := temp(Column0'element'length*i+j);
      end loop;  -- j
    end loop;  -- i
    Column0 := Column0 * Coefficients;
    for i in Column0'range loop
      for j in Column0'element'range loop
        temp(Column0'element'length*i+j) := Column0(i)(j);
      end loop;  -- j
    end loop;  -- i
    for i in Column'range loop
      for j in Column'element'range loop
        Result(i)(j) := temp(Column'element'length*i+j);
      end loop;  -- j
    end loop;  -- i
    return Result;
  end function InvMixColumn;


  function MixColumns (
    StateIn : StateType)
    return StateType is
    variable StateOut :
      StateType(StateIn'range)
      (StateIn'element'range)
      (StateIn'element'element'range);
  begin  -- function MixColumns
    for j in StateIn'range loop
      StateOut(j) := MixColumn(StateIn(j));
    end loop;  -- j
    return StateOut;
  end function MixColumns;


  function InvMixColumns (
    StateIn : StateType)
    return StateType is
    variable StateOut :
      StateType(StateIn'range)
      (StateIn'element'range)
      (StateIn'element'element'range);
  begin  -- function InvMixColumns
    for j in StateIn'range loop
      StateOut(j) := InvMixColumn(StateIn(j));
    end loop;  -- j
    return StateOut;
  end function InvMixColumns;


  function LowerRijndaelRoundLimit (
    Nk : positive;
    Nb : positive)
    return positive is
    variable Nr : positive := 4;
  begin
    if Nk > Nr then
      Nr := Nk;
    end if;
    if Nb > Nr then
      Nr := Nb;
    end if;
    Nr := Nr + 6;
    return Nr;
  end function LowerRijndaelRoundLimit;


  function GenHashSubkey (
    Sbox        : SboxType;
    KeySchedule : KeyScheduleType)
    return StateType is
    constant ZeroState :
      StateType(KeySchedule'element'range)
      (KeySchedule'element'element'range)
      (KeySchedule'element'element'element'range) :=
      (others => (others => (others => '0')));
  begin  -- function GenHashSubkey
    return Encrypt(Sbox, KeySchedule, ZeroState);
  end function GenHashSubkey;


  function incr (
    x : StateType)
    return StateType is
    variable b :
      unsigned(x'length*x'element'length*x'element'element'length-1 downto 0);
    variable result :
      StateType(x'range)(x'element'range)(x'element'element'range);
  begin
    b              := unsigned(State2FiniteField(x));
    b(31 downto 0) := b(31 downto 0) + 1;
    result         := FiniteField2State(FiniteField(b), result);
    return result;
  end function incr;


  function ReverseFiniteField (a : in FiniteField)
    return FiniteField is
    variable result : FiniteField(a'reverse_range);
  begin
    for i in a'range loop
      result(i) := a(i);
    end loop;
    return result;
  end function ReverseFiniteField;


  function InitCounter0 (
    Iv : FiniteField;
    H  : StateType)
    return StateType is
    constant BlockLength : natural :=
      H'length*H'element'length*H'element'element'length;
    variable result :
      StateType(H'range)(H'element'range)(H'element'element'range);
    variable a, b, x : FiniteField(BlockLength-1 downto 0)
      := (others => '0');
    variable n : integer := Iv'left;
  begin
    if Iv'length = BlockLength-32 then
      b := (Iv, 32x"1");
    else

      x := State2FiniteField(H);
      for i in integer(ceil(real(Iv'length)/real(BlockLength)))-1 downto 0 loop
        a := (others => '0');
        for j in BlockLength-1 downto 0 loop
          a(j) := Iv(n);
          exit when n = 0;
          n    := n - 1;
        end loop;  -- j
        b := b + a;
        b := ReverseFiniteField(ReverseFiniteField(x) * ReverseFiniteField(b));
      end loop;  -- i
      b := b + (FiniteField(to_unsigned(0, BlockLength/2)),
                FiniteField(to_unsigned(Iv'length, BlockLength/2)));
      b := ReverseFiniteField(ReverseFiniteField(x) * ReverseFiniteField(b));

    end if;

    result := FiniteField2State(b, result);

    return result;
  end function InitCounter0;


  function InitAuthData (
    Auth : FiniteField;
    H    : StateType)
    return StateType is
    constant BlockLength : natural :=
      H'length*H'element'length*H'element'element'length;
    variable result :
      StateType(H'range)(H'element'range)(H'element'element'range);
    variable a, b, x : FiniteField(BlockLength-1 downto 0)
      := (others => '0');
    variable n : integer := Auth'left;
  begin
    if Auth'length = 0 then
      b := (others => '0');
    else

      x := State2FiniteField(H);
      for i in integer(ceil(real(Auth'length)/real(BlockLength)))-1 downto 0 loop
        a := (others => '0');
        for j in BlockLength-1 downto 0 loop
          a(j) := Auth(n);
          exit when n = 0;
          n    := n - 1;
        end loop;  -- j
        b := b + a;
        b := ReverseFiniteField(ReverseFiniteField(x) * ReverseFiniteField(b));
      end loop;  -- i

    end if;

    result := FiniteField2State(b, result);

    return result;
  end function InitAuthData;


  function MultH (
    x : in StateType;
    y : in StateType)
    return StateType is
    variable a, b, z :
      FiniteField(x'length*x'element'length*x'element'element'length-1 downto 0);
    variable result :
      StateType(x'range)(x'element'range)(x'element'element'range);
  begin
    a      := State2FiniteField(x);
    b      := State2FiniteField(y);
    z      := ReverseFiniteField(ReverseFiniteField(a) * ReverseFiniteField(b));
    result := FiniteField2State(z, result);
    return result;
  end function MultH;


  function ChangeEndianFiniteField (a : in FiniteField)
    return FiniteField is
    variable result : FiniteField(a'range);
  begin
    for i in a'range loop
      result((a'left/8-i/8)*8 + (i mod 8)) := a(i);
    end loop;  -- i
    return result;
  end function ChangeEndianFiniteField;


  function MultiplyByAlpha (
    x : FiniteField)
    return FiniteField is
    variable a, b  : FiniteField(x'range);
    constant Alpha : FiniteField(x'range) := (1 => '1', others => '0');
  begin  -- function MultiplyByAlpha
    a := ChangeEndianFiniteField(x);
    a := a * Alpha;
    b := ChangeEndianFiniteField(a);
    return b;
  end function MultiplyByAlpha;


  function SubState (
    Sbox    : SboxType;
    StateIn : StateType)
    return StateType is
    variable StateOut :
      StateType(StateIn'range)
      (StateIn'element'range)
      (StateIn'element'element'range);
  begin  -- function SubState
    for j in StateIn'range loop
      for i in StateIn'element'range loop
        StateOut(j)(i) := Sbox(to_integer(unsigned(StateIn(j)(i))));
      end loop;  -- i
    end loop;  -- j
    return StateOut;
  end function SubState;


  function InvSubState (
    InvSbox : SboxType;
    StateIn : StateType)
    return StateType is
    variable StateOut :
      StateType(StateIn'range)
      (StateIn'element'range)
      (StateIn'element'element'range);
  begin  -- function InvSubState
    for j in StateIn'range loop
      for i in StateIn'element'range loop
        StateOut(j)(i) := InvSbox(to_integer(unsigned(StateIn(j)(i))));
      end loop;  -- i
    end loop;  -- j
    return StateOut;
  end function InvSubState;


  function Encrypt (
    Sbox        : SboxType;
    KeySchedule : KeyScheduleType;
    StateIn     : StateType)
    return StateType is
    variable StateOut :
      StateType(StateIn'range)
      (StateIn'element'range)
      (StateIn'element'element'range);
  begin  -- function Encrypt
    StateOut := StateIn + KeySchedule(0);
    for i in 1 to KeySchedule'right-1 loop
      StateOut := SubState(Sbox, StateOut);
      StateOut := ShiftRows(StateOut);
      StateOut := MixColumns(StateOut);
      StateOut := StateOut + KeySchedule(i);
    end loop;  -- i
    StateOut := SubState(Sbox, StateOut);
    StateOut := ShiftRows(StateOut);
    StateOut := StateOut + KeySchedule(KeySchedule'right);
    return StateOut;
  end function Encrypt;


  function Encrypt (
    Sbox        : SboxType;
    KeySchedule : KeyScheduleType;
    StateIn     : FiniteField(127 downto 0))
    return FiniteField is
    variable z :
      StateType(0 to 3)(0 to 3)(7 downto 0);
    variable StateOut : FiniteField(StateIn'range);
  begin  -- function Encrypt
    z        := FiniteField2State(StateIn, z);
    z        := Encrypt(Sbox, KeySchedule, z);
    StateOut := State2FiniteField(z);
    return StateOut;
  end function Encrypt;


  function Decrypt (
    InvSbox     : SboxType;
    KeySchedule : KeyScheduleType;
    StateIn     : StateType)
    return StateType is
    variable StateOut :
      StateType(StateIn'range)
      (StateIn'element'range)
      (StateIn'element'element'range);
  begin  -- function Decrypt
    StateOut := StateIn + KeySchedule(KeySchedule'right);
    for i in KeySchedule'right-1 downto 1 loop
      StateOut := InvShiftRows(StateOut);
      StateOut := InvSubState(InvSbox, StateOut);
      StateOut := StateOut + KeySchedule(i);
      StateOut := InvMixColumns(StateOut);
    end loop;  -- i
    StateOut := InvShiftRows(StateOut);
    StateOut := InvSubState(InvSbox, StateOut);
    StateOut := StateOut + KeySchedule(0);
    return StateOut;
  end function Decrypt;


  function Decrypt (
    InvSbox     : SboxType;
    KeySchedule : KeyScheduleType;
    StateIn     : FiniteField(127 downto 0))
    return FiniteField is
    variable z :
      StateType(0 to 3)(0 to 3)(7 downto 0);
    variable StateOut : FiniteField(StateIn'range);
  begin  -- function Decrypt
    z        := FiniteField2State(StateIn, z);
    z        := Decrypt(InvSbox, KeySchedule, z);
    StateOut := State2FiniteField(z);
    return StateOut;
  end function Decrypt;

end package body Rijndael;

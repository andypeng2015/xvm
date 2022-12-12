const UInt32
        extends UIntNumber
        default(0)
    {
    // ----- constants -----------------------------------------------------------------------------

    /**
     * The minimum value for an UInt32.
     */
    static IntLiteral MinValue = 0;

    /**
     * The maximum value for an UInt32.
     */
    static IntLiteral MaxValue =  0xFFFFFFFF;


    // ----- Numeric funky interface ---------------------------------------------------------------

    @Override
    static conditional Int fixedByteLength()
        {
        return True, 4;
        }

    @Override
    static UInt32 zero()
        {
        return 0;
        }

    @Override
    static UInt32 one()
        {
        return 1;
        }

    @Override
    static conditional Range<UInt32> range()
        {
        return True, MinValue..MaxValue;
        }


    // ----- constructors --------------------------------------------------------------------------

    /**
     * Construct a 32-bit unsigned integer number from its bitwise machine representation.
     *
     * @param bits  an array of bit values that represent this number, ordered from left-to-right,
     *              Most Significant Bit (MSB) to Least Significant Bit (LSB)
     */
    @Override
    construct(Bit[] bits)
        {
        assert bits.size == 32;
        super(bits);
        }

    /**
     * Construct a 32-bit unsigned integer number from its network-portable representation.
     *
     * @param bytes  an array of byte values that represent this number, ordered from left-to-right,
     *               as they would appear on the wire or in a file
     */
    @Override
    construct(Byte[] bytes)
        {
        assert bytes.size == 4;
        super(bytes);
        }

    /**
     * Construct a 32-bit unsigned integer number from its `String` representation.
     *
     * @param text  an integer number, in text format
     */
    @Override
    construct(String text)
        {
        construct UInt32(new IntLiteral(text).toUInt32().bits);
        }


    // ----- properties ----------------------------------------------------------------------------

    @Override
    Signum sign.get()
        {
        return this == 0 ? Zero : Positive;
        }

    @Override
    UInt32 leftmostBit.get()
        {
        TODO
        }

    @Override
    UInt32 rightmostBit.get()
        {
        TODO
        }


    // ----- operations ----------------------------------------------------------------------------

    @Override
    @Op("+")
    UInt32 add(UInt32! n)
        {
        return this + n;
        }

    @Override
    @Op("-")
    UInt32 sub(UInt32! n)
        {
        return this - n;
        }

    @Override
    @Op("*")
    UInt32 mul(UInt32! n)
        {
        return this * n;
        }

    @Override
    @Op("/")
    UInt32 div(UInt32! n)
        {
        return this / n;
        }

    @Override
    @Op("%")
    UInt32 mod(UInt32! n)
        {
        return this % n;
        }

    @Override
    @Op("&")
    UInt32 and(UInt32! n)
        {
        return new UInt32(this.bits & n.bits);
        }

    @Override
    @Op("|")
    UInt32 or(UInt32! n)
        {
        return new UInt32(this.bits | n.bits);
        }

    @Override
    @Op("^")
    UInt32 xor(UInt32! n)
        {
        return new UInt32(this.bits ^ n.bits);
        }

    @Override
    @Op("~")
    UInt32 not()
        {
        return new UInt32(~bits);
        }

    @Override
    @Op("<<")
    UInt32 shiftLeft(Int count)
        {
        return new UInt32(bits << count);
        }

    @Override
    @Op(">>")
    UInt32 shiftRight(Int count)
        {
        return new UInt32(bits >> count);
        }

    @Override
    @Op(">>>")
    UInt32 shiftAllRight(Int count)
        {
        return new UInt32(bits >>> count);
        }

    @Override
    UInt32 rotateLeft(Int count)
        {
        return new UInt32(bits.rotateLeft(count));
        }

    @Override
    UInt32 rotateRight(Int count)
        {
        return new UInt32(bits.rotateRight(count));
        }

    @Override
    UInt32 retainLSBits(Int count)
        {
        if (count <= 0)
            {
            return 0;
            }

        if (count >= bitLength)
            {
            return this;
            }

        return new UInt32(bits.fill(0, 0 ..< bitLength-count));
        }

    @Override
    UInt32 retainMSBits(Int count)
        {
        if (count <= 0)
            {
            return 0;
            }

        if (count >= bitLength)
            {
            return this;
            }

        return new UInt32(bits.fill(0, count ..< bitLength));
        }

    @Override
    UInt32 reverseBits()
        {
        return new UInt32(bits.reversed());
        }

    @Override
    UInt32 reverseBytes()
        {
        return new UInt32(toByteArray().reversed());
        }

    @Override
    UInt32 pow(UInt32! n)
        {
        UInt32 result = 1;

        while (n-- > 0)
            {
            result *= this;
            }

        return result;
        }


    // ----- Sequential interface ------------------------------------------------------------------

    @Override
    conditional UInt32 next()
        {
        if (this < MaxValue)
            {
            return True, this + 1;
            }

        return False;
        }

    @Override
    conditional UInt32 prev()
        {
        if (this > MinValue)
            {
            return True, this - 1;
            }

        return False;
        }


    // ----- conversions ---------------------------------------------------------------------------

    @Override
    (UInt32 - Unchecked) toChecked()
        {
        return this.is(Unchecked) ? new UInt32(bits) : this;
        }

    @Override
    @Unchecked UInt32 toUnchecked()
        {
        return this.is(Unchecked) ? this : new @Unchecked UInt32(bits);
        }

    @Override
    Int8 toInt8()
        {
        assert:bounds this <= Int8.MaxValue;
        return new Int8(bits[bitLength-8 ..< bitLength]);
        }

    @Override
    Int16 toInt16()
        {
        assert:bounds this <= Int16.MaxValue;
        return new Int16(bits[bitLength-16 ..< bitLength]);
        }

    @Override
    Int32 toInt32()
        {
        assert:bounds this <= Int32.MaxValue;
        return new Int32(bits);
        }

    @Override
    @Auto Int64 toInt64()
        {
        return new Int64(new Array<Bit>(64, i -> i < 64-bitLength ? 0 : bits[i]));
        }

    @Override
    @Auto Int128 toInt128()
        {
        return new Int128(new Array<Bit>(128, i -> i < 128-bitLength ? 0 : bits[i]));
        }

    @Override
    @Auto IntN toIntN()
        {
        return bits[0] == 0 ? new IntN(bits) : toUIntN().toIntN();
        }

    @Override
    UInt8 toUInt8()
        {
        assert:bounds this <= UInt8.MaxValue;
        return new UInt8(bits[bitLength-8 ..< bitLength]);
        }

    @Override
    UInt16 toUInt16()
        {
        assert:bounds this <= UInt16.MaxValue;
        return new UInt16(bits[bitLength-16 ..< bitLength]);
        }

    @Override
    UInt32 toUInt32()
        {
        return this;
        }

    @Override
    @Auto UInt64 toUInt64()
        {
        return new UInt64(new Array<Bit>(64, i -> i < 64-bitLength ? 0 : bits[i]));
        }

    @Override
    @Auto UInt128 toUInt128()
        {
        return new UInt128(new Array<Bit>(128, i -> i < 128-bitLength ? 0 : bits[i]));
        }

    @Override
    @Auto UIntN toUIntN()
        {
        return new UIntN(bits);
        }

    @Override
    @Auto FloatN toFloatN()
        {
        TODO
        }

    @Override
    @Auto DecN toDecN()
        {
        TODO
        }


    // ----- Stringable implementation -------------------------------------------------------------

    @Override
    Int estimateStringLength()
        {
        return calculateStringSize(this, sizeArray);
        }

    @Override
    Appender<Char> appendTo(Appender<Char> buf)
        {
        if (sign == Zero)
            {
            buf.add('0');
            }
        else
            {
            (UInt32 left, UInt32 digit) = this /% 10;
            if (left.sign != Zero)
                {
                left.appendTo(buf);
                }
            buf.add(DIGITS[digit]);
            }
        return buf;
        }

    // MaxValue = 4_294_967_295 (10 digits)
    private static UInt32[] sizeArray =
         [
         9, 99, 999, 9_999, 99_999, 999_999,
         9_999_999, 99_999_999, 999_999_999,
         4_294_967_295
         ];
     }
const Nibble
    implements Sequential
    default(0)
    {
    // ----- constants -----------------------------------------------------------------------------

    /**
     * The minimum value for a Nibble.
     */
    static IntLiteral minvalue = 0;

    /**
     * The maximum value for a Nibble.
     */
    static IntLiteral maxvalue = 0xF;


    // ----- constructors --------------------------------------------------------------------------

    construct(Bit[] bits)
        {
        assert bits.size == 4;
        this.bits = bits;
        }

    static Nibble of(Char ch)
        {
        return switch (ch)
            {
            case '0'..'9': Nibble.of(ch - '0' + 0x0);
            case 'A'..'F': Nibble.of(ch - 'A' + 0xA);
            case 'a'..'f': Nibble.of(ch - 'a' + 0xa);
            default: assert:arg;
            };
        }

    /**
     * Get a Nibble for a given Int value.
     */
    static Nibble of(Int n)
        {
        assert:arg n >= 0 && n <= 0xF;
        return values[n];
        }


    // ----- properties ----------------------------------------------------------------------------

    private Bit[] bits;

    private static Nibble[] values =
        [
        new Nibble([0, 0, 0, 0]),
        new Nibble([1, 0, 0, 0]),
        new Nibble([0, 1, 0, 0]),
        new Nibble([1, 1, 0, 0]),
        new Nibble([0, 0, 1, 0]),
        new Nibble([1, 0, 1, 0]),
        new Nibble([0, 1, 1, 0]),
        new Nibble([1, 1, 1, 0]),
        new Nibble([0, 0, 0, 1]),
        new Nibble([1, 0, 0, 1]),
        new Nibble([0, 1, 0, 1]),
        new Nibble([1, 1, 0, 1]),
        new Nibble([0, 0, 1, 1]),
        new Nibble([1, 0, 1, 1]),
        new Nibble([0, 1, 1, 1]),
        new Nibble([1, 1, 1, 1])
        ];


    // ----- Sequential interface ------------------------------------------------------------------

    @Override
    conditional Nibble next()
        {
        if (this < maxvalue)
            {
            return True, of(this + 1);
            }

        return False;
        }

    @Override
    conditional Nibble prev()
        {
        if (this > minvalue)
            {
            return True, of(this - 1);
            }

        return False;
        }

    @Override
    Int stepsTo(Nibble that)
        {
        return that - this;
        }

    @Override
    Nibble skip(Int steps)
        {
        return Nibble.of(toInt64() + steps);
        }


    // ----- conversions ---------------------------------------------------------------------------

    immutable Bit[] toBitArray()
        {
        return bits.as(immutable Bit[]);
        }

    @Auto UInt8 toUInt8()
        {
        return bits.toUInt8();
        }

    UInt32 toUInt32()
        {
        return toUInt8();
        }

    Char toChar()
        {
        UInt32 n = toUInt32();
        return n <= 9 ? '0' + n : 'A' + n - 0xA;
        }

    @Auto Int64 toInt64()
        {
        return toUInt8().toInt64();
        }

    @Auto UInt64 toUInt64()
        {
        return toUInt8().toUInt64();
        }
    }

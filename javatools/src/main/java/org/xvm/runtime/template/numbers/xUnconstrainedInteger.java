package org.xvm.runtime.template.numbers;


import org.xvm.asm.ClassStructure;
import org.xvm.asm.Constant;
import org.xvm.asm.MethodStructure;

import org.xvm.asm.constants.IntConstant;
import org.xvm.asm.constants.TypeConstant;

import org.xvm.runtime.ClassComposition;
import org.xvm.runtime.Frame;
import org.xvm.runtime.ObjectHandle;
import org.xvm.runtime.TemplateRegistry;

import org.xvm.runtime.template.xBoolean;
import org.xvm.runtime.template.xConst;
import org.xvm.runtime.template.xOrdered;

import org.xvm.runtime.template.numbers.xIntLiteral.IntNHandle;

import org.xvm.runtime.template.text.xString;

import org.xvm.util.PackedInteger;


/**
 * Base class for IntN/UIntN integer types.
 */
public abstract class xUnconstrainedInteger
        extends xConst
    {
    protected xUnconstrainedInteger(TemplateRegistry templates, ClassStructure structure,
             boolean fUnsigned, boolean fChecked)
        {
        super(templates, structure, false);
        f_fChecked = fChecked;
        f_fSigned  = !fUnsigned;
        }

    @Override
    public void initNative()
        {
        markNativeProperty("bitCount");
        markNativeProperty("bitLength");
        markNativeProperty("leftmostBit");
        markNativeProperty("rightmostBit");
        markNativeProperty("leadingZeroCount");
        markNativeProperty("trailingZeroCount");

// TODO markNativeMethod("toUnchecked", VOID, null);

        markNativeMethod("toInt8"   , VOID, new String[]{"numbers.Int8"});
        markNativeMethod("toInt16"  , VOID, new String[]{"numbers.Int16"});
        markNativeMethod("toInt32"  , VOID, new String[]{"numbers.Int32"});
        markNativeMethod("toInt"    , VOID, new String[]{"numbers.Int64"});
        markNativeMethod("toInt128" , VOID, new String[]{"numbers.Int128"});
        markNativeMethod("toIntN"   , VOID, f_sName.equals("numbers.IntN")  ? THIS : new String[]{"numbers.IntN"});
        markNativeMethod("toByte"   , VOID, new String[]{"numbers.UInt8"});
        markNativeMethod("toUInt16" , VOID, new String[]{"numbers.UInt16"});
        markNativeMethod("toUInt32" , VOID, new String[]{"numbers.UInt32"});
        markNativeMethod("toUInt"   , VOID, new String[]{"numbers.UInt64"});
        markNativeMethod("toUInt128", VOID, new String[]{"numbers.UInt128"});
        markNativeMethod("toUIntN"  , VOID, f_sName.equals("numbers.UIntN") ? THIS : new String[]{"numbers.UIntN"});

// TODO markNativeMethod("toFloat16", VOID, new String[]{"numbers.Float16"});
// TODO markNativeMethod("toFloat32", VOID, new String[]{"numbers.Float32"});
// TODO markNativeMethod("toFloat64", VOID, new String[]{"numbers.Float64"});
// TODO markNativeMethod("toFloatN" , VOID, new String[]{"numbers.FloatN" });

// TODO markNativeMethod("toDecN"        , VOID, new String[]{"numbers.DecN"});

// TODO markNativeMethod("toChar"        , VOID, new String[]{"text.Char"});

// TODO markNativeMethod("toBooleanArray", VOID, null);
// TODO markNativeMethod("toBitArray"    , VOID, null);

// TODO markNativeMethod("rotateLeft"   , INT , THIS);
// TODO markNativeMethod("rotateRight"  , INT , THIS);
// TODO markNativeMethod("retainLSBits" , INT , THIS);
// TODO markNativeMethod("retainMSBits" , INT , THIS);
// TODO markNativeMethod("reverseBits"  , VOID, THIS);
// TODO markNativeMethod("reverseBytes" , VOID, THIS);
// TODO markNativeMethod("stepsTo"      , THIS, INT );

        // @Op methods
        markNativeMethod("add"          , THIS, THIS);
        markNativeMethod("sub"          , THIS, THIS);
        markNativeMethod("mul"          , THIS, THIS);
        markNativeMethod("div"          , THIS, THIS);
        markNativeMethod("mod"          , THIS, THIS);
        markNativeMethod("neg"          , VOID, THIS);
// TODO markNativeMethod("and"          , THIS, THIS);
// TODO markNativeMethod("or"           , THIS, THIS);
// TODO markNativeMethod("xor"          , THIS, THIS);
// TODO markNativeMethod("not"          , VOID, THIS);
// TODO markNativeMethod("shiftLeft"    , INT, THIS);
// TODO markNativeMethod("shiftRight"   , INT, THIS);
// TODO markNativeMethod("shiftAllRight", INT, THIS);

        getCanonicalType().invalidateTypeInfo();
        }

    @Override
    public boolean isGenericHandle()
        {
        return false;
        }

    @Override
    public int createConstHandle(Frame frame, Constant constant)
        {
        if (constant instanceof IntConstant)
            {
            return frame.pushStack(makeInt((((IntConstant) constant).getValue())));
            }

        return super.createConstHandle(frame, constant);
        }

    @Override
    public int invokeNativeGet(Frame frame, String sPropName, ObjectHandle hTarget, int iReturn)
        {
        switch (sPropName)
            {
            case "bitCount":
                {
                PackedInteger pi = ((xIntLiteral.IntNHandle) hTarget).m_piValue;
                int cBits = pi.isBig() ? pi.getBigInteger().bitCount() : Long.bitCount(pi.getLong());
                return frame.assignValue(iReturn, xInt64.makeHandle(cBits));
                }

            case "bitLength":
                {
                PackedInteger pi = ((xIntLiteral.IntNHandle) hTarget).m_piValue;
                int cBytes = f_fSigned ? pi.getSignedByteSize() : pi.getUnsignedByteSize();
                return frame.assignValue(iReturn, xInt64.makeHandle(cBytes * 8));
                }

            case "leftmostBit":
                {
                PackedInteger pi = ((xIntLiteral.IntNHandle) hTarget).m_piValue;
                if (pi.isBig())
                    {
                    throw new UnsupportedOperationException(); // TODO
                    }
                else
                    {
                    pi = PackedInteger.valueOf(Long.highestOneBit(pi.getLong()));
                    }
                return frame.assignValue(iReturn, makeInt(pi));
                }

            case "rightmostBit":
                {
                PackedInteger pi = ((xIntLiteral.IntNHandle) hTarget).m_piValue;
                if (pi.isBig())
                    {
                    throw new UnsupportedOperationException(); // TODO
                    }
                else
                    {
                    pi = PackedInteger.valueOf(Long.lowestOneBit(pi.getLong()));
                    }
                return frame.assignValue(iReturn, makeInt(pi));
                }

            case "leadingZeroCount":
                {
                PackedInteger pi = ((xIntLiteral.IntNHandle) hTarget).m_piValue;
                if (pi.isBig())
                    {
                    throw new UnsupportedOperationException(); // TODO
                    }
                else
                    {
                    pi = PackedInteger.valueOf(Long.numberOfLeadingZeros(pi.getLong()));
                    }
                return frame.assignValue(iReturn, makeInt(pi));
                }

            case "trailingZeroCount":
                {
                PackedInteger pi = ((xIntLiteral.IntNHandle) hTarget).m_piValue;
                if (pi.isBig())
                    {
                    throw new UnsupportedOperationException(); // TODO
                    }
                else
                    {
                    pi = PackedInteger.valueOf(Long.numberOfTrailingZeros(pi.getLong()));
                    }
                return frame.assignValue(iReturn, makeInt(pi));
                }
            }

        return super.invokeNativeGet(frame, sPropName, hTarget, iReturn);
        }

    @Override
    public int invokeNative1(Frame frame, MethodStructure method, ObjectHandle hTarget,
                             ObjectHandle hArg, int iReturn)
        {
        switch (method.getName())
            {
            case "add":
                return invokeAdd(frame, hTarget, hArg, iReturn);

            case "sub":
                return invokeSub(frame, hTarget, hArg, iReturn);

            case "mul":
                return invokeMul(frame, hTarget, hArg, iReturn);

            case "div":
                return invokeDiv(frame, hTarget, hArg, iReturn);

            case "mod":
                return invokeMod(frame, hTarget, hArg, iReturn);
            }

        return super.invokeNative1(frame, method, hTarget, hArg, iReturn);
        }

    @Override
    public int invokeNativeN(Frame frame, MethodStructure method, ObjectHandle hTarget,
                             ObjectHandle[] ahArg, int iReturn)
        {
        switch (method.getName())
            {
            case "abs":
                {
                PackedInteger pi = ((IntNHandle) hTarget).getValue();
                return frame.assignValue(iReturn,
                        pi.compareTo(PackedInteger.ZERO) >= 0 ? hTarget : makeInt(pi.negate()));
                }

            case "neg":
                return invokeNeg(frame, hTarget, iReturn);

            case "toInt8":
            case "toInt16":
            case "toInt32":
            case "toInt":
            case "toInt128":
            case "toUInt8":
            case "toUInt16":
            case "toUInt32":
            case "toUInt":
            case "toUInt128":
                {
                TypeConstant        typeRet  = method.getReturn(0).getType();
                xConstrainedInteger template = (xConstrainedInteger) f_templates.getTemplate(typeRet);
                PackedInteger       pi       = ((IntNHandle) hTarget).getValue();

                // check for overflow
                if (f_fChecked)
                    {
                    int cBytes = template.f_fSigned ? pi.getSignedByteSize() : pi.getUnsignedByteSize();
                    if (cBytes * 8 > template.f_cNumBits)
                        {
                        return template.overflow(frame);
                        }
                    }

                return template.convertLong(frame, pi.getLong(), iReturn, f_fChecked);
                }

            case "toIntN":
                {
                ObjectHandle hResult = hTarget;
                if (!f_fSigned)
                    {
                    TypeConstant          typeRet  = method.getReturn(0).getType();
                    xUnconstrainedInteger template = (xUnconstrainedInteger) f_templates.getTemplate(typeRet);
                    PackedInteger         pi       = ((IntNHandle) hTarget).getValue();
                    hResult = template.makeInt(pi);
                    }
                return frame.assignValue(iReturn, hResult);
                }

            case "toUIntN":
                {
                ObjectHandle hResult = hTarget;
                if (f_fSigned)
                    {
                    TypeConstant          typeRet  = method.getReturn(0).getType();
                    xUnconstrainedInteger template = (xUnconstrainedInteger) f_templates.getTemplate(typeRet);
                    PackedInteger         pi       = ((IntNHandle) hTarget).getValue();
                    if (f_fChecked && pi.isNegative())
                        {
                        return template.overflow(frame);
                        }

                    hResult = template.makeInt(pi);
                    }
                return frame.assignValue(iReturn, hResult);
                }
            }

        return super.invokeNativeN(frame, method, hTarget, ahArg, iReturn);
        }

    @Override
    public int invokeAdd(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        PackedInteger pi1 = ((IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();
        PackedInteger pir = pi1.add(pi2);

        return frame.assignValue(iReturn, makeInt(pir));
        }

    @Override
    public int invokeSub(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        PackedInteger pi1 = ((IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();
        PackedInteger pir = pi1.sub(pi2);

        return frame.assignValue(iReturn, makeInt(pir));
        }

    @Override
    public int invokeMul(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        PackedInteger pi1 = ((IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();
        PackedInteger pir = pi1.mul(pi2);

        return frame.assignValue(iReturn, makeInt(pir));
        }

    @Override
    public int invokeNeg(Frame frame, ObjectHandle hTarget, int iReturn)
        {
        PackedInteger pi = ((IntNHandle) hTarget).getValue();

        return frame.assignValue(iReturn, makeInt(pi.negate()));
        }

    @Override
    public int invokePrev(Frame frame, ObjectHandle hTarget, int iReturn)
        {
        PackedInteger pi = ((IntNHandle) hTarget).getValue();

        return frame.assignValue(iReturn, makeInt(pi.previous()));
        }

    @Override
    public int invokeNext(Frame frame, ObjectHandle hTarget, int iReturn)
        {
        PackedInteger pi = ((IntNHandle) hTarget).getValue();

        return frame.assignValue(iReturn, makeInt(pi.next()));
        }

    @Override
    public int invokeDiv(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        PackedInteger pi1 = ((IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeInt(pi1.div(pi2)));
        }

    @Override
    public int invokeMod(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        PackedInteger pi1 = ((IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();

        PackedInteger piMod = pi1.mod(pi2);
        if (piMod.compareTo(PackedInteger.ZERO) < 0)
            {
            piMod = piMod.add((pi2.compareTo(PackedInteger.ZERO) < 0 ? pi2.negate() : pi2));
            }

        return frame.assignValue(iReturn, makeInt(piMod));
        }

    @Override
    public int invokeShl(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        PackedInteger pi1 = ((xIntLiteral.IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeInt(pi1.shl(pi2)));
        }

    @Override
    public int invokeShr(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        PackedInteger pi1 = ((IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeInt(pi1.shr(pi2)));
        }

    @Override
    public int invokeShrAll(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        PackedInteger pi1 = ((IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeInt(pi1.ushr(pi2)));
        }

    @Override
    public int invokeAnd(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        PackedInteger pi1 = ((IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeInt(pi1.and(pi2)));
        }

    @Override
    public int invokeOr(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        PackedInteger pi1 = ((IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeInt(pi1.or(pi2)));
        }

    @Override
    public int invokeXor(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        PackedInteger pi1 = ((IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeInt(pi1.xor(pi2)));
        }

    @Override
    public int invokeDivRem(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int[] aiReturn)
        {
        PackedInteger pi1 = ((IntNHandle) hTarget).getValue();
        PackedInteger pi2 = ((IntNHandle) hArg).getValue();

        PackedInteger[] aQuoRem = pi1.divrem(pi2);
        return frame.assignValues(aiReturn, makeInt(aQuoRem[0]), makeInt(aQuoRem[1]));
        }

    @Override
    public int invokeCompl(Frame frame, ObjectHandle hTarget, int iReturn)
        {
        PackedInteger pi = ((IntNHandle) hTarget).getValue();

        return frame.assignValue(iReturn, makeInt(pi.complement()));
        }

    @Override
    public int buildHashCode(Frame frame, ClassComposition clazz, ObjectHandle hTarget, int iReturn)
        {
        long l = ((ObjectHandle.JavaLong) hTarget).getValue();

        return frame.assignValue(iReturn, xInt64.makeHandle(l));
        }


    // ----- comparison support --------------------------------------------------------------------

    @Override
    public int callEquals(Frame frame, ClassComposition clazz,
                          ObjectHandle hValue1, ObjectHandle hValue2, int iReturn)
        {
        IntNHandle h1 = (xIntLiteral.IntNHandle) hValue1;
        IntNHandle h2 = (IntNHandle) hValue2;

        return frame.assignValue(iReturn, xBoolean.makeHandle(h1.getValue().equals(h2.getValue())));
        }

    @Override
    public int callCompare(Frame frame, ClassComposition clazz,
                           ObjectHandle hValue1, ObjectHandle hValue2, int iReturn)
        {
        IntNHandle h1 = (IntNHandle) hValue1;
        IntNHandle h2 = (IntNHandle) hValue2;

        return frame.assignValue(iReturn, xOrdered.makeHandle(h1.getValue().compareTo(h2.getValue())));
        }


    // ----- Object methods ------------------------------------------------------------------------

    @Override
    protected int buildStringValue(Frame frame, ObjectHandle hTarget, int iReturn)
        {
        PackedInteger pi = ((IntNHandle) hTarget).getValue();

        return frame.assignValue(iReturn, xString.makeHandle(pi.toString()));
        }

    /**
     * NOTE: we are using the IntNHandle for objects of UnconstrainedInteger types.
     */
    protected IntNHandle makeInt(PackedInteger iValue)
        {
        return new IntNHandle(getCanonicalClass(), iValue, null);
        }


    // ----- fields --------------------------------------------------------------------------------

    protected final boolean f_fChecked;
    protected final boolean f_fSigned;
    }

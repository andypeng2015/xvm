package org.xvm.runtime.template.numbers;


import org.xvm.asm.ClassStructure;
import org.xvm.asm.Constant;
import org.xvm.asm.MethodStructure;
import org.xvm.asm.Op;

import org.xvm.asm.constants.IntConstant;
import org.xvm.asm.constants.TypeConstant;

import org.xvm.runtime.ClassComposition;
import org.xvm.runtime.ClassTemplate;
import org.xvm.runtime.Frame;
import org.xvm.runtime.ObjectHandle;
import org.xvm.runtime.TemplateRegistry;
import org.xvm.runtime.TypeComposition;

import org.xvm.runtime.template.xBoolean;
import org.xvm.runtime.template.xConst;
import org.xvm.runtime.template.xException;
import org.xvm.runtime.template.xOrdered;

import org.xvm.runtime.template.text.xString;

import org.xvm.util.PackedInteger;

/**
 * Abstract base for Int128 and UInt128.
 */
public abstract class BaseInt128
        extends xConst
    {
    public final boolean f_fSigned;

    public BaseInt128(TemplateRegistry templates, ClassStructure structure, boolean fSigned)
        {
        super(templates, structure, false);

        f_fSigned = fSigned;
        }

    @Override
    public void initNative()
        {
        String sName = f_sName;

        if (f_fSigned)
            {
            markNativeProperty("magnitude");
            }
        markNativeMethod("toUnchecked", VOID, null);

        markNativeMethod("toInt128" , VOID, sName.equals("numbers.Int128") ? THIS : new String[]{"numbers.Int128"});
        markNativeMethod("toInt"    , VOID, new String[]{"numbers.Int64"});
        markNativeMethod("toInt32"  , VOID, new String[]{"numbers.Int32"});
        markNativeMethod("toInt16"  , VOID, new String[]{"numbers.Int16"});
        markNativeMethod("toInt8"   , VOID, new String[]{"numbers.Int8"});
        markNativeMethod("toUInt128", VOID, sName.equals("numbers.UInt128") ? THIS : new String[]{"numbers.UInt128"});
        markNativeMethod("toUInt"   , VOID, new String[]{"numbers.UInt64"});
        markNativeMethod("toUInt32" , VOID, new String[]{"numbers.UInt32"});
        markNativeMethod("toUInt16" , VOID, new String[]{"numbers.UInt16"});
        markNativeMethod("toByte"   , VOID, new String[]{"numbers.UInt8"});

        // @Op methods
        markNativeMethod("abs", VOID, THIS);
        markNativeMethod("add", THIS, THIS);
        markNativeMethod("sub", THIS, THIS);
        markNativeMethod("mul", THIS, THIS);
        markNativeMethod("div", THIS, THIS);
        markNativeMethod("mod", THIS, THIS);
        markNativeMethod("neg", VOID, THIS);

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
            PackedInteger piValue = ((IntConstant) constant).getValue();

            return frame.pushStack(makeLongLong(
                LongLong.fromBigInteger(piValue.getBigInteger())));
            }

        return super.createConstHandle(frame, constant);
        }

    @Override
    public int invokeNativeGet(Frame frame, String sPropName, ObjectHandle hTarget, int iReturn)
        {
        switch (sPropName)
            {
            case "magnitude":
                {
                if (f_fSigned)
                    {
                    LongLong ll = ((LongLongHandle) hTarget).getValue();
                    if (ll.signum() < 0)
                        {
                        ll = new LongLong(ll.getLowValue(), -ll.getHighValue());
                        }

                    return frame.assignValue(iReturn, xUInt128.INSTANCE.makeLongLong(ll));
                    }
                return frame.assignValue(iReturn, hTarget);
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
            case "abs":
                return invokeAbs(frame, hTarget, iReturn);

            case "add":
                return invokeAdd(frame, hTarget, hArg, iReturn);

            case "sub":
                return invokeSub(frame, hTarget, hArg, iReturn);

            case "mul":
                return invokeMul(frame, hTarget, hArg, iReturn);

            case "div":
                return invokeDiv(frame, hTarget, hArg, iReturn);

            case "neg":
                return invokeNeg(frame, hTarget, iReturn);
            }

        return super.invokeNative1(frame, method, hTarget, hArg, iReturn);
        }

    @Override
    public int invokeNativeN(Frame frame, MethodStructure method, ObjectHandle hTarget,
                             ObjectHandle[] ahArg, int iReturn)
        {
        switch (method.getName())
            {
            case "toUnchecked":
                {
                return frame.raiseException(xException.unsupportedOperation(frame, "toUnchecked"));
                }

            case "toInt8":
            case "toInt16":
            case "toInt32":
            case "toInt":
            case "toInt128":
            case "toByte":
            case "toUInt16":
            case "toUInt32":
            case "toUInt":
            case "toUInt128":
                {
                TypeConstant  typeRet  = method.getReturn(0).getType();
                ClassTemplate template = f_templates.getTemplate(typeRet);

                if (template == this)
                    {
                    return frame.assignValue(iReturn, hTarget);
                    }

                if (template instanceof xConstrainedInteger)
                    {
                    return convertToConstrainedType(frame, (xConstrainedInteger) template, hTarget, iReturn);
                    }

                if (template instanceof BaseInt128)
                    {
                    BaseInt128 templateTo = (BaseInt128) template;
                    LongLong    llValue    = ((LongLongHandle) hTarget).getValue();

                    if (f_fSigned && llValue.signum() < 0 && !templateTo.f_fSigned)
                        {
                        // cannot assign negative value to the unsigned type
                        return overflow(frame);
                        }

                    if (!f_fSigned && llValue.getHighValue() < 0 && templateTo.f_fSigned)
                        {
                        // too large value for signed LongLong
                        return overflow(frame);
                        }
                    return frame.assignValue(iReturn, templateTo.makeLongLong(llValue));
                    }
                break;
                }
            }

        return super.invokeNativeN(frame, method, hTarget, ahArg, iReturn);
        }

    protected int invokeAbs(Frame frame, ObjectHandle hTarget, int iReturn)
        {
        if (!f_fSigned)
            {
            return frame.assignValue(iReturn, hTarget);
            }

        LongLong ll = ((LongLongHandle) hTarget).getValue();

        if (ll.signum() >= 0)
            {
            frame.assignValue(iReturn, hTarget);
            }

        LongLong llr = ll.negate();
        if (llr == LongLong.OVERFLOW)
            {
            return overflow(frame);
            }

        return frame.assignValue(iReturn, makeLongLong(llr));
        }

    @Override
    public int invokeNeg(Frame frame, ObjectHandle hTarget, int iReturn)
        {
        if (!f_fSigned)
            {
            return overflow(frame);
            }

        LongLong ll = ((LongLongHandle) hTarget).getValue();
        LongLong llr = ll.negate();

        if (llr == LongLong.OVERFLOW)
            {
            return overflow(frame);
            }

        return frame.assignValue(iReturn, makeLongLong(llr));
        }

    @Override
    public int invokeAdd(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();
        LongLong llr = f_fSigned ? ll1.add(ll2) : ll1.addUnsigned(ll2);

        if (llr == LongLong.OVERFLOW)
            {
            return overflow(frame);
            }

        return frame.assignValue(iReturn, makeLongLong(llr));
        }

    @Override
    public int invokeSub(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();
        LongLong llr = f_fSigned ?  ll1.sub(ll2) : ll1.subUnassigned(ll2);

        if (llr == LongLong.OVERFLOW)
            {
            return overflow(frame);
            }

        return frame.assignValue(iReturn, makeLongLong(llr));
        }

    @Override
    public int invokeMul(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();
        LongLong llr = f_fSigned ? ll1.mul(ll2) : ll1.mulUnsigned(ll2);

        if (llr == LongLong.OVERFLOW)
            {
            return overflow(frame);
            }

        return frame.assignValue(iReturn, makeLongLong(llr));
        }

    @Override
    public int invokePrev(Frame frame, ObjectHandle hTarget, int iReturn)
        {
        LongLong ll = ((LongLongHandle) hTarget).getValue();
        LongLong llr = ll.prev(f_fSigned);

        if (llr == LongLong.OVERFLOW)
            {
            return overflow(frame);
            }

        return frame.assignValue(iReturn, makeLongLong(llr));
        }

    @Override
    public int invokeNext(Frame frame, ObjectHandle hTarget, int iReturn)
        {
        LongLong ll = ((LongLongHandle) hTarget).getValue();
        LongLong llr = ll.next(f_fSigned);

        if (llr == LongLong.OVERFLOW)
            {
            return overflow(frame);
            }

        return frame.assignValue(iReturn, makeLongLong(llr));
        }

    @Override
    public int invokeDiv(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();

        LongLong llDiv = f_fSigned
            ? ll1.div(ll2)
            : ll1.divUnsigned(ll2);

        if (llDiv == LongLong.OVERFLOW)
            {
            return overflow(frame);
            }

        return frame.assignValue(iReturn, makeLongLong(llDiv));
        }

    @Override
    public int invokeMod(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();

        LongLong llMod = f_fSigned
            ? ll1.mod(ll2)
            : ll1.modUnsigned(ll2);

        if (llMod == LongLong.OVERFLOW)
            {
            return overflow(frame);
            }

        return frame.assignValue(iReturn, makeLongLong(llMod));
        }

    @Override
    public int invokeDivRem(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int[] aiReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();

        LongLong[] allQuoRem;
        if (f_fSigned)
            {
            allQuoRem = ll1.divrem(ll2);
            }
        else
            {
            allQuoRem = ll1.divremUnsigned(ll2);
            }

        LongLong llDiv = allQuoRem[0];
        LongLong llRem = allQuoRem[1];
        if (llDiv == LongLong.OVERFLOW)
            {
            return overflow(frame);
            }
        return frame.assignValues(aiReturn, makeLongLong(llDiv), makeLongLong(llRem));
        }

    @Override
    public int invokeShl(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeLongLong(ll1.shl(ll2)));
        }

    @Override
    public int invokeShr(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeLongLong(ll1.shr(ll2)));
        }

    @Override
    public int invokeShrAll(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeLongLong(ll1.ushr(ll2)));
        }

    @Override
    public int invokeAnd(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeLongLong(ll1.and(ll2)));
        }

    @Override
    public int invokeOr(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeLongLong(ll1.or(ll2)));
        }

    @Override
    public int invokeXor(Frame frame, ObjectHandle hTarget, ObjectHandle hArg, int iReturn)
        {
        LongLong ll1 = ((LongLongHandle) hTarget).getValue();
        LongLong ll2 = ((LongLongHandle) hArg).getValue();

        return frame.assignValue(iReturn, makeLongLong(ll1.xor(ll2)));
        }

    @Override
    public int invokeCompl(Frame frame, ObjectHandle hTarget, int iReturn)
        {
        LongLong ll = ((LongLongHandle) hTarget).getValue();

        return frame.assignValue(iReturn, makeLongLong(ll.complement()));
        }

    @Override
    public int buildHashCode(Frame frame, ClassComposition clazz, ObjectHandle hTarget, int iReturn)
        {
        LongLong ll = ((LongLongHandle) hTarget).getValue();

        return frame.assignValue(iReturn, xInt64.makeHandle(ll.hashCode()));
        }

    // ----- comparison support -----

    @Override
    public int callEquals(Frame frame, ClassComposition clazz,
                          ObjectHandle hValue1, ObjectHandle hValue2, int iReturn)
        {
        LongLongHandle h1 = (LongLongHandle) hValue1;
        LongLongHandle h2 = (LongLongHandle) hValue2;

        return frame.assignValue(iReturn, xBoolean.makeHandle(h1.getValue().equals(h2.getValue())));
        }

    @Override
    public int callCompare(Frame frame, ClassComposition clazz,
                           ObjectHandle hValue1, ObjectHandle hValue2, int iReturn)
        {
        LongLongHandle h1 = (LongLongHandle) hValue1;
        LongLongHandle h2 = (LongLongHandle) hValue2;

        return frame.assignValue(iReturn, xOrdered.makeHandle(
            f_fSigned
                ? h1.getValue().compare(h2.getValue())
                : h1.getValue().compareUnsigned(h2.getValue())));
        }

    @Override
    protected int buildStringValue(Frame frame, ObjectHandle hTarget, int iReturn)
        {
        LongLong ll = ((LongLongHandle) hTarget).getValue();

        return frame.assignValue(iReturn, xString.makeHandle(
            f_fSigned
                ? ll.toBigInteger().toString()
                : ll.toUnsignedBigInteger().toString()));
        }


    // ----- helpers -------------------------------------------------------------------------------

    /**
     * Convert a long value into a handle for the type represented by this template.
     *
     * @return one of the {@link Op#R_NEXT} or {@link Op#R_EXCEPTION} values
     */
    protected int convertLong(Frame frame, long lValue, int iReturn)
        {
        return frame.assignValue(iReturn, makeLongLong(
            f_fSigned
                ? new LongLong(lValue)
                : new LongLong(lValue, 0)));
        }

    /**
     * Converts an object of "this" integer type to the type represented by the template.
     *
     * @return one of the {@link Op#R_NEXT} or {@link Op#R_EXCEPTION} values
     */
    abstract protected int convertToConstrainedType(Frame frame, xConstrainedInteger template,
                                                    ObjectHandle hTarget, int iReturn);

    public LongLongHandle makeLongLong(LongLong ll)
        {
        return new LongLongHandle(getCanonicalClass(), ll);
        }

    public static class LongLongHandle
            extends ObjectHandle
        {
        protected LongLong m_llValue;

        public LongLongHandle(TypeComposition clazz, LongLong ll)
            {
            super(clazz);
            m_llValue = ll;
            }

        public LongLong getValue()
            {
            return m_llValue;
            }

        @Override
        public int hashCode()
            {
            return m_llValue.hashCode();
            }

        @Override
        public boolean equals(Object obj)
            {
            return obj instanceof LongLongHandle &&
                m_llValue.equals(((LongLongHandle) obj).getValue());
            }

        @Override
        public String toString()
            {
            return super.toString() + m_llValue;
            }
        }
    }

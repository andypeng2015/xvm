package org.xvm.runtime.template._native.collections.arrays;


import org.xvm.asm.ClassStructure;
import org.xvm.asm.Op;

import org.xvm.runtime.ClassComposition;
import org.xvm.runtime.Container;
import org.xvm.runtime.Frame;
import org.xvm.runtime.ObjectHandle;
import org.xvm.runtime.ObjectHandle.JavaLong;
import org.xvm.runtime.TypeComposition;

import org.xvm.runtime.template.collections.xArray.Mutability;

import org.xvm.runtime.template.numbers.xBit;

import org.xvm.runtime.template._native.collections.arrays.ByteBasedDelegate.ByteArrayHandle;
import org.xvm.runtime.template._native.collections.arrays.xRTSlicingDelegate.SliceHandle;


/**
 * A base class for native ArrayDelegate<Bit> views that point to delegates holding byte arrays.
 */
public abstract class ByteBasedBitView
        extends xRTViewToBit
        implements BitView {
    public ByteBasedBitView(Container container, ClassStructure structure) {
        super(container, structure, false);
    }

    @Override
    public DelegateHandle createBitViewDelegate(DelegateHandle hSource, Mutability mutability) {
        ClassComposition clzView = getCanonicalClass();
        if (hSource instanceof SliceHandle hSlice) {
            // bytes.slice().asBitArray() -> bytes.asBitArray().slice()
            hSource = hSlice.f_hSource;

            if (hSource instanceof xRTView.ViewHandle hView) {
                hSource = hView.unwrapSource();
            }

            DelegateHandle hView = hSource instanceof ByteArrayHandle hBytes
                    ? new ViewHandle(clzView, hBytes, hBytes.getBitCount(), mutability)
                    : xRTViewToBit.INSTANCE.createBitViewDelegate(hSource, mutability);

            return slice(hView, hSlice.f_ofStart*8, hSlice.m_cSize*8, false);
        }

        if (hSource instanceof xRTView.ViewHandle hView) {
            hSource = hView.unwrapSource();
        }

        return hSource instanceof ByteArrayHandle hBytes
                    ? new ViewHandle(clzView, hBytes, hBytes.getBitCount(), mutability)
                    : xRTViewToBit.INSTANCE.createBitViewDelegate(hSource, mutability);
    }


    // ----- RTDelegate API ------------------------------------------------------------------------

    @Override
    protected DelegateHandle createCopyImpl(DelegateHandle hTarget, Mutability mutability,
                                            long ofStart, long cSize, boolean fReverse) {
        ViewHandle hView = (ViewHandle) hTarget;

        byte[] abBits = getBits(hView, ofStart, cSize, fReverse);

        return xRTBitDelegate.INSTANCE.makeHandle(abBits, cSize, mutability);
    }

    @Override
    protected int extractArrayValueImpl(Frame frame, DelegateHandle hTarget, long lIndex, int iReturn) {
        ViewHandle hView = (ViewHandle) hTarget;

        return frame.assignValue(iReturn, xBit.makeHandle(
                BitBasedDelegate.getBit(hView.f_hSource.m_abValue, lIndex)));
    }

    @Override
    public int assignArrayValueImpl(Frame frame, DelegateHandle hTarget, long lIndex,
                                    ObjectHandle hValue) {
        ViewHandle hView = (ViewHandle) hTarget;

        BitBasedDelegate.setBit(hView.f_hSource.m_abValue, lIndex, ((JavaLong) hValue).getValue() != 0);
        return Op.R_NEXT;
    }


    // ----- BitView implementation ----------------------------------------------------------------

    @Override
    public byte[] getBits(DelegateHandle hDelegate, long ofStart, long cBits, boolean fReverse) {
        ViewHandle hView = (ViewHandle) hDelegate;

        byte[] abBits = BitBasedDelegate.extractBits(hView.f_hSource.m_abValue, ofStart, cBits);

        if (fReverse) {
            abBits = BitBasedDelegate.reverseBits(abBits, cBits);
        }
        return abBits;
    }

    @Override
    public boolean extractBit(DelegateHandle hDelegate, long of) {
        ViewHandle hView = (ViewHandle) hDelegate;

        return BitBasedDelegate.getBit(hView.f_hSource.m_abValue, of);
    }

    @Override
    public void assignBit(DelegateHandle hDelegate, long of, boolean fBit) {
        ViewHandle hView = (ViewHandle) hDelegate;

        BitBasedDelegate.setBit(hView.f_hSource.m_abValue, of, fBit);
    }


    // ----- ByteView implementation ---------------------------------------------------------------

    @Override
    public byte[] getBytes(DelegateHandle hDelegate, long ofStart, long cBytes, boolean fReverse) {
        return getBits(hDelegate, ofStart*8, cBytes*8, fReverse);
    }

    @Override
    public byte extractByte(DelegateHandle hDelegate, long of) {
        ViewHandle hView = (ViewHandle) hDelegate;

        return hView.f_hSource.m_abValue[(int) of];
    }

    @Override
    public void assignByte(DelegateHandle hDelegate, long of, byte bValue) {
        ViewHandle hView = (ViewHandle) hDelegate;

        hView.f_hSource.m_abValue[(int) of] = bValue;
    }


    // ----- handle --------------------------------------------------------------------------------

    /**
     * DelegateArray<Bit> view delegate.
     */
    protected static class ViewHandle
            extends xRTView.ViewHandle {
        protected final ByteArrayHandle f_hSource;

        protected ViewHandle(TypeComposition clazz, ByteArrayHandle hSource, long cSize,
                             Mutability mutability) {
            super(clazz, mutability);

            f_hSource = hSource;
            m_cSize   = cSize;
        }

        @Override
        public DelegateHandle getSource() {
            return f_hSource;
        }
    }
}
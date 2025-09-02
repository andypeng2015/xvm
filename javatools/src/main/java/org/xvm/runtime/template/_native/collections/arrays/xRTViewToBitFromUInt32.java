package org.xvm.runtime.template._native.collections.arrays;


import org.xvm.asm.ClassStructure;
import org.xvm.asm.ConstantPool;

import org.xvm.asm.constants.TypeConstant;

import org.xvm.runtime.Container;


/**
 * The native RTViewToBit<UInt32> implementation.
 */
public class xRTViewToBitFromUInt32
        extends LongBasedBitView {
    public static xRTViewToBitFromUInt32 INSTANCE;

    public xRTViewToBitFromUInt32(Container container, ClassStructure structure, boolean fInstance) {
        super(container, structure, 32);

        if (fInstance) {
            INSTANCE = this;
        }
    }

    @Override
    public void initNative() {
    }

    @Override
    public TypeConstant getCanonicalType() {
        ConstantPool pool = pool();
        return pool.ensureParameterizedTypeConstant(
                getInceptionClassConstant().getType(),
                pool.typeUInt32());
    }
}
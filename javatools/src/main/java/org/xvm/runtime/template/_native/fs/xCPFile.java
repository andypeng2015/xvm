package org.xvm.runtime.template._native.fs;


import org.xvm.asm.ClassStructure;
import org.xvm.asm.Constant;
import org.xvm.asm.Constant.Format;
import org.xvm.asm.ConstantPool;
import org.xvm.asm.Constants.Access;
import org.xvm.asm.MethodStructure;
import org.xvm.asm.Op;

import org.xvm.asm.constants.FSNodeConstant;

import org.xvm.runtime.Frame;
import org.xvm.runtime.ObjectHandle;
import org.xvm.runtime.ObjectHandle.ConstantHandle;
import org.xvm.runtime.ObjectHandle.GenericHandle;
import org.xvm.runtime.TemplateRegistry;
import org.xvm.runtime.TypeComposition;
import org.xvm.runtime.Utils;

import org.xvm.runtime.template.xConst;


/**
 * Native OSFileStore implementation.
 */
public class xCPFile
        extends xConst
    {
    public xCPFile(TemplateRegistry templates, ClassStructure structure, boolean fInstance)
        {
        super(templates, structure, false);
        }

    @Override
    public void initNative()
        {
        ConstantPool pool = pool();

        s_clz         = ensureClass(getCanonicalType(), pool.typeFile());
        s_clzStruct   = s_clz.ensureAccess(Access.STRUCT);
        s_constructor = getStructure().findConstructor(pool.typeObject());
        }

    @Override
    public int createConstHandle(Frame frame, Constant constant)
        {
        if (constant instanceof FSNodeConstant && constant.getFormat() == Format.FSFile)
            {
            FSNodeConstant constFile = (FSNodeConstant) constant;

            GenericHandle  hStruct = new GenericHandle(s_clzStruct);
            ObjectHandle[] ahVar   = Utils.ensureSize(Utils.OBJECTS_NONE, s_constructor.getMaxVars());
            ahVar[0] = new ConstantHandle(constFile);

            return proceedConstruction(frame, s_constructor, true, hStruct, ahVar, Op.A_STACK);
            }

        return super.createConstHandle(frame, constant);
        }


    // ----- constants -----------------------------------------------------------------------------

    private static TypeComposition s_clz;
    private static TypeComposition s_clzStruct;
    private static MethodStructure s_constructor;


    // ----- data members --------------------------------------------------------------------------
    }

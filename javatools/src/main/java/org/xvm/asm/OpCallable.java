package org.xvm.asm;


import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

import org.xvm.asm.Constants.Access;

import org.xvm.asm.constants.ClassConstant;
import org.xvm.asm.constants.FormalConstant;
import org.xvm.asm.constants.IdentityConstant;
import org.xvm.asm.constants.MethodConstant;
import org.xvm.asm.constants.MethodInfo;
import org.xvm.asm.constants.SignatureConstant;
import org.xvm.asm.constants.TypeConstant;
import org.xvm.asm.constants.TypeInfo;

import org.xvm.runtime.ClassTemplate;
import org.xvm.runtime.Frame;
import org.xvm.runtime.ObjectHandle;
import org.xvm.runtime.ServiceContext;
import org.xvm.runtime.TypeComposition;

import org.xvm.runtime.template._native.reflect.xRTType.TypeHandle;

import static org.xvm.util.Handy.readPackedInt;
import static org.xvm.util.Handy.writePackedLong;


/**
 * Common base for CALL_ ops.
 */
public abstract class OpCallable extends Op
    {
    /**
     * Construct an op based on the passed argument.
     *
     * @param argFunction  the function Argument
     */
    protected OpCallable(Argument argFunction)
        {
        m_argFunction = argFunction;
        }

    /**
     * Deserialization constructor.
     *
     * @param in      the DataInput to read from
     * @param aconst  an array of constants used within the method
     */
    protected OpCallable(DataInput in, Constant[] aconst)
            throws IOException
        {
        m_nFunctionId = readPackedInt(in);
        }

    @Override
    public void write(DataOutput out, ConstantRegistry registry)
            throws IOException
        {
        super.write(out, registry);

        if (m_argFunction != null)
            {
            m_nFunctionId = encodeArgument(m_argFunction, registry);
            }

        writePackedLong(out, m_nFunctionId);
        }

    @Override
    public boolean usesSuper()
        {
        return m_nFunctionId == A_SUPER;
        }

    /**
     * A "virtual constant" indicating whether or not this op has multiple return values.
     *
     * @return true iff the op has multiple return values.
     */
    protected boolean isMultiReturn()
        {
        return false;
        }

    @Override
    public void resetSimulation()
        {
        if (isMultiReturn())
            {
            resetRegisters(m_aArgReturn);
            }
        else
            {
            resetRegister(m_argReturn);
            }
        }

    @Override
    public void simulate(Scope scope)
        {
        if (isMultiReturn())
            {
            checkNextRegisters(scope, m_aArgReturn, m_anRetValue);
            }
        else
            {
            checkNextRegister(scope, m_argReturn, m_nRetValue);
            }
        }

    @Override
    public void registerConstants(ConstantRegistry registry)
        {
        m_argFunction = registerArgument(m_argFunction, registry);

        if (isMultiReturn())
            {
            registerArguments(m_aArgReturn, registry);
            }
        else
            {
            m_argReturn = registerArgument(m_argReturn, registry);
            }
        }

    /**
     * This Op holds a constant for the constructor of a child of the compile-time parent.
     * The run-time type of the parent could extend the compile-time type and that parent
     * may have a corresponding child extension.
     *
     * @return a child constructor for the specified parent
     */
    protected MethodStructure getChildConstructor(Frame frame, ObjectHandle hParent)
        {
        // suffix "C" indicates the compile-time constants; "R" - the run-time
        ClassConstant   idParentR   = (ClassConstant) hParent.getTemplate().getClassConstant();
        ServiceContext  context     = frame.f_context;
        MethodStructure constructor = (MethodStructure) context.getOpInfo(this, Category.Constructor);
        if (constructor != null)
            {
            ClassConstant idParent = (ClassConstant) context.getOpInfo(this, Category.ParentClass);
            if (idParent.equals(idParentR))
                {
                // cached constructor fits the parent's class
                return constructor;
                }
            }

        constructor = getMethodStructure(frame);
        if (constructor == null)
            {
            return null;
            }
        ClassStructure clzTargetC = (ClassStructure) constructor.getParent().getParent();
        ClassStructure clzParentC = (ClassStructure) clzTargetC.getParent();
        ClassConstant  idParentC  = (ClassConstant)  clzParentC.getIdentityConstant();

        if (!idParentR.equals(idParentC))
            {
            // find the run-time target's constructor;
            // note that we don't need to resolve the actual types
            String         sChild      = clzTargetC.getSimpleName();
            ClassStructure clzParentR  = (ClassStructure) idParentR.getComponent();
            ClassStructure clzChild    = clzParentR.getVirtualChild(sChild);
            TypeInfo       infoTarget  = clzChild.getFormalType().ensureTypeInfo();

            MethodInfo info = infoTarget.getMethodBySignature(
                constructor.getIdentityConstant().getSignature());
            constructor = info.getTopmostMethodStructure(infoTarget);
            }

        context.setOpInfo(this, Category.ParentClass, idParentR);
        context.setOpInfo(this, Category.Constructor, constructor);
        return constructor;
        }

    /**
     * This Op holds a constant for the constructor of the compile-time target.
     * The run-time type of the target could extend the compile-time type and that target
     * must have the corresponding constructor
     *
     * @return a constructor for the specified type
     */
    protected MethodStructure getTypeConstructor(Frame frame, TypeHandle hType)
        {
        TypeConstant    typeR       = hType.getDataType();
        ClassConstant   idTargetR   = (ClassConstant) typeR.getDefiningConstant();
        ServiceContext  context     = frame.f_context;
        MethodStructure constructor = (MethodStructure) context.getOpInfo(this, Category.Constructor);
        if (constructor != null)
            {
            ClassConstant idTarget = (ClassConstant) context.getOpInfo(this, Category.ParentClass);
            if (idTarget.equals(idTargetR))
                {
                // cached constructor fits the parent's class
                return constructor;
                }
            }

        constructor = getMethodStructure(frame);
        if (constructor == null)
            {
            return null;
            }

        ClassStructure clzTargetC = (ClassStructure) constructor.getParent().getParent();
        ClassConstant  idTargetC  = (ClassConstant)  clzTargetC.getIdentityConstant();

        if (!idTargetR.equals(idTargetC))
            {
            TypeInfo infoTarget = typeR.ensureTypeInfo();

            MethodInfo info = infoTarget.getMethodBySignature(
                constructor.getIdentityConstant().getSignature());
            if (info == null)
                {
                return null;
                }
            constructor = info.getTopmostMethodStructure(infoTarget);
            }

        context.setOpInfo(this, Category.ParentClass, idTargetR);
        context.setOpInfo(this, Category.Constructor, constructor);
        return constructor;
        }

    /**
     * @return R_EXCEPTION
     */
    protected int reportMissingConstructor(Frame frame, ObjectHandle hParent)
        {
        IdentityConstant idParent    = hParent.getTemplate().getClassConstant();
        MethodStructure  constructor = getMethodStructure(frame);
        if (constructor == null)
            {
            return R_EXCEPTION;
            }

        SignatureConstant sigConstructor = constructor.getIdentityConstant().getSignature();
        return frame.raiseException("Missing constructor \"" + sigConstructor.getValueString() +
                                     "\" at class " + idParent.getValueString());
        }

    @Override
    public String toString()
        {
        return super.toString() + ' ' + getFunctionString() + '(' + getParamsString() + ") -> " + getReturnsString();
        }
    protected String getFunctionString()
        {
        return Argument.toIdString(m_argFunction, m_nFunctionId);
        }
    protected String getParamsString()
        {
        return "";
        }
    protected static String getParamsString(int[] anArgValue, Argument[] aArgValue)
        {
        StringBuilder sb = new StringBuilder();
        int cArgNums = anArgValue == null ? 0 : anArgValue.length;
        int cArgRefs = aArgValue == null ? 0 : aArgValue.length;
        for (int i = 0, c = Math.max(cArgNums, cArgRefs); i < c; ++i)
            {
            if (i > 0)
                {
                sb.append(", ");
                }
            sb.append(Argument.toIdString(i < cArgRefs ? aArgValue[i] : null,
                    i < cArgNums ? anArgValue[i] : Register.UNKNOWN));
            }
        return sb.toString();
        }
    protected String getReturnsString()
        {
        if (m_anRetValue != null || m_aArgReturn != null)
            {
            // multi-return
            StringBuilder sb = new StringBuilder();
            int cArgNums = m_anRetValue == null ? 0 : m_anRetValue.length;
            int cArgRefs = m_aArgReturn == null ? 0 : m_aArgReturn.length;
            for (int i = 0, c = Math.max(cArgNums, cArgRefs); i < c; ++i)
                {
                sb.append(i == 0 ? "(" : ", ")
                        .append(Argument.toIdString(i < cArgRefs ? m_aArgReturn[i] : null,
                                i < cArgNums ? m_anRetValue[i] : Register.UNKNOWN));
                }
            return sb.append(')').toString();
            }

        if (m_nRetValue != A_IGNORE || m_argReturn != null)
            {
            return Argument.toIdString(m_argReturn, m_nRetValue);
            }

        return "void";
        }

    // ----- helper methods ------------------------------------------------------------------------

    /**
     * Retrieve the method structure for this op-code and cache the parent's template
     * to be used by {@link #getNativeTemplate}.
     *
     * @return the method structure or null if cannot be found, in which case an exception
     *         has been raised on the frame
     */
    protected MethodStructure getMethodStructure(Frame frame)
        {
        ServiceContext   context    = frame.f_context;
        MethodConstant   idFunction = (MethodConstant) frame.getConstant(m_nFunctionId);
        MethodStructure  function   = (MethodStructure) context.getOpInfo(this, Category.Function);
        IdentityConstant idParent   = idFunction.getNamespace();

        switch (idParent.getFormat())
            {
            case Module:
            case Package:
            case Class:
                {
                if (function == null)
                    {
                    ConstantPool        pool     = frame.poolContext();
                    GenericTypeResolver resolver = frame.getGenericsResolver();

                    TypeConstant typeParent = idParent.getFormalType().resolveGenerics(pool, resolver);

                    function = (MethodStructure) idFunction.getComponent();
                    if (function == null)
                        {
                        function = pool.ensureAccessTypeConstant(typeParent, Access.PRIVATE).
                            findCallable(idFunction.getSignature().resolveGenericTypes(pool, resolver));
                        }

                    if (function == null)
                        {
                        frame.raiseException("Unresolvable or ambiguous function \"" +
                            idFunction.getValueString() + "\" for " + typeParent.getValueString());
                        return null;
                        }

                    context.setOpInfo(this, Category.Function, function);
                    context.setOpInfo(this, Category.Template,
                            context.f_templates.getTemplate(typeParent));
                    }
                break;
                }

            case FormalTypeChild:
            case Property:
            case TypeParameter:
                {
                GenericTypeResolver resolver   = frame.getGenericsResolver();
                TypeConstant        typeParent = ((FormalConstant) idParent).resolve(resolver);
                TypeConstant        typePrev   = (TypeConstant) context.getOpInfo(this, Category.ParentType);
                if (function == null || !typeParent.equals(typePrev))
                    {
                    function = typeParent.findCallable(idFunction.getSignature());
                    if (function == null)
                        {
                        frame.raiseException("Unresolvable or ambiguous function \"" +
                            idFunction.getValueString() + "\" for " + typeParent.getValueString());
                        return null;
                        }

                    context.setOpInfo(this, Category.Function, function);
                    context.setOpInfo(this, Category.ParentType, typeParent);
                    context.setOpInfo(this, Category.Template,
                            context.f_templates.getTemplate(typeParent));
                    }
                break;
                }

            case Method:
                {
                if (function == null)
                    {
                    function = (MethodStructure) idFunction.getComponent();
                    assert !function.isNative();

                    // since the function is never native, no need to save the template
                    context.setOpInfo(this, Category.Function, function);
                    }
                break;
                }

            default:
                throw new IllegalStateException();
            }

        return function;
        }

    /**
     * @return the ClassTemplate that defines a native implementation for the specified function
     *         using the information collected by {@link #getMethodStructure}
     */
    protected ClassTemplate getNativeTemplate(Frame frame, MethodStructure function)
        {
        assert function == frame.f_context.getOpInfo(this, Category.Function);
        return (ClassTemplate) frame.f_context.getOpInfo(this, Category.Template);
        }

    protected int constructChild(Frame frame, MethodStructure constructor,
                                 ObjectHandle hParent, ObjectHandle[] ahVar)
        {
        ClassStructure  structChild = (ClassStructure) constructor.getParent().getParent();
        TypeConstant    typeChild   = getCanonicalChildType(frame, hParent.getType(), structChild.getName());
        TypeComposition clzTarget   = frame.ensureClass(typeChild);

        if (frame.isNextRegister(m_nRetValue))
            {
            frame.introduceResolvedVar(m_nRetValue, clzTarget.getType());
            }

        return clzTarget.getTemplate().construct(
                frame, constructor, clzTarget, hParent, ahVar, m_nRetValue);
        }

    // return the corresponding VirtualChildType constant
    protected TypeConstant getCanonicalChildType(Frame frame, TypeConstant typeParent, String sName)
        {
        return frame.poolContext().ensureVirtualChildTypeConstant(typeParent, sName);
        }

    // check if a register for the return value needs to be allocated
    protected void checkReturnRegister(Frame frame, MethodStructure method)
        {
        assert !isMultiReturn();

        if (frame.isNextRegister(m_nRetValue))
            {
            frame.introduceMethodReturnVar(m_nRetValue, method.getIdentityConstant().getPosition(), 0);
            }
        }

    // check if a register for the return Tuple value needs to be allocated
    protected void checkReturnTupleRegister(Frame frame, MethodStructure method)
        {
        assert !isMultiReturn();

        if (frame.isNextRegister(m_nRetValue))
            {
            frame.introduceMethodReturnVar(m_nRetValue, method.getIdentityConstant().getPosition(), 0);
            }
        }

    // check if any registers for the return values need to be allocated
    protected void checkReturnRegisters(Frame frame, MethodStructure method)
        {
        assert isMultiReturn();

        int[] anRet = m_anRetValue;
        for (int i = 0, c = anRet.length; i < c; i++)
            {
            if (frame.isNextRegister(anRet[i]))
                {
                frame.introduceMethodReturnVar(anRet[i], method.getIdentityConstant().getPosition(), i);
                }
            }
        }

    protected int   m_nFunctionId;
    protected int   m_nRetValue = A_IGNORE;
    protected int[] m_anRetValue;

    protected Argument   m_argFunction;
    protected Argument   m_argReturn;  // optional
    protected Argument[] m_aArgReturn; // optional

    // categories for cached info
    enum Category {Function, Template, ParentClass, ParentType, Constructor};
    }

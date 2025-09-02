package org.xvm.runtime;


import org.xvm.asm.Op;

import org.xvm.runtime.template.reflect.xRef.RefHandle;


/**
 * {@link VarSupport} represents a run-time facet of a Var.
 */
public interface VarSupport
        extends OpSupport {
    // ----- construction --------------------------------------------------------------------------

    /**
     * Create an uninitialized Ref or a Var for the specified referent class.
     *
     * @param frame  the current frame if a register is created; null for properties
     * @param clazz  the referent class
     * @param sName  an optional Ref/Var name
     *
     * @return the uninitialized corresponding {@link RefHandle}
     */
    RefHandle createRefHandle(Frame frame, TypeComposition clazz, String sName);

    /**
     * Introduce a Ref or a Var for the specified referent class.
     *
     * @param frame    the current frame
     * @param clazz    the referent class
     * @param sName    an optional Ref/Var name
     * @param iReturn  the register to place the handle to
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int introduceRef(Frame frame, TypeComposition clazz, String sName, int iReturn);


    // ----- built-in unary operations -------------------------------------------------------------

    /**
     * Get the Var's referent.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var or Ref handle
     * @param iReturn  the register id to place a result of the operation into
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int getReferent(Frame frame, RefHandle hTarget, int iReturn);

    /**
     * Increment the Var value and retrieve the new value.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param iReturn  the register id to place a result of the operation into
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarPreInc(Frame frame, RefHandle hTarget, int iReturn);

    /**
     * Retrieve the Var value and then increment it.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param iReturn  the register id to place a result of the operation into
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarPostInc(Frame frame, RefHandle hTarget, int iReturn);

    /**
     * Decrement the Var value and retrieve the new value.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param iReturn  the register id to place a result of the operation into
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarPreDec(Frame frame, RefHandle hTarget, int iReturn);

    /**
     * Retrieve the Var value and then decrement it.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param iReturn  the register id to place a result of the operation into
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarPostDec(Frame frame, RefHandle hTarget, int iReturn);


    // ----- built-in binary operations ------------------------------------------------------------

    /**
     * Set the Var's referent.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hValue   the new value
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int setReferent(Frame frame, RefHandle hTarget, ObjectHandle hValue);

    /**
     * Perform an "add" operation on the Var.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hArg     the argument handle
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarAdd(Frame frame, RefHandle hTarget, ObjectHandle hArg);

    /**
     * Perform a "subtract" operation on the Var.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hArg     the argument handle
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarSub(Frame frame, RefHandle hTarget, ObjectHandle hArg);

    /**
     * Perform a "multiply" operation on the Var.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hArg     the argument handle
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarMul(Frame frame, RefHandle hTarget, ObjectHandle hArg);

    /**
     * Perform a "divide" operation on the Var.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hArg     the argument handle
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarDiv(Frame frame, RefHandle hTarget, ObjectHandle hArg);

    /**
     * Perform a "modulo" operation on the Var.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hArg     the argument handle
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarMod(Frame frame, RefHandle hTarget, ObjectHandle hArg);

    /**
     * Perform a "shift-left" operation on the Var.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hArg     the argument handle
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarShl(Frame frame, RefHandle hTarget, ObjectHandle hArg);

    /**
     * Perform a "shift-right" operation on the Var.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hArg     the argument handle
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarShr(Frame frame, RefHandle hTarget, ObjectHandle hArg);

    /**
     * Perform an "unsigned shift right" operation on the Var.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hArg     the argument handle
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarShrAll(Frame frame, RefHandle hTarget, ObjectHandle hArg);

    /**
     * Perform an "and" operation on the Var.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hArg     the argument handle
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarAnd(Frame frame, RefHandle hTarget, ObjectHandle hArg);

    /**
     * Perform an "or" operation on the Var.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hArg     the argument handle
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarOr(Frame frame, RefHandle hTarget, ObjectHandle hArg);

    /**
     * Perform an "exclusive or" operation on the Var.
     *
     * @param frame    the current frame
     * @param hTarget  the target Var handle
     * @param hArg     the argument handle
     *
     * @return one of the {@link Op#R_NEXT}, {@link Op#R_CALL} or {@link Op#R_EXCEPTION}
     */
    int invokeVarXor(Frame frame, RefHandle hTarget, ObjectHandle hArg);
}

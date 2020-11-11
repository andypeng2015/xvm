package org.xvm.compiler.ast;


import java.lang.reflect.Field;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.xvm.asm.Argument;
import org.xvm.asm.Assignment;
import org.xvm.asm.ConstantPool;
import org.xvm.asm.ErrorListener;
import org.xvm.asm.MethodStructure.Code;

import org.xvm.asm.constants.MethodConstant;
import org.xvm.asm.constants.StringConstant;
import org.xvm.asm.constants.TypeConstant;

import org.xvm.asm.op.Assert;
import org.xvm.asm.op.AssertM;
import org.xvm.asm.op.AssertV;
import org.xvm.asm.op.JumpNCond;
import org.xvm.asm.op.JumpNFirst;
import org.xvm.asm.op.JumpNSample;

import org.xvm.compiler.Compiler;
import org.xvm.compiler.Token;
import org.xvm.compiler.Token.Id;

import org.xvm.util.Handy;
import org.xvm.util.ListMap;
import org.xvm.util.Severity;


/**
 * An assert statement.
 */
public class AssertStatement
        extends Statement
    {
    // ----- constructors --------------------------------------------------------------------------

    public AssertStatement(Token keyword, Expression exprInterval, List<AstNode> conds, long lEndPos)
        {
        switch (keyword.getId())
            {
            case ASSERT:
            case ASSERT_RND:
            case ASSERT_ARG:
            case ASSERT_BOUNDS:
            case ASSERT_TODO:
            case ASSERT_ONCE:
            case ASSERT_TEST:
            case ASSERT_DBG:
                break;

            default:
                throw new IllegalArgumentException("keyword=" + keyword);
            }

        this.keyword  = keyword;
        this.interval = exprInterval;
        this.conds    = conds == null ? Collections.emptyList() : conds;
        this.lEndPos  = lEndPos;
        }


    // ----- accessors -----------------------------------------------------------------------------

    @Override
    public long getStartPosition()
        {
        return keyword.getStartPosition();
        }

    @Override
    public long getEndPosition()
        {
        return conds.isEmpty()
                ? keyword.getEndPosition()
                : conds.get(conds.size()-1).getEndPosition();
        }

    /**
     * @return the number of conditions
     */
    public int getConditionCount()
        {
        return conds.size();
        }

    /**
     * @param i  a value between 0 and {@link #getConditionCount()}-1
     *
     * @return the condition, which is either an Expression or an AssignmentStatement
     */
    public AstNode getCondition(int i)
        {
        return conds.get(i);
        }

    /**
     * @param exprChild  an expression that is a child of this statement
     *
     * @return the index of the expression in the list of conditions within this statement, or -1
     */
    public int findCondition(Expression exprChild)
        {
        for (int i = 0, c = getConditionCount(); i < c; ++i)
            {
            if (conds.get(i) == exprChild)
                {
                return i;
                }
            }
        return -1;
        }

    /**
     * @return true iff the assertion occurs explicitly within conditional "debug" mode
     */
    public boolean isDebugOnly()
        {
        return keyword.getId() == Id.ASSERT_DBG;
        }

    /**
     * @return true iff the assertion occurs explicitly within conditional "test" mode
     */
    public boolean isTestOnly()
        {
        return keyword.getId() == Id.ASSERT_TEST;
        }

    /**
     * @return true iff the assertion occurs explicitly within a conditional mode
     */
    public boolean isLinktimeConditional()
        {
        return isDebugOnly() | isTestOnly();
        }

    /**
     * @return true iff the assertion is executed only the first time that the execution reaches it
     */
    public boolean isOnlyOnce()
        {
        return keyword.getId() == Id.ASSERT_ONCE;
        }

    /**
     * @return true iff the assertion is executed as if it were statistically sampling
     */
    public boolean isSampling()
        {
        return keyword.getId() == Id.ASSERT_RND;
        }

    /**
     * @return true iff the assertion does not occur each time the execution reaches it
     */
    public boolean isNotAlways()
        {
        return isOnlyOnce() | isSampling();
        }

    /**
     * @return the inverse rate of assertion evaluation; for example "5" means (on average) 1/5 of
     *         the time
     */
    public Expression getSampleInterval()
        {
        return interval;
        }

    @Override
    protected Field[] getChildFields()
        {
        return CHILD_FIELDS;
        }


    // ----- compilation ---------------------------------------------------------------------------

    @Override
    protected boolean allowsShortCircuit(AstNode nodeChild)
        {
        return true;
        }

    @Override
    protected Statement validateImpl(Context ctx, ErrorListener errs)
        {
        if (keyword.getId() == Id.ASSERT && conds.isEmpty())
            {
            ctx.setReachable(false);
            return this;
            }

        boolean fValid  = true;

        // break apart complex conditions if possible
        demorgan();

        if (interval != null)
            {
            Expression exprNew = interval.validate(ctx, pool().typeInt(), errs);
            if (exprNew == null)
                {
                fValid = false;
                }
            else
                {
                interval = exprNew;
                if (!interval.isRuntimeConstant())
                    {
                    interval.log(errs, Severity.ERROR, Compiler.CONSTANT_REQUIRED);
                    }
                }
            }

        for (int i = 0, c = getConditionCount(); i < c; ++i)
            {
            AstNode cond = getCondition(i);
            // the condition is either a boolean expression or an assignment statement whose R-value
            // is a multi-value with the first value being a boolean
            if (cond instanceof AssignmentStatement)
                {
                AssignmentStatement stmtOld = (AssignmentStatement) cond;
                AssignmentStatement stmtNew = (AssignmentStatement) stmtOld.validate(ctx, errs);
                if (stmtNew == null)
                    {
                    fValid = false;
                    }
                else
                    {
                    if (stmtNew != stmtOld)
                        {
                        cond = stmtNew;
                        conds.set(i, cond);
                        }
                    }
                }
            else if (cond instanceof Expression)
                {
                ctx = new AssertContext(ctx);

                Expression exprOld = (Expression) cond;
                Expression exprNew = exprOld.validate(ctx, pool().typeBoolean(), errs);
                if (exprNew == null)
                    {
                    fValid = false;
                    }
                else
                    {
                    if (exprNew != exprOld)
                        {
                        cond = exprNew;
                        conds.set(i, cond);
                        }

                    if (exprNew.isConstantFalse())
                        {
                        ctx.setReachable(false);
                        }
                    }

                ctx = ctx.exit();
                }
            }

        return fValid
                ? this
                : null;
        }

    @Override
    protected boolean emit(Context ctx, boolean fReachable, Code code, ErrorListener errs)
        {
        ConstantPool pool = pool();

        if (isLinktimeConditional())
            {
            // for "assert:debug", the assertion only is evaluated if the "debug" named condition
            // exists; similarly, for "assert:test", it is evaluated only if "test" is defined
            String sCond = isDebugOnly() ? "debug" : "test";
            code.add(new JumpNCond(pool.ensureNamedCondition(sCond), getEndLabel()));
            }

        if (isNotAlways())
            {
            code.add(isOnlyOnce()
                    ? new JumpNFirst(getEndLabel())
                    : new JumpNSample(interval.generateArgument(ctx, code, true, true, errs), getEndLabel()));
            }

        MethodConstant constructException;
        switch (keyword.getId())
            {
            default:
            case ASSERT:
                constructException = findExceptionConstructor(pool, "IllegalState", errs);
                break;

            case ASSERT_ARG:
                constructException = findExceptionConstructor(pool, "IllegalArgument", errs);
                break;

            case ASSERT_BOUNDS:
                constructException = findExceptionConstructor(pool, "OutOfBounds", errs);
                break;

            case ASSERT_TODO:
                constructException = findExceptionConstructor(pool, "UnsupportedOperation", errs);
                break;

            case ASSERT_ONCE:
            case ASSERT_RND:
            case ASSERT_TEST:
                constructException = findExceptionConstructor(pool, "Assertion", errs);
                break;

            case ASSERT_DBG:
                constructException = null;
                break;
            }

        int cConds = getConditionCount();
        if (cConds == 0)
            {
            code.add(new Assert(pool.valFalse(), constructException));
            return isNotAlways() || isLinktimeConditional();
            }

        boolean fCompletes = fReachable;
        for (int i = 0; i < cConds; ++i)
            {
            AstNode cond   = getCondition(i);
            String  sCond  = m_listTexts.get(i);
            int     cTrace = 0;

            // add traces (if anything is interesting to trace)
            Map<String, Expression> mapTrace = new ListMap<>();
            cond.selectTraceableExpressions(mapTrace);
            if (!mapTrace.isEmpty())
                {
                StringBuilder sb = new StringBuilder(sCond);
                for (Map.Entry<String, Expression> entry : mapTrace.entrySet())
                    {
                    Expression expr = entry.getValue();
                    expr.requireTrace();

                    sb.append(", ")
                      .append(entry.getKey())
                      .append('=');

                    TypeConstant[] aTypes = expr.getTypes();
                    int            cTypes = aTypes.length;
                    if (cTypes != 1)
                        {
                        sb.append('(');
                        }

                    for (int iType = 0; iType < cTypes; ++iType)
                        {
                        if (iType > 0)
                            {
                            sb.append(", ");
                            }

                        sb.append('{')
                          .append(cTrace++)
                          .append('}');
                        }

                    if (cTypes != 1)
                        {
                        sb.append(')');
                        }
                    }
                sCond = sb.toString();
                }
            StringConstant constText = pool.ensureStringConstant(sCond);

            // it is possible that the condition was modified by the addition of traces
            cond = getCondition(i);

            Argument argCond;
            if (cond instanceof AssignmentStatement)
                {
                AssignmentStatement stmtCond = (AssignmentStatement) cond;
                fCompletes &= stmtCond.completes(ctx, fCompletes, code, errs);
                argCond = stmtCond.getConditionRegister();
                }
            else
                {
                Expression exprCond = (Expression) cond;

                // "assert False" always asserts
                if (exprCond.isConstantFalse())
                    {
                    code.add(new Assert(pool.valFalse(), constructException));
                    fCompletes = false;
                    continue;
                    }

                // "assert True" is a no-op
                if (exprCond.isConstantTrue())
                    {
                    continue;
                    }

                fCompletes &= exprCond.isCompletable();
                argCond = exprCond.generateArgument(ctx, code, true, true, errs);
                }

            if (mapTrace.isEmpty())
                {
                code.add(new AssertM(argCond, constructException, constText));
                }
            else
                {
                List<Argument> argV = new ArrayList<>();
                for (Expression expr : mapTrace.values())
                    {
                    Argument[] aArgs = ((TraceExpression) expr.getParent()).getArguments();
                    Collections.addAll(argV, aArgs);
                    }
                code.add(new AssertV(
                    argCond, constructException, constText, argV.toArray(Expression.NO_RVALUES)));
                }
            }

        return fCompletes;
        }

    /**
     * Obtain the "takes one parameter, a String message" constructor for the specified Ecstasy
     * exception class.
     *
     * @param pool   the ConstantPool
     * @param sName  the name of the Exception class
     * @param errs   the ErrorListener to log to
     *
     * @return the desired constructor MethodConstant
     */
    public static MethodConstant findExceptionConstructor(ConstantPool pool, String sName, ErrorListener errs)
        {
        return pool.ensureEcstasyTypeConstant(sName).ensureTypeInfo(errs).findConstructor(null);
        }

    /**
     * Re-arrange the conditions, if possible, to split them into smaller chunks by applying the
     * rules of De Morgan.
     */
    protected void demorgan()
        {
        if (!conds.isEmpty())
            {
            List<AstNode> listOldConds = conds;
            conds       = new ArrayList<>(conds.size());
            m_listTexts = new ArrayList<>(conds.size());
            for (AstNode cond : listOldConds)
                {
                demorgan(cond);
                }
            }
        }

    private void demorgan(AstNode cond)
        {
        String sCond = Handy.appendString(new StringBuilder(),
                cond.getSource().toString(cond.getStartPosition(), cond.getEndPosition()))
                .toString();

        if (cond instanceof UnaryComplementExpression)
            {
            // demorgan
            UnaryComplementExpression exprNot = (UnaryComplementExpression) cond;
            Expression                exprSub = exprNot.expr;
            if (exprSub instanceof BiExpression
                    && ((BiExpression) exprSub).operator.getId() == Id.COND_OR)
                {
                BiExpression              exprOr   = (BiExpression) exprSub;
                UnaryComplementExpression exprNot2 = (UnaryComplementExpression) exprNot.clone();

                exprNot .expr = exprOr.expr1;
                exprNot2.expr = exprOr.expr2;
                demorgan(exprNot);
                demorgan(exprNot2);
                exprOr.discard(false);
                return;
                }
            }
        else if (cond instanceof BiExpression
                && ((BiExpression) cond).operator.getId() == Id.COND_AND)
            {
            BiExpression exprAnd = (BiExpression) cond;
            demorgan(exprAnd.expr1);
            demorgan(exprAnd.expr2);
            exprAnd.discard(false);
            return;
            }

        conds.add(cond);
        m_listTexts.add(sCond);
        }

    /**
     * A custom context implementation to provide type-narrowing as a natural side-effect of an
     * assertion.
     */
    static class AssertContext
            extends Context
        {
        public AssertContext(Context outer)
            {
            super(outer, true);
            }

        @Override
        protected Assignment promote(String sName, Assignment asnInner, Assignment asnOuter)
            {
            return asnInner.whenTrue();
            }

        @Override
        protected void promoteNarrowedType(String sName, Argument arg, Branch branch)
            {
            super.promoteNarrowedType(sName, arg, branch);

            // promote our "true" into the parent's "always" branch
            if (branch == Branch.WhenTrue)
                {
                getOuterContext().replaceArgument(sName, Branch.Always, arg);
                }
            }

        @Override
        protected void promoteNarrowedGenericType(String sName, TypeConstant typeNarrowed, Branch branch)
            {
            super.promoteNarrowedGenericType(sName, typeNarrowed, branch);

            // promote our "true" into the parent's "always" branch
            if (branch == Branch.WhenTrue)
                {
                getOuterContext().replaceGenericType(sName, Branch.Always, typeNarrowed);
                }
            }
        }


    // ----- debugging assistance ------------------------------------------------------------------

    @Override
    public String toString()
        {
        StringBuilder sb = new StringBuilder();

        sb.append(keyword.getId().TEXT);
        if (interval != null)
            {
            sb.append('(')
              .append(interval)
              .append(')');
            }

        if (!conds.isEmpty())
            {
            sb.append(' ')
              .append(conds.get(0));
            for (int i = 1, c = conds.size(); i < c; ++i)
                {
                sb.append(", ")
                  .append(conds.get(i));
                }
            }

        sb.append(';');

        return sb.toString();
        }

    @Override
    public String getDumpDesc()
        {
        return toString();
        }


    // ----- fields --------------------------------------------------------------------------------

    protected Token         keyword;
    protected Expression    interval;
    protected List<AstNode> conds;
    protected long          lEndPos;

    private List<String> m_listTexts;

    private static final Field[] CHILD_FIELDS = fieldsForNames(AssertStatement.class, "interval", "conds");
    }

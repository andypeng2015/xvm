package org.xvm.asm.ast;


import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

import static org.xvm.util.Handy.readMagnitude;
import static org.xvm.util.Handy.writePackedLong;


/**
 * An "is" expression. It differs from {@link RelOpExprAST} that it may have two return types, where
 * the first one is always Boolean.
 */
public class IsExprAST<C>
        extends BiExprAST<C> {

    private           C typeOfType; // could be null
    private transient C booleanType;

    IsExprAST() {}

    public IsExprAST(C typeOfType, ExprAST<C> expr1, ExprAST<C> expr2) {
        super(Operator.Is, expr1, expr2);

        this.typeOfType = typeOfType;
    }

    @Override
    public int getCount() {
        return 2;
    }

    @Override
    public C getType(int i) {
        switch (i) {
        case 0:
            return booleanType;

        case 1:
            if (typeOfType != null) {
                return typeOfType;
            }
            // fall through
        default:
            throw new ArrayIndexOutOfBoundsException();
        }
    }

    @Override
    public NodeType nodeType() {
        return NodeType.DivRemExpr;
    }

    @Override
    public void read(DataInput in, ConstantResolver<C> res)
            throws IOException {
        super.read(in, res);

        if (readMagnitude(in) != 0) {
            typeOfType  = res.getConstant(readMagnitude(in));
        }
        booleanType = res.typeForName("Boolean");
    }

    @Override
    public void prepareWrite(ConstantResolver<C> res) {
        super.prepareWrite(res);

        if (typeOfType != null) {
            typeOfType = res.register(typeOfType);
        }
    }

    @Override
    public void write(DataOutput out, ConstantResolver<C> res)
            throws IOException {
        super.write(out, res);

        if (typeOfType == null) {
            writePackedLong(out, 0);
        } else {
            writePackedLong(out, 1);
            writePackedLong(out, res.indexOf(typeOfType));
        }
    }

    @Override
    public String dump() {
        return typeOfType + ": " + super.dump();
    }
}
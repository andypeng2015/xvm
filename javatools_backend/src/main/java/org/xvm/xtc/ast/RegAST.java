package org.xvm.xtc.ast;

import org.xvm.util.SB;
import org.xvm.xtc.ClassPart;
import org.xvm.xtc.ClzBuilder;
import org.xvm.xtc.XClz;
import org.xvm.xtc.XCons;
import org.xvm.xtc.XType;

// Always replaced before writing out.
// E.g. XTC encoded a default arg (-4) for a call.
// Since Java has no defaults, explicitly replace.
public class RegAST extends AST {
  final int _reg;
  String _name;
  public RegAST( String name, XType type ) { this(-99,name,type); }
  public RegAST( int reg, String name, XType type ) {
    super(null);
    _reg  = reg;
    _name = name;
    _type = type;
  }
  RegAST( int reg, ClzBuilder X ) {
    super(null);
    XClz xt = X._tclz;
    _reg  = reg ;
    _name = switch( reg ) {
    case -2 ->  "%ignore";  // A_IGNORE
    case -4 ->  "default";  // A_DEFAULT
    case -5 ->  "this";     // A_THIS
    case -10 -> "this";     // A_STRUCT: this as a struct
    case -11 -> "class";    // A_CLASS
    case -13 -> "super";    // A_SUPER
    default -> X._locals.at(reg);
    };
    _type = switch( reg ) {
    case -2 ->  XCons.VOID;  // A_IGNORE
    case -4 ->  XCons.VOID;  // A_DEFAULT
    case -5 ->  xt;          // A_THIS
    case -10 -> xt == null ? XCons.VOID : xt;          // A_STRUCT: this as a struct
    case -11 -> xt;          // A_CLASS
    case -13 -> xt.iface() ? xt : (xt._super==null ? XCons.XXTC : xt._super); // A_SUPER
    default -> X._ltypes.at(reg);
    };
    assert _type!=null;
  }
  @Override String name() { return _name; }
  @Override XType _type() { return _type; }
  @Override void jpre ( SB sb ) {
    sb.p(_name);
    if( _type.isVar() )
      sb.p(".$get()");
  }
}

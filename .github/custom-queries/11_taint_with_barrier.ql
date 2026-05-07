/**
 * @name U-Boot Memcpy Taint Analysis
 * @description Rileva flussi di dati non validati provenienti dalla rete verso memcpy
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id c/u-boot-memcpy-taint
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation invocation |
      invocation.getMacro().getName().matches("ntoh%") and
      invocation.getExpr() = this
    )
  }
}

module MyConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    exists(Expr e | source.asExpr() = e and e instanceof NetworkByteSwap)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().hasName("memcpy") and
      sink.asExpr() = call.getArgument(2)
    )
  }
}

module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink)
// Modifica cruciale: esattamente 4 elementi nel select
select sink.getNode(), source, sink, "Dati di rete non validati raggiungono memcpy."

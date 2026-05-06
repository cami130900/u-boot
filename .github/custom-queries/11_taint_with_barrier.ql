/**
 * @name Unsafe use of network data
 * @description Tracciamento dati rete semplificato
 * @kind path-problem
 * @problem.severity error
 * @id c/unsafe-network-data
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class MyTaintConfig extends TaintTracking::Configuration {
  MyTaintConfig() { this = "MyTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p | 
      p.getFunction().getName().matches("%net%") or 
      p.getFunction().getName().matches("%receive%")
    | source.asParameter() = p)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().getName() = "memcpy" or
      call.getTarget().getName() = "memmove"
    | sink.asExpr() = call.getArgument(2))
  }

  override predicate isBarrier(DataFlow::Node barrier) {
    none() 
  }
}

from MyTaintConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Dato di rete non sicuro che arriva a una memcpy"

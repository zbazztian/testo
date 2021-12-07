/**
 * @name Test
 * @description Test
 * @kind path-problem
 * @id cpp/customquery
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class ThisIsACustomConfig extends TaintTracking::Configuration {
  ThisIsACustomConfig() { this = "ThisIsACustomConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr().(Call).getTarget().getName() = "query"
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call c | c.getTarget().getName() = "execute_sql" and sink.asExpr() = c.getArgument(0))
  }

  override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(Assignment a |
      a.getLValue().(FieldAccess).getQualifier().(VariableAccess).getTarget().getAnAccess() =
        n2.asExpr() and
      a.getRValue() = n1.asExpr()
    )
    or
    exists(Call c |
      c.getTarget().getName() = "operator=" and
      c.getArgument(0) = n1.asExpr() and
      n2.asExpr() =
        c.getQualifier().(FieldAccess).getQualifier().(VariableAccess).getTarget().getAnAccess()
    )
    or
    exists(Call c |
      c.getTarget().getName() = "push_back" and
      n1.asExpr() = c.getArgument(0) and
      c.getQualifier().(FieldAccess).getQualifier().(VariableAccess).getTarget().getAnAccess() =
        n2.asExpr()
    )
    or
    exists(FieldAccess fa | fa.getQualifier() = n1.asExpr() and fa = n2.asExpr())
  }
}

from ThisIsACustomConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "sql injection"

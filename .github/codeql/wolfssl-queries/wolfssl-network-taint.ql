/**
 * @name wolfSSL unchecked DER length reaches memory operation
 * @description A length value decoded via GetLength_ex with check=0 (no
 *              bounds validation that idx+len fits the buffer) reaches a
 *              memory operation. These are the only sites in wolfSSL where
 *              GetLength_ex is called without the buffer-fit check.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id wolfssl/unchecked-length-memop
 * @tags security
 *       external/cwe/cwe-119
 *       external/cwe/cwe-125
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

//
// Sources: GetLength_ex called with check=0 (5th argument literal 0).
// wolfSSL has exactly 3 such call sites. The output length parameter
// (3rd arg, passed by pointer) is unvalidated against the buffer bound.
//
class UncheckedLengthSource extends DataFlow::Node {
  UncheckedLengthSource() {
    exists(FunctionCall fc |
      fc.getTarget().getName() = "GetLength_ex" and
      fc.getArgument(4).(Literal).getValue() = "0" and
      // The length output variable: third argument is &len
      this.asExpr() = fc.getArgument(2)
    )
  }
}

//
// Sanitizers: subsequent bounds checks on the length value before use.
// Any comparison of the length against a buffer-size variable or MAX constant.
//
class LengthBoundsCheck extends DataFlow::Node {
  LengthBoundsCheck() {
    exists(ComparisonOperation cmp |
      cmp.getAnOperand() = this.asExpr() and
      // The other side is a size variable or MAX constant
      exists(Expr bound | bound = cmp.getAnOperand() and bound != this.asExpr() |
        bound.(VariableAccess).getTarget().getName().regexpMatch(".*[Ss]z$|.*[Ll]en$|.*[Ss]ize$|.*[Mm]ax.*")
        or
        bound instanceof Literal
      )
    )
  }
}

//
// Sinks: memory operations whose size/length argument is attacker-derived.
//
class MemorySink extends DataFlow::Node {
  MemorySink() {
    exists(FunctionCall fc |
      fc.getTarget().getName() in [
        "XMEMCPY", "XMEMSET", "XMEMMOVE", "memcpy", "memmove", "memset"
      ] and this.asExpr() = fc.getArgument(2)
      or
      fc.getTarget().getName() in [
        "XMALLOC", "XREALLOC", "malloc", "realloc", "AllocDer", "XNEW"
      ] and this.asExpr() = fc.getArgument(0)
    )
  }
}

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof UncheckedLengthSource
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof LengthBoundsCheck
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof MemorySink
  }
}

module Taint = TaintTracking::Global<TaintConfig>;

import Taint::PathGraph

from Taint::PathNode source, Taint::PathNode sink
where Taint::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Length from unchecked GetLength_ex (check=0) at $@ reaches memory operation without bounds validation.",
  source.getNode(), "GetLength_ex check=0"

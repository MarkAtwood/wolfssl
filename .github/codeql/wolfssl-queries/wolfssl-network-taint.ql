/**
 * @name wolfSSL unchecked DER length reaches memory operation
 * @description A length value decoded via GetLength_ex with check=0 (no
 *              bounds validation that idx+len <= maxIdx) reaches a memory
 *              operation. Includes sites using the NO_USER_CHECK macro (= 0).
 *              Most PKCS7 streaming sites are intentional; focus on paths
 *              that reach allocation or copy outside wc_PKCS7_GrowStream.
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id wolfssl/unchecked-length-memop
 * @tags security
 *       external/cwe/cwe-119
 *       external/cwe/cwe-125
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

//
// Source: the output-parameter address-of expression (&len / &objSz) passed
// to GetLength_ex with check=0. CodeQL will then propagate taint through the
// pointer into the dereferenced variable via isAdditionalTaintStep below.
//
class UncheckedLengthSource extends DataFlow::Node {
  UncheckedLengthSource() {
    exists(FunctionCall fc |
      fc.getTarget().getName() = "GetLength_ex" and
      fc.getArgument(4).(Literal).getValue() = "0" and
      this.asExpr() = fc.getArgument(2)
    )
  }
}

//
// Sinks: the size/count argument of memory allocation and copy operations.
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

//
// Barriers: the length was compared against a named max/capacity variable.
// Only fires when the other comparison operand is a variable with "max",
// "sz", "size", "limit", "bound", or "cap" in its name — not bare literals,
// which would over-suppress (e.g. "if (len == 0)" is not a bounds check).
//
class ValidatedLength extends DataFlow::Node {
  ValidatedLength() {
    exists(ComparisonOperation cmp, VariableAccess bound |
      cmp.getAnOperand() = this.asExpr() and
      bound = cmp.getAnOperand() and
      bound != this.asExpr() and
      bound.getTarget().getName().regexpMatch("(?i).*(max|sz|size|limit|bound|cap).*") and
      not bound.getTarget().getName().regexpMatch("(?i).*min.*")
    )
  }
}

module TaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof UncheckedLengthSource
  }

  //
  // Model the output-parameter write: after GetLength_ex(check=0) returns,
  // the variable pointed to by argument 2 holds an attacker-derived length.
  // Propagate taint from &var (the address-of expression) to subsequent reads
  // of var within the same function so the path shows the real variable name.
  //
  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(FunctionCall fc, Variable v |
      fc.getTarget().getName() = "GetLength_ex" and
      fc.getArgument(4).(Literal).getValue() = "0" and
      fc.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget() = v and
      n1.asExpr() = fc.getArgument(2) and
      n2.asExpr().(VariableAccess).getTarget() = v and
      n2.asExpr().getEnclosingFunction() = fc.getEnclosingFunction()
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof ValidatedLength
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
  "Length from GetLength_ex(check=0) at $@ flows to memory operation without validated upper bound.",
  source.getNode(), "unchecked GetLength_ex output"

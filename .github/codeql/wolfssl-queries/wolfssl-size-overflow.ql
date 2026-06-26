/**
 * @name Integer overflow risk in memory operation size argument
 * @description The size argument to an allocation or copy operation is a
 *              binary arithmetic expression involving two or more non-constant
 *              terms. If both operands are large (e.g., both network-derived),
 *              the sum or product can silently wrap to a small value on a 32-bit
 *              word32, causing the subsequent operation to under-allocate or
 *              under-copy. wolfSSL uses word32 for most sizes; wrapping at 2^32
 *              is possible when lengths approach INT_MAX.
 *
 *              These are not all bugs — many have guards elsewhere. The query
 *              is an audit tool: each result needs a human to verify that at
 *              least one operand is bounded below a value that makes overflow
 *              impossible (e.g., MAX_RECORD_SZ, EXTERNAL_SERIAL_SIZE).
 *
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id wolfssl/size-arithmetic-overflow
 * @tags security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-122
 */

import cpp

// Memory operations where argument N is the size/count.
class MemOpSizeArg extends Expr {
  MemOpSizeArg() {
    exists(FunctionCall fc |
      // Allocation: first arg is the size
      fc.getTarget().getName() in ["XMALLOC", "XREALLOC", "AllocDer", "XNEW"] and
      this = fc.getArgument(0)
    )
    or
    exists(FunctionCall fc |
      // Copy/set: third arg is the size
      fc.getTarget().getName() in [
        "XMEMCPY", "XMEMSET", "XMEMMOVE", "memcpy", "memmove", "memset"
      ] and
      this = fc.getArgument(2)
    )
  }
}

// An arithmetic op in a size expression that involves two non-constant operands.
class RiskyArithInSize extends BinaryArithmeticOperation {
  RiskyArithInSize() {
    // The operation must appear (possibly nested) inside a size argument
    exists(MemOpSizeArg sz | sz.getAChild*() = this) and
    (
      this instanceof AddExpr or
      this instanceof MulExpr
    ) and
    // Neither operand is a small compile-time constant (< 32).
    // Constants like +4, *8 rarely cause overflow; skip them to reduce noise.
    not exists(Literal lit |
      lit = this.getAnOperand() and
      lit.getValue().toInt() < 32
    ) and
    // Exclude sizeof() operands — those are always safe constants.
    not exists(SizeofOperator s | s = this.getAnOperand())
  }
}

from RiskyArithInSize op, MemOpSizeArg sz, FunctionCall fc
where
  sz.getAChild*() = op and
  (
    fc.getArgument(0) = sz or
    fc.getArgument(2) = sz
  ) and
  fc.getTarget().getName() in [
    "XMALLOC", "XREALLOC", "AllocDer", "XNEW",
    "XMEMCPY", "XMEMSET", "XMEMMOVE", "memcpy", "memmove", "memset"
  ]
select op,
  op.getOperator() + " of two non-constant terms in size argument to " +
  fc.getTarget().getName() + " — verify neither operand can approach 2^32"

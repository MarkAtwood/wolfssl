/**
 * @name Unsigned addition result used in comparison without overflow check
 * @description A value computed as `a + b` (where a and b are both unsigned
 *              non-constant expressions) is used directly as an operand of a
 *              relational comparison. If `a + b` wraps past 2^32, the computed
 *              sum is smaller than both operands, silently defeating the intended
 *              bounds check.
 *
 *              The correct guard is `b > limit || a > limit - b` (or equivalent),
 *              which avoids the addition entirely. Alternatively, use 64-bit
 *              arithmetic for the intermediate result and check before truncating.
 *
 *              Common real-world pattern:
 *
 *                  word32 end = offset + size;      // wraps if offset near UINT32_MAX
 *                  if (end > bufferLen) error;      // guard defeated by wrap
 *
 *              Confirmed instance: DtlsMsgSet internal.c ~line 9938
 *              (fragOffset + fragSz — bounded by 24-bit wire format, so not
 *              exploitable there, but the shape is the same as the risky pattern).
 *
 *              Triage priority: focus on pkcs7.c and asn.c sites where length
 *              values can reach INT_MAX via GetLength_ex(check=0). DTLS fragment
 *              field sums are bounded by the 24-bit wire format (max 33 MB).
 *              Timestamp arithmetic (bornOn + timeout) is also low priority.
 *
 *              Not all results are bugs — this is an audit tool.
 *
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id wolfssl/unsigned-wrap-in-guard
 * @tags security
 *       correctness
 *       external/cwe/cwe-190
 *       external/cwe/cwe-787
 */

import cpp

// An unsigned add whose both operands are non-constant, making wraparound possible.
// Filtering: exclude cases where one operand is a small literal (< 32) since those
// can only cause overflow when the other is within 31 of UINT32_MAX, which is
// implausible in practice. Also exclude sizeof and pointer difference (SubExpr)
// operands, since those are bounded.
class PotentiallyWrappingAdd extends AddExpr {
  PotentiallyWrappingAdd() {
    // Result is unsigned (word32 = unsigned int, etc.)
    this.getType().getUnderlyingType().(IntegralType).isUnsigned() and
    // Neither operand is a small compile-time constant (< 32).
    // Uses isConstant() + getValue() to catch both integer literals AND
    // enum constants (like OPAQUE8_LEN = 1) which are not Literal instances.
    not exists(Expr operand |
      operand = this.getAnOperand() and
      operand.isConstant() and
      operand.getValue().toInt() < 32
    ) and
    // Exclude sizeof — those are bounded constants
    not exists(SizeofOperator s | s = this.getAnOperand()) and
    // Exclude when either operand is a subtraction expression (pointer difference /
    // remaining-space patterns like `end - idx`): those are already bounded.
    not this.getAnOperand() instanceof SubExpr
  }
}

// The add result is used as a comparison operand — i.e., the sum IS the
// value being compared, not just part of a larger expression.  This targets
// the "compute sum, then check sum > limit" shape directly.
from PotentiallyWrappingAdd add, ComparisonOperation cmp
where
  (cmp.getLeftOperand() = add or cmp.getRightOperand() = add) and
  // Only relational comparisons (> >= < <=), not == !=
  (
    cmp instanceof GTExpr or
    cmp instanceof GEExpr or
    cmp instanceof LTExpr or
    cmp instanceof LEExpr
  ) and
  // Exclude test files — those often use arithmetic intentionally
  not add.getFile().getRelativePath().matches("%test%") and
  not add.getFile().getRelativePath().matches("%Test%")
select add,
  "Unsigned addition " + add.getLeftOperand() + " + " + add.getRightOperand() +
  " used directly in a relational comparison — wrap past 2^32 silently defeats the guard"

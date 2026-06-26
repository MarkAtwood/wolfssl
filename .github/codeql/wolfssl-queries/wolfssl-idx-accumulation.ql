/**
 * @name Multiple GetLength_ex(check=0) calls accumulating into the same index variable
 * @description A single function contains two or more calls to GetLength_ex
 *              with check=0 (NO_USER_CHECK), all sharing the same *inOutIdx
 *              variable. Each call advances the index past the length encoding
 *              bytes; the caller then typically does `idx += len` to skip the
 *              content. If two such lengths each approach INT_MAX, their
 *              accumulated sum in idx can wrap past 2^32 before any bounds
 *              check fires.
 *
 *              Minimal overflow scenario (2 calls):
 *                GetLength_ex(..., &idx, &len1, maxSz, 0); idx += len1; // len1 = 0x7FFFFFFE
 *                GetLength_ex(..., &idx, &len2, maxSz, 0); idx += len2; // len2 = 0x7FFFFFFE
 *                // idx is now ~0xFFFFFFFC + header bytes → wraps to ~0x00000003
 *                if (idx > maxSz) return error;  // passes! idx looks tiny
 *
 *              Most results will have intermediate per-step bounds checks that
 *              prevent this. Focus review on functions with high call counts
 *              and on whether any check of the form `if (idx > maxSz)` appears
 *              BETWEEN each consecutive pair of GetLength_ex(check=0) calls.
 *
 *              pkcs7.c results dominate because NO_USER_CHECK = 0 is a macro
 *              constant; see pkcs7.c:95. The streaming state machine is the
 *              highest-priority manual review target.
 *
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id wolfssl/idx-accumulation
 * @tags security
 *       correctness
 *       external/cwe/cwe-190
 *       external/cwe/cwe-787
 */

import cpp

/**
 * Count of GetLength_ex(check=0) calls in function f that use idxVar as
 * the *inOutIdx parameter.
 */
int checkZeroCallCount(Function f, Variable idxVar) {
  result =
    count(FunctionCall fc |
      fc.getTarget().getName() = "GetLength_ex" and
      fc.getArgument(4).(Literal).getValue() = "0" and
      fc.getEnclosingFunction() = f and
      fc.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget() = idxVar
    )
}

from Function f, Variable idxVar, int n
where
  n = checkZeroCallCount(f, idxVar) and
  n >= 2 and
  // Exclude test code
  not f.getFile().getRelativePath().matches("%test%") and
  not f.getFile().getRelativePath().matches("%Test%")
select f,
  f.getName() + " accumulates '" + idxVar.getName() + "' across " + n +
  " GetLength_ex(check=0) calls — verify per-step bounds checks prevent idx overflow"

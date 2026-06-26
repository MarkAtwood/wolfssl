/**
 * @name WOLFSSL_ASN1_INTEGER dataMax set outside safe sizing functions
 * @description Audits the invariant required by wolfSSL_i2c_ASN1_INTEGER
 *              to call GetLength_ex with check=0 safely.
 *
 *              wolfSSL_i2c_ASN1_INTEGER reads the DER length from a->data via
 *              GetLength_ex(a->data, &idx, &len, a->dataMax, 0). For check=0 to
 *              be safe, every caller must ensure a->dataMax >= idx + len where
 *              idx is the DER header size and len is the encoded value. DER length
 *              encoding for content >= 128 bytes requires an extra byte (0x81 ...),
 *              so dataMax = contentSz + 2 is only correct when contentSz < 128.
 *
 *              The three internal sizing functions maintain this invariant by
 *              construction. Any other direct assignment to dataMax is flagged.
 *
 *              Expected results as of this writing (all justified):
 *
 *              wolfSSL_X509_get_serialNumber (x509.c): dataMax = serialSz + 2.
 *              Correct because serialSz <= EXTERNAL_SERIAL_SIZE = 32 < 128, so
 *              DER length encoding is always 1 byte (idx=2, idx+len=dataMax).
 *
 *              wolfSSL_OCSP_id_get0_info (ocsp.c): same +2 pattern, same cap.
 *
 *              RevokedCertToRevoked (x509.c): dataMax = serialSz, raw bytes (no
 *              DER header). i2c_ASN1_INTEGER should not be called on these structs.
 *              wolfSSL has no internal callers that do so.
 *
 *              wolfSSL_X509_CRL_add_revoked_cert (crl.c): same raw-bytes pattern.
 *
 *              If this query returns results beyond those four functions, investigate
 *              whether the new site allows content >= 128 bytes and adjusts dataMax
 *              accordingly using SetLength/SetASNInt rather than a fixed offset.
 *
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id wolfssl/asn1-integer-datamax-audit
 * @tags correctness
 *       security
 */

import cpp

// The three functions that correctly manage WOLFSSL_ASN1_INTEGER buffer sizing:
//   wolfssl_asn1_integer_require_len  — allocates/resizes, sets dataMax = len
//   wolfssl_asn1_integer_reset_data   — resets to intData[], dataMax = sizeof(intData)
//   wolfSSL_ASN1_INTEGER_new          — initialises to intData[], dataMax = WOLFSSL_ASN1_INTEGER_MAX
predicate isSafeContext(Function f) {
  f.getName() = "wolfssl_asn1_integer_require_len" or
  f.getName() = "wolfssl_asn1_integer_reset_data" or
  f.getName() = "wolfSSL_ASN1_INTEGER_new"
}

from AssignExpr assign, FieldAccess fa
where
  fa.getTarget().getName() = "dataMax" and
  fa.getQualifier().getType().(PointerType).getBaseType().getName() = "WOLFSSL_ASN1_INTEGER" and
  assign.getLValue() = fa and
  not isSafeContext(assign.getEnclosingFunction())
select assign,
  "Direct WOLFSSL_ASN1_INTEGER.dataMax assignment in " +
  assign.getEnclosingFunction().getName() +
  " — verify the value accounts for DER multi-byte length encoding " +
  "(content >= 128 bytes requires an extra byte, making '+2' insufficient)"

/**
 * @name wolfSSL network-tainted length reaches memory operation
 * @description A length or size value derived from attacker-controlled
 *              TLS/DTLS wire data reaches a memory operation without
 *              passing through wolfSSL's bounds-checking length decoder
 *              (GetLength_ex / GetASNHeader_ex with check=1).
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id wolfssl/network-tainted-length
 * @tags security
 *       external/cwe/cwe-119
 *       external/cwe/cwe-125
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.security.Security
import DataFlow::PathGraph

//
// Sources: functions where attacker-controlled network data enters.
// Return values and output-buffer parameters are tainted.
//
class WolfSSLNetworkSource extends DataFlow::Node {
  WolfSSLNetworkSource() {
    exists(FunctionCall fc |
      fc.getTarget().getName() in [
        // TLS record / handshake layer
        "wolfSSL_read", "wolfSSL_recv", "ProcessReply", "DoRecord",
        "DoHandShakeMsgType", "DoTls13HandShakeMsg",
        // DTLS
        "DtlsMsgStore", "DoClientHello", "wolfSSL_dtls_get_peer",
        // Sniffer (raw packet input)
        "ProcessPacket", "ssl_DecodePacket"
      ] and
      (
        // return value carries attacker data
        this.asExpr() = fc
        or
        // output buffer parameters (ptr args) carry attacker data
        exists(int i |
          i > 0 and
          this.asExpr() = fc.getArgument(i) and
          fc.getArgument(i).getType() instanceof PointerType
        )
      )
    )
  }
}

//
// Sanitizers: wolfSSL's length-decoding functions that validate a
// decoded length fits within the remaining buffer before returning it.
// After these calls, the length is safe to use as a buffer size.
//
class WolfSSLLengthSanitizer extends DataFlow::Node {
  WolfSSLLengthSanitizer() {
    exists(FunctionCall fc |
      fc.getTarget().getName() in [
        // Core ASN.1 length decoder — check=1 validates idx+len<=maxIdx
        "GetLength_ex", "GetLength",
        // ASN.1 tag+length decoder — same guarantee
        "GetASNHeader_ex", "GetASNHeader",
        // Higher-level typed decoders (all call GetLength internally)
        "GetASN_Length",
        "GetOctetString", "GetSequence", "GetSet",
        "GetInteger", "GetShortInt",
        // PKCS overflow-checked accumulator
        "WC_SAFE_SUM_WORD32"
      ] and
      // The sanitized value flows out via an output pointer argument
      this.asExpr() = fc.getArgument(_)
    )
  }
}

//
// Sinks: operations where an unsanitized attacker-controlled length
// causes memory corruption or OOB access.
//
class WolfSSLMemorySink extends DataFlow::Node {
  WolfSSLMemorySink() {
    exists(FunctionCall fc |
      (
        // Memory copy/set with attacker-controlled size
        fc.getTarget().getName() in [
          "XMEMCPY", "XMEMSET", "XMEMMOVE",
          "memcpy", "memmove", "memset",
          "XSTRNCPY", "strncpy"
        ] and
        this.asExpr() = fc.getArgument(2)
        or
        // Allocation with attacker-controlled size
        fc.getTarget().getName() in [
          "XMALLOC", "XREALLOC", "malloc", "realloc",
          "AllocDer", "XNEW"
        ] and
        this.asExpr() = fc.getArgument(0)
        or
        // wolfSSL ASN.1 leaf decoders called with attacker-controlled length
        fc.getTarget().getName() in [
          "GetASN_Integer", "GetASN_ObjectId", "GetASN_UTF8String",
          "GetASN_IA5String", "GetASN_BitString", "GetASN_OctetString",
          "GetASNInt", "CheckBitString"
        ] and
        this.asExpr() = fc.getArgument(2)  // the length/maxIdx argument
      )
    )
  }
}

//
// Taint configuration
//
module WolfSSLTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof WolfSSLNetworkSource
  }

  predicate isSanitizer(DataFlow::Node node) {
    node instanceof WolfSSLLengthSanitizer
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof WolfSSLMemorySink
  }
}

module WolfSSLTaint = TaintTracking::Global<WolfSSLTaintConfig>;

from WolfSSLTaint::PathNode source, WolfSSLTaint::PathNode sink
where WolfSSLTaint::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Network-tainted length from $@ reaches memory operation without bounds validation.",
  source.getNode(), "network source"

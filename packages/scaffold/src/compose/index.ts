// Host-assembled request bodies: the `composed` channel and `multipart[].staged`
// (issue #59). Bytes never cross the sandbox; the host validates the shape,
// resolves staged references, builds the inspection view, and writes the body
// block by block into a fixed-length sink under the transfer gate.
export {
  validateComposed,
  parseStagedRef,
  isPlainObject,
  hasExactKeys,
  isWellFormedText,
  COMPOSED_MAX_SEGMENTS,
  COMPOSED_MAX_TEXT_BYTES,
  STAGED_SENTINEL,
  type Segment,
  type StagedEncoding,
  type ComposedReason,
  type ValidateComposedResult,
} from "./validate";
export {
  assembledLength,
  buildInspectionView,
  compileStagedMultipart,
  writeAssembled,
  sanitiseStagedFilename,
  sanitiseRowContentType,
  stagedPartDefaults,
  type ComposeMultipartPart,
} from "./assemble";
export { TransferGate, PER_RUN_MESSAGE, RETRY_MESSAGE, type TransferGateOptions } from "./gate";
export {
  sendAssembled,
  transferController,
  transferFailure,
  platformSuppliesContentLength,
  type AssembledBody,
  type AssembledSend,
  type TransferController,
} from "./transfer";

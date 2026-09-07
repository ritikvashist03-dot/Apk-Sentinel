package app.apksentinel.inspector

sealed interface InspectionFailure {
    val stage: InspectionStage
    val code: InspectionFailureCode
}

/** A typed failure retained with the bounded path of the nested APK that produced it. */
data class NestedMemberInspectionFailure(
    val memberPath: String,
    override val stage: InspectionStage,
    override val code: InspectionFailureCode,
) : InspectionFailure

/** Exhaustive, stable failure identifiers; callers own localized wording. */
enum class InspectionFailureCode {
    TEMP_FILE_CREATION_FAILED,
    SOURCE_PERMISSION_DENIED,
    SOURCE_OPEN_FAILED,
    SOURCE_NOT_FOUND,
    SOURCE_COPY_FAILED,
    PACKAGE_NAME_INVALID,
    INSTALLED_PACKAGE_UNAVAILABLE,
    SOURCE_SIZE_LIMIT_EXCEEDED,
    ZIP_OPEN_FAILED,
    ZIP_SIGNATURE_MISSING,
    ZIP_READ_FAILED,
    ARCHIVE_LIMIT_EXCEEDED,
    MANIFEST_PARSE_FAILED,
    MANIFEST_NOT_PARSEABLE,
    MANIFEST_TEXT_DECODE_FAILED,
    MANIFEST_ENTRY_MISSING,
    SIGNATURE_VERIFICATION_FAILED,
    HEURISTIC_SCAN_TRUNCATED,
    HEURISTIC_FINDINGS_TRUNCATED,
    TEMP_FILE_DELETE_FAILED,
}

data class SourceUnavailable(
    override val code: InspectionFailureCode,
) : InspectionFailure {
    override val stage: InspectionStage = InspectionStage.COPY_INPUT
}

data class SourceSizeLimitExceeded(
    val observedBytes: Long,
    val maximumBytes: Long,
) : InspectionFailure {
    override val stage: InspectionStage = InspectionStage.COPY_INPUT
    override val code: InspectionFailureCode = InspectionFailureCode.SOURCE_SIZE_LIMIT_EXCEEDED
}

data class ArchiveUnreadable(
    override val code: InspectionFailureCode,
) : InspectionFailure {
    override val stage: InspectionStage = InspectionStage.INSPECT_ARCHIVE
}

data class ArchiveLimitExceeded(
    val limit: ArchiveLimit,
    val observed: Double,
    val maximum: Double,
) : InspectionFailure {
    override val stage: InspectionStage = InspectionStage.INSPECT_ARCHIVE
    override val code: InspectionFailureCode = InspectionFailureCode.ARCHIVE_LIMIT_EXCEEDED
}

enum class ArchiveLimit {
    ENTRY_COUNT,
    TOTAL_UNCOMPRESSED_BYTES,
    ENTRY_UNCOMPRESSED_BYTES,
    COMPRESSION_RATIO,
}

data class AndroidManifestUnavailable(
    override val code: InspectionFailureCode,
) : InspectionFailure {
    override val stage: InspectionStage = InspectionStage.INSPECT_MANIFEST
}

data class SigningUnavailable(
    override val code: InspectionFailureCode,
) : InspectionFailure {
    override val stage: InspectionStage = InspectionStage.VERIFY_SIGNATURE
}

data class HeuristicScanTruncated(
    val scannedBytes: Long,
    val maximumBytes: Long,
) : InspectionFailure {
    override val stage: InspectionStage = InspectionStage.INSPECT_ARCHIVE
    override val code: InspectionFailureCode = InspectionFailureCode.HEURISTIC_SCAN_TRUNCATED
}

/**
 * The collector retained its configured maximum number of distinct findings.
 * This is a partial result, not a claim that no additional literal signals exist.
 */
data class HeuristicFindingsTruncated(
    val retainedFindings: Int,
    val maximumFindings: Int,
) : InspectionFailure {
    override val stage: InspectionStage = InspectionStage.INSPECT_ARCHIVE
    override val code: InspectionFailureCode = InspectionFailureCode.HEURISTIC_FINDINGS_TRUNCATED
}

data class TemporaryFileCleanupFailed(
    override val code: InspectionFailureCode,
) : InspectionFailure {
    override val stage: InspectionStage = InspectionStage.COMPLETE
}

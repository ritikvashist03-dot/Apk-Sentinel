package app.apksentinel.core.reporting

import app.apksentinel.core.security.SafeTextNormalizer

/** Classification is applied before rendering, never inferred from a field label. */
enum class ReportSensitivity { PUBLIC_SUMMARY, TECHNICAL, SENSITIVE }

data class ReportField(
    val key: String,
    val label: String,
    val value: String,
    val sensitivity: ReportSensitivity = ReportSensitivity.PUBLIC_SUMMARY,
)

data class ReportSection(
    val id: String,
    val title: String,
    val fields: List<ReportField>,
)

/** Use this for new notes that may need the same policy gate as a field. */
data class ReportNote(
    val value: String,
    val sensitivity: ReportSensitivity = ReportSensitivity.PUBLIC_SUMMARY,
)

/**
 * A report is an in-memory description. This module never writes files,
 * transmits data, or keeps a history. Callers must classify every value before
 * passing it here; labels and keys are not used to guess sensitivity.
 */
data class LocalReport(
    val schemaVersion: Int = CURRENT_SCHEMA_VERSION,
    val reportType: String,
    val generatedAtMillis: Long,
    val sections: List<ReportSection>,
    /** Compatibility-only public notes. Do not place destinations, paths, app IDs or user data here. */
    val limitations: List<String> = emptyList(),
    val notes: List<ReportNote> = emptyList(),
)

enum class SensitiveExportAuthorization {
    NOT_AUTHORIZED,
    USER_CONFIRMED,
}

/**
 * Sensitive content requires both switches. This prevents an accidental
 * includeSensitive=true from exporting traffic/app identifiers before an
 * explicit, per-export user acknowledgement is recorded by the caller.
 */
data class ReportExportPolicy(
    val includeTechnical: Boolean = true,
    val includeSensitive: Boolean = false,
    val sensitiveExportAuthorization: SensitiveExportAuthorization = SensitiveExportAuthorization.NOT_AUTHORIZED,
    val maximumSections: Int = 1_000,
    val maximumFields: Int = 10_000,
    val maximumNotes: Int = 1_000,
    val maximumValueCodePoints: Int = 512,
) {
    init {
        require(maximumSections in 1..10_000)
        require(maximumFields in 1..100_000)
        require(maximumNotes in 1..10_000)
        require(maximumValueCodePoints in 1..512)
    }

    val mayIncludeSensitive: Boolean
        get() = includeSensitive && sensitiveExportAuthorization == SensitiveExportAuthorization.USER_CONFIRMED
}

/**
 * Renderers produce deterministic JSON/CSV for a given report and policy.
 * They are intentionally not general serializers: every string is bounded and
 * normalized, and CSV cells are neutralized against spreadsheet formulas.
 */
object LocalReportRenderer {
    fun json(report: LocalReport, policy: ReportExportPolicy = ReportExportPolicy()): String {
        val selection = select(report, policy)
        return buildString {
            append('{')
            appendJsonProperty("schemaVersion", report.schemaVersion.coerceAtLeast(1).toString(), raw = true)
            append(',')
            appendJsonProperty("reportType", safeMetadata(report.reportType, "report"))
            append(',')
            appendJsonProperty("generatedAtMillis", report.generatedAtMillis.coerceAtLeast(0L).toString(), raw = true)
            append(',')
            append("\"truncated\":").append(selection.truncated)
            append(',')
            append("\"redacted\":").append(selection.redacted)
            append(',')
            append("\"sensitiveContentOmitted\":").append(selection.sensitiveContentOmitted)
            append(',')
            append("\"fields\":[")
            selection.fields.forEachIndexed { index, field ->
                if (index > 0) append(',')
                append('{')
                appendJsonProperty("sectionId", safeSectionId(field.section.id))
                append(',')
                appendJsonProperty("section", safeMetadata(field.section.title, "Section"))
                append(',')
                appendJsonProperty("key", safeFieldKey(field.field.key))
                append(',')
                appendJsonProperty("label", safeMetadata(field.field.label, "Field"))
                append(',')
                appendJsonProperty("value", safeValue(field.field.value, policy.maximumValueCodePoints))
                append(',')
                appendJsonProperty("sensitivity", field.field.sensitivity.name)
                append('}')
            }
            append(']')
            append(',')
            append("\"limitations\":[")
            selection.legacyLimitations.forEachIndexed { index, limitation ->
                if (index > 0) append(',')
                appendJsonString(safeValue(limitation, policy.maximumValueCodePoints))
            }
            append(']')
            append(',')
            append("\"notes\":[")
            selection.notes.forEachIndexed { index, note ->
                if (index > 0) append(',')
                append('{')
                appendJsonProperty("value", safeValue(note.value, policy.maximumValueCodePoints))
                append(',')
                appendJsonProperty("sensitivity", note.sensitivity.name)
                append('}')
            }
            append(']')
            append('}')
        }
    }

    fun csv(report: LocalReport, policy: ReportExportPolicy = ReportExportPolicy()): String {
        val selection = select(report, policy)
        return buildString {
            append("section_id,section,key,label,value,sensitivity\r\n")
            selection.fields.forEach { field ->
                append(csvCell(safeSectionId(field.section.id))).append(',')
                append(csvCell(safeMetadata(field.section.title, "Section"))).append(',')
                append(csvCell(safeFieldKey(field.field.key))).append(',')
                append(csvCell(safeMetadata(field.field.label, "Field"))).append(',')
                append(csvCell(safeValue(field.field.value, policy.maximumValueCodePoints))).append(',')
                append(csvCell(field.field.sensitivity.name)).append("\r\n")
            }
            selection.legacyLimitations.forEachIndexed { index, limitation ->
                append(csvCell("limitations")).append(',')
                append(csvCell("Limitations")).append(',')
                append(csvCell("limitation_${index + 1}")).append(',')
                append(csvCell("Limitation")).append(',')
                append(csvCell(safeValue(limitation, policy.maximumValueCodePoints))).append(',')
                append(csvCell(ReportSensitivity.PUBLIC_SUMMARY.name)).append("\r\n")
            }
            selection.notes.forEachIndexed { index, note ->
                append(csvCell("notes")).append(',')
                append(csvCell("Notes")).append(',')
                append(csvCell("note_${index + 1}")).append(',')
                append(csvCell("Note")).append(',')
                append(csvCell(safeValue(note.value, policy.maximumValueCodePoints))).append(',')
                append(csvCell(note.sensitivity.name)).append("\r\n")
            }
        }
    }

    private fun select(report: LocalReport, policy: ReportExportPolicy): SelectedReport {
        val fields = ArrayList<SelectedField>(minOf(report.sections.size, policy.maximumFields))
        var truncated = report.sections.size > policy.maximumSections
        var redacted = false
        var sensitiveContentOmitted = false
        var inspectedFields = 0
        sectionLoop@ for (section in report.sections.take(policy.maximumSections)) {
            for (field in section.fields) {
                if (inspectedFields >= policy.maximumFields) {
                    truncated = true
                    break@sectionLoop
                }
                inspectedFields += 1
                if (policyAllows(field.sensitivity, policy)) {
                    fields += SelectedField(section, field)
                    if (exceedsValueLimit(field.value, policy.maximumValueCodePoints)) truncated = true
                } else {
                    redacted = true
                    if (field.sensitivity == ReportSensitivity.SENSITIVE) sensitiveContentOmitted = true
                }
            }
        }

        val legacyLimitations = report.limitations.take(policy.maximumNotes)
        if (legacyLimitations.any { exceedsValueLimit(it, policy.maximumValueCodePoints) }) truncated = true
        val selectedNotes = ArrayList<ReportNote>(policy.maximumNotes)
        var inspectedNotes = 0
        for (note in report.notes) {
            if (inspectedNotes >= policy.maximumNotes) {
                truncated = true
                break
            }
            inspectedNotes += 1
            if (policyAllows(note.sensitivity, policy)) {
                selectedNotes += note
                if (exceedsValueLimit(note.value, policy.maximumValueCodePoints)) truncated = true
            } else {
                redacted = true
                if (note.sensitivity == ReportSensitivity.SENSITIVE) sensitiveContentOmitted = true
            }
        }
        if (report.limitations.size > policy.maximumNotes) truncated = true
        return SelectedReport(
            fields = fields,
            legacyLimitations = legacyLimitations,
            notes = selectedNotes,
            truncated = truncated,
            redacted = redacted,
            sensitiveContentOmitted = sensitiveContentOmitted,
        )
    }

    private fun exceedsValueLimit(value: String, maximum: Int): Boolean =
        value.codePointCount(0, value.length) > maximum

    private fun policyAllows(sensitivity: ReportSensitivity, policy: ReportExportPolicy): Boolean = when (sensitivity) {
        ReportSensitivity.PUBLIC_SUMMARY -> true
        ReportSensitivity.TECHNICAL -> policy.includeTechnical
        ReportSensitivity.SENSITIVE -> policy.mayIncludeSensitive
    }

    private fun StringBuilder.appendJsonProperty(key: String, value: String, raw: Boolean = false) {
        appendJsonString(key)
        append(':')
        if (raw) append(value) else appendJsonString(value)
    }

    private fun StringBuilder.appendJsonString(value: String) {
        append('"')
        var index = 0
        while (index < value.length) {
            val character = value[index]
            when {
                Character.isHighSurrogate(character) -> {
                    if (index + 1 < value.length && Character.isLowSurrogate(value[index + 1])) {
                        append(character)
                        append(value[index + 1])
                        index += 2
                    } else {
                        append("\\ufffd")
                        index += 1
                    }
                }
                Character.isLowSurrogate(character) -> {
                    append("\\ufffd")
                    index += 1
                }
                else -> {
                    when (character) {
                        '\\' -> append("\\\\")
                        '"' -> append("\\\"")
                        '\b' -> append("\\b")
                        '\u000C' -> append("\\f")
                        '\n' -> append("\\n")
                        '\r' -> append("\\r")
                        '\t' -> append("\\t")
                        '\u2028', '\u2029' -> append("\\u").append(character.code.toString(16).padStart(4, '0'))
                        else -> if (character.code < 0x20) {
                            append("\\u").append(character.code.toString(16).padStart(4, '0'))
                        } else {
                            append(character)
                        }
                    }
                    index += 1
                }
            }
        }
        append('"')
    }

    private fun csvCell(value: String): String {
        val safe = neutralizeSpreadsheetFormula(value)
            .replace('\r', ' ')
            .replace('\n', ' ')
        return "\"${safe.replace("\"", "\"\"")}\""
    }

    private fun neutralizeSpreadsheetFormula(value: String): String {
        val firstMeaningful = value.firstOrNull { !it.isWhitespace() }
        return if (firstMeaningful in SPREADSHEET_FORMULA_PREFIXES) "'$value" else value
    }

    private fun safeMetadata(value: String, fallback: String): String =
        SafeTextNormalizer.normalizeDisplayText(value, fallback, MAX_METADATA_CODE_POINTS)

    private fun safeValue(value: String, maximum: Int): String =
        SafeTextNormalizer.normalizeDisplayText(value, "Unavailable", maximum)

    private fun safeSectionId(value: String): String =
        SafeTextNormalizer.normalizeDisplayText(value, "section", MAX_IDENTIFIER_CODE_POINTS)

    private fun safeFieldKey(value: String): String =
        SafeTextNormalizer.normalizeDisplayText(value, "field", MAX_IDENTIFIER_CODE_POINTS)

    private data class SelectedField(
        val section: ReportSection,
        val field: ReportField,
    )

    private data class SelectedReport(
        val fields: List<SelectedField>,
        val legacyLimitations: List<String>,
        val notes: List<ReportNote>,
        val truncated: Boolean,
        val redacted: Boolean,
        val sensitiveContentOmitted: Boolean,
    )

    private const val MAX_METADATA_CODE_POINTS = 120
    private const val MAX_IDENTIFIER_CODE_POINTS = 96
    private val SPREADSHEET_FORMULA_PREFIXES = setOf('=', '+', '-', '@')
}

const val CURRENT_SCHEMA_VERSION = 3

/**
 * The reporting module only constructs strings. For app-owned temporary
 * artifacts, this planner gives the integration layer a deterministic cleanup
 * deadline. It intentionally never authorizes deletion of a user-selected
 * Storage Access Framework destination.
 */
data class LocalReportRetentionPolicy(
    val keepAppOwnedArtifactsForMillis: Long = 0L,
) {
    init {
        require(keepAppOwnedArtifactsForMillis in 0L..MAX_REPORT_RETENTION_MILLIS) {
            "keepAppOwnedArtifactsForMillis is outside the supported range."
        }
    }
}

sealed interface LocalReportRetentionDecision {
    object DeleteNow : LocalReportRetentionDecision
    data class KeepUntil(val deleteAtMillis: Long) : LocalReportRetentionDecision
}

object LocalReportRetentionPlanner {
    fun decision(
        createdAtMillis: Long,
        nowMillis: Long,
        policy: LocalReportRetentionPolicy = LocalReportRetentionPolicy(),
    ): LocalReportRetentionDecision {
        val created = createdAtMillis.coerceAtLeast(0L)
        val deleteAt = safeAdd(created, policy.keepAppOwnedArtifactsForMillis)
        return if (nowMillis >= deleteAt) LocalReportRetentionDecision.DeleteNow else LocalReportRetentionDecision.KeepUntil(deleteAt)
    }
}

/** App integration boundary for deleting only files/databases the app owns. */
interface AppOwnedReportArtifactStore {
    fun deleteExpiredAppOwnedArtifacts(deleteThroughMillis: Long): Boolean
}

private fun safeAdd(left: Long, right: Long): Long =
    if (left > Long.MAX_VALUE - right) Long.MAX_VALUE else left + right

private const val MAX_REPORT_RETENTION_MILLIS = 90L * 24L * 60L * 60L * 1_000L

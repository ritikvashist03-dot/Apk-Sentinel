package app.apksentinel.core.model

@JvmInline
value class RiskFindingId(val value: String) {
    init {
        require(ID_PATTERN.matches(value)) { "Risk finding IDs must be stable, non-empty identifiers." }
    }

    override fun toString(): String = value

    private companion object {
        val ID_PATTERN = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")
    }
}

enum class RiskSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}

enum class RiskFindingState {
    OPEN,
    ACKNOWLEDGED,
    RESOLVED,
    DISMISSED,
}

/**
 * A bounded risk assessment. It intentionally separates a raw observation
 * from an interpretation so a UI can accurately show uncertainty and scope.
 */
data class RiskFinding(
    val id: RiskFindingId,
    val title: String,
    val observation: String,
    val interpretation: String,
    val context: String,
    val severity: RiskSeverity,
    val confidence: Confidence,
    val evidenceIds: Set<EvidenceId>,
    val recommendation: String,
    val limitations: List<String>,
    val detectedAtEpochMillis: Long,
    val state: RiskFindingState = RiskFindingState.OPEN,
) {
    init {
        require(title.isNotBlank() && title.length <= MAX_TITLE_LENGTH) { "A concise title is required." }
        require(observation.isNotBlank() && observation.length <= MAX_TEXT_LENGTH) {
            "An observation is required."
        }
        require(interpretation.isNotBlank() && interpretation.length <= MAX_TEXT_LENGTH) {
            "An interpretation is required."
        }
        require(context.isNotBlank() && context.length <= MAX_TEXT_LENGTH) { "Context is required." }
        require(recommendation.isNotBlank() && recommendation.length <= MAX_TEXT_LENGTH) {
            "A recommendation is required."
        }
        require(evidenceIds.isNotEmpty()) { "A risk finding must reference evidence." }
        require(limitations.size <= MAX_LIMITATIONS) { "Too many limitations." }
        require(limitations.all { it.isNotBlank() && it.length <= MAX_TEXT_LENGTH }) {
            "Limitations must be concise, non-blank text."
        }
        require(detectedAtEpochMillis >= 0) { "detectedAtEpochMillis cannot be negative." }
    }

    private companion object {
        const val MAX_TITLE_LENGTH = 140
        const val MAX_TEXT_LENGTH = 1_000
        const val MAX_LIMITATIONS = 12
    }
}

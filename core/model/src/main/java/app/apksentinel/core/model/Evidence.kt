package app.apksentinel.core.model

@JvmInline
value class EvidenceId(val value: String) {
    init {
        require(ID_PATTERN.matches(value)) { "Evidence IDs must be stable, non-empty identifiers." }
    }

    override fun toString(): String = value

    private companion object {
        val ID_PATTERN = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")
    }
}

/**
 * Describes where an observation came from. A source indicates provenance, not
 * that the observation is complete, trusted, or sufficient on its own.
 */
enum class EvidenceSource {
    DEVICE_API,
    PACKAGE_MANIFEST,
    APK_ARCHIVE,
    NETWORK_VPN_OBSERVATION,
    LOCAL_RULESET,
    OPTIONAL_REPUTATION_LOOKUP,
    USER_PROVIDED,
    UNKNOWN,
}

enum class ConfidenceLevel {
    VERY_LOW,
    LOW,
    MODERATE,
    HIGH,
    VERY_HIGH,
}

/**
 * Numeric confidence is intentionally bounded and always paired with an
 * explanation so consumers cannot present an unexplained certainty score.
 */
data class Confidence(
    val score: Int,
    val rationale: String,
) {
    init {
        require(score in 0..100) { "Confidence score must be between 0 and 100." }
        require(rationale.isNotBlank()) { "A confidence rationale is required." }
        require(rationale.length <= MAX_RATIONALE_LENGTH) { "Confidence rationale is too long." }
    }

    val level: ConfidenceLevel
        get() = when (score) {
            in 0..19 -> ConfidenceLevel.VERY_LOW
            in 20..39 -> ConfidenceLevel.LOW
            in 40..59 -> ConfidenceLevel.MODERATE
            in 60..79 -> ConfidenceLevel.HIGH
            else -> ConfidenceLevel.VERY_HIGH
        }

    private companion object {
        const val MAX_RATIONALE_LENGTH = 280
    }
}

/**
 * An evidence record keeps the observed fact distinct from its context and
 * limitations. Interpretation belongs on RiskFinding, not here.
 */
data class Evidence(
    val id: EvidenceId,
    val source: EvidenceSource,
    val observedAtEpochMillis: Long,
    val observation: String,
    val context: String,
    val confidence: Confidence,
    val limitations: List<String> = emptyList(),
) {
    init {
        require(observedAtEpochMillis >= 0) { "observedAtEpochMillis cannot be negative." }
        require(observation.isNotBlank()) { "An evidence observation is required." }
        require(context.isNotBlank()) { "Evidence context is required." }
        require(observation.length <= MAX_TEXT_LENGTH) { "Observation is too long." }
        require(context.length <= MAX_TEXT_LENGTH) { "Context is too long." }
        require(limitations.size <= MAX_LIMITATIONS) { "Too many limitations." }
        require(limitations.all { it.isNotBlank() && it.length <= MAX_TEXT_LENGTH }) {
            "Limitations must be concise, non-blank text."
        }
    }

    private companion object {
        const val MAX_TEXT_LENGTH = 1_000
        const val MAX_LIMITATIONS = 12
    }
}

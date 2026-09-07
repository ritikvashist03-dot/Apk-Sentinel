package app.apksentinel.core.model

/**
 * Metadata is bounded, deterministically ordered, and intentionally omits its
 * values from toString. Build it from already-redacted fields in the security
 * layer rather than placing secrets or raw identifiers in it.
 */
class AuditMetadata private constructor(
    private val values: Map<String, String>,
) {
    fun asMap(): Map<String, String> = values.toMap()

    override fun equals(other: Any?): Boolean =
        other is AuditMetadata && values == other.values

    override fun hashCode(): Int = values.hashCode()

    override fun toString(): String = "AuditMetadata(fieldCount=" + values.size + ")"

    companion object {
        private const val MAX_ENTRIES = 24
        private const val MAX_VALUE_LENGTH = 256
        private val KEY_PATTERN = Regex("^[a-z][a-z0-9_.-]{0,63}$")

        fun empty(): AuditMetadata = AuditMetadata(emptyMap())

        fun fromPublicFields(fields: Map<String, String>): AuditMetadata {
            require(fields.size <= MAX_ENTRIES) { "Too many audit metadata fields." }
            require(fields.all { (key, value) ->
                KEY_PATTERN.matches(key) && value.length <= MAX_VALUE_LENGTH && value.none(Char::isISOControl)
            }) {
                "Audit metadata must contain concise, public, machine-readable fields."
            }
            return AuditMetadata(fields.toSortedMap())
        }
    }
}

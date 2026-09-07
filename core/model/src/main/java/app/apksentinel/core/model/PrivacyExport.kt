package app.apksentinel.core.model

enum class RedactionLevel {
    /**
     * Reserved for trusted in-memory/internal use. An export flow should
     * require an explicit sensitive-export consent before selecting it.
     */
    NONE,
    STANDARD,
    STRICT,
}

enum class SensitiveDataCategory {
    DEVICE_IDENTIFIER,
    APP_IDENTIFIER,
    NETWORK_ADDRESS,
    NETWORK_DESTINATION,
    FILESYSTEM_PATH,
    USER_CONTENT,
    AUTHENTICATION_MATERIAL,
    CONTACT_DETAIL,
}

data class RedactionPolicy(
    val level: RedactionLevel,
    val categories: Set<SensitiveDataCategory>,
    val replacement: String = "[redacted]",
) {
    init {
        require(replacement.isNotBlank() && replacement.length <= MAX_REPLACEMENT_LENGTH) {
            "A concise replacement marker is required."
        }
    }

    companion object {
        const val MAX_REPLACEMENT_LENGTH = 64

        val Standard = RedactionPolicy(
            level = RedactionLevel.STANDARD,
            categories = setOf(
                SensitiveDataCategory.DEVICE_IDENTIFIER,
                SensitiveDataCategory.NETWORK_ADDRESS,
                SensitiveDataCategory.NETWORK_DESTINATION,
                SensitiveDataCategory.FILESYSTEM_PATH,
                SensitiveDataCategory.AUTHENTICATION_MATERIAL,
                SensitiveDataCategory.CONTACT_DETAIL,
            ),
        )

        val Strict = RedactionPolicy(
            level = RedactionLevel.STRICT,
            categories = SensitiveDataCategory.entries.toSet(),
        )
    }
}

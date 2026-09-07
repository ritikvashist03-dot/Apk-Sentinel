package app.apksentinel.core.security

/**
 * Single source of truth for validating externally-supplied Android package
 * names, DNS domain names, and numeric CIDR blocks.
 *
 * Before this file existed, the same three concepts were reimplemented
 * several times across the codebase with different strictness, so a value
 * one layer accepted could be rejected by another (see
 * `.sentinel-work/FINDINGS-SWEEP.md`, sections A1-A3, for the audit that
 * found this). Each function here ports the *union* of every check found in
 * its prior implementations, adopting the strictest behaviour for each:
 * ASCII-only, leading/trailing-hyphen rejection, bidi/control-character
 * rejection, length bounds, leading-zero-octet rejection, and a zero-host-bit
 * requirement for CIDR blocks. [parseCidr] never performs a DNS lookup.
 *
 * IMPORTANT — as of this writing, no production call site has been migrated
 * to use this object. The prior implementations (in `NetworkScreen.kt`,
 * `NetworkSessionSettings.kt`, `FirewallRules.kt`, `FirewallPolicy.kt`,
 * `ProtocolEvidence.kt`, `TlsInspectionBridge.kt`, and
 * `OfflineIpAttribution.kt`) are untouched and still run their own,
 * disagreeing logic. See the consolidation report for the exact file:line
 * follow-ups needed to make this the live implementation.
 */
object HostValidation {

    private const val MAX_PACKAGE_NAME_LENGTH = 255
    private const val MAX_DOMAIN_LENGTH = 253
    private const val MAX_DOMAIN_LABEL_LENGTH = 63

    /**
     * A generous pre-check applied before any per-character or per-label
     * work, mirroring `FirewallPolicy.isStrictUtf8`'s `MAX_TEXT_CHARS` guard.
     * It bounds work done on pathological input; the real length limits for
     * package names (255) and domains (253) are enforced separately.
     */
    private const val MAX_INPUT_LENGTH = 512

    private val PACKAGE_NAME_PATTERN = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")

    /**
     * True if [value] is a syntactically valid Android package / application
     * ID: ASCII letters, digits, and underscores in two or more dot-separated
     * segments, each segment starting with a letter.
     *
     * Ports the shared regex used by `NetworkScreen.isValidNetworkPackage`,
     * `NetworkSessionSettings.isValidPackageName`, and
     * `FirewallRules.isValidPackageName`, plus the 255-character length bound
     * from the strictest of the four, `FirewallPolicy.isSafePackageName`.
     * The regex full-match requirement already makes every character outside
     * `[A-Za-z0-9_.]` — including any non-ASCII, control, or bidi-override
     * character — impossible to match, so no separate charset pass is
     * needed.
     */
    fun isValidPackageName(value: String): Boolean =
        value.length in 1..MAX_PACKAGE_NAME_LENGTH && PACKAGE_NAME_PATTERN.matches(value)

    /**
     * True if [value] is a syntactically valid ASCII DNS domain name.
     *
     * Ports, from the five prior domain validators:
     *  - the label/length structure common to all five
     *    (`NetworkScreen.isValidNetworkDomain`, `FirewallRules.isValidDomainRule`,
     *    `FirewallPolicy.isSafeDomain`, `ProtocolEvidence.isSafeAsciiDnsName`,
     *    `TlsInspectionBridge.isValidDnsName`);
     *  - ASCII-only labels and leading/trailing-hyphen rejection, from
     *    `FirewallPolicy.isSafeDomain` and `ProtocolEvidence.isSafeAsciiDnsName`
     *    (the two other implementations accept any Unicode letter/digit via
     *    `Char.isLetterOrDigit()`, which is how a Cyrillic homograph domain
     *    could slip past them);
     *  - explicit control/bidi-override rejection, from
     *    `FirewallPolicy.isStrictUtf8` (redundant with the ASCII-only label
     *    charset below, but kept as an explicit, independently-testable
     *    guard rather than an incidental side effect of the character
     *    allow-list);
     *  - dotted-decimal IPv4-literal rejection, from
     *    `ProtocolEvidence.isSafeAsciiDnsName` alone — no other
     *    implementation had this check, so a bare IP address could otherwise
     *    masquerade as a validated "domain".
     *
     * A trailing dot is rejected by default rather than silently trimmed:
     * three of the five prior implementations trim-and-accept a trailing dot,
     * but the other two reject it outright, and rejecting is the stricter
     * default choice.
     *
     * Two call sites need a deliberately different rule from that strict
     * default — not a bug, a legitimate product/protocol requirement — so
     * each is exposed as a named, off-by-default parameter rather than a
     * silent behavioural difference:
     *
     *  - [allowTrailingDot]: `FirewallPolicy`'s stored domain rules accept a
     *    FQDN-style trailing dot and canonicalize it away before persisting
     *    (see `FirewallPolicy.normalizeDomain`); a trailing dot is legitimate
     *    DNS syntax there, not a security-relevant relaxation, and an
     *    existing test (`FirewallPolicyControllerTest.
     *    persistedCodecRoundTripLoadsAValidatedRuleWithoutPlaintextStoreAssumptions`)
     *    depends on `"Tracker.Example."` being accepted and stored as
     *    `"tracker.example"`.
     *  - [allowIpv4Literal]: `ProtocolEvidence`'s HTTP `Host` header evidence
     *    capture accepts either a safe domain name or a bare dotted-decimal
     *    IPv4 literal, because an HTTP `Host` header may legitimately be a
     *    literal IP address (e.g. `http://192.168.1.1/`). This is distinct
     *    from a TLS SNI or a firewall domain rule, where an IP masquerading
     *    as a "domain" is exactly the confusion this function exists to
     *    prevent — so the default stays reject-IPv4-literal, and only this
     *    one call site opts in by name.
     */
    fun isValidDomain(
        value: String,
        allowTrailingDot: Boolean = false,
        allowIpv4Literal: Boolean = false,
    ): Boolean {
        if (value.length > MAX_INPUT_LENGTH || value.any(::isDisallowedControlOrBidi)) return false
        var candidate = value.trim()
        if (allowTrailingDot) candidate = candidate.trimEnd('.')
        if (candidate.isEmpty() || candidate.length > MAX_DOMAIN_LENGTH) return false
        if (candidate.isDottedDecimalIpv4Literal()) return allowIpv4Literal
        val labels = candidate.split('.')
        return labels.all { label ->
            label.isNotEmpty() && label.length <= MAX_DOMAIN_LABEL_LENGTH &&
                label.first() != '-' && label.last() != '-' &&
                label.all { char -> char.isAsciiLetterOrDigit() || char == '-' }
        }
    }

    /**
     * Parses a numeric CIDR block, e.g. `"192.168.0.0/24"` or
     * `"2001:db8::/32"`. Returns `null` for anything else, including a bare
     * hostname — this function never performs a DNS lookup, and never falls
     * back to one.
     *
     * Ports, from the two prior CIDR parsers:
     *  - literal-only address parsing that never touches DNS, and the
     *    zero-host-bits requirement, from `OfflineIpAttribution.parseCidr`
     *    (the sibling `FirewallRules.IpCidr.parse` can fall through to
     *    `InetAddress.getByName` for IPv6-shaped input, and never checks
     *    host bits — a rule like `"10.0.0.5/24"` is accepted there even
     *    though it does not describe a network);
     *  - leading-zero octet rejection for IPv4 (`"010.0.0.0/8"` is refused),
     *    also from `OfflineIpAttribution.parseCidr` — `FirewallRules.IpCidr`
     *    accepts leading zeros, which is ambiguous between octal and decimal
     *    interpretation in some parsers;
     *  - leading-zero prefix-length rejection (`".../024"` is refused),
     *    likewise from `OfflineIpAttribution.parseCidr`.
     */
    fun parseCidr(value: String): ParsedCidr? {
        val separator = value.indexOf('/')
        if (separator <= 0 || separator != value.lastIndexOf('/') || separator == value.lastIndex) return null
        val addressBytes = parseLiteralAddress(value.substring(0, separator)) ?: return null
        val prefixText = value.substring(separator + 1)
        if (prefixText.isEmpty() || prefixText.any { it !in '0'..'9' }) return null
        val prefixLength = prefixText.toIntOrNull() ?: return null
        if (prefixText != prefixLength.toString()) return null
        if (prefixLength !in 0..addressBytes.size * 8) return null
        if (!hasZeroHostBits(addressBytes, prefixLength)) return null
        return ParsedCidr(addressBytes, prefixLength)
    }
}

/**
 * A parsed, numeric-only CIDR block. Two blocks are equal iff they cover the
 * exact same address and prefix length.
 */
class ParsedCidr internal constructor(addressBytes: ByteArray, val prefixLength: Int) {
    private val addressBytes: ByteArray = addressBytes.copyOf()

    /** `4` for an IPv4 block, `16` for an IPv6 block. */
    val addressByteCount: Int get() = addressBytes.size

    val isIpv4: Boolean get() = addressBytes.size == 4
    val isIpv6: Boolean get() = addressBytes.size == 16

    /** A defensive copy of the network address bytes (host bits are guaranteed zero). */
    fun addressBytes(): ByteArray = addressBytes.copyOf()

    /** True if [candidate] (raw address bytes, same length as this block's family) falls within this block. */
    fun matches(candidate: ByteArray): Boolean {
        if (candidate.size != addressBytes.size) return false
        for (index in 0 until prefixLength) {
            if (bitAt(addressBytes, index) != bitAt(candidate, index)) return false
        }
        return true
    }

    /**
     * Parses [address] as a numeric literal — never a hostname, never via
     * DNS — and checks membership. Returns `false` for anything that is not
     * a literal address of this block's family.
     */
    fun matches(address: String): Boolean = parseLiteralAddress(address.trim())?.let(::matches) ?: false

    override fun equals(other: Any?): Boolean =
        other is ParsedCidr && prefixLength == other.prefixLength && addressBytes.contentEquals(other.addressBytes)

    override fun hashCode(): Int = 31 * prefixLength + addressBytes.contentHashCode()

    override fun toString(): String = "${formatAddress(addressBytes)}/$prefixLength"
}

private fun parseLiteralAddress(raw: String): ByteArray? = parseIpv4Literal(raw) ?: parseIpv6Literal(raw)

private fun parseIpv4Literal(raw: String): ByteArray? {
    if (raw.length !in 7..15 || raw.any { it !in '0'..'9' && it != '.' }) return null
    val parts = raw.split('.')
    if (parts.size != 4) return null
    val bytes = ByteArray(4)
    parts.forEachIndexed { index, part ->
        if (part.isEmpty() || part.length > 3 || (part.length > 1 && part[0] == '0')) return null
        val numeric = part.toIntOrNull() ?: return null
        if (numeric !in 0..255) return null
        bytes[index] = numeric.toByte()
    }
    return bytes
}

/** Standard hexadecimal IPv6 with optional `::` compression. Zone IDs and dotted suffixes are rejected by the charset filter below. */
private fun parseIpv6Literal(raw: String): ByteArray? {
    if (raw.length !in 2..45 || raw.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' && it != ':' }) return null
    val doubleIndex = raw.indexOf("::")
    if (doubleIndex >= 0 && doubleIndex != raw.lastIndexOf("::")) return null
    val groups = ArrayList<String>(8)
    if (doubleIndex >= 0) {
        val left = raw.substring(0, doubleIndex).takeIf { it.isNotEmpty() }?.split(':') ?: emptyList()
        val right = raw.substring(doubleIndex + 2).takeIf { it.isNotEmpty() }?.split(':') ?: emptyList()
        if (left.any { it.isEmpty() } || right.any { it.isEmpty() } || left.size + right.size >= 8) return null
        groups.addAll(left)
        repeat(8 - left.size - right.size) { groups += "0" }
        groups.addAll(right)
    } else {
        groups.addAll(raw.split(':'))
        if (groups.size != 8 || groups.any { it.isEmpty() }) return null
    }
    if (groups.size != 8 || groups.any { it.length !in 1..4 || it.any { character -> character.digitToIntOrNull(16) == null } }) {
        return null
    }
    return ByteArray(16).also { result ->
        groups.forEachIndexed { index, group ->
            val value = group.toInt(16)
            result[index * 2] = (value ushr 8).toByte()
            result[index * 2 + 1] = value.toByte()
        }
    }
}

private fun hasZeroHostBits(bytes: ByteArray, prefixLength: Int): Boolean {
    for (index in prefixLength until bytes.size * 8) if (bitAt(bytes, index) != 0) return false
    return true
}

private fun bitAt(bytes: ByteArray, index: Int): Int =
    ((bytes[index / 8].toInt() and 0xff) ushr (7 - (index % 8))) and 1

private fun String.isDottedDecimalIpv4Literal(): Boolean {
    val parts = split('.')
    return parts.size == 4 && parts.all { part ->
        part.isNotEmpty() && part.all { it in '0'..'9' } && part.toIntOrNull() in 0..255
    }
}

private fun Char.isAsciiLetterOrDigit(): Boolean = this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9'

private fun isDisallowedControlOrBidi(value: Char): Boolean =
    value.code in 0..31 || value.code == 127 || value.code in 0x202a..0x202e || value.code in 0x2066..0x2069

private fun formatAddress(bytes: ByteArray): String = if (bytes.size == 16) formatIpv6(bytes) else formatIpv4(bytes)

private fun formatIpv4(bytes: ByteArray): String = bytes.joinToString(".") { (it.toInt() and 0xff).toString() }

private fun formatIpv6(bytes: ByteArray): String {
    val groups = IntArray(8) { index -> ((bytes[index * 2].toInt() and 0xff) shl 8) or (bytes[index * 2 + 1].toInt() and 0xff) }
    var bestStart = -1
    var bestLength = 0
    var currentStart = -1
    var currentLength = 0
    for (index in 0..7) {
        if (groups[index] == 0) {
            if (currentStart == -1) currentStart = index
            currentLength += 1
            if (currentLength > bestLength) {
                bestLength = currentLength
                bestStart = currentStart
            }
        } else {
            currentStart = -1
            currentLength = 0
        }
    }
    return if (bestLength >= 2) {
        val left = groups.slice(0 until bestStart).joinToString(":") { it.toString(16) }
        val right = groups.slice((bestStart + bestLength) until 8).joinToString(":") { it.toString(16) }
        "$left::$right"
    } else {
        groups.joinToString(":") { it.toString(16) }
    }
}

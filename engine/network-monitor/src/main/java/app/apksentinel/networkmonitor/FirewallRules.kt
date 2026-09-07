package app.apksentinel.networkmonitor

import app.apksentinel.core.security.HostValidation
import app.apksentinel.core.security.ParsedCidr
import java.util.Locale

enum class FirewallAction {
    ALLOW,
    BLOCK,
}

enum class RuleCriterion {
    APP,
    APP_UID,
    DESTINATION_CIDR,
    DOMAIN,
    TRANSPORT_PROTOCOL,
    DESTINATION_PORT,
}

enum class FirewallDecisionReason {
    DEFAULT_ALLOW_NO_MATCHING_RULE,
    DEFAULT_ALLOW_DOMAIN_RULE_NOT_EVALUABLE,
    MATCHED_ALLOW_RULE,
    MATCHED_BLOCK_RULE,
}

/** A rule decision is not an enforcement claim. See [FirewallEnforcementState]. */
enum class FirewallEnforcementState {
    NOT_APPLICABLE,
    PENDING_FORWARDER_CONFIRMATION,
    NOT_ENFORCED_FORWARDER_CAPABILITY_MISSING,
    CONFIRMED_ALLOWED,
    CONFIRMED_BLOCKED,
    FORWARDER_FAILED,
}

data class FirewallDecision(
    val directiveId: String,
    val requestedAction: FirewallAction,
    val matchedRuleId: String?,
    val reason: FirewallDecisionReason,
    val enforcement: FirewallEnforcementState,
    val matchedCriteria: Set<RuleCriterion> = emptySet(),
    val competingRuleIds: List<String> = emptyList(),
    val skippedExpiredRuleIds: List<String> = emptyList(),
) {
    val requestsBlock: Boolean get() = requestedAction == FirewallAction.BLOCK
}

enum class FirewallEnforcementOutcome {
    ALLOWED,
    BLOCKED,
    FAILED,
}

data class FirewallEnforcementResult(
    val directiveId: String,
    val outcome: FirewallEnforcementOutcome,
    val detail: String,
)

/**
 * A numeric CIDR only. [parse] rejects host names so creating or evaluating a
 * rule cannot trigger a DNS lookup.
 *
 * Parsing and matching both delegate to [HostValidation.parseCidr] /
 * [ParsedCidr] — the shared, union-strict implementation (see
 * `.sentinel-work/FINDINGS-SWEEP.md`, A3). This class previously reimplemented
 * CIDR parsing itself: it fell through to `InetAddress.getByName` for
 * IPv6-shaped input (a possible DNS lookup for malformed input), accepted
 * leading-zero octets, and never checked that host bits were zero. `IpCidr`
 * is kept as the public type here (rather than replaced outright by
 * [ParsedCidr]) because it is still constructed directly by call sites this
 * migration does not own, e.g. `NetworkScreen.kt`.
 */
class IpCidr private constructor(private val parsed: ParsedCidr) {
    val prefixLength: Int get() = parsed.prefixLength

    fun matches(address: String): Boolean = parsed.matches(address)

    fun matches(candidate: ByteArray): Boolean = parsed.matches(candidate)

    override fun equals(other: Any?): Boolean = other is IpCidr && parsed == other.parsed

    override fun hashCode(): Int = parsed.hashCode()

    override fun toString(): String = parsed.toString()

    companion object {
        fun parse(value: String): IpCidr? = HostValidation.parseCidr(value)?.let { IpCidr(it) }
    }
}

data class FirewallRule(
    val id: String,
    val action: FirewallAction,
    val priority: Int = 0,
    val enabled: Boolean = true,
    /**
     * Exact Android UIDs only. A rule with this criterion is evaluated only
     * when the active VPN owner lookup produced a single, high-confidence UID.
     */
    val appUids: Set<Int> = emptySet(),
    val appPackageNames: Set<String> = emptySet(),
    val destinationCidrs: Set<IpCidr> = emptySet(),
    /** User-supplied rule input, not packet-derived DNS content. */
    val domainNames: Set<String> = emptySet(),
    val protocols: Set<TransportProtocol> = emptySet(),
    val destinationPortRange: IntRange? = null,
    val expiresAtMillis: Long? = null,
) {
    init {
        require(id.isNotBlank() && id.length <= 128) { "Rule ID must be between 1 and 128 characters." }
        require(appUids.all { it >= 0 }) { "One or more app UIDs are invalid." }
        require(appPackageNames.all(HostValidation::isValidPackageName)) { "One or more app package names are invalid." }
        // allowTrailingDot: matches FirewallPolicy's stored domain rules, which accept and
        // canonicalize away a FQDN-style trailing dot (see HostValidation.isValidDomain's doc).
        require(domainNames.all { HostValidation.isValidDomain(it, allowTrailingDot = true) }) { "One or more domain rules are invalid." }
        require(destinationPortRange == null ||
            destinationPortRange.first in 0..65_535 && destinationPortRange.last in 0..65_535
        ) { "Destination port range must be within 0..65535." }
    }

    fun isExpired(atMillis: Long): Boolean = expiresAtMillis?.let { it <= atMillis } ?: false
}

/**
 * [explicitDomainForRule] is ephemeral input from a reviewed data plane or a
 * separately-consented resolver. It is never added to [NetworkEvent] by this
 * rule engine, and default packet parsing supplies null.
 */
data class FirewallEvaluationContext(
    val metadata: PacketMetadata,
    val attribution: AppAttribution,
    val explicitDomainForRule: String? = null,
)

/** Implementations installed in [NetworkMonitorRuntime] must provide thread-safe snapshots. */
interface FirewallRuleProvider {
    fun snapshot(): List<FirewallRule>
}

object EmptyFirewallRuleProvider : FirewallRuleProvider {
    override fun snapshot(): List<FirewallRule> = emptyList()
}

class InMemoryFirewallRuleProvider(
    initialRules: List<FirewallRule> = emptyList(),
) : FirewallRuleProvider {
    private val lock = Any()
    private var rules: List<FirewallRule> = validated(initialRules)

    override fun snapshot(): List<FirewallRule> = synchronized(lock) { rules }

    fun replace(nextRules: List<FirewallRule>) {
        synchronized(lock) {
            rules = validated(nextRules)
        }
    }

    /** Atomically adds a rule or replaces the existing rule with the same ID. */
    fun upsert(rule: FirewallRule) {
        synchronized(lock) {
            rules = validated(rules.filterNot { it.id == rule.id } + rule)
        }
    }

    /** Atomically removes one rule and reports whether that rule was present. */
    fun remove(ruleId: String): Boolean {
        require(ruleId.isNotBlank()) { "Firewall rule ID must not be blank." }
        return synchronized(lock) {
            val next = rules.filterNot { it.id == ruleId }
            if (next.size == rules.size) {
                false
            } else {
                rules = next
                true
            }
        }
    }

    /** Removes all process-local rules and returns the number removed. */
    fun clear(): Int = synchronized(lock) {
        val count = rules.size
        rules = emptyList()
        count
    }

    private fun validated(value: List<FirewallRule>): List<FirewallRule> {
        require(value.map(FirewallRule::id).distinct().size == value.size) { "Firewall rule IDs must be unique." }
        return value.toList()
    }
}

class FirewallRuleEngine(
    private val ruleProvider: FirewallRuleProvider,
    private val idSource: () -> String,
) {
    fun evaluate(
        context: FirewallEvaluationContext,
        atMillis: Long,
        forwarderCanEnforceRules: Boolean,
    ): FirewallDecision {
        val activeRules = ruleProvider.snapshot().filter(FirewallRule::enabled)
        val expiredRuleIds = activeRules.filter { it.isExpired(atMillis) }.map(FirewallRule::id)
        val matchResult = activeRules
            .filterNot { it.isExpired(atMillis) }
            .map { rule -> rule to evaluateRule(rule, context) }
        val matches = matchResult.filter { it.second.matched }
            .sortedWith(compareByDescending<Pair<FirewallRule, RuleMatch>> { it.first.priority }.thenBy { it.first.id })
        val domainWasNotEvaluable = matchResult.any { (_, result) -> result.domainWasRequiredButUnavailable }

        if (matches.isEmpty()) {
            return FirewallDecision(
                directiveId = idSource(),
                requestedAction = FirewallAction.ALLOW,
                matchedRuleId = null,
                reason = if (domainWasNotEvaluable) {
                    FirewallDecisionReason.DEFAULT_ALLOW_DOMAIN_RULE_NOT_EVALUABLE
                } else {
                    FirewallDecisionReason.DEFAULT_ALLOW_NO_MATCHING_RULE
                },
                enforcement = FirewallEnforcementState.NOT_APPLICABLE,
                skippedExpiredRuleIds = expiredRuleIds,
            )
        }

        val selected = matches.first()
        val action = selected.first.action
        return FirewallDecision(
            directiveId = idSource(),
            requestedAction = action,
            matchedRuleId = selected.first.id,
            reason = if (action == FirewallAction.BLOCK) {
                FirewallDecisionReason.MATCHED_BLOCK_RULE
            } else {
                FirewallDecisionReason.MATCHED_ALLOW_RULE
            },
            enforcement = when {
                action == FirewallAction.ALLOW -> FirewallEnforcementState.NOT_APPLICABLE
                forwarderCanEnforceRules -> FirewallEnforcementState.PENDING_FORWARDER_CONFIRMATION
                else -> FirewallEnforcementState.NOT_ENFORCED_FORWARDER_CAPABILITY_MISSING
            },
            matchedCriteria = selected.second.criteria,
            competingRuleIds = matches.drop(1).map { it.first.id },
            skippedExpiredRuleIds = expiredRuleIds,
        )
    }

    private fun evaluateRule(
        rule: FirewallRule,
        context: FirewallEvaluationContext,
    ): RuleMatch {
        val criteria = linkedSetOf<RuleCriterion>()

        if (rule.appUids.isNotEmpty()) {
            val uid = (context.attribution as? AppAttribution.Known)?.uid
            if (uid !in rule.appUids) return RuleMatch.notMatched()
            criteria += RuleCriterion.APP_UID
        }

        if (rule.appPackageNames.isNotEmpty()) {
            val packageName = (context.attribution as? AppAttribution.Known)?.packageName
            if (packageName !in rule.appPackageNames) return RuleMatch.notMatched()
            criteria += RuleCriterion.APP
        }

        if (rule.destinationCidrs.isNotEmpty()) {
            if (rule.destinationCidrs.none { it.matches(context.metadata.destination.address) }) {
                return RuleMatch.notMatched()
            }
            criteria += RuleCriterion.DESTINATION_CIDR
        }

        if (rule.domainNames.isNotEmpty()) {
            val domain = context.explicitDomainForRule?.normalizedDomain()
                ?: return RuleMatch.notMatched(domainWasRequiredButUnavailable = true)
            if (rule.domainNames.none { domainMatches(domain, it.normalizedDomain()) }) return RuleMatch.notMatched()
            criteria += RuleCriterion.DOMAIN
        }

        if (rule.protocols.isNotEmpty()) {
            if (context.metadata.transportProtocol !in rule.protocols) return RuleMatch.notMatched()
            criteria += RuleCriterion.TRANSPORT_PROTOCOL
        }

        if (rule.destinationPortRange != null) {
            val port = context.metadata.destination.port
            if (port == null || port !in rule.destinationPortRange) return RuleMatch.notMatched()
            criteria += RuleCriterion.DESTINATION_PORT
        }

        return RuleMatch(matched = true, criteria = criteria)
    }

    private data class RuleMatch(
        val matched: Boolean,
        val criteria: Set<RuleCriterion> = emptySet(),
        val domainWasRequiredButUnavailable: Boolean = false,
    ) {
        companion object {
            fun notMatched(domainWasRequiredButUnavailable: Boolean = false): RuleMatch = RuleMatch(
                matched = false,
                domainWasRequiredButUnavailable = domainWasRequiredButUnavailable,
            )
        }
    }
}

fun FirewallDecision.withEnforcementResult(result: FirewallEnforcementResult): FirewallDecision {
    require(result.directiveId == directiveId) { "Enforcement result does not belong to this decision." }
    return copy(
        enforcement = when (result.outcome) {
            FirewallEnforcementOutcome.ALLOWED -> FirewallEnforcementState.CONFIRMED_ALLOWED
            FirewallEnforcementOutcome.BLOCKED -> FirewallEnforcementState.CONFIRMED_BLOCKED
            FirewallEnforcementOutcome.FAILED -> FirewallEnforcementState.FORWARDER_FAILED
        },
    )
}

private fun domainMatches(candidate: String, ruleDomain: String): Boolean =
    candidate == ruleDomain || candidate.endsWith(".$ruleDomain")

private fun String.normalizedDomain(): String = trim().trimEnd('.').lowercase(Locale.ROOT)


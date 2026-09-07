package app.apksentinel.core.model

/**
 * What a piece of evidence is about — normally an installed package name.
 *
 * Evidence itself carries no subject, which is exactly why the four engines could never
 * be related to one another: each produced correct findings about something, with no
 * shared way to say what that something was.
 */
@JvmInline
value class FindingSubject(val value: String) {
    init {
        require(value.isNotBlank() && value.length <= MAX_LENGTH) { "A finding subject is required." }
    }

    override fun toString(): String = value

    private companion object {
        const val MAX_LENGTH = 255
    }
}

/** Everything currently known about one subject, from every source that reported on it. */
data class SubjectFindings(
    val subject: FindingSubject,
    val evidence: List<Evidence>,
    val findings: List<RiskFinding>,
) {
    /** The distinct provenances that contributed, which is what makes corroboration visible. */
    val sources: Set<EvidenceSource> get() = evidence.map(Evidence::source).toSet()

    /**
     * True when this subject was seen both as an installed/inspected artifact AND on the
     * network. That combination is the thing no single engine could report on its own.
     */
    val hasCrossSourceCorroboration: Boolean
        get() = sources.any { it in ARTIFACT_SOURCES } && EvidenceSource.NETWORK_VPN_OBSERVATION in sources

    private companion object {
        val ARTIFACT_SOURCES = setOf(
            EvidenceSource.DEVICE_API,
            EvidenceSource.PACKAGE_MANIFEST,
            EvidenceSource.APK_ARCHIVE,
        )
    }
}

/**
 * Where an engine or feature hands its observations in.
 *
 * Not a `fun interface`: an abstract method there cannot carry a default value, and most
 * callers submit evidence without an interpretation attached.
 */
interface FindingsSink {
    fun submit(subject: FindingSubject, evidence: List<Evidence>, findings: List<RiskFinding>)
}

/**
 * Relates observations from different engines to the same subject.
 *
 * The product describes "one calm status and findings system spanning apps and network
 * events", but in the code each engine kept its own results and nothing joined them: an
 * app's risk view could not say what that app did on the network, and the network log
 * could not say whose traffic it was looking at. The domain model for this
 * ([Evidence], [RiskFinding]) already existed and was referenced only by its own tests.
 *
 * Deliberately in-memory and bounded. Correlating observations is useful; persisting a
 * per-app dossier across sessions is a different product with a different privacy story,
 * and is not what this is.
 */
class FindingsRepository(
    private val maximumSubjects: Int = DEFAULT_MAXIMUM_SUBJECTS,
    private val maximumEvidencePerSubject: Int = DEFAULT_MAXIMUM_EVIDENCE_PER_SUBJECT,
    private val maximumFindingsPerSubject: Int = DEFAULT_MAXIMUM_FINDINGS_PER_SUBJECT,
) : FindingsSink {
    private val lock = Any()
    private val evidenceBySubject = LinkedHashMap<FindingSubject, MutableList<Evidence>>()
    private val findingsBySubject = LinkedHashMap<FindingSubject, MutableList<RiskFinding>>()

    /** Submits observations that carry no interpretation yet, which is the common case. */
    fun submit(subject: FindingSubject, evidence: List<Evidence>) = submit(subject, evidence, emptyList())

    override fun submit(subject: FindingSubject, evidence: List<Evidence>, findings: List<RiskFinding>) {
        if (evidence.isEmpty() && findings.isEmpty()) return
        synchronized(lock) {
            val currentEvidence = evidenceBySubject.remove(subject) ?: ArrayList()
            evidence.forEach { item ->
                // An engine re-reporting the same evidence id replaces it rather than
                // accumulating duplicates every refresh tick.
                currentEvidence.removeAll { it.id == item.id }
                currentEvidence.add(item)
            }
            while (currentEvidence.size > maximumEvidencePerSubject) currentEvidence.removeAt(0)
            evidenceBySubject[subject] = currentEvidence

            if (findings.isNotEmpty()) {
                val currentFindings = findingsBySubject.remove(subject) ?: ArrayList()
                findings.forEach { finding ->
                    currentFindings.removeAll { it.id == finding.id }
                    currentFindings.add(finding)
                }
                while (currentFindings.size > maximumFindingsPerSubject) currentFindings.removeAt(0)
                findingsBySubject[subject] = currentFindings
            }
            evictOldestSubjectsBeyondLimit()
        }
    }

    fun forSubject(subject: FindingSubject): SubjectFindings? = synchronized(lock) {
        val evidence = evidenceBySubject[subject].orEmpty()
        val findings = findingsBySubject[subject].orEmpty()
        if (evidence.isEmpty() && findings.isEmpty()) return null
        SubjectFindings(subject, evidence.toList(), findings.toList())
    }

    fun snapshot(): List<SubjectFindings> = synchronized(lock) {
        evidenceBySubject.keys.mapNotNull { subject ->
            val evidence = evidenceBySubject[subject].orEmpty()
            val findings = findingsBySubject[subject].orEmpty()
            if (evidence.isEmpty() && findings.isEmpty()) null
            else SubjectFindings(subject, evidence.toList(), findings.toList())
        }
    }

    /** Subjects corroborated by both an artifact source and a network observation. */
    fun crossSourceSubjects(): List<SubjectFindings> = snapshot().filter { it.hasCrossSourceCorroboration }

    fun subjectCount(): Int = synchronized(lock) { evidenceBySubject.size }

    fun clear() = synchronized(lock) {
        evidenceBySubject.clear()
        findingsBySubject.clear()
    }

    private fun evictOldestSubjectsBeyondLimit() {
        while (evidenceBySubject.size > maximumSubjects) {
            val oldest = evidenceBySubject.keys.firstOrNull() ?: break
            evidenceBySubject.remove(oldest)
            findingsBySubject.remove(oldest)
        }
    }

    private companion object {
        const val DEFAULT_MAXIMUM_SUBJECTS = 512
        const val DEFAULT_MAXIMUM_EVIDENCE_PER_SUBJECT = 32
        const val DEFAULT_MAXIMUM_FINDINGS_PER_SUBJECT = 16
    }
}

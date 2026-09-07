package app.apksentinel.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FindingsRepositoryTest {
    private val subject = FindingSubject("com.example.app")

    @Test
    fun relatesObservationsFromDifferentEnginesToOneSubject() {
        val repository = FindingsRepository()
        repository.submit(subject, listOf(evidence("pkg-1", EvidenceSource.PACKAGE_MANIFEST)))
        repository.submit(subject, listOf(evidence("net-1", EvidenceSource.NETWORK_VPN_OBSERVATION)))

        val related = requireNotNull(repository.forSubject(subject))
        assertEquals(2, related.evidence.size)
        assertEquals(
            setOf(EvidenceSource.PACKAGE_MANIFEST, EvidenceSource.NETWORK_VPN_OBSERVATION),
            related.sources,
        )
    }

    @Test
    fun corroborationNeedsBothAnArtifactSourceAndANetworkObservation() {
        val repository = FindingsRepository()
        repository.submit(subject, listOf(evidence("pkg-1", EvidenceSource.PACKAGE_MANIFEST)))
        assertFalse(requireNotNull(repository.forSubject(subject)).hasCrossSourceCorroboration)
        assertTrue(repository.crossSourceSubjects().isEmpty())

        repository.submit(subject, listOf(evidence("net-1", EvidenceSource.NETWORK_VPN_OBSERVATION)))
        assertTrue(requireNotNull(repository.forSubject(subject)).hasCrossSourceCorroboration)
        assertEquals(1, repository.crossSourceSubjects().size)
    }

    @Test
    fun twoNetworkObservationsAloneAreNotCorroboration() {
        val repository = FindingsRepository()
        repository.submit(
            subject,
            listOf(
                evidence("net-1", EvidenceSource.NETWORK_VPN_OBSERVATION),
                evidence("net-2", EvidenceSource.NETWORK_VPN_OBSERVATION),
            ),
        )
        assertFalse(requireNotNull(repository.forSubject(subject)).hasCrossSourceCorroboration)
    }

    @Test
    fun resubmittingTheSameEvidenceIdReplacesRatherThanAccumulates() {
        val repository = FindingsRepository()
        repeat(5) {
            repository.submit(subject, listOf(evidence("pkg-1", EvidenceSource.PACKAGE_MANIFEST)))
        }
        assertEquals(1, requireNotNull(repository.forSubject(subject)).evidence.size)
    }

    @Test
    fun anUnknownSubjectIsNullRatherThanAnEmptyShell() {
        assertNull(FindingsRepository().forSubject(FindingSubject("com.absent.app")))
    }

    @Test
    fun subjectsAreBoundedAndEvictOldestFirst() {
        val repository = FindingsRepository(maximumSubjects = 3)
        listOf("a", "b", "c", "d").forEach { name ->
            repository.submit(FindingSubject("com.example.$name"), listOf(evidence("e-$name", EvidenceSource.DEVICE_API)))
        }
        assertEquals(3, repository.subjectCount())
        assertNull(repository.forSubject(FindingSubject("com.example.a")))
        assertTrue(repository.forSubject(FindingSubject("com.example.d")) != null)
    }

    @Test
    fun evidencePerSubjectIsBounded() {
        val repository = FindingsRepository(maximumEvidencePerSubject = 2)
        repeat(5) { index ->
            repository.submit(subject, listOf(evidence("e-$index", EvidenceSource.DEVICE_API)))
        }
        assertEquals(2, requireNotNull(repository.forSubject(subject)).evidence.size)
    }

    @Test
    fun anEmptySubmissionChangesNothing() {
        val repository = FindingsRepository()
        repository.submit(subject, emptyList(), emptyList())
        assertEquals(0, repository.subjectCount())
    }

    private fun evidence(id: String, source: EvidenceSource) = Evidence(
        id = EvidenceId(id),
        source = source,
        observedAtEpochMillis = 1_000L,
        observation = "observed",
        context = "test context",
        confidence = Confidence(score = 50, rationale = "fixture"),
    )
}

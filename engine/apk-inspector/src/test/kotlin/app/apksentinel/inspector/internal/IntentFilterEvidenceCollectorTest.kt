package app.apksentinel.inspector.internal

import app.apksentinel.inspector.ComponentType
import app.apksentinel.inspector.InspectionLimits
import app.apksentinel.inspector.IntentFilterPathKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IntentFilterEvidenceCollectorTest {
    @Test
    fun retainsTypedActivityServiceReceiverAndProviderEvidence() {
        val collector = BoundedIntentFilterEvidenceCollector(InspectionLimits())
        collector.startElement("manifest", listOf(attribute(null, "package", "example.safe")))
        addFilter(collector, "activity", ".Main", "android.intent.action.VIEW", "android.intent.category.BROWSABLE")
        addFilter(collector, "service", ".Sync", "example.SYNC", null)
        addFilter(collector, "receiver", ".Boot", "android.intent.action.BOOT_COMPLETED", null)
        addFilter(collector, "provider", ".Provider", "example.READ", null)

        val collection = collector.finish()

        assertFalse(collection.isTruncated)
        assertEquals(4, collection.components.size)
        val activity = collection.components.getValue(IntentFilterComponentKey(ComponentType.ACTIVITY, "example.safe.Main"))
        assertEquals(listOf("android.intent.action.VIEW"), activity.filters.single().actions)
        assertEquals(listOf("android.intent.category.BROWSABLE"), activity.filters.single().categories)
    }

    @Test
    fun retainsDataSchemeHostPathsAndMimeTypeWithTypedPathKinds() {
        val collector = BoundedIntentFilterEvidenceCollector(InspectionLimits(maxIntentFilterPathsPerData = 8))
        collector.startElement("manifest", listOf(attribute(null, "package", "example.safe")))
        collector.startElement("activity", listOf(attribute(androidNamespace, "name", ".Main")))
        collector.startElement("intent-filter", emptyList())
        collector.startElement(
            "data",
            listOf(
                attribute(androidNamespace, "scheme", "https"),
                attribute(androidNamespace, "host", "example.test"),
                attribute(androidNamespace, "port", "443"),
                attribute(androidNamespace, "mimeType", "image/png"),
                attribute(androidNamespace, "path", "/literal"),
                attribute(androidNamespace, "pathPrefix", "/prefix"),
                attribute(androidNamespace, "pathPattern", "/.*"),
                attribute(androidNamespace, "pathAdvancedPattern", "/[a-z]+"),
                attribute(androidNamespace, "pathSuffix", ".png"),
            ),
        )
        collector.endElement("data")
        collector.endElement("intent-filter")
        collector.endElement("activity")

        val data = collector.finish().components
            .getValue(IntentFilterComponentKey(ComponentType.ACTIVITY, "example.safe.Main"))
            .filters.single().data.single()

        assertEquals("https", data.scheme)
        assertEquals("example.test", data.host)
        assertEquals("443", data.port)
        assertEquals("image/png", data.mimeType)
        assertEquals(
            listOf(
                IntentFilterPathKind.LITERAL,
                IntentFilterPathKind.PREFIX,
                IntentFilterPathKind.PATTERN,
                IntentFilterPathKind.ADVANCED_PATTERN,
                IntentFilterPathKind.SUFFIX,
            ),
            data.paths.map { it.kind },
        )
    }

    @Test
    fun appliesPerFilterPerComponentAndGlobalCapsWithFlags() {
        val collector = BoundedIntentFilterEvidenceCollector(
            InspectionLimits(
                maxManifestIntentFilters = 2,
                maxIntentFiltersPerComponent = 1,
                maxIntentFilterActionsPerFilter = 1,
                maxIntentFilterCategoriesPerFilter = 1,
                maxIntentFilterDataPerFilter = 1,
                maxIntentFilterPathsPerData = 1,
            ),
        )
        collector.startElement("manifest", listOf(attribute(null, "package", "example.safe")))
        collector.startElement("activity", listOf(attribute(androidNamespace, "name", ".One")))
        collector.startElement("intent-filter", emptyList())
        collector.startElement("action", listOf(attribute(androidNamespace, "name", "one")))
        collector.startElement("action", listOf(attribute(androidNamespace, "name", "two")))
        collector.startElement("category", listOf(attribute(androidNamespace, "name", "one")))
        collector.startElement("category", listOf(attribute(androidNamespace, "name", "two")))
        collector.startElement("data", listOf(attribute(androidNamespace, "scheme", "one")))
        collector.startElement("data", listOf(attribute(androidNamespace, "scheme", "two")))
        collector.endElement("intent-filter")
        collector.startElement("intent-filter", emptyList())
        collector.endElement("intent-filter")
        collector.endElement("activity")
        addFilter(collector, "service", ".Two", "two", null)
        addFilter(collector, "receiver", ".Three", "three", null)

        val collection = collector.finish()
        val first = collection.components.getValue(IntentFilterComponentKey(ComponentType.ACTIVITY, "example.safe.One"))
        val filter = first.filters.single()

        assertTrue(first.isTruncated)
        assertTrue(filter.actionsTruncated)
        assertTrue(filter.categoriesTruncated)
        assertTrue(filter.dataTruncated)
        assertEquals(1, filter.actions.size)
        assertEquals(1, filter.categories.size)
        assertEquals(1, filter.data.size)
        assertFalse(filter.data.single().isTruncated)
        assertTrue(collection.isTruncated)
        assertTrue(collection.components.getValue(IntentFilterComponentKey(ComponentType.RECEIVER, "example.safe.Three")).isTruncated)
    }

    @Test
    fun ignoresSpoofedNamespacesAndBoundsMalformedOversizedValues() {
        val collector = BoundedIntentFilterEvidenceCollector(InspectionLimits(maxIntentFilterValueBytes = 16))
        collector.startElement("manifest", listOf(attribute(null, "package", "example.safe")))
        collector.startElement("activity", listOf(attribute(androidNamespace, "name", ".Main")))
        collector.startElement("intent-filter", emptyList())
        collector.startElement("action", listOf(attribute(null, "name", "spoofed")))
        collector.startElement("action", listOf(attribute(androidNamespace, "name", "x".repeat(1_000_000))))
        collector.endElement("intent-filter")
        // Leave the component open to verify malformed nesting becomes an explicit bounded limitation.

        val collection = collector.finish()
        val component = collection.components.getValue(IntentFilterComponentKey(ComponentType.ACTIVITY, "example.safe.Main"))
        val filter = component.filters.single()

        assertTrue(collection.isTruncated)
        assertTrue(component.isTruncated)
        assertTrue(filter.actionsTruncated)
        assertEquals(16, filter.actions.single().toByteArray().size)
        assertFalse(filter.actions.contains("spoofed"))
    }

    private fun addFilter(
        collector: BoundedIntentFilterEvidenceCollector,
        component: String,
        componentName: String,
        action: String,
        category: String?,
    ) {
        collector.startElement(component, listOf(attribute(androidNamespace, "name", componentName)))
        collector.startElement("intent-filter", emptyList())
        collector.startElement("action", listOf(attribute(androidNamespace, "name", action)))
        category?.let { collector.startElement("category", listOf(attribute(androidNamespace, "name", it))) }
        collector.endElement("intent-filter")
        collector.endElement(component)
    }

    private fun attribute(namespace: String?, name: String, value: String) = RenderedManifestAttribute(
        namespace = namespace,
        name = name,
        fallbackName = name,
        value = value,
    )

    private companion object {
        const val androidNamespace = "http://schemas.android.com/apk/res/android"
    }
}

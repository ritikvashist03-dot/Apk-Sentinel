package app.apksentinel.inspector.internal

import app.apksentinel.inspector.ComponentType
import app.apksentinel.inspector.InspectionLimits
import app.apksentinel.inspector.IntentFilterDataEvidence
import app.apksentinel.inspector.IntentFilterEvidence
import app.apksentinel.inspector.IntentFilterPathEvidence
import app.apksentinel.inspector.IntentFilterPathKind

/** Internal key used to join raw AXML evidence to PackageManager component records. */
internal data class IntentFilterComponentKey(
    val type: ComponentType,
    val className: String,
)

internal data class ComponentIntentFilterEvidence(
    val filters: List<IntentFilterEvidence>,
    val isTruncated: Boolean,
)

internal data class IntentFilterEvidenceCollection(
    val components: Map<IntentFilterComponentKey, ComponentIntentFilterEvidence>,
    val isTruncated: Boolean,
)

/**
 * Bounded, namespace-aware collector for declarative intent-filter metadata.
 * It is fed the same parser events that produce the readable manifest, never
 * opens a second input stream, and does not retain exceptions or parser prose.
 */
internal class BoundedIntentFilterEvidenceCollector(
    private val limits: InspectionLimits,
) {
    private val components = linkedMapOf<IntentFilterComponentKey, MutableComponentEvidence>()
    private val componentStack = ArrayDeque<MutableComponentEvidence>()
    private val filterStack = ArrayDeque<FilterFrame>()
    private var packageName = ""
    private var globallyTruncated = false
    private var retainedFilterCount = 0

    fun startElement(rawName: String?, attributes: List<RenderedManifestAttribute>) {
        when (rawName.normalizedElementName()) {
            "manifest" -> packageName = attributes.unqualifiedValue("package")?.boundedValue(limits.maxIntentFilterValueBytes)?.value.orEmpty()
            "activity", "activity-alias", "service", "receiver", "provider" -> startComponent(rawName, attributes)
            "intent-filter" -> startFilter()
            "action" -> currentFilter()?.addAction(attributes.androidValue("name"))
            "category" -> currentFilter()?.addCategory(attributes.androidValue("name"))
            "data" -> currentFilter()?.addData(attributes)
        }
    }

    fun endElement(rawName: String?) {
        when (rawName.normalizedElementName()) {
            "intent-filter" -> finishFilter()
            "activity", "activity-alias", "service", "receiver", "provider" -> finishComponent(rawName)
        }
    }

    /** The decoded XML writer stopped before the binary stream ended. */
    fun markManifestTruncated() {
        globallyTruncated = true
        componentStack.forEach { it.isTruncated = true }
        filterStack.forEach { frame -> frame.filter?.markManifestTruncated() }
    }

    fun finish(): IntentFilterEvidenceCollection {
        if (filterStack.isNotEmpty() || componentStack.isNotEmpty()) {
            markManifestTruncated()
        }
        return IntentFilterEvidenceCollection(
            components = components.mapValues { (_, component) ->
                ComponentIntentFilterEvidence(
                    filters = component.filters.toList(),
                    isTruncated = component.isTruncated,
                )
            },
            isTruncated = globallyTruncated,
        )
    }

    private fun startComponent(rawName: String?, attributes: List<RenderedManifestAttribute>) {
        val type = rawName.componentType() ?: return
        val rawClassName = attributes.androidValue("name") ?: return
        val className = normalizeComponentName(rawClassName.boundedValue(limits.maxIntentFilterValueBytes)?.value.orEmpty())
        if (className.isBlank()) return
        val key = IntentFilterComponentKey(type, className)
        val component = components.getOrPut(key) { MutableComponentEvidence(key) }
        componentStack.addLast(component)
    }

    private fun finishComponent(rawName: String?) {
        val expected = rawName.componentType() ?: return
        val component = componentStack.lastOrNull() ?: return
        if (component.key.type == expected) componentStack.removeLast()
    }

    private fun startFilter() {
        val component = componentStack.lastOrNull()
        if (component == null) {
            filterStack.addLast(FilterFrame(null, null))
            return
        }
        val filter = when {
            retainedFilterCount >= limits.maxManifestIntentFilters -> {
                globallyTruncated = true
                component.isTruncated = true
                null
            }
            component.filters.size >= limits.maxIntentFiltersPerComponent -> {
                component.isTruncated = true
                null
            }
            else -> MutableIntentFilter(limits)
        }
        if (filter != null) retainedFilterCount += 1
        filterStack.addLast(FilterFrame(component, filter))
    }

    private fun finishFilter() {
        val frame = filterStack.removeLastOrNull() ?: return
        val filter = frame.filter ?: return
        frame.component?.filters?.add(filter.toEvidence())
    }

    private fun currentFilter(): MutableIntentFilter? = filterStack.lastOrNull()?.filter

    private fun normalizeComponentName(value: String): String = when {
        value.isBlank() -> ""
        value.startsWith('.') && packageName.isNotBlank() -> packageName + value
        '.' !in value && packageName.isNotBlank() -> "$packageName.$value"
        else -> value
    }
}

private data class FilterFrame(
    val component: MutableComponentEvidence?,
    val filter: MutableIntentFilter?,
)

private class MutableComponentEvidence(
    val key: IntentFilterComponentKey,
    val filters: MutableList<IntentFilterEvidence> = mutableListOf(),
    var isTruncated: Boolean = false,
)

private class MutableIntentFilter(
    private val limits: InspectionLimits,
) {
    private val actions = linkedSetOf<String>()
    private val categories = linkedSetOf<String>()
    private val data = mutableListOf<IntentFilterDataEvidence>()
    var actionsTruncated = false
        private set
    var categoriesTruncated = false
        private set
    var dataTruncated = false
        private set
    var manifestTruncated = false
        private set

    fun markManifestTruncated() {
        manifestTruncated = true
    }

    fun addAction(rawValue: String?) {
        addUnique(actions, rawValue, limits.maxIntentFilterActionsPerFilter, { actionsTruncated = true }) { actionsTruncated = true }
    }

    fun addCategory(rawValue: String?) {
        addUnique(categories, rawValue, limits.maxIntentFilterCategoriesPerFilter, { categoriesTruncated = true }) { categoriesTruncated = true }
    }

    fun addData(attributes: List<RenderedManifestAttribute>) {
        if (data.size >= limits.maxIntentFilterDataPerFilter) {
            dataTruncated = true
            return
        }
        val evidence = MutableIntentFilterData(limits)
        evidence.scheme = evidence.setValue(attributes.androidValue("scheme"))
        evidence.host = evidence.setValue(attributes.androidValue("host"))
        evidence.port = evidence.setValue(attributes.androidValue("port"))
        evidence.mimeType = evidence.setValue(attributes.androidValue("mimeType"))
        evidence.addPath(IntentFilterPathKind.LITERAL, attributes.androidValue("path"))
        evidence.addPath(IntentFilterPathKind.PREFIX, attributes.androidValue("pathPrefix"))
        evidence.addPath(IntentFilterPathKind.PATTERN, attributes.androidValue("pathPattern"))
        evidence.addPath(IntentFilterPathKind.ADVANCED_PATTERN, attributes.androidValue("pathAdvancedPattern"))
        evidence.addPath(IntentFilterPathKind.SUFFIX, attributes.androidValue("pathSuffix"))
        if (evidence.hasEvidence()) {
            data += evidence.toEvidence()
        }
    }

    fun toEvidence(): IntentFilterEvidence = IntentFilterEvidence(
        actions = actions.toList(),
        categories = categories.toList(),
        data = data.toList(),
        actionsTruncated = actionsTruncated,
        categoriesTruncated = categoriesTruncated,
        dataTruncated = dataTruncated,
        manifestTruncated = manifestTruncated,
    )

    private fun addUnique(
        target: MutableSet<String>,
        rawValue: String?,
        maximum: Int,
        onLimit: () -> Unit,
        onValueTruncated: () -> Unit,
    ) {
        val bounded = rawValue.boundedValue(limits.maxIntentFilterValueBytes) ?: return
        if (bounded.wasTruncated) onValueTruncated()
        if (target.contains(bounded.value)) return
        if (target.size >= maximum) {
            onLimit()
            return
        }
        target += bounded.value
    }
}

private class MutableIntentFilterData(
    private val limits: InspectionLimits,
) {
    var scheme: String? = null
    var host: String? = null
    var port: String? = null
    var mimeType: String? = null
    private val paths = mutableListOf<IntentFilterPathEvidence>()
    private var pathsTruncated = false
    private var valuesTruncated = false

    fun setValue(rawValue: String?): String? {
        val bounded = rawValue.boundedValue(limits.maxIntentFilterValueBytes) ?: return null
        if (bounded.wasTruncated) valuesTruncated = true
        return bounded.value
    }

    fun addPath(kind: IntentFilterPathKind, rawValue: String?) {
        val bounded = rawValue.boundedValue(limits.maxIntentFilterValueBytes) ?: return
        if (bounded.wasTruncated) valuesTruncated = true
        if (paths.size >= limits.maxIntentFilterPathsPerData) {
            pathsTruncated = true
            return
        }
        paths += IntentFilterPathEvidence(kind, bounded.value)
    }

    fun hasEvidence(): Boolean = scheme != null || host != null || port != null || mimeType != null || paths.isNotEmpty()

    fun toEvidence(): IntentFilterDataEvidence = IntentFilterDataEvidence(
        scheme = scheme,
        host = host,
        port = port,
        paths = paths.toList(),
        mimeType = mimeType,
        pathsTruncated = pathsTruncated,
        valuesTruncated = valuesTruncated,
    )
}

private fun List<RenderedManifestAttribute>.androidValue(name: String): String? = firstOrNull {
    it.namespace == ANDROID_MANIFEST_NAMESPACE && it.name == name
}?.value

private fun List<RenderedManifestAttribute>.unqualifiedValue(name: String): String? = firstOrNull {
    it.namespace.isNullOrBlank() && it.name == name
}?.value

private fun String?.normalizedElementName(): String = this.orEmpty().substringAfterLast(':')

private fun String?.componentType(): ComponentType? = when (normalizedElementName()) {
    "activity", "activity-alias" -> ComponentType.ACTIVITY
    "service" -> ComponentType.SERVICE
    "receiver" -> ComponentType.RECEIVER
    "provider" -> ComponentType.PROVIDER
    else -> null
}

private data class BoundedIntentValue(
    val value: String,
    val wasTruncated: Boolean,
)

/** Stops as soon as the fixed UTF-8 budget is exhausted; hostile values are never retained whole. */
private fun String?.boundedValue(maximumBytes: Int = DEFAULT_INTENT_VALUE_BYTES): BoundedIntentValue? {
    val source = this ?: return null
    if (source.isEmpty()) return null
    val output = StringBuilder()
    var bytes = 0
    var index = 0
    var changed = false
    while (index < source.length) {
        val character = source[index]
        val unit = when {
            Character.isHighSurrogate(character) && index + 1 < source.length && Character.isLowSurrogate(source[index + 1]) -> {
                source.substring(index, index + 2).also { index += 2 }
            }
            Character.isHighSurrogate(character) || Character.isLowSurrogate(character) -> {
                index += 1
                changed = true
                "\uFFFD"
            }
            character.isISOControl() -> {
                index += 1
                changed = true
                "\uFFFD"
            }
            else -> character.toString().also { index += 1 }
        }
        val unitBytes = unit.toByteArray(Charsets.UTF_8).size
        if (bytes + unitBytes > maximumBytes) return BoundedIntentValue(output.toString(), wasTruncated = true)
        output.append(unit)
        bytes += unitBytes
    }
    return output.toString().takeIf { it.isNotEmpty() }?.let { BoundedIntentValue(it, changed) }
}

private const val ANDROID_MANIFEST_NAMESPACE = "http://schemas.android.com/apk/res/android"
private const val DEFAULT_INTENT_VALUE_BYTES = 512

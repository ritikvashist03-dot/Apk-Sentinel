package app.apksentinel.feature.apps

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import app.apksentinel.design.SentinelCard
import app.apksentinel.design.SentinelExpandableSection
import app.apksentinel.design.SentinelLoadingRow
import app.apksentinel.design.SentinelPagedList
import app.apksentinel.design.SentinelToggleRow
import app.apksentinel.design.SentinelStatusLabel
import app.apksentinel.design.SentinelStatusTone
import app.apksentinel.design.FullWidthOutlinedAction
import app.apksentinel.core.security.SafeDocumentWriter
import app.apksentinel.core.security.SafeTextNormalizer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

@Composable
fun InstalledAppsScreen(
    modifier: Modifier = Modifier,
    onAnalyzePackage: (String) -> Unit = {},
    /**
     * Reports the loaded inventory so the host can relate these packages to other
     * evidence. This module does not depend on core:model, so it hands the records out
     * rather than reaching for a repository it cannot see.
     */
    onInventoryLoaded: (List<InstalledAppRecord>) -> Unit = {},
) {
    val context = LocalContext.current
    val repository = remember(context) { InstalledAppRepository(context.applicationContext) }
    val scope = rememberCoroutineScope()
    var inventory by remember { mutableStateOf<InstalledAppInventory?>(null) }
    var loading by remember { mutableStateOf(true) }
    var loadError by remember { mutableStateOf(false) }
    var refreshKey by remember { mutableStateOf(0) }
    var query by rememberSaveable { mutableStateOf("") }
    var sideloadedOnly by rememberSaveable { mutableStateOf(false) }
    var updateAgeFilter by rememberSaveable { mutableStateOf(UpdateAgeFilter.ALL) }
    var selectedPackage by rememberSaveable { mutableStateOf<String?>(null) }
    var permissionEvidence by remember { mutableStateOf<List<PermissionEvidence>>(emptyList()) }
    var componentEvidence by remember { mutableStateOf<List<ComponentEvidence>>(emptyList()) }
    var providerPathEvidence by remember { mutableStateOf<List<ProviderPathPermissionEvidence>>(emptyList()) }
    var hardwareFeatureEvidence by remember { mutableStateOf(HardwareFeatureEvidenceResult(emptyList(), HardwareFeatureAvailability.UNKNOWN, false)) }
    var permissionAppEvidence by remember { mutableStateOf(PermissionAppEvidenceResult(emptyList(), false)) }
    var permissionExplorerQuery by rememberSaveable { mutableStateOf("") }
    var permissionGrantFilter by rememberSaveable { mutableStateOf(PermissionGrantFilter.REQUESTED) }
    var permissionProtectionFilter by rememberSaveable { mutableStateOf<PermissionProtection?>(null) }
    var launcherAction by remember { mutableStateOf<LauncherActionEvidence?>(null) }
    var sdkIndicatorEvidence by remember { mutableStateOf<List<SdkIndicatorEvidence>>(emptyList()) }
    var reviewSummary by remember { mutableStateOf<InstalledAppReviewSummary?>(null) }
    var launcherStatus by rememberSaveable { mutableStateOf<String?>(null) }
    var pendingExportPackage by rememberSaveable { mutableStateOf<String?>(null) }
    var exportStatus by rememberSaveable { mutableStateOf<String?>(null) }
    var exportInProgress by remember { mutableStateOf(false) }
    var advancedInsights by remember { mutableStateOf<AdvancedInsights?>(null) }
    var attributeQuery by rememberSaveable { mutableStateOf("") }
    var attributeFilter by rememberSaveable { mutableStateOf(InstalledAppAttribute.TARGET_SDK_BAND) }
    var lastUsedEvidence by remember { mutableStateOf(LastUsedEvidenceBuilder.unknown()) }
    var usageAccessStatus by rememberSaveable { mutableStateOf<String?>(null) }
    val apkSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { uri ->
        val packageName = pendingExportPackage
        if (uri != null && packageName != null) {
            scope.launch {
                exportInProgress = true
                exportStatus = context.getString(R.string.export_saving_base_apk)
                try {
                    val result = withContext(Dispatchers.IO) {
                        SafeDocumentWriter.useOutputStream(context, uri) { repository.exportBaseApk(packageName, it) }
                            ?: InstalledExportResult.DestinationUnavailable
                    }
                    exportStatus = when (result) {
                        is InstalledExportResult.Saved -> context.getString(R.string.export_base_success, result.value)
                        else -> context.getString(installedExportFailureString(result))
                    }
                } finally { exportInProgress = false }
            }
        } else exportStatus = context.getString(R.string.export_apk_cancelled)
    }
    val bundleSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
        val packageName = pendingExportPackage
        if (uri != null && packageName != null) {
            scope.launch {
                exportInProgress = true
                exportStatus = context.getString(R.string.export_saving_apk_set)
                try {
                    val result = withContext(Dispatchers.IO) {
                        SafeDocumentWriter.useOutputStream(context, uri) { repository.exportInstallBundle(packageName, it) }
                            ?: InstalledExportResult.DestinationUnavailable
                    }
                    exportStatus = when (result) {
                        is InstalledExportResult.Saved -> context.getString(R.string.export_apk_set_success, result.value.apkFileCount, result.value.bytesCopied)
                        else -> context.getString(installedExportFailureString(result))
                    }
                } finally { exportInProgress = false }
            }
        } else exportStatus = context.getString(R.string.export_apk_set_cancelled)
    }
    val iconSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("image/png")) { uri ->
        val packageName = pendingExportPackage
        if (uri != null && packageName != null) {
            scope.launch {
                exportInProgress = true
                exportStatus = context.getString(R.string.export_saving_icon)
                try {
                    val result = withContext(Dispatchers.IO) {
                        SafeDocumentWriter.useOutputStream(context, uri) { repository.exportIconPng(packageName, it) }
                            ?: InstalledExportResult.DestinationUnavailable
                    }
                    exportStatus = when (result) {
                        is InstalledExportResult.Saved -> context.getString(R.string.export_icon_success, result.value.width, result.value.height)
                        else -> context.getString(installedExportFailureString(result))
                    }
                } finally { exportInProgress = false }
            }
        } else exportStatus = context.getString(R.string.export_icon_cancelled)
    }

    LaunchedEffect(refreshKey) {
        loading = true
        loadError = false
        runCatching { withContext(Dispatchers.IO) { repository.load() } }
            .onSuccess { freshInventory ->
                inventory = freshInventory
                onInventoryLoaded(freshInventory.apps)
            }
            .onFailure { loadError = true }
        loading = false
    }
    val shown = remember(inventory, query, sideloadedOnly, updateAgeFilter) {
        InstalledAppFilters.apply(inventory?.apps.orEmpty(), query, sideloadedOnly, updateAgeFilter.months, System.currentTimeMillis())
    }
    val selected = inventory?.apps?.firstOrNull { it.packageName == selectedPackage }
    LaunchedEffect(selectedPackage, inventory) {
        val evidence = selected?.let { record ->
            withContext(Dispatchers.IO) {
                repository.permissionEvidence(record) to repository.componentEvidence(record)
            }
        }
        permissionEvidence = evidence?.first.orEmpty()
        componentEvidence = evidence?.second.orEmpty()
        providerPathEvidence = selected?.let { withContext(Dispatchers.IO) { repository.providerPathPermissionEvidence(it) } }.orEmpty()
        hardwareFeatureEvidence = selected?.let { withContext(Dispatchers.IO) { repository.hardwareFeatureEvidence(it) } }
            ?: HardwareFeatureEvidenceResult(emptyList(), HardwareFeatureAvailability.UNKNOWN, false)
        launcherAction = selected?.let { withContext(Dispatchers.IO) { repository.launcherActionEvidence(it) } }
        sdkIndicatorEvidence = selected?.let { withContext(Dispatchers.IO) { repository.sdkIndicatorEvidence(it) } }.orEmpty()
        lastUsedEvidence = selected?.let { withContext(Dispatchers.IO) { repository.lastUsedEvidence(it) } } ?: LastUsedEvidenceBuilder.unknown()
        launcherStatus = null
        usageAccessStatus = null
        reviewSummary = null
    }
    LaunchedEffect(selectedPackage, permissionEvidence, componentEvidence, hardwareFeatureEvidence, sdkIndicatorEvidence) {
        reviewSummary = selected?.let { app ->
            InstalledAppReviewSynthesizer.summarize(
                app = app,
                permissionEvidence = permissionEvidence,
                components = componentEvidence,
                sdkIndicators = sdkIndicatorEvidence,
                hardware = hardwareFeatureEvidence,
            )
        }
    }
    LaunchedEffect(inventory) {
        permissionAppEvidence = inventory?.apps?.let { apps ->
            withContext(Dispatchers.IO) { repository.permissionAppEvidence(apps) }
        } ?: PermissionAppEvidenceResult(emptyList(), false)
    }
    // Previously gated on a master toggle that no longer exists. Each section now discloses
    // itself, so this follows the inventory instead - otherwise advancedInsights stayed null
    // and the advanced section silently never rendered.
    LaunchedEffect(inventory) {
        advancedInsights = inventory?.apps?.let { withContext(Dispatchers.IO) { repository.advancedInsights(it) } }
    }
    LazyColumn(modifier.fillMaxSize().padding(horizontal = 18.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        // Keep the controls and the selected evidence in the same scroll container
        // as the inventory. At 2x font scale this prevents the detail actions from
        // being placed below an unscrollable parent column.
        item {
            Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        inventory?.let { current ->
            Text(
                pluralStringResource(
                    R.plurals.installed_apps_overview_count,
                    current.apps.size,
                    current.apps.size,
                ),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
            SentinelExpandableSection(
                title = stringResource(R.string.installed_apps_overview_title),
                summary = stringResource(R.string.installed_apps_scope_summary),
                flat = true,
            ) {
                Text(
                    stringResource(R.string.installed_apps_overview_detail),
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    current.visibilityNotice,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Button(
            onClick = { refreshKey++ },
            enabled = !loading,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(if (inventory == null) R.string.installed_apps_primary_scan else R.string.installed_apps_primary_refresh)) }
        inventory?.snapshot?.let { snapshot ->
            SentinelCard { Text(snapshotStateText(snapshot), style = MaterialTheme.typography.bodySmall) }
        }
        if (loadError) {
            SentinelCard {
                Text(stringResource(R.string.inventory_error), color = MaterialTheme.colorScheme.error, fontWeight = FontWeight.SemiBold)
                Text(stringResource(if (inventory == null) R.string.inventory_error_detail else R.string.inventory_refresh_error_detail), style = MaterialTheme.typography.bodySmall)
                FullWidthOutlinedAction(label = stringResource(R.string.inventory_retry), onClick = { refreshKey++ }, enabled = !loading)
            }
        }
        if (inventory != null) {
            val visibleApps = inventory?.apps.orEmpty()
            val commonPermissions = remember(visibleApps) {
                visibleApps.flatMap { it.requestedPermissions }.groupingBy { it }.eachCount().entries.sortedByDescending { it.value }.take(20)
            }
            SentinelExpandableSection(
                title = stringResource(R.string.collection_insights_title),
                summary = stringResource(R.string.apps_insight_collection_summary),
                flat = true,
            ) {
                Text(stringResource(R.string.collection_summary, visibleApps.count { it.isSystemApp }, visibleApps.count { !it.isSystemApp }, visibleApps.count { it.installSourceKind == InstallSourceKind.SIDELOADED_OR_ADB }))
                Text(stringResource(R.string.common_requested_permissions), fontWeight = FontWeight.Medium)
                commonPermissions.forEach { (permission, count) -> Text(stringResource(R.string.permission_app_count, count, permission), style = MaterialTheme.typography.bodySmall) }
                Text(stringResource(R.string.collection_visibility_note), style = MaterialTheme.typography.bodySmall)
            }
            advancedInsights?.let { insight ->
                SentinelExpandableSection(
                    title = stringResource(R.string.advanced_insights_title),
                    summary = stringResource(R.string.apps_insight_advanced_summary),
                    flat = true,
                ) {
                    Text(stringResource(R.string.advanced_insights_notice), style = MaterialTheme.typography.bodySmall)
                    Text(stringResource(R.string.advanced_sdk_levels, insight.targetSdkBelow26, insight.targetSdk26To32, insight.targetSdk33Plus, insight.targetSdkUnknown), style = MaterialTheme.typography.bodySmall)
                    Text(stringResource(R.string.advanced_signer_evidence, insight.signerAvailable, insight.signerUnavailable), style = MaterialTheme.typography.bodySmall)
                    Text(snapshotStateText(inventory?.snapshot ?: InventorySnapshotResult(InventorySnapshotState.COVERAGE_UNKNOWN)), style = MaterialTheme.typography.bodySmall)
                    Text(stringResource(R.string.advanced_components, insight.components, insight.exportedComponents), style = MaterialTheme.typography.bodySmall)
                    Text(stringResource(R.string.advanced_install_visibility, insight.visibleApps, insight.systemApps, insight.sideloadedEvidenceApps), style = MaterialTheme.typography.bodySmall)
                    Text(stringResource(R.string.advanced_sdk_indicators, insight.sdkIndicatorApps, insight.sdkEvidenceUnknownApps), style = MaterialTheme.typography.bodySmall)
                    if (insight.truncated) Text(stringResource(R.string.advanced_insights_cap), style = MaterialTheme.typography.bodySmall)
                }
            }
            val permissionRows = remember(permissionAppEvidence, permissionExplorerQuery, permissionGrantFilter, permissionProtectionFilter) {
                PermissionExplorerFilters.apply(permissionAppEvidence.rows, permissionExplorerQuery, permissionGrantFilter, permissionProtectionFilter)
            }
            val attributeRows = remember(visibleApps, attributeFilter, attributeQuery) {
                InstalledAppAttributeFilters.apply(visibleApps, attributeFilter, attributeQuery)
            }
            SentinelExpandableSection(
                title = stringResource(R.string.permission_explorer_title),
                summary = stringResource(R.string.apps_insight_permission_summary),
                flat = true,
            ) {
                Text(stringResource(R.string.permission_explorer_notice), style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(
                    value = permissionExplorerQuery,
                    onValueChange = { permissionExplorerQuery = it.take(120) },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.search_permission_app_or_package)) },
                    singleLine = true,
                )
                androidx.compose.foundation.layout.Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    PermissionGrantFilter.entries.forEach { filter ->
                        FilterChip(selected = permissionGrantFilter == filter, onClick = { permissionGrantFilter = filter }, label = { Text(stringResource(permissionGrantFilterLabel(filter))) })
                    }
                    FilterChip(selected = permissionProtectionFilter == null, onClick = { permissionProtectionFilter = null }, label = { Text(stringResource(R.string.protection_all)) })
                    PermissionProtection.entries.forEach { protection ->
                        FilterChip(selected = permissionProtectionFilter == protection, onClick = { permissionProtectionFilter = protection }, label = { Text(permissionProtectionLabel(protection)) })
                    }
                }
                Text(stringResource(R.string.permission_explorer_shown, permissionRows.size, permissionAppEvidence.rows.size), style = MaterialTheme.typography.bodySmall)
                if (permissionAppEvidence.truncated) Text(stringResource(R.string.permission_explorer_cap), style = MaterialTheme.typography.bodySmall)
                SentinelPagedList(items = permissionRows, initialVisibleCount = 8) { row ->
                    Text(stringResource(R.string.permission_explorer_row, stringResource(if (row.granted) R.string.granted else R.string.not_granted), permissionProtectionLabel(row.protection), row.permission, row.appLabel), style = MaterialTheme.typography.bodySmall)
                    SelectableTechnicalText(row.packageName, modifier = Modifier.fillMaxWidth())
                }
            }
            SentinelExpandableSection(
                title = stringResource(R.string.attribute_explorer_title),
                summary = stringResource(R.string.apps_insight_attribute_summary),
                flat = true,
            ) {
                Text(stringResource(R.string.attribute_explorer_notice), style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(
                    value = attributeQuery,
                    onValueChange = { attributeQuery = it.take(120) },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.search_attribute_app_or_package)) },
                    singleLine = true,
                )
                androidx.compose.foundation.layout.Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    InstalledAppAttribute.entries.forEach { attribute ->
                        FilterChip(selected = attributeFilter == attribute, onClick = { attributeFilter = attribute }, label = { Text(attributeLabel(attribute)) })
                    }
                }
                Text(stringResource(R.string.attribute_explorer_shown, attributeRows.size, visibleApps.size), style = MaterialTheme.typography.bodySmall)
                SentinelPagedList(items = attributeRows, initialVisibleCount = 8) { app ->
                    SelectableTechnicalText(stringResource(R.string.attribute_explorer_row, app.label, app.packageName, attributeValueLabel(app, attributeFilter)), modifier = Modifier.fillMaxWidth())
                }
            }
        }
        OutlinedTextField(value = query, onValueChange = { query = it.take(120) }, modifier = Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.search_app_or_package)) }, singleLine = true)
        SentinelToggleRow(
            title = stringResource(R.string.sideloaded_only),
            description = stringResource(R.string.sideloaded_description),
            checked = sideloadedOnly,
            onCheckedChange = { sideloadedOnly = it },
        )
        Text(stringResource(R.string.update_age_filter), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Medium)
        Text(stringResource(R.string.update_age_filter_description), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        androidx.compose.foundation.layout.Row(
            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            UpdateAgeFilter.entries.forEach { filter ->
                FilterChip(
                    selected = updateAgeFilter == filter,
                    onClick = { updateAgeFilter = filter },
                    label = { Text(stringResource(updateAgeFilterLabel(filter))) },
                )
            }
        }
        selected?.let { app ->
            SentinelCard {
                Text(stringResource(R.string.app_details, app.label), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.version_sdk_evidence, app.versionName ?: app.versionCode, app.minSdk, app.targetSdk))
                Text(stringResource(R.string.first_install_date, localizedDate(app.firstInstallMillis) ?: stringResource(R.string.lifecycle_date_unknown)))
                Text(stringResource(R.string.last_update_date, localizedDate(app.lastUpdateMillis) ?: stringResource(R.string.lifecycle_date_unknown)))
                Text(stringResource(R.string.component_counts, app.activityCount, app.serviceCount, app.receiverCount, app.providerCount))
                Text(stringResource(R.string.exported_component_notice, app.exportedComponentCount))
                SelectableTechnicalText(stringResource(R.string.install_source_chain, app.installSourceChain.installingPackageName ?: stringResource(R.string.technical_value_not_reported), app.installSourceChain.initiatingPackageName ?: stringResource(R.string.technical_value_not_reported), app.installSourceChain.originatingPackageName ?: stringResource(R.string.technical_value_not_reported), packageSourceLabel(app.installSourceChain.packageSource)), modifier = Modifier.fillMaxWidth())
                Text(stringResource(R.string.app_category, categoryLabel(app.category)), style = MaterialTheme.typography.bodySmall)
                // Official-link handoff for the authentic-app verifier outcome. It opens the
                // listing and asserts nothing about whether this install matches it.
                if (OfficialListingHandoff.isHandoffEligible(app.packageName)) {
                    Text(stringResource(R.string.official_listing_title), fontWeight = FontWeight.Medium)
                    Text(stringResource(R.string.official_listing_body), style = MaterialTheme.typography.bodySmall)
                    FullWidthOutlinedAction(
                        label = stringResource(R.string.official_listing_open),
                        onClick = {
                            val opened = OfficialListingHandoff.candidateIntents(app.packageName).any { intent ->
                                runCatching {
                                    context.startActivity(intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
                                }.isSuccess
                            }
                            if (!opened) exportStatus = context.getString(R.string.official_listing_unavailable)
                        },
                    )
                }
                Text(stringResource(R.string.shared_uid_evidence, app.sharedUid.uid?.toString() ?: stringResource(R.string.technical_value_not_reported), app.sharedUid.visiblePackages.size), style = MaterialTheme.typography.bodySmall)
                app.sharedUid.visiblePackages.take(64).forEach { packageName -> SelectableTechnicalText(packageName, modifier = Modifier.fillMaxWidth()) }
                Text(stringResource(R.string.artifact_sizes_title), fontWeight = FontWeight.Medium)
                if (app.artifactSizesAvailability == EvidenceAvailability.UNKNOWN) Text(stringResource(R.string.artifact_sizes_unknown), style = MaterialTheme.typography.bodySmall)
                app.artifactSizes.forEach { artifact -> SelectableTechnicalText(stringResource(R.string.artifact_size_row, artifact.name, artifact.sizeBytes?.toString() ?: stringResource(R.string.technical_value_not_reported)), modifier = Modifier.fillMaxWidth()) }
                if (app.artifactSizesTruncated) Text(stringResource(R.string.artifact_sizes_cap), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.artifact_sizes_scope), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(stringResource(R.string.native_libraries_title), fontWeight = FontWeight.Medium)
                if (app.nativeLibrariesAvailability == EvidenceAvailability.UNKNOWN) Text(stringResource(R.string.native_libraries_unknown), style = MaterialTheme.typography.bodySmall)
                app.nativeLibraries.forEach { library -> SelectableTechnicalText(stringResource(R.string.native_library_row, library.name, library.abi ?: stringResource(R.string.technical_value_not_reported)), modifier = Modifier.fillMaxWidth()) }
                if (app.nativeLibrariesTruncated) Text(stringResource(R.string.native_libraries_cap), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.native_libraries_scope), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(stringResource(R.string.security_flags_title), fontWeight = FontWeight.Medium)
                app.securityFlags.filter { it.enabled }.take(32).forEach { flag -> Text(stringResource(R.string.security_flag_row, flag.name), style = MaterialTheme.typography.bodySmall) }
                if (app.securityFlags.none { it.enabled }) Text(stringResource(R.string.security_flags_none), style = MaterialTheme.typography.bodySmall)
                reviewSummary?.let { summary ->
                    Text(stringResource(R.string.installed_review_title), fontWeight = FontWeight.Medium)
                    Text(stringResource(R.string.installed_review_notice), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(stringResource(R.string.installed_review_local_summary, summary.localFactualSummary), style = MaterialTheme.typography.bodySmall)
                    Text(
                        stringResource(
                            R.string.installed_review_authenticity,
                            localContextStatusLabel(summary.authenticityContext.status),
                            localEvidenceConfidenceLabel(summary.authenticityContext.confidence),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    summary.authenticityContext.evidence.forEach { evidence ->
                        Text(stringResource(R.string.installed_review_evidence, evidence), style = MaterialTheme.typography.bodySmall)
                    }
                    Text(
                        stringResource(
                            R.string.installed_review_adware,
                            localContextStatusLabel(summary.adwareContext.status),
                            localEvidenceConfidenceLabel(summary.adwareContext.confidence),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    summary.adwareContext.evidence.forEach { evidence ->
                        Text(stringResource(R.string.installed_review_evidence, evidence), style = MaterialTheme.typography.bodySmall)
                    }
                    Text(stringResource(R.string.installed_review_limitations), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (componentEvidence.isNotEmpty()) {
                    Text(stringResource(R.string.manifest_components), fontWeight = FontWeight.Medium)
                    SentinelPagedList(items = componentEvidence, initialVisibleCount = 8) { component ->
                        Text(
                            stringResource(
                                R.string.component_evidence,
                                componentKindLabel(component.kind),
                                stringResource(if (component.exported) R.string.component_exported else R.string.component_not_exported),
                                component.name,
                            ),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        component.requiredPermission?.let { permission ->
                            Text(stringResource(R.string.component_required_permission, permission), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    val remainingComponents = app.activityCount + app.serviceCount + app.receiverCount + app.providerCount - componentEvidence.size
                    if (componentEvidence.size > 50) Text(stringResource(R.string.more_components, componentEvidence.size - 50), style = MaterialTheme.typography.bodySmall)
                    if (remainingComponents > 0) Text(stringResource(R.string.components_not_shown, remainingComponents), style = MaterialTheme.typography.bodySmall)
                }
                if (permissionEvidence.isNotEmpty()) {
                Text(stringResource(R.string.requested_and_granted_permissions), fontWeight = FontWeight.Medium)
                    SentinelPagedList(items = permissionEvidence, initialVisibleCount = 6) { permission ->
                        Text(stringResource(R.string.permission_evidence, stringResource(if (permission.granted) R.string.granted else R.string.not_granted), permissionProtectionLabel(permission.protection), permission.name), style = MaterialTheme.typography.bodySmall)
                        Text(permissionProtectionExplanation(permission.protection), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if (permissionEvidence.size > 30) Text(stringResource(R.string.more_permissions, permissionEvidence.size - 30), style = MaterialTheme.typography.bodySmall)
                }
                Text(stringResource(R.string.hardware_features_title), fontWeight = FontWeight.Medium)
                when (hardwareFeatureEvidence.availability) {
                    HardwareFeatureAvailability.UNKNOWN -> Text(stringResource(R.string.hardware_features_unknown), style = MaterialTheme.typography.bodySmall)
                    HardwareFeatureAvailability.AVAILABLE -> {
                        if (hardwareFeatureEvidence.features.isEmpty()) Text(stringResource(R.string.hardware_features_none), style = MaterialTheme.typography.bodySmall)
                        hardwareFeatureEvidence.features.forEach { feature ->
                            Text(stringResource(R.string.hardware_feature_row, stringResource(if (feature.required) R.string.hardware_feature_required else R.string.hardware_feature_optional), feature.name), style = MaterialTheme.typography.bodySmall)
                        }
                        if (hardwareFeatureEvidence.truncated) Text(stringResource(R.string.hardware_features_cap), style = MaterialTheme.typography.bodySmall)
                    }
                }
                Text(stringResource(R.string.hardware_features_notice), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                app.signerSha256.forEach { hash ->
                    SelectableTechnicalText(stringResource(R.string.signer_sha256, hash), modifier = Modifier.fillMaxWidth())
                }
                app.signerSha1.forEach { hash ->
                    SelectableTechnicalText(stringResource(R.string.signer_sha1, hash), modifier = Modifier.fillMaxWidth())
                }
                Text(stringResource(R.string.sdk_indicator_title), fontWeight = FontWeight.Medium)
                if (sdkIndicatorEvidence.isEmpty()) Text(stringResource(R.string.sdk_indicator_none), style = MaterialTheme.typography.bodySmall)
                sdkIndicatorEvidence.forEach { indicator ->
                    SelectableTechnicalText(stringResource(R.string.sdk_indicator_row, indicator.name, indicator.manifestKey), modifier = Modifier.fillMaxWidth())
                }
                Text(stringResource(R.string.sdk_indicator_notice), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(stringResource(R.string.last_used_title), fontWeight = FontWeight.Medium)
                if (lastUsedEvidence.availability == EvidenceAvailability.AVAILABLE) {
                    val lastUsedDate = lastUsedEvidence.lastUsedMillis?.let(::localizedDate)
                        ?: stringResource(R.string.lifecycle_date_unknown)
                    Text(stringResource(R.string.last_used_value, lastUsedDate), style = MaterialTheme.typography.bodySmall)
                } else {
                    Text(stringResource(R.string.last_used_unknown), style = MaterialTheme.typography.bodySmall)
                    Button(onClick = {
                        runCatching { context.startActivity(repository.usageAccessSettingsIntent().addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)) }
                            .onSuccess { usageAccessStatus = context.getString(R.string.usage_access_settings_opened) }
                            .onFailure { usageAccessStatus = context.getString(R.string.usage_access_settings_failed) }
                    }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.open_usage_access_settings)) }
                }
                usageAccessStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                if (providerPathEvidence.isNotEmpty()) {
                    Text(stringResource(R.string.provider_path_permissions_title), fontWeight = FontWeight.Medium)
                    providerPathEvidence.take(ProviderPathPermissionEvidenceExtractor.MAX_ROWS).forEach { path ->
                        SelectableTechnicalText(stringResource(R.string.provider_path_permission_row, path.provider, path.path ?: path.pathPattern ?: path.pathPrefix ?: stringResource(R.string.technical_value_not_reported), path.readPermission ?: stringResource(R.string.technical_value_not_reported), path.writePermission ?: stringResource(R.string.technical_value_not_reported)), modifier = Modifier.fillMaxWidth())
                    }
                }
                Text(stringResource(if (app.splitApkCount > 0) R.string.split_apk_notice else R.string.no_split_apk_notice, app.splitApkCount), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.export_destination_notice), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Button(
                    onClick = {
                        pendingExportPackage = app.packageName
                        val name = SafeTextNormalizer.normalizeFileName("${app.packageName}-${app.versionName ?: app.versionCode}.apk", "installed-base.apk")
                        apkSaver.launch(name)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !exportInProgress,
                ) { Text(stringResource(R.string.save_base_apk)) }
                Button(
                    onClick = {
                        pendingExportPackage = app.packageName
                        val name = SafeTextNormalizer.normalizeFileName("${app.packageName}-${app.versionName ?: app.versionCode}.apks.zip", "installed-package.apks.zip")
                        bundleSaver.launch(name)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !exportInProgress,
                ) { Text(stringResource(if (app.splitApkCount > 0) R.string.save_base_and_splits else R.string.save_install_bundle)) }
                Button(
                    onClick = {
                        pendingExportPackage = app.packageName
                        val name = SafeTextNormalizer.normalizeFileName("${app.packageName}-icon.png", "installed-app-icon.png")
                        iconSaver.launch(name)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !exportInProgress,
                ) { Text(stringResource(R.string.save_app_icon)) }
                Button(onClick = { onAnalyzePackage(app.packageName) }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.run_full_analysis))
                }
                exportStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                launcherAction?.let { action ->
                    val launcherStarted = stringResource(R.string.launcher_action_started)
                    val launcherFailed = stringResource(R.string.launcher_action_failed)
                    Text(stringResource(R.string.launcher_action_evidence, action.component.flattenToShortString()), style = MaterialTheme.typography.bodySmall)
                    Button(onClick = { scope.launch { launcherStatus = if (repository.launchResolvedLauncher(action)) launcherStarted else launcherFailed } }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.open_through_android)) }
                } ?: Text(stringResource(R.string.launcher_action_unknown), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                launcherStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                Button(onClick = { selectedPackage = null }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.close_details)) }
            }
            }
        }
        }
        when {
            loading && inventory == null -> item { SentinelCard { SentinelLoadingRow(stringResource(R.string.indexing_visible_apps)) } }
            loadError && inventory == null -> item { SentinelCard { Text(stringResource(R.string.inventory_error_detail), style = MaterialTheme.typography.bodySmall) } }
            shown.isEmpty() -> item { SentinelCard { Text(stringResource(R.string.no_apps_match)) } }
            else -> {
                item {
                    Text(stringResource(R.string.shown_visible_total, shown.size, inventory?.apps?.size ?: 0), style = MaterialTheme.typography.labelLarge)
                    Text(inventory?.visibilityNotice.orEmpty(), style = MaterialTheme.typography.bodySmall)
                }
                items(shown, key = { it.packageName }) { app ->
                    SentinelCard {
                        Text(app.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        val staleMonths = app.monthsSinceUpdate(System.currentTimeMillis())?.takeIf { it >= 6 }
                        androidx.compose.foundation.layout.Row(
                            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            val (originTone, originLabel) = when {
                                app.installSourceKind == InstallSourceKind.SIDELOADED_OR_ADB ->
                                    SentinelStatusTone.REVIEW to stringResource(R.string.app_status_chip_sideloaded)
                                app.isSystemApp ->
                                    SentinelStatusTone.INFORMATION to stringResource(R.string.app_status_chip_system)
                                else ->
                                    SentinelStatusTone.NEUTRAL to stringResource(R.string.app_status_chip_user_installed)
                            }
                            SentinelStatusLabel(label = originLabel, tone = originTone)
                            staleMonths?.let { months ->
                                SentinelStatusLabel(
                                    label = stringResource(R.string.app_status_chip_update_stale, months),
                                    tone = SentinelStatusTone.REVIEW,
                                )
                            }
                        }
                        SelectableTechnicalText(app.packageName, modifier = Modifier.fillMaxWidth())
                        Text(
                            stringResource(R.string.version_sdk_evidence, app.versionName ?: app.versionCode, app.minSdk, app.targetSdk),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Text(
                            stringResource(R.string.requested_granted_counts, app.requestedPermissionCount, app.grantedPermissionCount),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Text(
                            stringResource(R.string.install_source, installSourceLabel(app.installSourceKind)),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        app.signerSha256.firstOrNull()?.let { SelectableTechnicalText(stringResource(R.string.signer_sha256_short, it.take(24)), modifier = Modifier.fillMaxWidth()) }
                        Button(onClick = { selectedPackage = app.packageName }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.view_evidence)) }
                    }
                }
            }
        }
    }
}

@Composable
private fun updateAgeFilterLabel(filter: UpdateAgeFilter): Int = when (filter) {
    UpdateAgeFilter.ALL -> R.string.update_age_all
    UpdateAgeFilter.SIX_MONTHS -> R.string.update_age_six_months
    UpdateAgeFilter.TWELVE_MONTHS -> R.string.update_age_twelve_months
    UpdateAgeFilter.TWENTY_FOUR_MONTHS -> R.string.update_age_twenty_four_months
}

private fun localizedDate(millis: Long): String? =
    millis.takeIf { it > 0L }?.let { DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(it)) }

/** Technical identifiers remain easy to copy without allowing hidden bidi controls to mislead. */
@Composable
private fun SelectableTechnicalText(
    value: String,
    modifier: Modifier = Modifier,
) {
    val safeValue = SafeTextNormalizer.normalizeDisplayText(
        input = value,
        fallback = stringResource(R.string.technical_value_not_reported),
        maxCodePoints = 512,
    )
    SelectionContainer(modifier = modifier) {
        Text(
            text = safeValue,
            style = MaterialTheme.typography.bodySmall.copy(textDirection = TextDirection.Ltr),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private fun installedExportFailureString(result: InstalledExportResult<*>): Int = when (result) {
    is InstalledExportResult.Saved -> R.string.export_generic_failure
    InstalledExportResult.PackageUnavailable -> R.string.export_package_unavailable
    InstalledExportResult.DestinationUnavailable -> R.string.export_destination_unavailable
    InstalledExportResult.LimitReached -> R.string.export_limit_reached
    InstalledExportResult.Failed -> R.string.export_generic_failure
}

@Composable
private fun snapshotStateText(snapshot: InventorySnapshotResult): String = when (snapshot.state) {
    InventorySnapshotState.FIRST_SCAN -> stringResource(R.string.snapshot_first_scan)
    InventorySnapshotState.UNCHANGED -> stringResource(R.string.snapshot_unchanged)
    InventorySnapshotState.CHANGED -> stringResource(R.string.snapshot_changed, snapshot.addedCount, snapshot.removedCount, snapshot.changedCount)
    InventorySnapshotState.COVERAGE_UNKNOWN -> stringResource(R.string.snapshot_coverage_unknown)
}

@Composable
private fun installSourceLabel(source: InstallSourceKind): String = stringResource(
    when (source) {
        InstallSourceKind.PLAY_STORE -> R.string.install_source_play_store
        InstallSourceKind.SYSTEM_IMAGE -> R.string.install_source_system_image
        InstallSourceKind.OTHER_STORE -> R.string.install_source_other_store
        InstallSourceKind.SIDELOADED_OR_ADB -> R.string.install_source_sideloaded_adb
        InstallSourceKind.UNKNOWN -> R.string.install_source_unknown
    },
)

@Composable
private fun packageSourceLabel(source: InstallSourcePackageSource): String = stringResource(when (source) {
    InstallSourcePackageSource.STORE -> R.string.package_source_store
    InstallSourcePackageSource.LOCAL_FILE -> R.string.package_source_local_file
    InstallSourcePackageSource.DOWNLOADED_FILE -> R.string.package_source_downloaded_file
    InstallSourcePackageSource.OTHER -> R.string.package_source_other
    InstallSourcePackageSource.UNKNOWN -> R.string.package_source_unknown
})

@Composable
private fun categoryLabel(category: AppCategoryKind): String = stringResource(when (category) {
    AppCategoryKind.GAME -> R.string.category_game
    AppCategoryKind.AUDIO -> R.string.category_audio
    AppCategoryKind.VIDEO -> R.string.category_video
    AppCategoryKind.IMAGE -> R.string.category_image
    AppCategoryKind.UNKNOWN -> R.string.category_unknown
})

@Composable
private fun attributeLabel(attribute: InstalledAppAttribute): String = stringResource(when (attribute) {
    InstalledAppAttribute.TARGET_SDK_BAND -> R.string.attribute_target_sdk_band
    InstalledAppAttribute.SIGNER_FINGERPRINT -> R.string.attribute_signer
    InstalledAppAttribute.ORIGIN -> R.string.attribute_origin
    InstalledAppAttribute.CATEGORY -> R.string.attribute_category
    InstalledAppAttribute.SHARED_UID -> R.string.attribute_shared_uid
})

@Composable
private fun attributeValueLabel(app: InstalledAppRecord, attribute: InstalledAppAttribute): String = when (attribute) {
    InstalledAppAttribute.TARGET_SDK_BAND -> InstalledAppAttributeFilters.targetSdkBand(app.targetSdk)
    InstalledAppAttribute.SIGNER_FINGERPRINT -> app.signerSha256.firstOrNull() ?: stringResource(R.string.technical_value_not_reported)
    InstalledAppAttribute.ORIGIN -> packageSourceLabel(app.installSourceChain.packageSource)
    InstalledAppAttribute.CATEGORY -> categoryLabel(app.category)
    InstalledAppAttribute.SHARED_UID -> app.sharedUid.uid?.toString() ?: stringResource(R.string.technical_value_not_reported)
}

@Composable
private fun permissionGrantFilterLabel(filter: PermissionGrantFilter): Int = when (filter) {
    PermissionGrantFilter.REQUESTED -> R.string.permission_filter_requested
    PermissionGrantFilter.GRANTED -> R.string.permission_filter_granted
}

@Composable
private fun localContextStatusLabel(status: LocalContextStatus): String = stringResource(when (status) {
    LocalContextStatus.SUPPORTING_EVIDENCE -> R.string.installed_review_status_supporting
    LocalContextStatus.LOCAL_SIGNALS_ONLY -> R.string.installed_review_status_local_signals
    LocalContextStatus.UNKNOWN -> R.string.installed_review_status_unknown
})

@Composable
private fun localEvidenceConfidenceLabel(confidence: LocalEvidenceConfidence): String = stringResource(when (confidence) {
    LocalEvidenceConfidence.HIGH -> R.string.installed_review_confidence_high
    LocalEvidenceConfidence.MEDIUM -> R.string.installed_review_confidence_medium
    LocalEvidenceConfidence.LOW -> R.string.installed_review_confidence_low
    LocalEvidenceConfidence.UNKNOWN -> R.string.installed_review_confidence_unknown
})

@Composable
private fun permissionProtectionLabel(protection: PermissionProtection): String = stringResource(
    when (protection) {
        PermissionProtection.DANGEROUS -> R.string.protection_dangerous_runtime
        PermissionProtection.SIGNATURE -> R.string.protection_signature
        PermissionProtection.NORMAL -> R.string.protection_normal
        PermissionProtection.UNKNOWN -> R.string.protection_unknown
    },
)

@Composable
private fun permissionProtectionExplanation(protection: PermissionProtection): String = stringResource(
    when (protection) {
        PermissionProtection.DANGEROUS -> R.string.permission_dangerous_explanation
        PermissionProtection.SIGNATURE -> R.string.permission_signature_explanation
        PermissionProtection.NORMAL -> R.string.permission_normal_explanation
        PermissionProtection.UNKNOWN -> R.string.permission_unknown_explanation
    },
)

@Composable
private fun componentKindLabel(kind: ComponentKind): String = stringResource(
    when (kind) {
        ComponentKind.ACTIVITY -> R.string.component_activity
        ComponentKind.SERVICE -> R.string.component_service
        ComponentKind.RECEIVER -> R.string.component_receiver
        ComponentKind.PROVIDER -> R.string.component_provider
    },
)

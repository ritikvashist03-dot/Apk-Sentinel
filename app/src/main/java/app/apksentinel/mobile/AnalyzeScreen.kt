package app.apksentinel.mobile

import android.content.ClipData
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.text.format.Formatter
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.core.content.FileProvider
import app.apksentinel.core.reporting.LocalReportRenderer
import app.apksentinel.core.reporting.ReportExportPolicy
import app.apksentinel.core.security.SafeTextNormalizer
import app.apksentinel.core.security.SafeDocumentWriter
import app.apksentinel.design.FullWidthOutlinedAction
import app.apksentinel.design.KeyValueRow
import app.apksentinel.design.SentinelCard
import app.apksentinel.design.SentinelExpandableSection
import app.apksentinel.design.SentinelLoadingRow
import app.apksentinel.design.SentinelPagedList
import app.apksentinel.design.SentinelStatusLabel
import app.apksentinel.design.SentinelStatusTone
import app.apksentinel.design.SentinelToggleRow
import app.apksentinel.engine.threatintel.IndicatorType
import app.apksentinel.engine.threatintel.ThreatIndicator
import app.apksentinel.engine.threatintel.ThreatConfidence
import app.apksentinel.engine.url.RedirectResolution
import app.apksentinel.engine.url.RedirectResolutionReason
import app.apksentinel.engine.url.SafeRedirectResolver
import app.apksentinel.engine.url.UrlFindingMessage
import app.apksentinel.engine.url.UrlInspection
import app.apksentinel.engine.url.UrlInspectionLimitation
import app.apksentinel.engine.url.UrlSafetyAnalyzer
import app.apksentinel.engine.url.UrlVerdict
import app.apksentinel.feature.apps.InstalledAppRepository
import app.apksentinel.inspector.ApkInspectionRequest
import app.apksentinel.inspector.ApkInspectionResult
import app.apksentinel.inspector.ApkInspector
import app.apksentinel.inspector.FindingSeverity
import app.apksentinel.inspector.InspectionCancellation
import app.apksentinel.inspector.InspectionCancelledException
import app.apksentinel.inspector.InspectionProgressListener
import app.apksentinel.inspector.ManifestComponent
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
internal fun AnalyzeEntryScreen(
    padding: PaddingValues,
    installedPackageName: String?,
    onInstalledPackageHandled: () -> Unit,
) {
    val context = LocalContext.current
    val threatIntelManager = remember(context) { ThreatIntelManager(context.applicationContext) }
    val safeActivityStore = remember(context) { SafeActivityStoreController.android(context.applicationContext) }
    val inspector = remember(context) { ApkInspector(context.applicationContext) }
    val installedAppRepository = remember(context) { InstalledAppRepository(context.applicationContext) }
    val executor = remember { Executors.newSingleThreadExecutor() }
    val mainHandler = remember { Handler(Looper.getMainLooper()) }
    val cancellation = remember { AtomicBoolean(false) }
    val screenActive = remember { AtomicBoolean(true) }
    var selectedUri by rememberSaveable { mutableStateOf<String?>(null) }
    var selectedInstalledPackage by rememberSaveable { mutableStateOf<String?>(null) }
    var inspection by remember { mutableStateOf<ApkInspectionResult?>(null) }
    var installedComparison by remember { mutableStateOf<InstalledApkComparison?>(null) }
    var apkThreatIndicators by remember { mutableStateOf<List<ThreatIndicator>>(emptyList()) }
    var inspectionError by rememberSaveable { mutableStateOf<String?>(null) }
    var inspectionProgress by rememberSaveable { mutableStateOf<String?>(null) }
    var isInspecting by rememberSaveable { mutableStateOf(false) }
    var exportPayload by remember { mutableStateOf<String?>(null) }
    var manifestExportPayload by remember { mutableStateOf<String?>(null) }
    var pdfExportPayload by remember { mutableStateOf<ByteArray?>(null) }
    var pendingPdfShare by remember { mutableStateOf<ByteArray?>(null) }
    var showPdfShareConfirmation by rememberSaveable { mutableStateOf(false) }
    var exportStatus by rememberSaveable { mutableStateOf<String?>(null) }
    // Link text can contain credentials or sensitive query parameters. Keep it
    // only in the current composition; do not write it into saved instance state.
    var linkText by remember { mutableStateOf("") }
    var linkResult by remember { mutableStateOf<UrlInspection?>(null) }
    var redirectConsent by remember { mutableStateOf(false) }
    var redirectResult by remember { mutableStateOf<RedirectResolution?>(null) }
    var redirectInProgress by remember { mutableStateOf(false) }
    var fraudHandoffStatus by rememberSaveable { mutableStateOf<String?>(null) }
    var fraudPortalConfirmed by remember { mutableStateOf(false) }
    var analyzeModeName by rememberSaveable { mutableStateOf(AnalyzeMode.APK.name) }
    val analyzeMode = runCatching { AnalyzeMode.valueOf(analyzeModeName) }.getOrDefault(AnalyzeMode.APK)
    var displayName by remember { mutableStateOf<String?>(null) }
    var selectedSizeBytes by remember { mutableStateOf<Long?>(null) }
    var completedInspectionLabel by remember { mutableStateOf<String?>(null) }
    fun clearPdfBytes(bytes: ByteArray?) {
        bytes?.fill(0)
    }
    fun submitPdfTask(task: () -> Unit): Boolean = runCatching {
        executor.execute {
            if (screenActive.get()) task()
        }
    }.isSuccess
    /** Never pass file, package, link, host, report, finding, or error text to Activity. */
    fun recordActivity(category: SafeActivityCategory, outcome: SafeActivityOutcome, code: SafeActivityCode) {
        runCatching {
            executor.execute {
                safeActivityStore.append(
                    SafeActivityRecord(category = category, outcome = outcome, atMillis = System.currentTimeMillis(), code = code),
                )
            }
        }
    }
    fun inspectLinkLocally() {
        val threatHosts = threatIntelManager.activeFeed()?.indicators.orEmpty()
            .filter { it.type == IndicatorType.HOST }
            .map { it.value }
            .toSet()
        val result = UrlSafetyAnalyzer(threatHosts).inspect(linkText)
        linkResult = result
        recordActivity(
            category = SafeActivityCategory.LINK_CHECK,
            outcome = if (result.verdict == UrlVerdict.NO_KNOWN_WARNING) SafeActivityOutcome.COMPLETED else SafeActivityOutcome.ATTENTION,
            code = SafeActivityCode.LOCAL_CHECK,
        )
    }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            runCatching { context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            selectedUri = uri.toString()
            selectedInstalledPackage = null
            displayName = null
            selectedSizeBytes = null
            inspectionError = null
            inspectionProgress = null
        }
    }
    val reportSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri: Uri? ->
        val payload = exportPayload
        if (uri != null && payload != null) {
            exportStatus = context.getString(R.string.status_saving_report)
            executor.submit {
                val saved = SafeDocumentWriter.writeText(context, uri, payload)
                mainHandler.post {
                    if (!screenActive.get()) return@post
                    exportPayload = null
                    exportStatus = if (saved) context.getString(R.string.status_report_saved) else context.getString(R.string.status_report_save_failed)
                }
            }
        } else {
            exportPayload = null
            exportStatus = context.getString(R.string.status_save_cancelled)
        }
    }
    val manifestSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/xml")) { uri: Uri? ->
        val payload = manifestExportPayload
        if (uri != null && payload != null) {
            exportStatus = context.getString(R.string.status_saving_manifest)
            executor.submit {
                val saved = SafeDocumentWriter.writeText(context, uri, payload)
                mainHandler.post {
                    if (!screenActive.get()) return@post
                    manifestExportPayload = null
                    exportStatus = if (saved) context.getString(R.string.status_manifest_saved) else context.getString(R.string.status_manifest_save_failed)
                }
            }
        } else {
            manifestExportPayload = null
            exportStatus = context.getString(R.string.status_save_cancelled)
        }
    }
    val pdfSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri: Uri? ->
        val payload = pdfExportPayload
        if (uri != null && payload != null) {
            exportStatus = context.getString(R.string.status_saving_pdf_report)
            if (!submitPdfTask {
                val saved = SafeDocumentWriter.writeBytes(context, uri, payload)
                mainHandler.post {
                    if (!screenActive.get()) {
                        clearPdfBytes(payload)
                        return@post
                    }
                    pdfExportPayload = null
                    clearPdfBytes(payload)
                    exportStatus = if (saved) context.getString(R.string.status_pdf_report_saved) else context.getString(R.string.status_pdf_report_save_failed)
                }
            }) {
                pdfExportPayload = null
                clearPdfBytes(payload)
                exportStatus = context.getString(R.string.status_pdf_report_save_failed)
            }
        } else {
            clearPdfBytes(payload)
            pdfExportPayload = null
            exportStatus = context.getString(R.string.status_save_cancelled)
        }
    }
    LaunchedEffect(context) {
        submitPdfTask { RedactedPdfCache.cleanup(context.applicationContext) }
    }
    LaunchedEffect(selectedUri) {
        val metadata = selectedUri?.let { value ->
            withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.query(
                        Uri.parse(value),
                        arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                        null,
                        null,
                        null,
                    )?.use { cursor ->
                        if (!cursor.moveToFirst()) return@use null
                        val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                        SelectedDocumentMetadata(
                            displayName = nameIndex.takeIf { it >= 0 }?.let(cursor::getString),
                            sizeBytes = sizeIndex.takeIf { it >= 0 && !cursor.isNull(it) }
                                ?.let(cursor::getLong)
                                ?.takeIf { it >= 0L },
                        )
                    }
                }.getOrNull()
            }
        }
        displayName = metadata?.displayName
        selectedSizeBytes = metadata?.sizeBytes
    }
    fun submitInspection(action: (ApkInspectionRequest) -> ApkInspectionResult) {
        val requestedSourceLabel = SafeTextNormalizer.normalizeDisplayText(
            displayName ?: selectedInstalledPackage,
            context.getString(R.string.analyze_document_fallback),
            160,
        )
        cancellation.set(false)
        isInspecting = true
        inspectionError = null
        inspectionProgress = context.getString(R.string.status_inspection_starting)
        executor.submit {
            try {
                val result = action(
                    ApkInspectionRequest(
                        cancellation = InspectionCancellation { cancellation.get() },
                        progressListener = InspectionProgressListener { update ->
                            mainHandler.post {
                                if (screenActive.get()) inspectionProgress = context.apkInspectionProgress(update.code)
                            }
                        },
                    ),
                )
                val installed = result.manifest?.packageName?.takeIf { it.isNotBlank() }?.let(installedAppRepository::find)
                fun normalizedFingerprint(value: String): String = value.filter(Char::isLetterOrDigit).lowercase()
                val apkSigners = result.signing?.certificates?.map { normalizedFingerprint(it.sha256) }?.toSet().orEmpty()
                val comparison = installed?.let { record ->
                    val installedSigners = record.signerSha256.map(::normalizedFingerprint).toSet()
                    InstalledApkComparison(
                        installed = record,
                        sameSigner = if (apkSigners.isEmpty() || installedSigners.isEmpty()) null else apkSigners == installedSigners,
                        sameVersion = result.manifest?.versionCode == record.versionCode,
                        requestedPermissionsAdded = result.manifest?.permissions.orEmpty().toSet().minus(record.requestedPermissions.toSet()).sorted(),
                        requestedPermissionsRemoved = record.requestedPermissions.toSet().minus(result.manifest?.permissions.orEmpty().toSet()).sorted(),
                        selectedExportedComponentCount = result.manifest?.components.orEmpty().count { it.exported == true },
                    )
                }
                val threatMatches = result.source?.sha256?.let(threatIntelManager::apkIndicators).orEmpty()
                runCatching {
                    safeActivityStore.append(
                        SafeActivityRecord(SafeActivityCategory.APK_CHECK, SafeActivityOutcome.COMPLETED, System.currentTimeMillis(), SafeActivityCode.LOCAL_CHECK),
                    )
                }
                mainHandler.post {
                    if (!screenActive.get()) return@post
                    inspection = result
                    installedComparison = comparison
                    apkThreatIndicators = threatMatches
                    completedInspectionLabel = requestedSourceLabel
                    inspectionProgress = context.getString(R.string.status_inspection_complete)
                    isInspecting = false
                }
            } catch (_: InspectionCancelledException) {
                runCatching {
                    safeActivityStore.append(
                        SafeActivityRecord(SafeActivityCategory.APK_CHECK, SafeActivityOutcome.CANCELLED, System.currentTimeMillis(), SafeActivityCode.USER_CANCELLED),
                    )
                }
                mainHandler.post {
                    if (!screenActive.get()) return@post
                    inspectionProgress = context.getString(R.string.status_inspection_cancelled)
                    isInspecting = false
                }
            } catch (_: Throwable) {
                runCatching {
                    safeActivityStore.append(
                        SafeActivityRecord(SafeActivityCategory.APK_CHECK, SafeActivityOutcome.UNAVAILABLE, System.currentTimeMillis(), SafeActivityCode.CAPABILITY_UNAVAILABLE),
                    )
                }
                mainHandler.post {
                    if (!screenActive.get()) return@post
                    inspectionError = context.getString(R.string.status_inspection_failed)
                    inspectionProgress = null
                    isInspecting = false
                }
            }
        }
    }
    DisposableEffect(Unit) {
        onDispose {
            screenActive.set(false)
            cancellation.set(true)
            clearPdfBytes(pdfExportPayload)
            clearPdfBytes(pendingPdfShare)
            pdfExportPayload = null
            pendingPdfShare = null
            executor.shutdownNow()
        }
    }
    LaunchedEffect(installedPackageName) {
        val packageName = installedPackageName ?: return@LaunchedEffect
        analyzeModeName = AnalyzeMode.APK.name
        selectedUri = null
        displayName = null
        selectedSizeBytes = null
        selectedInstalledPackage = packageName
        submitInspection { request -> inspector.inspectInstalledPackage(packageName, request) }
        onInstalledPackageHandled()
    }
    ScreenColumn(padding) {
        SentinelCard {
            Text(stringResource(R.string.analyze_task_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            FullWidthOutlinedAction(
                label = stringResource(if (analyzeMode == AnalyzeMode.APK) R.string.analyze_task_apk_selected else R.string.analyze_task_apk),
                onClick = { analyzeModeName = AnalyzeMode.APK.name },
            )
            FullWidthOutlinedAction(
                label = stringResource(if (analyzeMode == AnalyzeMode.LINK) R.string.analyze_task_link_selected else R.string.analyze_task_link),
                onClick = { analyzeModeName = AnalyzeMode.LINK.name },
            )
        }
        if (analyzeMode == AnalyzeMode.APK) {
        SentinelCard {
            Text(stringResource(R.string.analyze_what_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.analyze_what_body))
        }
        Button(onClick = { picker.launch(arrayOf("application/vnd.android.package-archive", "application/zip", "application/octet-stream")) }, modifier = Modifier.fillMaxWidth()) {
            Text(if (selectedUri == null) stringResource(R.string.analyze_choose_file) else stringResource(R.string.analyze_choose_other))
        }
        if (selectedUri != null || selectedInstalledPackage != null) SentinelCard {
            Text(stringResource(R.string.analyze_selected), style = MaterialTheme.typography.labelLarge)
            Text(
                SafeTextNormalizer.normalizeDisplayText(
                    displayName ?: selectedInstalledPackage?.let { context.getString(R.string.analyze_installed_base, it) },
                    context.getString(R.string.analyze_document_fallback),
                    160,
                ),
                fontWeight = FontWeight.SemiBold,
            )
            Text(stringResource(R.string.analyze_bounded_hint), style = MaterialTheme.typography.bodySmall)
            KeyValueRow(
                label = stringResource(R.string.analyze_selected_size),
                value = selectedSizeBytes?.let { Formatter.formatShortFileSize(context, it) }
                    ?: stringResource(R.string.analyze_size_unknown),
            )
            Text(stringResource(R.string.analyze_time_hint), style = MaterialTheme.typography.bodySmall)
            Button(
                onClick = {
                    val installed = selectedInstalledPackage
                    val input = selectedUri
                    when {
                        installed != null -> submitInspection { request -> inspector.inspectInstalledPackage(installed, request) }
                        input != null -> submitInspection { request -> inspector.inspect(Uri.parse(input), request) }
                    }
                },
                enabled = !isInspecting,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (isInspecting) stringResource(R.string.analyze_inspecting) else stringResource(R.string.analyze_run)) }
            if (isInspecting) {
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            if (isInspecting) FullWidthOutlinedAction(label = stringResource(R.string.analyze_cancel), onClick = { cancellation.set(true) })
            inspectionProgress?.let {
                Text(it, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }, style = MaterialTheme.typography.bodySmall)
            }
            inspectionError?.let {
                Text(it, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }, color = MaterialTheme.colorScheme.error)
            }
        }
        inspection?.let { result ->
            completedInspectionLabel?.let { label ->
                SentinelCard {
                    Text(stringResource(R.string.report_completed_source_title), style = MaterialTheme.typography.labelLarge)
                    Text(label, fontWeight = FontWeight.SemiBold)
                    if (isInspecting) Text(stringResource(R.string.report_previous_while_running), style = MaterialTheme.typography.bodySmall)
                }
            }
            ApkInspectionReport(
                result = result,
                onExportTechnical = {
                    exportPayload = LocalReportRenderer.json(
                        result.toLocalReport(ApkReportText.from(context), threatIndicators = apkThreatIndicators),
                    )
                    val base = SafeTextNormalizer.normalizeFileName(displayName?.substringBeforeLast('.'), "apk-sentinel")
                    reportSaver.launch("${base}-technical-inspection.json")
                },
                onExportRedacted = {
                    exportPayload = LocalReportRenderer.json(
                        result.toLocalReport(ApkReportText.from(context), threatIndicators = apkThreatIndicators, redacted = true),
                        ReportExportPolicy(includeTechnical = false),
                    )
                    val base = SafeTextNormalizer.normalizeFileName(displayName?.substringBeforeLast('.'), "apk-sentinel")
                    reportSaver.launch("${base}-redacted-inspection.json")
                },
                onSaveRedactedPdf = {
                    if (!submitPdfTask {
                        val payload = runCatching {
                            RedactedPdfRenderer.render(
                                result.toRedactedPdfReport(AppLocaleController.wrap(context.applicationContext)),
                            )
                        }.getOrNull()
                        mainHandler.post {
                            if (!screenActive.get()) {
                                clearPdfBytes(payload)
                                return@post
                            }
                            if (payload == null) {
                                exportStatus = context.getString(R.string.status_pdf_report_unavailable)
                            } else {
                                pdfExportPayload = payload
                                val base = SafeTextNormalizer.normalizeFileName(displayName?.substringBeforeLast('.'), "apk-sentinel")
                                pdfSaver.launch("${base}-redacted-report.pdf")
                            }
                        }
                    }) {
                        exportStatus = context.getString(R.string.status_pdf_report_unavailable)
                    }
                },
                onRequestShareRedactedPdf = {
                    if (!submitPdfTask {
                        val payload = runCatching {
                            RedactedPdfRenderer.render(
                                result.toRedactedPdfReport(AppLocaleController.wrap(context.applicationContext)),
                            )
                        }.getOrNull()
                        mainHandler.post {
                            if (!screenActive.get()) {
                                clearPdfBytes(payload)
                                return@post
                            }
                            if (payload == null) {
                                exportStatus = context.getString(R.string.status_pdf_report_unavailable)
                            } else {
                                pendingPdfShare = payload
                                showPdfShareConfirmation = true
                            }
                        }
                    }) {
                        exportStatus = context.getString(R.string.status_pdf_report_unavailable)
                    }
                },
                onExportManifest = result.decodedManifest?.let { decoded ->
                    {
                        manifestExportPayload = decoded.xml
                        val base = SafeTextNormalizer.normalizeFileName(displayName?.substringBeforeLast('.'), "apk-sentinel")
                        manifestSaver.launch("${base}-AndroidManifest.xml")
                    }
                },
                installedComparison = installedComparison,
                threatIndicators = apkThreatIndicators,
            )
            exportStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        } else {
        OutlinedTextField(
            value = linkText,
        onValueChange = { linkText = it.take(2_048); linkResult = null; redirectResult = null; redirectConsent = false; fraudHandoffStatus = null; fraudPortalConfirmed = false },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.link_input_label)) },
            supportingText = { Text(stringResource(R.string.link_input_hint)) },
            minLines = 2,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(onDone = {
                if (linkText.isNotBlank()) {
                    inspectLinkLocally()
                }
            }),
        )
        Button(
            onClick = {
                inspectLinkLocally()
            },
            enabled = linkText.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.link_inspect)) }
        if (linkText.isNotEmpty()) {
            FullWidthOutlinedAction(
                label = stringResource(R.string.link_clear),
                onClick = {
                    linkText = ""
                    linkResult = null
                    redirectResult = null
                    redirectConsent = false
                    fraudHandoffStatus = null
                    fraudPortalConfirmed = false
                },
            )
        }
        linkResult?.let { result ->
            SentinelCard {
                SentinelStatusLabel(
                    label = when (result.verdict) {
                        UrlVerdict.NO_KNOWN_WARNING -> stringResource(R.string.link_verdict_no_warning)
                        UrlVerdict.REVIEW -> stringResource(R.string.link_verdict_review)
                        UrlVerdict.BLOCKED_LOCAL_MATCH -> stringResource(R.string.link_verdict_threat_match)
                        UrlVerdict.INVALID -> stringResource(R.string.link_verdict_invalid)
                    },
                    tone = when (result.verdict) {
                        UrlVerdict.NO_KNOWN_WARNING -> SentinelStatusTone.NEUTRAL
                        UrlVerdict.REVIEW -> SentinelStatusTone.REVIEW
                        UrlVerdict.BLOCKED_LOCAL_MATCH, UrlVerdict.INVALID -> SentinelStatusTone.URGENT
                    },
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                result.displayHost?.let { Text(stringResource(R.string.link_hostname, it)) }
                result.findings.forEach { finding ->
                    Text(
                        stringResource(R.string.link_bullet_item, stringResource(urlFindingMessageResource(finding.message))),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                Text(
                    stringResource(urlInspectionLimitationResource(result.limitation)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (result.normalizedUrl != null && result.verdict != UrlVerdict.INVALID) SentinelCard {
                Text(stringResource(R.string.link_redirect_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.link_redirect_body))
                SentinelToggleRow(
                    title = stringResource(R.string.link_redirect_allow),
                    description = stringResource(R.string.link_redirect_consent),
                    checked = redirectConsent,
                    onCheckedChange = { redirectConsent = it },
                    onStateLabel = stringResource(R.string.link_redirect_allowed),
                    offStateLabel = stringResource(R.string.link_redirect_not_allowed),
                )
                Button(
                    onClick = {
                        val normalized = result.normalizedUrl ?: return@Button
                        redirectInProgress = true
                        redirectResult = null
                        executor.submit {
                            val resolved = SafeRedirectResolver().resolve(normalized)
                            mainHandler.post {
                                if (!screenActive.get()) return@post
                                redirectResult = resolved
                                redirectInProgress = false
                            }
                        }
                    },
                    enabled = redirectConsent && !redirectInProgress,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (redirectInProgress) stringResource(R.string.link_resolving) else stringResource(R.string.link_resolve)) }
                // A redirect resolution is a real network round trip; a disabled button
                // alone reads as "nothing happened".
                if (redirectInProgress) SentinelLoadingRow(stringResource(R.string.link_resolving))
                redirectResult?.let { resolution ->
                    when (resolution) {
                        is RedirectResolution.Resolved -> {
                            Text(stringResource(R.string.link_final_hostname, resolution.finalDisplayHost), fontWeight = FontWeight.Medium)
                            resolution.hops.forEach { hop ->
                                Text(stringResource(R.string.link_redirect_hop, hop.statusCode, hop.displayHost), style = MaterialTheme.typography.bodySmall)
                            }
                        }
                        is RedirectResolution.Rejected -> Text(stringResource(redirectResolutionReasonResource(resolution.reason)), color = MaterialTheme.colorScheme.error)
                        is RedirectResolution.Failed -> {
                            Text(stringResource(redirectResolutionReasonResource(resolution.reason)), color = MaterialTheme.colorScheme.error)
                            resolution.hops.forEach { hop ->
                                Text(stringResource(R.string.link_redirect_hop, hop.statusCode, hop.displayHost), style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }
            FraudReportDraftBuilder.build(result)?.let { draft -> SentinelCard {
                Text(stringResource(R.string.link_fraud_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.link_fraud_body))
                Text(stringResource(R.string.link_fraud_recipient, draft.recipient, draft.recipientHost), fontWeight = FontWeight.Medium)
                draft.fields.forEach { field ->
                    Text(
                        stringResource(fraudReportFieldLabel(field.kind), field.preview),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (field.redacted) Text(stringResource(R.string.link_fraud_field_redacted), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Text(stringResource(R.string.link_fraud_instructions), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                SentinelToggleRow(
                    title = stringResource(R.string.link_fraud_confirm_recipient),
                    description = stringResource(R.string.link_fraud_confirm_recipient_body, draft.recipientHost),
                    checked = fraudPortalConfirmed,
                    onCheckedChange = { fraudPortalConfirmed = it; if (!it) fraudHandoffStatus = context.getString(R.string.link_fraud_cancelled) },
                    onStateLabel = stringResource(R.string.link_fraud_confirmed),
                    offStateLabel = stringResource(R.string.link_fraud_not_confirmed),
                )
                FullWidthOutlinedAction(
                    label = stringResource(R.string.link_fraud_open),
                    onClick = {
                        val outcome = fraudHandoffOutcome(fraudPortalConfirmed) {
                            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(OfficialFraudPortal.url)))
                            true
                        }
                        fraudHandoffStatus = when (outcome) {
                            FraudPortalHandoffOutcome.OPENED -> context.getString(R.string.link_fraud_opened)
                            FraudPortalHandoffOutcome.CANCELLED -> context.getString(R.string.link_fraud_cancelled)
                            FraudPortalHandoffOutcome.UNAVAILABLE -> context.getString(R.string.link_fraud_open_failed)
                        }
                    },
                    enabled = fraudPortalConfirmed,
                )
                fraudHandoffStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            } }
        }
        }
    }
    if (showPdfShareConfirmation) AlertDialog(
        onDismissRequest = {
            clearPdfBytes(pendingPdfShare)
            pendingPdfShare = null
            showPdfShareConfirmation = false
            submitPdfTask { RedactedPdfCache.cleanup(context.applicationContext) }
        },
        title = { Text(stringResource(R.string.report_pdf_share_title)) },
        text = { Text(stringResource(R.string.report_pdf_share_body)) },
        confirmButton = {
            TextButton(onClick = {
                val payload = pendingPdfShare
                pendingPdfShare = null
                showPdfShareConfirmation = false
                if (payload == null) return@TextButton
                if (!submitPdfTask {
                    val file = RedactedPdfCache.write(context.applicationContext, payload)
                    clearPdfBytes(payload)
                    mainHandler.post {
                        if (!screenActive.get()) {
                            file?.delete()
                            return@post
                        }
                        if (file == null) {
                            exportStatus = context.getString(R.string.status_pdf_report_unavailable)
                        } else {
                            val uri = FileProvider.getUriForFile(context, "${context.packageName}.reportfileprovider", file)
                            val share = Intent(Intent.ACTION_SEND)
                                .setType("application/pdf")
                                .putExtra(Intent.EXTRA_STREAM, uri)
                                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                .also { it.clipData = ClipData.newRawUri("redacted-report", uri) }
                            val started = runCatching {
                                context.startActivity(Intent.createChooser(share, context.getString(R.string.report_pdf_share_chooser)).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
                            }.isSuccess
                            if (!started) {
                                file.delete()
                                exportStatus = context.getString(R.string.status_pdf_report_unavailable)
                            }
                        }
                    }
                }) {
                    clearPdfBytes(payload)
                    exportStatus = context.getString(R.string.status_pdf_report_unavailable)
                }
            }) { Text(stringResource(R.string.report_pdf_share_confirm)) }
        },
        dismissButton = {
            TextButton(onClick = {
                clearPdfBytes(pendingPdfShare)
                pendingPdfShare = null
                showPdfShareConfirmation = false
                submitPdfTask { RedactedPdfCache.cleanup(context.applicationContext) }
            }) { Text(stringResource(R.string.report_pdf_share_cancel)) }
        },
    )
}

private enum class AnalyzeMode { APK, LINK }

private fun fraudReportFieldLabel(kind: FraudReportFieldKind): Int = when (kind) {
    FraudReportFieldKind.URL -> R.string.link_fraud_field_url
    FraudReportFieldKind.HOST -> R.string.link_fraud_field_host
    FraudReportFieldKind.FINDINGS -> R.string.link_fraud_field_findings
    FraudReportFieldKind.LIMITATION -> R.string.link_fraud_field_limitation
}

private data class SelectedDocumentMetadata(
    val displayName: String?,
    val sizeBytes: Long?,
)

private fun urlFindingMessageResource(message: UrlFindingMessage): Int = when (message) {
    UrlFindingMessage.INVALID_WEB_ADDRESS -> R.string.link_finding_invalid_web_address
    UrlFindingMessage.HTTP_HTTPS_ONLY -> R.string.link_finding_http_https_only
    UrlFindingMessage.NO_VALID_HOSTNAME -> R.string.link_finding_no_valid_hostname
    UrlFindingMessage.HOSTNAME_NORMALIZATION_FAILED -> R.string.link_finding_hostname_normalization_failed
    UrlFindingMessage.BIDI_REMOVED_BEFORE_DISPLAY -> R.string.link_finding_bidi_removed_before_display
    UrlFindingMessage.BIDI_REMOVED_BEFORE_VALIDATION -> R.string.link_finding_bidi_removed_before_validation
    UrlFindingMessage.CREDENTIALS_IN_URL -> R.string.link_finding_credentials_in_url
    UrlFindingMessage.LOCAL_THREAT_MATCH -> R.string.link_finding_local_threat_match
    UrlFindingMessage.IP_LITERAL -> R.string.link_finding_ip_literal
    UrlFindingMessage.PUNYCODE -> R.string.link_finding_punycode
    UrlFindingMessage.MIXED_SCRIPT -> R.string.link_finding_mixed_script
    UrlFindingMessage.SHORTENER -> R.string.link_finding_shortener
    UrlFindingMessage.SENSITIVE_QUERY -> R.string.link_finding_sensitive_query
}

private fun urlInspectionLimitationResource(limitation: UrlInspectionLimitation): Int = when (limitation) {
    UrlInspectionLimitation.NO_REMOTE_REPUTATION_OR_REDIRECT_LOOKUP -> R.string.link_limitation_local_only
}

private fun redirectResolutionReasonResource(reason: RedirectResolutionReason): Int = when (reason) {
    RedirectResolutionReason.INVALID_HTTP_URL -> R.string.link_redirect_reason_invalid_http_url
    RedirectResolutionReason.MISSING_HOSTNAME -> R.string.link_redirect_reason_missing_hostname
    RedirectResolutionReason.HOSTNAME_UNRESOLVED -> R.string.link_redirect_reason_hostname_unresolved
    RedirectResolutionReason.UNSAFE_NETWORK_TARGET -> R.string.link_redirect_reason_unsafe_network_target
    RedirectResolutionReason.DESTINATION_CHECK_FAILED -> R.string.link_redirect_reason_destination_check_failed
    RedirectResolutionReason.REDIRECT_LOCATION_MISSING -> R.string.link_redirect_reason_location_missing
    RedirectResolutionReason.REDIRECT_HOP_LIMIT_EXCEEDED -> R.string.link_redirect_reason_hop_limit
    RedirectResolutionReason.INVALID_REDIRECT_TARGET -> R.string.link_redirect_reason_invalid_target
    RedirectResolutionReason.REDIRECT_CHAIN_INCOMPLETE -> R.string.link_redirect_reason_chain_incomplete
}

@Composable
private fun ApkInspectionReport(
    result: ApkInspectionResult,
    onExportTechnical: () -> Unit,
    onExportRedacted: () -> Unit,
    onSaveRedactedPdf: () -> Unit,
    onRequestShareRedactedPdf: () -> Unit,
    onExportManifest: (() -> Unit)?,
    installedComparison: InstalledApkComparison?,
    threatIndicators: List<ThreatIndicator>,
) {
    val context = LocalContext.current
    var manifestQuery by rememberSaveable(result.source?.sha256) { mutableStateOf("") }
    var showManifestEvidence by rememberSaveable(result.source?.sha256) { mutableStateOf(false) }
    var showPackagePaths by rememberSaveable(result.source?.sha256) { mutableStateOf(false) }
    result.risk?.let { risk ->
        SentinelCard {
            Text(stringResource(R.string.report_risk_evidence, risk.score, context.apkRiskLevel(risk.level)), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(stringResource(R.string.report_risk_hint))
            risk.explanations.take(8).forEach { explanation ->
                Text(stringResource(R.string.report_risk_explanation, explanation.points, context.apkRiskExplanation(explanation.code)))
                explanation.evidence.take(4).forEach { evidence ->
                    Text(stringResource(R.string.report_bullet_item, context.apkTechnicalEvidence(evidence)), style = MaterialTheme.typography.bodySmall)
                }
            }
            risk.limitations.take(4).forEach { limitation ->
                Text(stringResource(R.string.report_limit, context.apkRiskLimitation(limitation.code)), style = MaterialTheme.typography.bodySmall)
                limitation.evidence.take(4).forEach { evidence ->
                    Text(stringResource(R.string.report_bullet_item, context.apkTechnicalEvidence(evidence)), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
    result.bundle?.let { bundle ->
        SentinelCard {
            Text(stringResource(R.string.bundle_summary_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(
                if (bundle.format == app.apksentinel.inspector.BundleFormat.AAB) {
                    stringResource(R.string.bundle_summary_aab_body)
                } else {
                    stringResource(R.string.bundle_summary_body)
                },
                style = MaterialTheme.typography.bodySmall,
            )
            KeyValueRow(label = stringResource(R.string.bundle_summary_format), value = context.apkBundleFormat(bundle.format))
            KeyValueRow(label = stringResource(R.string.bundle_summary_apk_count), value = bundle.nestedApks.size.toString())
            KeyValueRow(label = stringResource(R.string.bundle_summary_apk_bytes), value = Formatter.formatShortFileSize(context, bundle.nestedApkBytes))
            KeyValueRow(label = stringResource(R.string.bundle_summary_expanded_bytes), value = Formatter.formatShortFileSize(context, bundle.nestedExpandedBytes))
            KeyValueRow(label = stringResource(R.string.bundle_summary_identity_status), value = context.apkBundleIdentityStatus(bundle.identityStatus))
            bundle.publishingEvidence?.let { aab ->
                Text(stringResource(R.string.bundle_summary_aab_modules), fontWeight = FontWeight.Medium)
                Text(
                    stringResource(
                        R.string.bundle_summary_aab_entries,
                        aab.entryCount,
                        Formatter.formatShortFileSize(context, aab.declaredBytes),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    stringResource(
                        R.string.bundle_summary_aab_config,
                        stringResource(if (aab.bundleConfigPresent) R.string.bundle_summary_aab_yes else R.string.bundle_summary_aab_no),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(stringResource(R.string.bundle_summary_aab_metadata, aab.metadataPaths.size), style = MaterialTheme.typography.bodySmall)
                aab.modules.take(24).forEach { module ->
                    Text(
                        stringResource(
                            R.string.bundle_summary_aab_module,
                            module.name.safeApkTechnicalDisplay(stringResource(R.string.report_unavailable), 120),
                            module.entryCount,
                            Formatter.formatShortFileSize(context, module.declaredBytes),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        stringResource(
                            R.string.bundle_summary_aab_flags,
                            stringResource(if (module.hasManifest) R.string.bundle_summary_aab_yes else R.string.bundle_summary_aab_no),
                            stringResource(if (module.hasDex) R.string.bundle_summary_aab_yes else R.string.bundle_summary_aab_no),
                            stringResource(if (module.hasResources) R.string.bundle_summary_aab_yes else R.string.bundle_summary_aab_no),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (bundle.identityStatus != app.apksentinel.inspector.BundleIdentityStatus.VERIFIED && result.risk == null) {
                Text(stringResource(R.string.bundle_summary_top_level_unavailable), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            Text(stringResource(R.string.bundle_summary_roles), fontWeight = FontWeight.Medium)
            bundle.nestedApks.take(24).forEach { nested ->
                Text(
                    stringResource(
                        R.string.bundle_summary_entry,
                        nested.path.safeApkTechnicalDisplay(stringResource(R.string.report_unavailable), 180),
                        context.apkBundleRole(nested.role),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
                nested.failures.take(6).forEach { failure ->
                    Text(
                        stringResource(
                            R.string.bundle_summary_entry_failure,
                            context.apkInspectionFailure(failure),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
            if (bundle.nestedApks.size > 24) Text(stringResource(R.string.bundle_summary_entries_truncated), style = MaterialTheme.typography.bodySmall)
            if (bundle.obbFiles.isNotEmpty()) {
                Text(stringResource(R.string.bundle_summary_obb_title), fontWeight = FontWeight.Medium)
                Text(stringResource(R.string.bundle_summary_obb_body), style = MaterialTheme.typography.bodySmall)
                bundle.obbFiles.take(12).forEach { obb ->
                    Text(
                        stringResource(
                            R.string.bundle_summary_obb_entry,
                            obb.path.safeApkTechnicalDisplay(stringResource(R.string.report_unavailable), 180),
                            obb.byteCount?.let { Formatter.formatShortFileSize(context, it) } ?: stringResource(R.string.report_unknown),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            if (bundle.limitations.isNotEmpty()) {
                Text(stringResource(R.string.bundle_summary_limitations), fontWeight = FontWeight.Medium)
                bundle.limitations.take(12).forEach { limitation ->
                    Text(stringResource(R.string.report_bullet_item, context.apkBundleLimitation(limitation)), style = MaterialTheme.typography.bodySmall)
                }
            }
            Text(stringResource(R.string.bundle_summary_no_installability), style = MaterialTheme.typography.bodySmall)
        }
    }
    if (threatIndicators.isNotEmpty()) SentinelCard {
        Text(stringResource(R.string.report_threat_match_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.error)
        Text(stringResource(R.string.report_threat_match_body))
        threatIndicators.take(8).forEach { indicator ->
            SentinelStatusLabel(
                label = threatConfidenceText(indicator.confidence),
                tone = threatIndicatorTone(indicator.confidence),
            )
            Text(
                stringResource(
                    R.string.report_threat_indicator,
                    threatConfidenceText(indicator.confidence),
                    indicator.category.safeApkTechnicalDisplay(stringResource(R.string.report_unavailable), 120),
                    indicator.evidenceId.safeApkTechnicalDisplay(stringResource(R.string.report_unavailable), 120),
                ),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
    SentinelCard {
        Text(stringResource(R.string.report_identity_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        result.manifest?.let { manifest ->
            Text(SafeTextNormalizer.normalizeDisplayText(manifest.packageName, stringResource(R.string.report_unknown_package)))
            Text(stringResource(R.string.report_version_sdk, manifest.versionName ?: stringResource(R.string.report_unknown), manifest.sdk.minSdk ?: "?", manifest.sdk.targetSdk ?: "?"))
            Text(stringResource(R.string.report_manifest_counts, manifest.permissions.size, manifest.components.size, manifest.hardwareFeatures.size))
            FullWidthOutlinedAction(
                label = stringResource(if (showManifestEvidence) R.string.report_hide_manifest_evidence else R.string.report_show_manifest_evidence),
                onClick = { showManifestEvidence = !showManifestEvidence },
            )
            if (showManifestEvidence) {
                Text(stringResource(R.string.report_requested_permissions), fontWeight = FontWeight.Medium)
                SentinelPagedList(items = manifest.permissions, initialVisibleCount = 8) {
                    Text(stringResource(R.string.report_bullet_item, it), style = MaterialTheme.typography.bodySmall)
                }
                // The inspector itself bounds hostile input; that limit is still worth stating.
                if (manifest.permissionsTruncated) Text(stringResource(R.string.report_additional_permissions), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.report_components), fontWeight = FontWeight.Medium)
                if (manifest.intentFiltersTruncated) {
                    Text(stringResource(R.string.apk_intent_filters_global_truncated), style = MaterialTheme.typography.bodySmall)
                }
                SentinelPagedList(items = manifest.components, initialVisibleCount = 8) { component ->
                    Text(stringResource(R.string.report_component_summary, context.apkComponentType(component.type), component.className.safeApkTechnicalDisplay(stringResource(R.string.report_unknown)), component.exported ?: false, component.enabled ?: false), style = MaterialTheme.typography.bodySmall)
                    ComponentIntentFilterEvidence(component)
                }
                if (manifest.componentsTruncated) Text(stringResource(R.string.report_additional_components), style = MaterialTheme.typography.bodySmall)
                if (manifest.hardwareFeatures.isNotEmpty()) {
                    Text(stringResource(R.string.report_hardware_requirements), fontWeight = FontWeight.Medium)
                    SentinelPagedList(items = manifest.hardwareFeatures, initialVisibleCount = 6) { feature ->
                        Text(stringResource(R.string.report_hardware_feature, feature.name ?: stringResource(R.string.report_opengl_es, feature.openGlEsVersion ?: stringResource(R.string.report_unknown)), feature.required), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        } ?: Text(stringResource(R.string.report_manifest_unavailable))
        result.source?.let { Text(stringResource(R.string.report_sha256, it.sha256), style = MaterialTheme.typography.bodySmall) }
        result.signing?.let { signing ->
            Text(stringResource(R.string.report_signing_summary, context.apkSigningStatus(signing.status), signing.certificates.size))
            Text(stringResource(R.string.report_verified_schemes, signing.verifiedSchemes.ifEmpty { listOf(stringResource(R.string.report_none)) }.joinToString()), style = MaterialTheme.typography.bodySmall)
            signing.certificates.take(3).forEach {
                Text(stringResource(R.string.report_certificate_sha256, it.sha256), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.report_certificate_sha1, it.sha1.ifBlank { stringResource(R.string.report_unavailable) }), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.report_subject, SafeTextNormalizer.normalizeDisplayText(it.subject, stringResource(R.string.report_unavailable), 240)), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.report_issuer, SafeTextNormalizer.normalizeDisplayText(it.issuer, stringResource(R.string.report_unavailable), 240)), style = MaterialTheme.typography.bodySmall)
            }
            signing.diagnostics.forEach { diagnostic ->
                Text(stringResource(R.string.report_bullet_item, context.apkSigningDiagnostic(diagnostic)), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    result.archive?.let { archive ->
        SentinelExpandableSection(
            title = stringResource(R.string.report_archive_safety),
            summary = stringResource(R.string.analyze_archive_summary),
            flat = true,
        ) {
            Text(stringResource(R.string.report_archive_counts, archive.entryCount, archive.observedUncompressedBytes))
            Text(stringResource(R.string.report_compression_ratio, archive.maximumObservedCompressionRatio ?: stringResource(R.string.report_unknown)))
            Text(stringResource(R.string.report_unsafe_paths, archive.pathTraversalEntryCount, archive.isComplete))
        }
    }
    installedComparison?.let { comparison ->
        SentinelExpandableSection(
            title = stringResource(R.string.report_compared_installed),
            summary = stringResource(R.string.analyze_compared_summary),
            flat = true,
        ) {
            Text(stringResource(R.string.report_installed_version, comparison.installed.versionName ?: comparison.installed.versionCode.toString()))
            Text(stringResource(if (comparison.sameVersion) R.string.report_version_matches else R.string.report_version_differs))
            Text(stringResource(R.string.report_target_sdk_comparison, result.manifest?.sdk?.targetSdk ?: stringResource(R.string.report_unknown), comparison.installed.targetSdk))
            Text(stringResource(R.string.report_exported_components_comparison, comparison.selectedExportedComponentCount, comparison.installed.exportedComponentCount))
            Text(
                when (comparison.sameSigner) {
                    true -> stringResource(R.string.report_signer_matches)
                    false -> stringResource(R.string.report_signer_differs)
                    null -> stringResource(R.string.report_signer_unavailable)
                },
                color = if (comparison.sameSigner == false) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            )
            if (comparison.requestedPermissionsAdded.isNotEmpty()) {
                Text(stringResource(R.string.report_permissions_added), fontWeight = FontWeight.Medium)
                comparison.requestedPermissionsAdded.take(40).forEach { Text(stringResource(R.string.report_added_item, it), style = MaterialTheme.typography.bodySmall) }
            }
            if (comparison.requestedPermissionsRemoved.isNotEmpty()) {
                Text(stringResource(R.string.report_permissions_removed), fontWeight = FontWeight.Medium)
                comparison.requestedPermissionsRemoved.take(40).forEach { Text(stringResource(R.string.report_removed_item, it), style = MaterialTheme.typography.bodySmall) }
            }
            if (comparison.requestedPermissionsAdded.isEmpty() && comparison.requestedPermissionsRemoved.isEmpty()) {
                Text(stringResource(R.string.report_permissions_match), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    result.inventory?.let { inventory ->
        SentinelExpandableSection(
            title = stringResource(R.string.report_package_contents),
            summary = stringResource(R.string.analyze_contents_summary),
            flat = true,
        ) {
            Text(stringResource(R.string.report_inventory_counts, inventory.dexFiles.count, inventory.nativeLibraries.count, inventory.assets.count))
            inventory.nativeLibraries.abiCounts.entries.sortedBy { it.key }.forEach { Text(stringResource(R.string.report_native_file_count, it.key, it.value)) }
            FullWidthOutlinedAction(
                label = stringResource(if (showPackagePaths) R.string.report_hide_package_paths else R.string.report_show_package_paths),
                onClick = { showPackagePaths = !showPackagePaths },
            )
            if (showPackagePaths) {
                (inventory.dexFiles.samplePaths + inventory.nativeLibraries.samplePaths + inventory.assets.samplePaths)
                    .distinct()
                    .take(120)
                    .forEach { Text(stringResource(R.string.report_bullet_item, SafeTextNormalizer.normalizeDisplayText(it, stringResource(R.string.report_unreadable_path), 300)), style = MaterialTheme.typography.bodySmall) }
                if (inventory.dexFiles.isTruncated || inventory.nativeLibraries.isTruncated || inventory.assets.isTruncated) {
                    Text(stringResource(R.string.report_paths_truncated), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
    result.decodedManifest?.let { decoded ->
        val visibleLines = remember(decoded.xml, manifestQuery) {
            val query = manifestQuery.trim()
            decoded.xml.lineSequence()
                .filter { query.isEmpty() || it.contains(query, ignoreCase = true) }
                .take(200)
                .joinToString("\n")
        }
        SentinelExpandableSection(
            title = stringResource(R.string.report_readable_manifest),
            summary = stringResource(R.string.analyze_manifest_summary),
            flat = true,
        ) {
            Text(
                stringResource(R.string.report_readable_manifest_hint, decoded.unresolvedResourceReferenceCount),
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedTextField(
                value = manifestQuery,
                onValueChange = { manifestQuery = it.take(120) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.report_find_manifest)) },
                singleLine = true,
            )
            Text(
                visibleLines.ifBlank { stringResource(R.string.report_no_manifest_matches) },
                style = MaterialTheme.typography.bodySmall,
            )
            if (decoded.isTruncated) Text(stringResource(R.string.report_manifest_truncated), color = MaterialTheme.colorScheme.error)
            onExportManifest?.let { action ->
                Text(stringResource(R.string.report_manifest_export_privacy), style = MaterialTheme.typography.bodySmall)
                FullWidthOutlinedAction(label = stringResource(R.string.report_save_manifest), onClick = action)
            }
        }
    }
    if (result.findings.isNotEmpty()) SentinelCard {
        Text(stringResource(R.string.report_observed_indicators), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        SentinelPagedList(items = result.findings, initialVisibleCount = 8) { finding ->
            SentinelStatusLabel(
                label = context.apkSeverity(finding.severity),
                tone = apkSeverityTone(finding.severity),
            )
            Text(stringResource(R.string.report_finding_summary, context.apkSeverity(finding.severity), context.apkFindingTitle(finding.code)), fontWeight = FontWeight.Medium)
            Text(context.apkFindingDescription(finding.code), style = MaterialTheme.typography.bodySmall)
            Text(context.apkConfidence(finding.confidence), style = MaterialTheme.typography.bodySmall)
            finding.evidence.take(4).forEach { evidence ->
                Text(stringResource(R.string.report_bullet_item, context.apkTechnicalEvidence(evidence)), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    if (result.failures.isNotEmpty()) SentinelCard {
            Text(stringResource(R.string.report_partial_notes), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        result.failures.take(12).forEach { failure ->
            Text(stringResource(R.string.report_bullet_item, context.apkInspectionFailure(failure.code)))
        }
    }
    SentinelCard {
        Text(stringResource(R.string.report_export_preview), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.report_export_body))
        Button(onClick = onExportRedacted, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.report_save_redacted_json)) }
        FullWidthOutlinedAction(label = stringResource(R.string.report_save_technical_json), onClick = onExportTechnical)
        FullWidthOutlinedAction(label = stringResource(R.string.report_save_pdf), onClick = onSaveRedactedPdf)
        FullWidthOutlinedAction(label = stringResource(R.string.report_share_pdf), onClick = onRequestShareRedactedPdf)
    }
}

@Composable
private fun threatConfidenceText(confidence: ThreatConfidence): String = stringResource(
    when (confidence) {
        ThreatConfidence.LOW -> R.string.apk_confidence_low
        ThreatConfidence.MEDIUM -> R.string.apk_confidence_medium
        ThreatConfidence.HIGH -> R.string.apk_confidence_high
    },
)

/**
 * Colour reinforces the severity/confidence the engine already assigned; it never adds a new
 * safe/unsafe judgement of its own. HIGH is the only URGENT case - it is a signed local
 * threat-data match or a high-severity heuristic finding, both already stated as fact in copy.
 */
private fun apkSeverityTone(severity: FindingSeverity): SentinelStatusTone = when (severity) {
    FindingSeverity.INFO -> SentinelStatusTone.INFORMATION
    FindingSeverity.LOW -> SentinelStatusTone.NEUTRAL
    FindingSeverity.MEDIUM -> SentinelStatusTone.REVIEW
    FindingSeverity.HIGH -> SentinelStatusTone.URGENT
}

private fun threatIndicatorTone(confidence: ThreatConfidence): SentinelStatusTone = when (confidence) {
    ThreatConfidence.LOW -> SentinelStatusTone.REVIEW
    ThreatConfidence.MEDIUM -> SentinelStatusTone.REVIEW
    ThreatConfidence.HIGH -> SentinelStatusTone.URGENT
}

/** Advanced-only declarative routing evidence; it is never a reachability or safety verdict. */
@Composable
private fun ComponentIntentFilterEvidence(component: ManifestComponent) {
    if (component.intentFilters.isEmpty() && !component.intentFiltersTruncated) return
    val context = LocalContext.current
    val unavailable = stringResource(R.string.report_unavailable)
    Text(stringResource(R.string.apk_intent_filters_title), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
    Text(stringResource(R.string.apk_intent_filters_neutrality), style = MaterialTheme.typography.bodySmall)
    if (component.intentFiltersTruncated) {
        Text(stringResource(R.string.apk_intent_filters_component_truncated), style = MaterialTheme.typography.bodySmall)
    }
    component.intentFilters.forEachIndexed { filterIndex, filter ->
        Text(stringResource(R.string.apk_intent_filter_label, filterIndex + 1), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
        IntentFilterValues(stringResource(R.string.apk_intent_filter_actions), filter.actions, unavailable)
        if (filter.actionsTruncated) Text(stringResource(R.string.apk_intent_filter_actions_truncated), style = MaterialTheme.typography.bodySmall)
        IntentFilterValues(stringResource(R.string.apk_intent_filter_categories), filter.categories, unavailable)
        if (filter.categoriesTruncated) Text(stringResource(R.string.apk_intent_filter_categories_truncated), style = MaterialTheme.typography.bodySmall)
        if (filter.data.isEmpty()) {
            Text(stringResource(R.string.apk_intent_filter_data_none), style = MaterialTheme.typography.bodySmall)
        }
        filter.data.forEachIndexed { dataIndex, data ->
            Text(stringResource(R.string.apk_intent_filter_data_label, dataIndex + 1), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
            data.scheme?.let { Text(stringResource(R.string.apk_intent_filter_scheme, it.safeApkTechnicalDisplay(unavailable)), style = MaterialTheme.typography.bodySmall) }
            data.host?.let { Text(stringResource(R.string.apk_intent_filter_host, it.safeApkTechnicalDisplay(unavailable)), style = MaterialTheme.typography.bodySmall) }
            data.port?.let { Text(stringResource(R.string.apk_intent_filter_port, it.safeApkTechnicalDisplay(unavailable)), style = MaterialTheme.typography.bodySmall) }
            data.mimeType?.let { Text(stringResource(R.string.apk_intent_filter_mime_type, it.safeApkTechnicalDisplay(unavailable)), style = MaterialTheme.typography.bodySmall) }
            data.paths.forEach { path ->
                Text(stringResource(R.string.apk_intent_filter_path, context.apkIntentFilterPathKind(path.kind), path.value.safeApkTechnicalDisplay(unavailable)), style = MaterialTheme.typography.bodySmall)
            }
            if (data.pathsTruncated) Text(stringResource(R.string.apk_intent_filter_paths_truncated), style = MaterialTheme.typography.bodySmall)
            if (data.valuesTruncated) Text(stringResource(R.string.apk_intent_filter_values_truncated), style = MaterialTheme.typography.bodySmall)
        }
        if (filter.dataTruncated) Text(stringResource(R.string.apk_intent_filter_data_truncated), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun IntentFilterValues(label: String, values: List<String>, unavailable: String) {
    if (values.isEmpty()) {
        Text(stringResource(R.string.apk_intent_filter_empty_values, label, stringResource(R.string.apk_intent_filter_none)), style = MaterialTheme.typography.bodySmall)
        return
    }
    Text(label, style = MaterialTheme.typography.bodySmall)
    values.forEach { value ->
        Text(stringResource(R.string.report_bullet_item, value.safeApkTechnicalDisplay(unavailable)), style = MaterialTheme.typography.bodySmall)
    }
}

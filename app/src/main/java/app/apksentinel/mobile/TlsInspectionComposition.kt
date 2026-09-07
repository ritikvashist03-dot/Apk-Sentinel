package app.apksentinel.mobile

import android.content.Context
import android.content.Intent
import android.os.Build
import android.content.pm.PackageManager
import app.apksentinel.engine.tlsinspection.CertificateInstallationState
import app.apksentinel.engine.tlsinspection.CertificateSetupConsent
import app.apksentinel.engine.tlsinspection.CertificateSetupResult
import app.apksentinel.engine.tlsinspection.TlsCaCertificateMetadata
import app.apksentinel.engine.tlsinspection.TlsCaCredentialLookup
import app.apksentinel.engine.tlsinspection.TlsCertificateSetupCoordinator
import app.apksentinel.engine.tlsinspection.android.AndroidCertificateRemovalGuidance
import app.apksentinel.engine.tlsinspection.android.AndroidKeyStoreCaCredentialProvider
import app.apksentinel.engine.tlsinspection.android.AndroidPublicApiCertificateInstallationVerifier
import app.apksentinel.engine.tlsinspection.android.AndroidUserMediatedCertificateInstallIntentFactory
import app.apksentinel.engine.tlsinspection.android.AndroidCertificateInstallIntentResult
import app.apksentinel.engine.tlsinspection.android.AndroidCaStoreCertificateInstallationVerifier
import app.apksentinel.engine.tlsinspection.TlsInspectionSnapshot
import app.apksentinel.engine.tlsinspection.TlsInspectionStartRejection
import app.apksentinel.engine.tlsinspection.AndroidCaStorePresence
import app.apksentinel.engine.tlsinspection.TlsInspectionPackageCategory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import app.apksentinel.engine.tlsinspection.TlsInspectionBridgeAcceptResult
import app.apksentinel.engine.tlsinspection.TlsInspectionBridgeEngineResult
import app.apksentinel.engine.tlsinspection.TlsInspectionBridgeEngineStatus
import app.apksentinel.engine.tlsinspection.TlsInspectionBridgeException
import app.apksentinel.engine.tlsinspection.TlsInspectionBridgeFailure
import app.apksentinel.engine.tlsinspection.DecryptedSessionConfiguration
import app.apksentinel.engine.tlsinspection.DecryptedSessionConsent
import app.apksentinel.engine.tlsinspection.DecryptedSessionRecorder
import app.apksentinel.engine.tlsinspection.DecryptedSessionSnapshot
import app.apksentinel.engine.tlsinspection.TlsKeyLogConfiguration
import app.apksentinel.engine.tlsinspection.TlsKeyLogConsent
import app.apksentinel.engine.tlsinspection.TlsKeyLogRecorder
import app.apksentinel.engine.tlsinspection.TlsKeyLogSnapshot
import app.apksentinel.networkmonitor.RawPcapngCaptureRuntime
import app.apksentinel.engine.tlsinspection.TlsInspectionBridgePlaintextConsumer
import app.apksentinel.engine.tlsinspection.TlsInspectionPlaintextDirection
import app.apksentinel.engine.tlsinspection.TlsInspectionSslenegineBridge
import app.apksentinel.networkmonitor.AppAttribution
import app.apksentinel.networkmonitor.NetworkMonitorRuntime
import app.apksentinel.networkmonitor.TlsInspectionFlow
import app.apksentinel.networkmonitor.TlsInspectionFlowDecision
import app.apksentinel.networkmonitor.TlsInspectionFlowResult
import app.apksentinel.networkmonitor.TlsInspectionFlowState
import app.apksentinel.networkmonitor.TlsInspectionRoute
import app.apksentinel.networkmonitor.TlsInspectionRouteFailure
import app.apksentinel.networkmonitor.TlsInspectionRouteSession
import app.apksentinel.networkmonitor.TlsInspectionSessionConfiguration
import app.apksentinel.networkmonitor.TlsInspectionSessionConsent
import app.apksentinel.networkmonitor.TlsInspectionSessionConsentRegistry
import app.apksentinel.networkmonitor.TlsInspectionBudget
import app.apksentinel.networkmonitor.TlsInspectionBudgetOpenResult
import java.io.ByteArrayOutputStream

/**
 * App boundary for the TLS-inspection foundation.
 *
 * This composition deliberately exposes certificate setup only. There is no
 * reviewed traffic bridge in this product, so it has no session-start or
 * decrypted-traffic API. That keeps the unavailable state fail-closed even
 * when a user has opened Android's certificate installer.
 */
object TlsInspectionComposition {
    private const val TLS_SESSION_DISCLOSURE_VERSION = "tls-session-v2"
    private const val DECRYPTED_SESSION_DISCLOSURE_VERSION = "decrypted-session-v1"
    private const val KEY_LOG_DISCLOSURE_VERSION = "tls-key-log-v1"
    private val lock = Any()
    private var credentialProvider: AndroidKeyStoreCaCredentialProvider? = null
    private var activeSession: app.apksentinel.engine.tlsinspection.TlsInspectionSession? = null
    private var appContext: Context? = null
    private var advancedEnabled: Boolean = false
    private var sessionConsentAcknowledged: Boolean = false
    private var sessionConsent: TlsInspectionSessionConsent? = null
    private var selectedPackages: Set<String> = emptySet()
    private var networkSessionActive: Boolean = false

    /** Off unless the user turns key logging on. A disabled recorder retains nothing. */
    @Volatile private var keyLogRecorder = TlsKeyLogRecorder()

    /** Startup performs no traffic action, certificate install, or key creation. */
    fun initialize(context: Context) {
        synchronized(lock) {
            appContext = context.applicationContext
            if (credentialProvider == null) credentialProvider = AndroidKeyStoreCaCredentialProvider()
        }
        NetworkMonitorRuntime.installTlsInspectionRouteForFutureSessions(AndroidTlsInspectionRoute)
    }

    internal fun certificateStatus(): TlsInspectionCertificateStatus = synchronized(lock) {
        val provider = credentialProvider ?: return@synchronized TlsInspectionCertificateStatus.NotInitialized
        when (val result = provider.existingMetadata()) {
            is TlsCaCredentialLookup.Available -> TlsInspectionCertificateStatus.Prepared(
                metadata = result.metadata,
                installationState = AndroidCaStoreCertificateInstallationVerifier {
                    provider.publicCertificateDerFor(it.alias, it.sha256Fingerprint)
                }.verify(result.metadata).state,
                caStorePresence = AndroidCaStoreCertificateInstallationVerifier.verifyPresence(
                    provider.publicCertificateDerFor(result.metadata.alias, result.metadata.sha256Fingerprint),
                ).presence,
            )
            is TlsCaCredentialLookup.Unavailable -> TlsInspectionCertificateStatus.Unavailable
        }
    }

    /**
     * Must be called directly from a deliberate certificate-setup click after
     * the caller has collected the distinct setup consent. The returned intent
     * is the Android system installer; this method never launches it itself.
     */
    internal fun prepareSystemCertificateInstaller(
        consent: CertificateSetupConsent,
        apiLevel: Int = Build.VERSION.SDK_INT,
    ): TlsInspectionCertificateSetupResult = synchronized(lock) {
        val provider = credentialProvider ?: return@synchronized TlsInspectionCertificateSetupResult.NotInitialized
        val coordinator = TlsCertificateSetupCoordinator(
            credentialProvider = provider,
            removalGuidanceProvider = AndroidCertificateRemovalGuidance::forVerificationState,
        )
        when (val setup = coordinator.prepareUserMediatedInstall(consent)) {
            is CertificateSetupResult.Rejected -> TlsInspectionCertificateSetupResult.Unavailable
            is CertificateSetupResult.ReadyForUserMediatedInstall -> when (
                val intent = AndroidUserMediatedCertificateInstallIntentFactory(provider)
                    .createInstallRoute(apiLevel, setup.installAction)
            ) {
                is AndroidCertificateInstallIntentResult.KeyChainInstaller ->
                    TlsInspectionCertificateSetupResult.SystemInstallerReady(intent.intent)
                is AndroidCertificateInstallIntentResult.SafCertificateExport ->
                    TlsInspectionCertificateSetupResult.SafExportReady(intent.intent, intent.certificateDer)
                AndroidCertificateInstallIntentResult.UnsupportedApi ->
                    TlsInspectionCertificateSetupResult.UnsupportedApi
                AndroidCertificateInstallIntentResult.CertificateUnavailable ->
                    TlsInspectionCertificateSetupResult.Unavailable
            }
        }
    }

    /** Legacy preflight hook; traffic starts only through NetworkMonitor's active VPN request. */
    internal fun operationalStartIsRejected(): TlsInspectionStartRejection? = null

    internal fun currentTunnelConfiguration(): app.apksentinel.networkmonitor.TlsInspectionTunnelConfiguration = synchronized(lock) {
        val consent = sessionConsent
        if (!advancedEnabled || !sessionConsentAcknowledged || consent == null || selectedPackages.isEmpty()) {
            app.apksentinel.networkmonitor.TlsInspectionTunnelConfiguration()
        } else {
            val configuration = app.apksentinel.networkmonitor.TlsInspectionTunnelConfiguration(
                enabled = true,
                selectedPackages = selectedPackages,
                sessionConsentVersion = TLS_SESSION_DISCLOSURE_VERSION,
                sessionConsentAcknowledgedAtMillis = consent.acknowledgedAtMillis,
                sessionConsentNonce = consent.nonce,
            )
            // Issuing a start request consumes the UI-side acknowledgement.
            // The service consumes the matching process-local nonce exactly
            // once; a later VPN start must collect a new acknowledgement.
            sessionConsentAcknowledged = false
            sessionConsent = null
            configuration
        }
    }

    /**
     * Retains decrypted content for export. Replaced wholesale rather than mutated, because
     * a recorder built from a disabled configuration can never retain anything — that makes
     * "off" a property of the object, not a flag some later call could forget to check.
     */
    @Volatile
    private var decryptedRecorder: DecryptedSessionRecorder = DecryptedSessionRecorder()

    /**
     * Turns decrypted-session retention on or off. Turning it off zeroizes immediately
     * rather than waiting for the session to end.
     */
    /**
     * Turns TLS key logging on or off for future flows.
     *
     * With this on, the leg facing the app is driven by BouncyCastle so its secrets can be
     * read, and those secrets are embedded in any running capture as a Decryption Secrets
     * Block. That is what lets the exported file decrypt when it is opened.
     *
     * It is the most sensitive switch in the product: a key log plus the capture reveals the
     * traffic to anyone holding both, and it stays useful for as long as the capture exists.
     */
    internal fun setKeyLogCapture(enabled: Boolean, nowMillis: Long = System.currentTimeMillis()) {
        synchronized(lock) { setKeyLogCaptureLocked(enabled, nowMillis) }
    }

    private fun setKeyLogCaptureLocked(enabled: Boolean, nowMillis: Long = System.currentTimeMillis()) {
        keyLogRecorder.clear()
        keyLogRecorder = if (enabled) {
            TlsKeyLogRecorder(
                TlsKeyLogConfiguration(
                    enabled = true,
                    consent = TlsKeyLogConsent(KEY_LOG_DISCLOSURE_VERSION, nowMillis),
                ),
            )
        } else {
            TlsKeyLogRecorder()
        }
    }

    internal fun isKeyLogCaptureEnabled(): Boolean = keyLogRecorder.snapshot().enabledForSession

    internal fun keyLogSnapshot(): TlsKeyLogSnapshot = keyLogRecorder.snapshot()

    internal fun exportKeyLog(output: java.io.OutputStream): Long = keyLogRecorder.exportTo(output)

    internal fun clearKeyLog() = keyLogRecorder.clear()

    /**
     * Records secrets and mirrors them into the running capture.
     *
     * The capture copy is what makes decrypt-on-open work; the recorder copy is what the
     * user exports as a standalone key log file.
     */
    private fun onKeyLogSecrets(secrets: List<app.apksentinel.engine.tlsinspection.TlsKeyLogSecrets>) {
        val recorder = keyLogRecorder
        recorder.record(secrets)
        recorder.drainPendingBlock()?.let(RawPcapngCaptureRuntime::offerTlsSecrets)
    }

    internal fun setDecryptedSessionCapture(enabled: Boolean, nowMillis: Long = System.currentTimeMillis()) {
        val previous = decryptedRecorder
        decryptedRecorder = if (enabled) {
            DecryptedSessionRecorder(
                DecryptedSessionConfiguration(
                    enabled = true,
                    consent = DecryptedSessionConsent(DECRYPTED_SESSION_DISCLOSURE_VERSION, nowMillis),
                ),
            )
        } else {
            DecryptedSessionRecorder()
        }
        previous.clear()
    }

    internal fun decryptedSessionSnapshot(): DecryptedSessionSnapshot = decryptedRecorder.snapshot()

    internal fun exportDecryptedSession(output: java.io.OutputStream): Long = decryptedRecorder.exportTo(output)

    internal fun clearDecryptedSession() = decryptedRecorder.clear()

    internal fun setAdvancedEnabled(enabled: Boolean) = synchronized(lock) {
        advancedEnabled = enabled
        if (!enabled) {
            TlsInspectionSessionConsentRegistry.revoke(sessionConsent?.nonce)
            sessionConsent = null
            sessionConsentAcknowledged = false
        }
    }

    internal fun setSessionConsentAcknowledged(acknowledged: Boolean) = synchronized(lock) {
        sessionConsentAcknowledged = acknowledged
        if (acknowledged) {
            TlsInspectionSessionConsentRegistry.revoke(sessionConsent?.nonce)
            val issued = TlsInspectionSessionConsentRegistry.issue(TLS_SESSION_DISCLOSURE_VERSION)
            sessionConsent = issued
        } else {
            TlsInspectionSessionConsentRegistry.revoke(sessionConsent?.nonce)
            sessionConsent = null
        }
    }

    internal fun isSessionConsentArmed(): Boolean = synchronized(lock) {
        sessionConsentAcknowledged && sessionConsent != null
    }

    internal fun setSelectedPackages(packages: Set<String>) = synchronized(lock) {
        selectedPackages = packages.toSet()
    }

    internal fun isNetworkSessionActive(): Boolean = synchronized(lock) { networkSessionActive }

    internal fun activeSessionSnapshot(): TlsInspectionSnapshot? = synchronized(lock) { activeSession?.snapshot() }

    /**
     * Returns a bounded display catalog. Shared-UID packages and conservative
     * sensitive-name matches are excluded; the remaining package names are
     * eligible only after explicit user selection and session consent.
     */
    internal fun packageOptions(context: Context): List<TlsInspectionPackageOption> = runCatching {
        val applications = if (Build.VERSION.SDK_INT >= 33) {
            context.packageManager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getInstalledApplications(0)
        }
        val sharedUids = applications.groupBy { it.uid }
            .filterValues { it.size > 1 }
            .keys
        applications
            .asSequence()
            .map { info ->
                TlsInspectionPackageOption(
                    packageName = info.packageName,
                    label = context.packageManager.getApplicationLabel(info).toString(),
                    category = if (info.uid in sharedUids) {
                        TlsInspectionPackageCategory.SHARED_UID
                    } else {
                        classifyPackageName(info.packageName)
                    },
                    sharedUid = info.uid in sharedUids,
                )
            }
            .sortedBy { it.label.lowercase() }
            .take(TlsInspectionPackageOption.MAX_DISPLAYED)
            .toList()
    }.getOrDefault(emptyList())

    /** Conservative name-only guard; sensitive-name matches remain excluded. */
    private fun classifyPackageName(packageName: String): TlsInspectionPackageCategory = when {
        SENSITIVE_BANKING_PATTERN.containsMatchIn(packageName) -> TlsInspectionPackageCategory.BANKING
        SENSITIVE_PAYMENT_PATTERN.containsMatchIn(packageName) -> TlsInspectionPackageCategory.PAYMENT
        SENSITIVE_AUTH_PATTERN.containsMatchIn(packageName) -> TlsInspectionPackageCategory.AUTHENTICATION
        SENSITIVE_PASSWORD_PATTERN.containsMatchIn(packageName) -> TlsInspectionPackageCategory.PASSWORD_MANAGER
        SENSITIVE_HEALTH_PATTERN.containsMatchIn(packageName) -> TlsInspectionPackageCategory.HEALTH
        packageName.substringBeforeLast('.', "").isBlank() -> TlsInspectionPackageCategory.UNKNOWN
        else -> TlsInspectionPackageCategory.GENERAL
    }

    private val SENSITIVE_BANKING_PATTERN = Regex("(bank|banking|wallet|finance|credit|loan)", RegexOption.IGNORE_CASE)
    private val SENSITIVE_PAYMENT_PATTERN = Regex("(paypal|stripe|payment|paytm|gpay|googlepay|phonepe)", RegexOption.IGNORE_CASE)
    private val SENSITIVE_AUTH_PATTERN = Regex("(auth|2fa|otp|identity|passport)", RegexOption.IGNORE_CASE)
    private val SENSITIVE_PASSWORD_PATTERN = Regex("(password|1password|bitwarden|keepass|lastpass|dashlane)", RegexOption.IGNORE_CASE)
    private val SENSITIVE_HEALTH_PATTERN = Regex("(health|medical|clinic|hospital|patient)", RegexOption.IGNORE_CASE)

    /** The only app-owned TLS route. It is installed in NetworkMonitorRuntime at startup. */
    private object AndroidTlsInspectionRoute : TlsInspectionRoute {
        override fun openSession(configuration: TlsInspectionSessionConfiguration): TlsInspectionRouteSession? = synchronized(TlsInspectionComposition.lock) {
            val context = TlsInspectionComposition.appContext ?: return@synchronized null
            val provider = TlsInspectionComposition.credentialProvider ?: return@synchronized null
            val selectable = TlsInspectionComposition.packageOptions(context).filter { it.selectable }.map { it.packageName }.toSet()
            if (!configuration.selectedPackages.all { it in selectable }) return@synchronized null
            val status = TlsInspectionComposition.certificateStatus()
            if (status !is TlsInspectionCertificateStatus.Prepared ||
                status.installationState != CertificateInstallationState.INSTALLED
            ) return@synchronized null
            provider.withEphemeralCredential { certificate, privateKey ->
                TlsInspectionComposition.networkSessionActive = true
                AndroidTlsInspectionRouteSession(
                    certificate,
                    privateKey,
                    configuration.selectedPackages,
                    configuration.maximumSessionBytes,
                    configuration.maximumBytesPerFlow,
                    configuration.maximumDurationMillis,
                )
            }
        }
    }

    private class AndroidTlsInspectionRouteSession(
        private val certificate: X509Certificate,
        private val privateKey: PrivateKey,
        private val selectedPackages: Set<String>,
        maximumSessionBytes: Int,
        maximumBytesPerFlow: Int,
        maximumDurationMillis: Long,
    ) : TlsInspectionRouteSession {
        @Volatile private var stopped = false
        private val budget = TlsInspectionBudget(
            maximumSessionBytes = maximumSessionBytes,
            maximumBytesPerFlow = maximumBytesPerFlow,
            maximumDurationMillis = maximumDurationMillis,
        )
        private val failureCounts = java.util.concurrent.ConcurrentHashMap<TlsInspectionRouteFailure, java.util.concurrent.atomic.AtomicLong>()

        override fun openTcpFlow(attribution: AppAttribution, remotePort: Int): TlsInspectionFlowDecision {
            if (stopped) return TlsInspectionFlowDecision.Reject(TlsInspectionRouteFailure.CLOSED)
            if (remotePort != 443) return TlsInspectionFlowDecision.Bypass
            val known = attribution as? AppAttribution.Known ?: return TlsInspectionFlowDecision.Bypass
            if (known.packageName !in selectedPackages) return TlsInspectionFlowDecision.Bypass
            return when (val opened = budget.openFlow()) {
                is TlsInspectionBudgetOpenResult.Rejected -> reject(opened.reason)
                is TlsInspectionBudgetOpenResult.Accepted -> TlsInspectionFlowDecision.Intercept(
                    AndroidTlsInspectionFlow(
                        certificate = certificate,
                        privateKey = privateKey,
                        budget = budget,
                        flowId = opened.flowId,
                        recordFailure = ::recordFailure,
                    ),
                )
            }
        }

        override fun rejectUdpFlow(attribution: AppAttribution, remotePort: Int): Boolean {
            val known = attribution as? AppAttribution.Known ?: return false
            return remotePort == 443 && known.packageName in selectedPackages
        }

        override fun stop() {
            stopped = true
            budget.stop()
            synchronized(TlsInspectionComposition.lock) { TlsInspectionComposition.networkSessionActive = false }
        }

        override fun failureCounts(): Map<TlsInspectionRouteFailure, Long> =
            failureCounts.mapValues { (_, count) -> count.get() }

        private fun reject(reason: TlsInspectionRouteFailure): TlsInspectionFlowDecision.Reject {
            recordFailure(reason)
            return TlsInspectionFlowDecision.Reject(reason)
        }

        private fun recordFailure(reason: TlsInspectionRouteFailure) {
            failureCounts.computeIfAbsent(reason) { java.util.concurrent.atomic.AtomicLong() }.incrementAndGet()
        }
    }

    /** SSLEngine adapter: callback re-wraps ephemeral plaintext and never stores it. */
    private class AndroidTlsInspectionFlow(
        private val certificate: X509Certificate,
        private val privateKey: PrivateKey,
        private val budget: TlsInspectionBudget,
        private val flowId: Long,
        private val recordFailure: (TlsInspectionRouteFailure) -> Unit,
    ) : TlsInspectionFlow {
        private val lock = Any()
        private var bridge: TlsInspectionSslenegineBridge? = null
        private var closed = false
        private var clientHelloAccepted = false
        private val clientHelloBytes = ByteArrayOutputStream()
        private val upstreamOutput = ByteArrayOutputStream()
        private val clientOutput = ByteArrayOutputStream()
        private val callback = TlsInspectionBridgePlaintextConsumer { direction, segment, _ ->
            // Copy before forwarding: this is the only point the segment is valid, and the
            // recorder is a no-op unless retention was separately consented.
            decryptedRecorder.record(direction, segment, System.currentTimeMillis())
            val active = bridge
            if (active != null) {
                val result = if (direction == TlsInspectionPlaintextDirection.CLIENT_TO_UPSTREAM) {
                    active.wrapForUpstream(segment)
                } else {
                    active.wrapForClient(segment)
                }
                if (direction == TlsInspectionPlaintextDirection.CLIENT_TO_UPSTREAM) {
                    upstreamOutput.write(result.outbound)
                } else {
                    clientOutput.write(result.outbound)
                }
            }
        }

        override fun onClientCiphertext(ciphertext: ByteArray): TlsInspectionFlowResult = synchronized(lock) {
            if (closed) return@synchronized TlsInspectionFlowResult.closed()
            clearOutputs()
            var completeClientHello = ByteArray(0)
            try {
                budget.admit(flowId, ciphertext.size)?.let { reason ->
                    return@synchronized failAndClose(reason)
                }
                val active = bridge ?: TlsInspectionSslenegineBridge(
                    caCertificate = certificate,
                    caPrivateKey = privateKey,
                    plaintextConsumer = callback,
                    // Null unless the user turned key logging on, which keeps the proven
                    // JSSE leg in place for every ordinary session.
                    keyLogSink = if (isKeyLogCaptureEnabled()) ::onKeyLogSecrets else null,
                ).also { bridge = it }
                if (clientHelloAccepted) {
                    val engineResult = active.unwrapFromClient(ciphertext)
                    drainHandshake(active)
                    return@synchronized if (engineResult.status == TlsInspectionBridgeEngineStatus.FAILED) {
                        failed(mapFailure(requireNotNull(engineResult.failure)))
                    } else {
                        result(
                            if (engineResult.status == TlsInspectionBridgeEngineStatus.NEED_MORE_INPUT) {
                                TlsInspectionFlowState.NEED_MORE_INPUT
                            } else TlsInspectionFlowState.PROGRESSED,
                        )
                    }
                }
                if (ciphertext.size > 64 * 1_024 - clientHelloBytes.size()) {
                    return@synchronized failed(TlsInspectionRouteFailure.OVERSIZE)
                }
                clientHelloBytes.write(ciphertext)
                completeClientHello = clientHelloBytes.toByteArray()
                when (val accepted = active.offerClientHello(ciphertext)) {
                    TlsInspectionBridgeAcceptResult.NeedMore -> result(TlsInspectionFlowState.NEED_MORE_INPUT)
                    is TlsInspectionBridgeAcceptResult.Rejected -> {
                        clientHelloBytes.reset()
                        failed(mapFailure(accepted.reason))
                    }
                    is TlsInspectionBridgeAcceptResult.Accepted -> {
                        clientHelloBytes.reset()
                        clientHelloAccepted = true
                        active.createClientFacingLeg()
                        active.createUpstreamEngine(SSLContext.getDefault())
                        upstreamOutput.write(active.wrapForUpstream(ByteArray(0)).outbound)
                        clientOutput.write(active.wrapForClient(ByteArray(0)).outbound)
                        val engineResult = active.unwrapFromClient(completeClientHello)
                        drainHandshake(active)
                        if (engineResult.status == TlsInspectionBridgeEngineStatus.FAILED) {
                            failed(mapFailure(requireNotNull(engineResult.failure)))
                        } else {
                            result(
                                if (engineResult.status == TlsInspectionBridgeEngineStatus.NEED_MORE_INPUT) {
                                    TlsInspectionFlowState.NEED_MORE_INPUT
                                } else TlsInspectionFlowState.PROGRESSED,
                            )
                        }
                    }
                }
            } catch (failure: TlsInspectionBridgeException) {
                failed(mapFailure(failure.reason))
            } catch (_: RuntimeException) {
                failed(TlsInspectionRouteFailure.TLS_PROVIDER_UNAVAILABLE)
            } finally {
                ciphertext.fill(0)
                completeClientHello.fill(0)
            }
        }

        override fun onUpstreamCiphertext(ciphertext: ByteArray): TlsInspectionFlowResult = synchronized(lock) {
            if (closed) return@synchronized TlsInspectionFlowResult.closed()
            clearOutputs()
            try {
                budget.admit(flowId, ciphertext.size)?.let { reason ->
                    return@synchronized failAndClose(reason)
                }
                val active = bridge ?: return@synchronized failAndClose(TlsInspectionRouteFailure.CLOSED)
                val engineResult = active.unwrapFromUpstream(ciphertext)
                drainHandshake(active)
                if (engineResult.status == TlsInspectionBridgeEngineStatus.FAILED) {
                    failed(mapFailure(requireNotNull(engineResult.failure)))
                } else {
                    result(
                        if (engineResult.status == TlsInspectionBridgeEngineStatus.NEED_MORE_INPUT) {
                            TlsInspectionFlowState.NEED_MORE_INPUT
                        } else TlsInspectionFlowState.PROGRESSED,
                    )
                }
            } finally {
                ciphertext.fill(0)
            }
        }

        override fun onClientClosed(): TlsInspectionFlowResult = synchronized(lock) {
            if (closed) return@synchronized TlsInspectionFlowResult.closed()
            clearOutputs()
            budget.admit(flowId, 0)?.let { reason ->
                return@synchronized failAndClose(reason)
            }
            val active = bridge ?: return@synchronized failAndClose(TlsInspectionRouteFailure.CLOSED)
            val result = active.closeForUpstream()
            if (result.status == TlsInspectionBridgeEngineStatus.FAILED) {
                failed(mapFailure(requireNotNull(result.failure)))
            } else {
                TlsInspectionFlowResult(
                    state = TlsInspectionFlowState.CLOSED,
                    toUpstream = result.outbound,
                )
            }
        }

        override fun onUpstreamClosed(): TlsInspectionFlowResult = synchronized(lock) {
            if (closed) return@synchronized TlsInspectionFlowResult.closed()
            clearOutputs()
            budget.admit(flowId, 0)?.let { reason ->
                return@synchronized failAndClose(reason)
            }
            val active = bridge ?: return@synchronized failAndClose(TlsInspectionRouteFailure.CLOSED)
            val result = active.closeForClient()
            if (result.status == TlsInspectionBridgeEngineStatus.FAILED) {
                failed(mapFailure(requireNotNull(result.failure)))
            } else {
                TlsInspectionFlowResult(
                    state = TlsInspectionFlowState.CLOSED,
                    toClient = result.outbound,
                )
            }
        }

        override fun close() = synchronized(lock) {
            closed = true
            bridge?.close()
            bridge = null
            clientHelloAccepted = false
            clientHelloBytes.reset()
            budget.closeFlow(flowId)
            clearOutputs()
        }

        private fun clearOutputs() {
            upstreamOutput.reset()
            clientOutput.reset()
        }

        private fun drainHandshake(active: TlsInspectionSslenegineBridge) {
            upstreamOutput.write(active.wrapForUpstream(ByteArray(0)).outbound)
            clientOutput.write(active.wrapForClient(ByteArray(0)).outbound)
        }

        private fun result(state: TlsInspectionFlowState) = TlsInspectionFlowResult(
            state = state,
            toUpstream = upstreamOutput.toByteArray().also {
                require(it.size <= TlsInspectionFlowResult.MAX_OUTPUT_BYTES)
            },
            toClient = clientOutput.toByteArray().also {
                require(it.size <= TlsInspectionFlowResult.MAX_OUTPUT_BYTES)
            },
        )

        private fun failed(reason: TlsInspectionRouteFailure) = TlsInspectionFlowResult.failed(reason)

        private fun failAndClose(reason: TlsInspectionRouteFailure): TlsInspectionFlowResult {
            recordFailure(reason)
            closed = true
            bridge?.close()
            bridge = null
            clientHelloAccepted = false
            clientHelloBytes.reset()
            budget.closeFlow(flowId)
            clearOutputs()
            return failed(reason)
        }

        private fun mapFailure(reason: TlsInspectionBridgeFailure): TlsInspectionRouteFailure = when (reason) {
            TlsInspectionBridgeFailure.NO_SNI -> TlsInspectionRouteFailure.NO_SNI
            TlsInspectionBridgeFailure.MALFORMED_CLIENT_HELLO,
            TlsInspectionBridgeFailure.INVALID_SNI,
            TlsInspectionBridgeFailure.UNSUPPORTED_TLS_RECORD -> TlsInspectionRouteFailure.MALFORMED_CLIENT_HELLO
            TlsInspectionBridgeFailure.QUIC_NOT_SUPPORTED -> TlsInspectionRouteFailure.QUIC_UNSUPPORTED
            TlsInspectionBridgeFailure.CLIENT_HELLO_TOO_LARGE,
            TlsInspectionBridgeFailure.CIPHERTEXT_BUFFER_FULL,
            TlsInspectionBridgeFailure.PLAINTEXT_TOO_LARGE -> TlsInspectionRouteFailure.OVERSIZE
            TlsInspectionBridgeFailure.UNSUPPORTED_PROTOCOL,
            TlsInspectionBridgeFailure.NO_UPSTREAM_PROTOCOL -> TlsInspectionRouteFailure.UNSUPPORTED_PROTOCOL
            TlsInspectionBridgeFailure.TLS_PROVIDER_UNAVAILABLE -> TlsInspectionRouteFailure.TLS_PROVIDER_UNAVAILABLE
            TlsInspectionBridgeFailure.USER_CA_REJECTED -> TlsInspectionRouteFailure.USER_CA_REJECTED
            TlsInspectionBridgeFailure.CERTIFICATE_PINNING_REJECTED -> TlsInspectionRouteFailure.CERTIFICATE_PINNING_REJECTED
            TlsInspectionBridgeFailure.NON_HTTP -> TlsInspectionRouteFailure.NON_HTTP
            TlsInspectionBridgeFailure.CLOSED -> TlsInspectionRouteFailure.CLOSED
            else -> TlsInspectionRouteFailure.UPSTREAM_TRUST_REJECTED
        }
    }

    internal fun stopSessionForUser(): TlsInspectionSnapshot? = synchronized(lock) {
        activeSession?.stop()
        activeSession?.snapshot()
    }

    /** No app-owned TLS session is currently composed; this remains safe for lifecycle cleanup. */
    fun stopForBackground() {
        // Decrypted content must not survive the app going to the background.
        setDecryptedSessionCapture(enabled = false)
        synchronized(lock) {
            activeSession?.stop()
            activeSession = null
            TlsInspectionSessionConsentRegistry.revoke(sessionConsent?.nonce)
            sessionConsent = null
            sessionConsentAcknowledged = false
        }
    }

    /**
     * Removes only the app's non-exportable Android Keystore key. A user CA
     * already added through Android Settings can remain and must be removed by
     * the user there; Android has no general API for APK Sentinel to remove it.
     */
    internal fun eraseForPrivacy(): TlsInspectionPrivacyEraseResult = synchronized(lock) {
        activeSession?.stop()
        activeSession = null
        advancedEnabled = false
        sessionConsentAcknowledged = false
        TlsInspectionSessionConsentRegistry.revoke(sessionConsent?.nonce)
        sessionConsent = null
        selectedPackages = emptySet()
        networkSessionActive = false
        // The retained decrypted transcript and TLS key log are the most revealing things
        // this app can hold, and neither lives in the keystore. Erase has to zeroize them
        // explicitly or "erase my data" leaves the readable material behind.
        decryptedRecorder.clear()
        keyLogRecorder.clear()
        setKeyLogCaptureLocked(enabled = false)
        val erased = runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(AndroidKeyStoreCaCredentialProvider.DEFAULT_ALIAS)) {
                keyStore.deleteEntry(AndroidKeyStoreCaCredentialProvider.DEFAULT_ALIAS)
            }
            val publicAlias = AndroidKeyStoreCaCredentialProvider.publicCertificateAlias(
                AndroidKeyStoreCaCredentialProvider.DEFAULT_ALIAS,
            )
            if (keyStore.containsAlias(publicAlias)) keyStore.deleteEntry(publicAlias)
            !keyStore.containsAlias(AndroidKeyStoreCaCredentialProvider.DEFAULT_ALIAS)
        }.getOrDefault(false)
        TlsInspectionPrivacyEraseResult(
            sessionStopped = true,
            appKeyErased = erased,
        )
    }
}

internal sealed interface TlsInspectionCertificateStatus {
    data object NotInitialized : TlsInspectionCertificateStatus
    data object Unavailable : TlsInspectionCertificateStatus
    data class Prepared(
        val metadata: TlsCaCertificateMetadata,
        val installationState: CertificateInstallationState,
        val caStorePresence: AndroidCaStorePresence,
    ) : TlsInspectionCertificateStatus
}

internal sealed interface TlsInspectionCertificateSetupResult {
    data object NotInitialized : TlsInspectionCertificateSetupResult
    data object Unavailable : TlsInspectionCertificateSetupResult
    data class SystemInstallerReady(val intent: Intent) : TlsInspectionCertificateSetupResult
    data class SafExportReady(val intent: Intent, val certificateDer: ByteArray) : TlsInspectionCertificateSetupResult
    data object UnsupportedApi : TlsInspectionCertificateSetupResult
}

internal data class TlsInspectionPrivacyEraseResult(
    val sessionStopped: Boolean,
    val appKeyErased: Boolean,
) {
    val confirmed: Boolean get() = sessionStopped && appKeyErased
}

internal data class TlsInspectionPackageOption(
    val packageName: String,
    val label: String,
    val category: TlsInspectionPackageCategory,
    val sharedUid: Boolean = false,
) {
    val selectable: Boolean get() = !sharedUid && !TlsInspectionUiPolicy.isMandatoryExcluded(category)

    companion object { const val MAX_DISPLAYED = 25 }
}

package app.apksentinel.mobile

import android.content.Context
import android.graphics.Paint
import android.graphics.pdf.PdfDocument
import app.apksentinel.core.security.SafeTextNormalizer
import app.apksentinel.inspector.ApkInspectionResult
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.text.DateFormat
import java.util.Date

/** A deliberately small, human-readable report. It never carries raw APK evidence or identifiers. */
internal data class RedactedPdfReport(
    val title: String,
    val generatedAt: String,
    val scope: String,
    val redaction: String,
    val summary: List<String>,
    val limitationsTitle: String,
    val limitations: List<String>,
)

internal fun ApkInspectionResult.toRedactedPdfReport(
    context: Context,
    generatedAtMillis: Long = System.currentTimeMillis(),
): RedactedPdfReport = RedactedPdfReport(
    title = context.getString(R.string.report_pdf_title),
    generatedAt = context.getString(
        R.string.report_pdf_generated_at,
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(generatedAtMillis)),
    ),
    scope = context.getString(R.string.report_pdf_scope),
    redaction = context.getString(R.string.report_pdf_redaction),
    summary = buildList {
        risk?.let { add(context.getString(R.string.report_pdf_risk, it.score, context.apkRiskLevel(it.level))) }
        add(context.getString(if (isComplete) R.string.report_pdf_complete else R.string.report_pdf_partial))
        findings.take(MAX_FINDINGS).forEach { finding ->
            add(context.getString(R.string.report_pdf_finding, context.apkSeverity(finding.severity), context.apkFindingTitle(finding.code)))
        }
    },
    limitationsTitle = context.getString(R.string.report_pdf_limitations),
    limitations = (risk?.limitations.orEmpty().map { context.apkRiskLimitation(it.code) } +
        failures.map { context.apkInspectionFailure(it.code) }).distinct().take(MAX_LIMITATIONS),
)

/** Pure line/page planner, retained separately so bounds are unit-testable without Android rendering. */
internal object RedactedPdfLayout {
    const val MAX_PAGES = 6
    const val MAX_LINES_PER_PAGE = 34
    const val MAX_LINE_CODE_POINTS = 72

    fun pages(report: RedactedPdfReport): List<List<String>> {
        val lines = buildList {
            add(report.title)
            add(report.generatedAt)
            add(report.scope)
            add(report.redaction)
            add("")
            addAll(report.summary.flatMap(::wrap))
            if (report.limitations.isNotEmpty()) {
                add("")
                add(report.limitationsTitle)
                report.limitations.forEach { addAll(wrap("\u2022 $it")) }
            }
        }.take(MAX_PAGES * MAX_LINES_PER_PAGE)
        return lines.chunked(MAX_LINES_PER_PAGE).ifEmpty { listOf(listOf(report.title)) }
    }

    private fun wrap(value: String): List<String> {
        val safe = SafeTextNormalizer.normalizeDisplayText(value, "Unavailable", MAX_LINE_CODE_POINTS * 4)
        if (safe.codePointCount(0, safe.length) <= MAX_LINE_CODE_POINTS) return listOf(safe)
        val result = mutableListOf<String>()
        var remaining = safe
        while (remaining.isNotBlank() && result.size < MAX_LINES_PER_PAGE) {
            val end = remaining.offsetByCodePoints(0, minOf(MAX_LINE_CODE_POINTS, remaining.codePointCount(0, remaining.length)))
            val candidate = remaining.substring(0, end)
            val split = candidate.lastIndexOf(' ').takeIf { it >= MAX_LINE_CODE_POINTS / 2 } ?: candidate.length
            result += remaining.substring(0, split).trim()
            remaining = remaining.substring(split).trimStart()
        }
        return result
    }
}

internal object RedactedPdfRenderer {
    const val MAX_BYTES = 512 * 1024

    fun render(report: RedactedPdfReport): ByteArray {
        val document = PdfDocument()
        return try {
            val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 11f }
            RedactedPdfLayout.pages(report).forEachIndexed { index, lines ->
                val page = document.startPage(PdfDocument.PageInfo.Builder(612, 792, index + 1).create())
                var y = 52f
                lines.forEach { line ->
                    page.canvas.drawText(line, 42f, y, paint)
                    y += 20f
                }
                document.finishPage(page)
            }
            val output = ByteArrayOutputStream()
            document.writeTo(BoundedOutputStream(output, MAX_BYTES))
            output.toByteArray()
        } finally {
            document.close()
        }
    }
}

internal object RedactedPdfCache {
    private const val DIRECTORY = "redacted-reports"
    const val MAX_AGE_MILLIS = 24L * 60L * 60L * 1_000L

    fun write(context: Context, bytes: ByteArray, nowMillis: Long = System.currentTimeMillis()): File? {
        if (bytes.isEmpty() || bytes.size > RedactedPdfRenderer.MAX_BYTES) return null
        val directory = File(context.cacheDir, DIRECTORY)
        if (!directory.exists() && !directory.mkdirs()) return null
        cleanup(context, nowMillis)
        var file: File? = null
        return runCatching {
            File.createTempFile("redacted-report-", ".pdf", directory).also { created ->
                file = created
                FileOutputStream(created).use { it.write(bytes) }
            }
        }.getOrElse {
            file?.delete()
            null
        }
    }

    fun cleanup(context: Context, nowMillis: Long = System.currentTimeMillis()) {
        File(context.cacheDir, DIRECTORY).listFiles().orEmpty().forEach { file ->
            if (RedactedPdfRetention.shouldDelete(file.lastModified(), nowMillis)) file.delete()
        }
    }
}

internal object RedactedPdfRetention {
    fun shouldDelete(lastModifiedMillis: Long, nowMillis: Long): Boolean =
        lastModifiedMillis <= 0L || nowMillis < lastModifiedMillis || nowMillis - lastModifiedMillis >= RedactedPdfCache.MAX_AGE_MILLIS
}

private class BoundedOutputStream(
    private val delegate: OutputStream,
    private val maximumBytes: Int,
) : OutputStream() {
    private var written = 0

    override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)
    override fun write(buffer: ByteArray, offset: Int, length: Int) {
        if (length < 0 || written > maximumBytes - length) throw IllegalStateException("PDF exceeds its size limit.")
        delegate.write(buffer, offset, length)
        written += length
    }
}

private const val MAX_FINDINGS = 12
private const val MAX_LIMITATIONS = 12

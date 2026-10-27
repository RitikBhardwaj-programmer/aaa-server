package `in`.ac.nitsri.wifi.core

import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

class HttpRequest(
    val method: String,
    val url: String,
    val headers: Map<String, String>,
    val body: String? = null,
) {
    // No toString with headers: the Authorization header must never reach a log.
    override fun toString() = "$method $url"
}

class HttpResponse(val status: Int, val body: String)

/** One HTTP exchange. Throws [IOException] when the server cannot be reached. */
fun interface HttpTransport {
    @Throws(IOException::class)
    fun execute(request: HttpRequest): HttpResponse
}

/**
 * [HttpURLConnection] transport (an https URL gives an `HttpsURLConnection` with the system trust
 * store and host name check). No cache, no redirects, no cookies.
 */
class UrlConnectionTransport(
    private val connectTimeoutMs: Int = 10_000,
    private val readTimeoutMs: Int = 20_000,
) : HttpTransport {

    override fun execute(request: HttpRequest): HttpResponse {
        val conn = URL(request.url).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = request.method
            conn.instanceFollowRedirects = false
            conn.useCaches = false
            conn.connectTimeout = connectTimeoutMs
            conn.readTimeout = readTimeoutMs
            request.headers.forEach { (name, value) -> conn.setRequestProperty(name, value) }
            if (request.body != null) {
                val bytes = request.body.toByteArray(Charsets.UTF_8)
                // Bodies are small (16 KB at most). No streaming mode: with it, the JDK connection
                // drops the body of a 401 answer.
                conn.doOutput = true
                conn.outputStream.use { it.write(bytes) }
            }
            val status = conn.responseCode
            val stream: InputStream? = try {
                conn.inputStream
            } catch (e: IOException) {
                conn.errorStream
            }
            return HttpResponse(status, stream?.use(::readCapped) ?: "")
        } finally {
            conn.disconnect()
        }
    }

    private fun readCapped(input: InputStream): String {
        // InputStream.readNBytes needs API 33, minSdk is 29
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            out.write(buffer, 0, n)
            if (out.size() > MAX_BODY_BYTES) throw IOException("response too large")
        }
        return out.toString(Charsets.UTF_8.name())
    }

    companion object {
        const val MAX_BODY_BYTES = 1 shl 20
    }
}

package validation.kotlinfixtures

import java.net.URL

fun kotlinSsrfClean(call: KotlinCall): String {
    val requested = call.parameters["service"]
    var endpoint = "https://status.example.test/health"
    if (requested == "metrics") {
        endpoint = "https://status.example.test/metrics"
    }
    return URL(endpoint).readText()
}

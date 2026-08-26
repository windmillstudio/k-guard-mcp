package validation.kotlinfixtures

import java.net.URL

fun kotlinSsrfVulnerable(call: KotlinCall): String {
    val target = call.parameters["target"]
    return URL(target).readText()
}

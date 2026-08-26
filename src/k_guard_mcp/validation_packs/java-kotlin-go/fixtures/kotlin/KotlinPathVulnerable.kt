package validation.kotlinfixtures

import java.io.File

fun kotlinPathVulnerable(call: KotlinCall): String {
    val path = call.parameters["path"]
    return File(path).readText()
}

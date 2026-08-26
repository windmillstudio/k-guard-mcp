package validation.kotlinfixtures

import java.nio.file.Files
import java.nio.file.Path

fun kotlinPathClean(call: KotlinCall): String {
    val requested = call.parameters["document"]
    var selected = Path.of("/srv/public/help.txt")
    if (requested == "terms") {
        selected = Path.of("/srv/public/terms.txt")
    }
    return Files.readString(selected)
}

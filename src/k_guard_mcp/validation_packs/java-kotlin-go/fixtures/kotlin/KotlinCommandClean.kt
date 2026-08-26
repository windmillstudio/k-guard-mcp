package validation.kotlinfixtures

fun kotlinCommandClean(call: KotlinCall): Process {
    val requested = call.parameters["operation"]
    var operation = "status"
    if (requested == "health") {
        operation = "health"
    }
    return ProcessBuilder("/usr/local/bin/ops-tool", operation).start()
}

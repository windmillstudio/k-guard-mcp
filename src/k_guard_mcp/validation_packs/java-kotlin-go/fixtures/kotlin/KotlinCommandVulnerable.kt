package validation.kotlinfixtures

fun kotlinCommandVulnerable(call: KotlinCall): Process {
    val command = call.parameters["command"]
    return ProcessBuilder(command).start()
}

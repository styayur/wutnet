package io.github.styayur.wutnet.protocol

internal data class JsonNumber(val value: String)

/** Small strict JSON reader: no Android or third-party dependency, no response logging. */
internal class JsonObjectReader(private val text: String) {
    private var offset = 0
    fun read(): Map<String, Any?> {
        require(text.length <= 1_048_576)
        val value = value(0)
        whitespace()
        require(offset == text.length && value is Map<*, *>)
        @Suppress("UNCHECKED_CAST")
        return value as Map<String, Any?>
    }
    private fun whitespace() { while (offset < text.length && text[offset] in " \t\r\n") offset++ }
    private fun take(c: Char) { whitespace(); require(offset < text.length && text[offset++] == c) }
    private fun consume(c: Char): Boolean {
        whitespace()
        return if (offset < text.length && text[offset] == c) { offset++; true } else false
    }
    private fun value(depth: Int): Any? {
        require(depth <= 20)
        whitespace()
        require(offset < text.length)
        return when (text[offset]) {
            '{' -> {
                offset++
                val map = linkedMapOf<String, Any?>()
                if (!consume('}')) {
                    do {
                        whitespace()
                        val key = string()
                        require(!map.containsKey(key))
                        take(':')
                        map[key] = value(depth + 1)
                    } while (consume(','))
                    take('}')
                }
                map
            }
            '[' -> {
                offset++
                val list = mutableListOf<Any?>()
                if (!consume(']')) {
                    do { list.add(value(depth + 1)) } while (consume(','))
                    take(']')
                }
                list
            }
            '"' -> string()
            't' -> literal("true", true)
            'f' -> literal("false", false)
            'n' -> literal("null", null)
            else -> {
                val match = NUMBER.find(text, offset)
                require(match != null && match.range.first == offset)
                offset += match.value.length
                JsonNumber(match.value)
            }
        }
    }
    private fun literal(expected: String, result: Any?): Any? {
        require(text.startsWith(expected, offset)); offset += expected.length; return result
    }
    private fun string(): String {
        take('"')
        val out = StringBuilder()
        while (offset < text.length) {
            val c = text[offset++]
            if (c == '"') return out.toString()
            require(c >= ' ')
            if (c != '\\') { out.append(c); continue }
            require(offset < text.length)
            when (val escaped = text[offset++]) {
                '"', '\\', '/' -> out.append(escaped)
                'b' -> out.append('\b')
                'f' -> out.append('\u000C')
                'n' -> out.append('\n')
                'r' -> out.append('\r')
                't' -> out.append('\t')
                'u' -> {
                    require(offset + 4 <= text.length)
                    val hex = text.substring(offset, offset + 4)
                    require(hex.all { it in "0123456789abcdefABCDEF" })
                    out.append(hex.toInt(16).toChar()); offset += 4
                }
                else -> throw IllegalArgumentException()
            }
        }
        throw IllegalArgumentException()
    }
    companion object { private val NUMBER = Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?") }
}

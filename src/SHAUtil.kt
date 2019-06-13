import java.security.MessageDigest

object SHAUtil {
    /**
     * SHA1 提取摘要
     */
    @JvmStatic
    @Throws(Exception::class)
    fun sha1Encode(inStr: String): String {
        val sha = MessageDigest.getInstance("SHA")
        val byteArray = inStr.toByteArray(charset(CHARSET_UTF8))
        val md5Bytes = sha.digest(byteArray)
        val hexValue = StringBuffer()
        for (i in md5Bytes.indices) {
            val num = md5Bytes[i].toInt() and 0xff
            if (num < 16) {
                hexValue.append("0")
            }
            hexValue.append(Integer.toHexString(num))
        }
        return hexValue.toString()
    }
}
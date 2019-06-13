import sun.misc.BASE64Decoder
import sun.misc.BASE64Encoder

const val CHARSET_UTF8 = "UTF-8"

/**
 * 编码解码
 *
 * 使用BASE64编码，任何二进制文件都可以编码成字符串[CoderUtil.base64Encode]，解码还原[CoderUtil.base64Decode]
 */
object CoderUtil {
    /**
     * 二进制byte数组，通过base64编码成字符串
     */
    @JvmStatic
    fun base64Encode(encodeData: ByteArray): String {
        val encoder = BASE64Encoder()
        return encoder.encode(encodeData)
    }

    /**
     * 将字符串通过base64解码成byte数组
     */
    @JvmStatic
    fun base64Decode(decodeData: String): ByteArray {
        val decode = BASE64Decoder()
        return decode.decodeBuffer(decodeData)
    }
}
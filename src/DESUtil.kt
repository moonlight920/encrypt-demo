import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.IvParameterSpec

/**
 * 对称加密，DES工具类
 *
 * 公钥私钥相同，必须是8位
 */
object DESUtil {

    /**
     * DES 算法
     */
    private const val DES_ALGORITHM = "DES/CBC/PKCS5Padding"

    @JvmStatic
    fun encrypt(data: ByteArray, key: String): ByteArray {
        val cipher = Cipher.getInstance(DES_ALGORITHM)
        val iv = IvParameterSpec(key.toByteArray(charset(CHARSET_UTF8)))
        cipher.init(Cipher.ENCRYPT_MODE, getDESKey(key), iv)
        return cipher.doFinal(data)
    }

    @JvmStatic
    fun decrypt(data: ByteArray, key: String): ByteArray {
        val cipher = Cipher.getInstance(DES_ALGORITHM)
        val iv = IvParameterSpec(key.toByteArray(charset(CHARSET_UTF8)))
        cipher.init(Cipher.DECRYPT_MODE, getDESKey(key), iv)
        return cipher.doFinal(data)
    }

    /**
     * 通过字符串的key，生成[SecretKey]
     */
    private fun getDESKey(key: String): SecretKey {
        val desKeySpec = DESKeySpec(key.toByteArray(charset(CHARSET_UTF8)))
        val keyFactory = SecretKeyFactory.getInstance("DES")
        return keyFactory.generateSecret(desKeySpec)
    }
}
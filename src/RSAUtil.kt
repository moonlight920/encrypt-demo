import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

/**
 * 非对称加密 RSA
 *
 * 1.生成一对公钥私钥[RSAUtil.getKeyPair]
 * 2.使用公钥加密[RSAUtil.encryptByPublicKey]后的数据，可以通过私钥解密出来[RSAUtil.decryptByPrivateKey]，可用于传输数据
 * 3.相反，使用私钥加密[RSAUtil.encryptByPrivateKey]的数据，也可以通过公钥解密出来[RSAUtil.decryptByPublicKey]，可用于签名验证
 */
object RSAUtil {
    /**
     * 加密算法
     */
    private const val KEY_ALGORITHM = "RSA"

    /**
     * 密钥长度，DH算法的默认密钥长度是1024
     * 密钥长度必须是64的倍数，在512到16384位之间
     */
    private const val KEY_SIZE = 1024

    /**
     * 获取一对公钥私钥
     */
    @JvmStatic
    fun getKeyPair(): Pair<ByteArray, ByteArray> {
        val keyPainGenerator = KeyPairGenerator.getInstance("RSA")
        keyPainGenerator.initialize(KEY_SIZE)
        val keyPair = keyPainGenerator.generateKeyPair()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        return Pair(publicKey.encoded, privateKey.encoded)
    }

    /**
     * 公钥加密
     *
     * @param data 待加密数据
     * @param key       密钥
     * @return byte[] 加密数据
     */
    @JvmStatic
    @Throws(Exception::class)
    fun encryptByPublicKey(data: ByteArray, key: ByteArray): ByteArray {

        //实例化密钥工厂
        val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
        //初始化公钥
        //密钥材料转换
        val x509KeySpec = X509EncodedKeySpec(key)
        //产生公钥
        val pubKey = keyFactory.generatePublic(x509KeySpec)

        //数据加密
        val cipher = Cipher.getInstance(keyFactory.algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, pubKey)
        return cipher.doFinal(data)
    }

    /**
     * 私钥解密
     *
     * @param data 待解密数据
     * @param key  密钥
     * @return byte[] 解密数据
     */
    @JvmStatic
    @Throws(Exception::class)
    fun decryptByPrivateKey(data: ByteArray, key: ByteArray): ByteArray {
        //取得私钥
        val pkcs8KeySpec = PKCS8EncodedKeySpec(key)
        val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
        //生成私钥
        val privateKey = keyFactory.generatePrivate(pkcs8KeySpec)
        //数据解密
        val cipher = Cipher.getInstance(keyFactory.algorithm)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(data)
    }

    /**
     * 私钥加密
     *
     * @param data 待加密数据
     * @param key       密钥
     * @return byte[] 加密数据
     */
    @JvmStatic
    @Throws(Exception::class)
    fun encryptByPrivateKey(data: ByteArray, key: ByteArray): ByteArray {

        //取得私钥
        val pkcs8KeySpec = PKCS8EncodedKeySpec(key)
        val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
        //生成私钥
        val privateKey = keyFactory.generatePrivate(pkcs8KeySpec)
        //数据加密
        val cipher = Cipher.getInstance(keyFactory.algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, privateKey)
        return cipher.doFinal(data)
    }

    /**
     * 公钥解密
     *
     * @param data 待解密数据
     * @param key  密钥
     * @return byte[] 解密数据
     */
    @JvmStatic
    @Throws(Exception::class)
    fun decryptByPublicKey(data: ByteArray, key: ByteArray): ByteArray {

        //实例化密钥工厂
        val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
        //初始化公钥
        //密钥材料转换
        val x509KeySpec = X509EncodedKeySpec(key)
        //产生公钥
        val pubKey = keyFactory.generatePublic(x509KeySpec)
        //数据解密
        val cipher = Cipher.getInstance(keyFactory.algorithm)
        cipher.init(Cipher.DECRYPT_MODE, pubKey)
        return cipher.doFinal(data)
    }
}
import kotlin.Pair;

import java.nio.charset.Charset;

public class Demo {

    private static final String data = "yuefeng";

    public static void main(String[] args) throws Exception {

        System.out.println("-----------------编码解码-----------------");
        // base64 编码解码字符串
        String base64EncodeResult = CoderUtil.base64Encode(data.getBytes());
        System.out.println("base64 encode result:  " + base64EncodeResult);

        byte[] base64DecodeResult = CoderUtil.base64Decode(base64EncodeResult);
        System.out.println("base64 decode result:  " + new String(base64DecodeResult));


        System.out.println("\n\n-----------------对称加密解密-----------------");
        // DES秘钥，公钥私钥一样(必须是8位)
        final String DES_KEY = "DES_KEY8";

        /*
         * 加密
         * 1.将要加密的数据转换成byte数组
         * 2.再将这个byte数组进行加密,得到另一个byte数组
         * 3.再将这个byte结果用base64编码成字符串
         */
        byte[] bytes = data.getBytes(Charset.forName("UTF-8"));
        byte[] encryptResultBytes = DESUtil.encrypt(bytes, DES_KEY);
        String encryptResultString = CoderUtil.base64Encode(encryptResultBytes);
        System.out.println("DES encrypt data: " + encryptResultString);
        /*
         * 解密
         * 1.将加密后的字符串使用base64解码，得到加密后的byte数组
         * 2.再将这个byte数组解密，得到原数据的byte数组
         * 3.将原数据的byte转成我们想要的格式
         */
        byte[] decodeByte = CoderUtil.base64Decode(encryptResultString);
        byte[] originData = DESUtil.decrypt(decodeByte, DES_KEY);
        String originString = new String(originData);
        System.out.println("DES decrypt data: " + originString);

        System.out.println("\n\n-----------------非对称加密解密（RSA）-----------------");

        //生成一对 公钥私钥
        Pair<byte[], byte[]> keyPair = RSAUtil.getKeyPair();
        byte[] publicKey = keyPair.getFirst();
        byte[] privateKey = keyPair.getSecond();
        System.out.println("-----公钥（BASE64编码后）-----");
        System.out.println(CoderUtil.base64Encode(publicKey));
        System.out.println("-----私钥（BASE64编码后）-----");
        System.out.println(CoderUtil.base64Encode(privateKey));

        /**
         * -----------------私钥加密，公钥解密（用于数字签名）-----------------
         */
        // RSA私钥加密
        byte[] encryptData = RSAUtil.encryptByPrivateKey(data.getBytes(), privateKey);
        String encryptDataString = CoderUtil.base64Encode(encryptData);
        System.out.println("-----使用私钥加密后数据（BASE64编码后）-----");
        System.out.println(encryptDataString);
        // RSA公钥解密
        byte[] decryptData = RSAUtil.decryptByPublicKey(CoderUtil.base64Decode(encryptDataString), publicKey);
        System.out.println("-----使用公钥解密后数据-----");
        System.out.println(new String(decryptData));

        /**
         * -----------------公钥加密，私钥解密（用于数据传输）-----------------
         */
        // RSA公钥加密
        byte[] encryptDataByPublic = RSAUtil.encryptByPublicKey(data.getBytes(), publicKey);
        String encryptDataByPublicString = CoderUtil.base64Encode(encryptDataByPublic);
        System.out.println("-----使用公钥加密后数据（BASE64编码后）-----");
        System.out.println(encryptDataByPublicString);
        // RSA私钥解密
        byte[] decryptDataByPrivate = RSAUtil.decryptByPrivateKey(CoderUtil.base64Decode(encryptDataByPublicString), privateKey);
        System.out.println("-----使用私钥解密后数据-----");
        System.out.println(new String(decryptDataByPrivate));

        System.out.println("\n\n-----------------MD5-----------------");
        System.out.println(data +" md5 : "+MD5Util.md5(data));
    }
}

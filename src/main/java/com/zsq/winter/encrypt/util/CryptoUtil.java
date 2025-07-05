package com.zsq.winter.encrypt.util;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.asymmetric.SignAlgorithm;
import cn.hutool.crypto.digest.DigestUtil;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.crypto.symmetric.DES;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class CryptoUtil {
    /**
     * 凯撒密码 它是一种替换加密的技术，明文中的所有字母都在字母表上向后（或向前）按照一个固定数目进行偏移后被替换成密文。
     * 使用凯撒加密方式加密数据
     *
     * @param original :原文
     * @param key      :位移
     * @return :加密后的数据
     */
    public static String winterEncryptKaiser(String original, int key) {
        // 将字符串转为字符数组
        char[] chars = original.toCharArray();
        StringBuilder sb = new StringBuilder();
        for (char aChar : chars) {
            // 获取字符的ascii编码
            int asciiCode = aChar;
            // 偏移数据
            asciiCode += key;
            // 将偏移后的数据转为字符
            char result = (char) asciiCode;
            // 拼接数据
            sb.append(result);
        }
        return sb.toString();
    }

    /**
     * 使用凯撒加密方式解密数据
     *
     * @param encryptedData :密文
     * @param key           :位移
     * @return : 源数据
     */
    public static String winterDecryptKaiser(String encryptedData, int key) {
        // 将字符串转为字符数组
        char[] chars = encryptedData.toCharArray();
        StringBuilder sb = new StringBuilder();
        for (char aChar : chars) {
            // 获取字符的ASCII编码
            int asciiCode = aChar;
            // 偏移数据
            asciiCode -= key;
            // 将偏移后的数据转为字符
            char result = (char) asciiCode;
            // 拼接数据
            sb.append(result);
        }
        return sb.toString();
    }


    /**
     * hutool工具随机生成密钥
     *
     * @return {@link byte[]}
     */
    public static byte[] winterGenerateKey() {
        return SecureUtil.generateKey(SymmetricAlgorithm.AES.getValue()).getEncoded();
    }

    /**
     * AES : Advanced Encryption Standard, 高级加密标准 .在密码学中又称Rijndael加密法，
     * 是美国联邦政府采用的一种区块加密标准。这个标准用来替代原先的DES，已经被多方分析且广为全世界所使用
     * hutool工具aes加密十六进制
     * 默认使用的是AES/ECB/PKCS5Padding模式。如果使用CryptoJS，请调整为：padding: CryptoJS.pad.Pkcs7
     *
     * @param key     hutool工具随机生成的密钥
     * @param content 内容
     * @return {@link String}
     */
    public static String winterAesEncryptHex(byte[] key, String content) {
        // 构建
        AES aes = SecureUtil.aes(key);
        // 加密为16进制表示
        return aes.encryptHex(content);
    }

    /**
     * aes加密十六进制
     *
     * @param mode    模式
     * @param padding 填充
     * @param key     钥匙
     * @param iv      偏移量
     * @param content 内容
     * @return 字符串
     */
    public static String winterAesEncryptHex(Mode mode, Padding padding, byte[] key, byte[] iv, String content) {
        // 创建一个包含特定加密模式的列表
        ArrayList<Mode> list = CollUtil.toList(Mode.CBC, Mode.CFB, Mode.OFB, Mode.CTR);
        // 判断传入的模式是否在列表中
        if (list.contains(mode)) {
            // 如果在列表中，则使用该模式、填充方式、密钥和偏移量进行加密，并返回加密后的十六进制字符串
            return new AES(mode, padding, key, iv).encryptHex(content);
        } else {
            // 如果不在列表中，则使用该模式、填充方式和密钥进行加密（不使用偏移量），并返回加密后的十六进制字符串
            return new AES(mode, padding, key).encryptHex(content);
        }
    }

    /**
     * hutool工具aes解密
     *
     * @param key        hutool工具随机生成的密钥
     * @param encryptHex aes加密后的十六进制字符串
     * @return {@link String}
     */
    public static String winterAesDecryptStr(byte[] key, String encryptHex) {
        // 构建
        AES aes = SecureUtil.aes(key);
        // 解密
        return aes.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
    }


    /**
     * aes解密str
     *
     * @param mode    模式
     * @param padding 填充
     * @param key     钥匙
     * @param iv      偏移量
     * @param content 加密后的内容
     * @return 字符串
     */
    public static String winterAesDecryptStr(Mode mode, Padding padding, byte[] key, byte[] iv, String content) {
        // 构建
        ArrayList<Mode> list = CollUtil.toList(Mode.CBC, Mode.CFB, Mode.OFB, Mode.CTR);
        if (list.contains(mode)) {
            return new AES(mode, padding, key, iv).decryptStr(content, CharsetUtil.CHARSET_UTF_8);
        } else {
            return new AES(mode, padding, key).decryptStr(content);
        }
    }

    /**
     * DES : Data Encryption Standard，即数据加密标准，是一种使用密钥加密的块算法，
     * 1977年被美国联邦政府的国家标准局确定为联邦资料处理标准（FIPS），并授权在非密级政府通信中使用，随后该算法在国际上广泛流传开来。
     * hutool工具des加密十六进制
     * 默认实现为：DES/CBC/PKCS5Padding 如果使用CryptoJS，请调整为：padding: CryptoJS.pad.Pkcs7
     *
     * @param key     hutool工具随机生成的密钥
     * @param content 内容
     * @return {@link String}
     */
    public static String winterDesEncryptHex(byte[] key, String content) {
        // 构建
        DES des = SecureUtil.des(key);
        // 加密为16进制表示
        return des.encryptHex(content);
    }

    /**
     * winter des加密十六进制
     *
     * @param mode    模式
     * @param padding 填充
     * @param key     钥匙
     * @param iv      偏移
     * @param content 内容
     * @return 字符串
     */
    public static String winterDesEncryptHex(Mode mode, Padding padding, byte[] key, byte[] iv, String content) {
        // 加密为16进制表示
        ArrayList<Mode> list = CollUtil.toList(Mode.CBC, Mode.CFB, Mode.OFB, Mode.CTR);
        if (list.contains(mode)) {
            // 如果模式是CBC、CFB、OFB或CTR，则使用偏移量iv进行加密
            return new DES(mode, padding, key, iv).encryptHex(content);
        } else {
            // 否则，不使用偏移量iv进行加密
            return new DES(mode, padding, key).encryptHex(content);
        }
    }

    /**
     * hutool工具des解密
     *
     * @param key        hutool工具随机生成的密钥
     * @param encryptHex des加密后的十六进制字符串
     * @return {@link String}
     */
    public static String winterDesDecryptStr(byte[] key, String encryptHex) {
        // 构建DES实例，使用给定的密钥
        DES des = SecureUtil.des(key);
        // 使用DES实例解密加密后的十六进制字符串，并指定字符集为UTF-8
        return des.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
    }

    /**
     * 使用指定模式和填充方式的DES算法进行字符串解密
     *
     * @param mode 操作模式，如CBC、CFB等
     * @param padding 填充方式，如PKCS5Padding、NoPadding等
     * @param key 密钥，用于解密操作
     * @param iv 初始化向量，某些模式下需要
     * @param content 待解密的字符串
     * @return 解密后的字符串
     *
     * 注意：当使用CBC、CFB、OFB或CTR模式时，需要提供初始化向量（iv）
     * 其他模式则不需要初始化向量
     */
    public static String winterDesDecryptStr(Mode mode, Padding padding, byte[] key, byte[] iv, String content) {
        // 加密为16进制表示
        ArrayList<Mode> list = CollUtil.toList(Mode.CBC, Mode.CFB, Mode.OFB, Mode.CTR);
        // 根据模式是否需要初始化向量来选择合适的解密方式
        if (list.contains(mode)) {
            // 当模式为CBC、CFB、OFB或CTR时，使用初始化向量进行解密
            return new DES(mode, padding, key, iv).decryptStr(content, CharsetUtil.CHARSET_UTF_8);
        } else {
            // 其他模式不需要初始化向量进行解密
            return new DES(mode, padding, key).decryptStr(content);
        }
    }


    /**
     * 消息摘要（Message Digest）又称为数字摘要(Digital Digest)
     * 它是一个唯一对应一个消息或文本的固定长度的值，它由一个单向Hash加密函数对消息进行作用而产生
     * 输入长度不定，输出长度一定。单向不可逆
     * 使用数字摘要生成的值是不可以篡改的，为了保证文件或者值的安全
     * MD2
     * MD5
     * SHA-1
     * SHA-256
     * SHA-384
     * SHA-512
     * hutool md5 hex16
     *
     * @param content 需要被加密的内容
     * @return {@link String}
     */
    public static String winterMd5Hex16(String content) {
        return DigestUtil.md5Hex16(content);
    }

    /**
     * hutool sha1十六进制
     *
     * @param content 内容
     * @return {@link String}
     */
    public static String winterSha1Hex(String content) {
        return DigestUtil.sha1Hex(content);
    }

    /**
     * 使用Hutool工具生成RSA私钥和公钥。
     * 非对称加密涉及公钥和私钥两个概念：
     * - 私钥：由所有者持有，不能公开。用于签名时的加密操作。
     * - 公钥：可以公开。用于签名验证或加密操作。
     *
     * 应用场景：
     * - 签名：使用私钥加密，公钥解密。确保内容的完整性和发送者的身份验证。
     * - 加密：使用公钥加密，私钥解密。确保只有私钥持有者能解密信息。
     *
     * @return 包含私钥和公钥的Map对象，键为"privateKey"和"publicKey"，值为对应的Base64编码字符串。
     */
    public static Map<String, String> winterGenerateRsAKey() {
        // 创建RSA对象并生成密钥对
        RSA rsa = new RSA();

        // 获取Base64编码的私钥和公钥
        String privateKey = rsa.getPrivateKeyBase64();
        String publicKey = rsa.getPublicKeyBase64();

        // 将私钥和公钥存入Map中
        Map<String, String> map = new HashMap<>();
        map.put("privateKey", privateKey);
        map.put("publicKey", publicKey);

        // 返回包含私钥和公钥的Map
        return map;
    }
    /**
     * 使用Hutool库进行RSA加密：用公钥加密，私钥解密。该方法用于向公钥所有者发布信息，
     * 确保信息在传输过程中不会被他人篡改或获取。
     *
     * @param privateKey 私钥字符串，用于后续解密操作。请注意，私钥不应泄露给未经授权的第三方。
     * @param publicKey  公钥字符串，用于加密内容。公钥可以安全地分发给需要发送加密信息的各方。
     * @param content    需要加密的内容，即明文数据。
     * @return 加密后的内容，以字节数组形式返回。调用方需要将此字节数组转换为适合传输的格式（如Base64编码）。
     */
    public static byte[] winterRsAPublicKeyEncrypt(String privateKey, String publicKey, String content) {
        // 创建RSA对象并初始化公钥和私钥。Hutool库的RSA类会根据提供的密钥字符串完成初始化。
        RSA rsa = new RSA(privateKey, publicKey);

        // 使用公钥对内容进行加密，并返回加密后的字节数组。加密过程确保只有持有对应私钥的接收方才能解密。
        return rsa.encrypt(content.getBytes(), KeyType.PublicKey);
    }


    /**
     * 使用私钥对内容进行加密的函数。本函数的目的是让所有拥有公钥的接收者能够确认信息确实来自于私钥的持有者，
     * 并且在传输过程中信息没有被篡改。需要注意的是，这种方式并不保证信息的保密性，因为公钥是公开的，任何人都可以解密信息。
     *
     * @param privateKey 私钥字符串，用于加密内容。
     * @param publicKey  公钥字符串，虽然在本函数中公钥不直接用于加密过程，但它对于验证加密信息的来源和完整性是必需的。
     * @param content    需要加密的内容。
     * @return 加密后的字节数组。
     */
    public static byte[] winterRsAPrivateKeyEncrypt(String privateKey, String publicKey, String content) {
        // 创建RSA加密器实例，加载私钥和公钥。
        RSA rsa = new RSA(privateKey, publicKey);
        // 使用私钥对内容进行加密，并返回加密后的字节数组。
        return rsa.encrypt(content.getBytes(), KeyType.PrivateKey);
    }

    /**
     * 使用私钥解密公钥加密的数据。
     * 该方法适用于 scenarios，其中信息需要被公钥所有者解密，确保了信息的 confidentiality 和 integrity。
     * 通过使用私钥解密，该方法 ensures 仅拥有对应公钥的 receiver 可以 decrypt 信息，从而 protecting 信息 from being intercepted 和 read by unauthorized parties。
     *
     * @param privateKey 私钥，用于解密数据。
     * @param publicKey  公钥，对应于私钥，用于验证解密操作的合法性。
     * @param encrypted  使用公钥加密后的数据，以字节数组形式提供。
     * @return 解密后的字符串信息。
     */
    public static String winterRsAPrivateKeyDecrypt(String privateKey, String publicKey, byte[] encrypted) {
        // 初始化RSA加密器，同时加载私钥和公钥。
        RSA rsa = new RSA(privateKey, publicKey);

        // 使用私钥对加密数据进行解密操作。
        byte[] decrypted = rsa.decrypt(encrypted, KeyType.PrivateKey);

        // 将解密后的字节数组转换为字符串并返回。
        return new String(decrypted);
    }


    /**
     * 使用私钥加密，公钥解密的方法。该方法的主要用途是让所有公钥的持有者能够验证私钥持有者的身份，
     * 并且用来防止私钥持有者发布的内容被篡改。然而，这种方法并不用于保证内容不会被其他人获取。
     *
     * @param privateKey 私钥字符串，用于加密数据。
     * @param publicKey  公钥字符串，用于解密数据。
     * @param encrypted  使用RSA公钥加密后的字节数组，即密文。
     * @return 解密后的字符串，即原始信息。
     */
    public static String winterRsAPublicKeyDecrypt(String privateKey, String publicKey, byte[] encrypted) {
        // 创建RSA加密器实例，加载私钥和公钥。
        RSA rsa = new RSA(privateKey, publicKey);
        // 使用公钥解密数据，得到解密后的字节数组。
        byte[] decrypted = rsa.decrypt(encrypted, KeyType.PublicKey);
        // 将解密后的字节数组转换为字符串并返回。
        return new String(decrypted);
    }


    /**
     * hutool 数字签名：数字签名是非对称密钥加密技术与数字摘要技术的应用。
     *
     * @param privateKey 私钥
     * @param publicKey  公钥
     * @param content    加密内容
     */
    public static byte[] winterMd5withRsaSign(String privateKey, String publicKey, String content) {
        // 使用自定义的私钥、公钥进行签名
        byte[] signData = SecureUtil.sign(SignAlgorithm.MD5withRSA, privateKey, publicKey).sign(content.getBytes());
        // 打印签名值
        // System.out.println("签名值: " + HexUtil.encodeHexStr(signData));
        return signData;
    }

    /**
     * hutool 数字签名：数字签名是非对称密钥加密技术与数字摘要技术的应用。
     *
     * @param privateKey 私钥
     * @param publicKey  公钥
     * @param signData   数字签名加密后的字节数组
     * @param content    需要被加密的内容
     */
    public static boolean winterMd5withRsaVerify(String privateKey, String publicKey, byte[] signData, String content) {
        return SecureUtil.sign(SignAlgorithm.MD5withRSA, privateKey, publicKey).verify(content.getBytes(), signData);
    }
}
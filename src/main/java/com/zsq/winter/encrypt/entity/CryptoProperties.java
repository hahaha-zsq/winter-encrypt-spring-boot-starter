package com.zsq.winter.encrypt.entity;

import com.zsq.winter.encrypt.enums.CryptoType;
import com.zsq.winter.encrypt.util.CryptoValidator;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 加密解密配置属性类
 *
 * <p>用于存储不同加密算法的配置属性，通过{@link ConfigurationProperties}注解
 * 绑定配置文件中的属性，前缀为"winter-crypto"。</p>
 *
 * <p>配置示例：</p>
 * <pre>{@code
 * winter-crypto:
 *   # AES配置
 *   aes:
 *     key: "1234567890123456"         # 16字节 = 128位
 *     iv: "1234567890123456"          # 16字节 = 128位
 *     auto-adjust-iv: true            # 是否自动调整IV长度（默认true）
 *
 *   # DES配置
 *   des:
 *     key: "12345678"                  # 8字节 = 64位
 *     iv: "87654321"                  # 8字节 = 64位
 *     auto-adjust-iv: true            # 是否自动调整IV长度（默认true）
 *
 *   # RSA配置
 *   rsa:
 *     private-key: "-----BEGIN PRIVATE KEY-----..."
 *     public-key: "-----BEGIN PUBLIC KEY-----..."
 *
 *   # 通用配置
 *   is-print: true
 *   default-algorithm: AES
 * }</pre>
 *
 * <p>不同算法的密钥长度要求：</p>
 * <ul>
 *   <li><strong>AES</strong>：密钥长度128位(16字节)、192位(24字节)、256位(32字节)，IV长度128位(16字节)</li>
 *   <li><strong>DES</strong>：密钥长度64位(8字节)，IV长度64位(8字节)</li>
 *   <li><strong>RSA</strong>：密钥长度1024位、2048位、4096位等，不需要IV</li>
 * </ul>
 *
 * @author dadandiaoming
 * @see ConfigurationProperties
 * @since 1.0.0
 */
@Data
@ConfigurationProperties("winter-crypto")
public class CryptoProperties {

    /**
     * AES算法配置
     */
    private AesConfig aes = new AesConfig();

    /**
     * DES算法配置
     */
    private DesConfig des = new DesConfig();

    /**
     * RSA算法配置
     */
    private RsaConfig rsa = new RsaConfig();

    /**
     * 是否打印启动Banner
     */
    private Boolean isPrint = true;

    /**
     * AES算法配置类
     *
     * <p>AES算法要求：
     * - 密钥长度：128位(16字节)、192位(24字节)、256位(32字节)
     * - IV长度：128位(16字节)</p>
     */
    @Data
    public static class AesConfig {
        /**
         * AES密钥
         *
         * <p>支持的长度：
         * - 16字节 = 128位（推荐）
         * - 24字节 = 192位
         * - 32字节 = 256位</p>
         */
        private String key;

        /**
         * AES初始化向量
         *
         * <p>长度要求：16字节(128位)</p>
         */
        private String iv;

        /**
         * 是否自动调整IV长度
         *
         * <p>当为true时，会自动截取或补充IV到16字节
         * 当为false时，会严格验证IV长度，不匹配时抛出异常</p>
         */
        private Boolean autoAdjustIv = true;

        /**
         * 获取调整后的IV
         */
        public String getAdjustedIv() {
            return autoAdjustIv ? CryptoValidator.adjustIvLength(iv, CryptoType.AES) : iv;
        }
    }


    /**
     * DES算法配置类
     *
     * <p>DES算法要求：
     * - 密钥长度：64位(8字节)
     * - IV长度：64位(8字节)</p>
     */
    @Data
    public static class DesConfig {
        /**
         * DES密钥
         *
         * <p>长度要求：8字节(64位)</p>
         */
        private String key;

        /**
         * DES初始化向量
         *
         * <p>长度要求：8字节(64位)</p>
         */
        private String iv;

        /**
         * 是否自动调整IV长度
         *
         * <p>当为true时，会自动截取或补充IV到8字节
         * 当为false时，会严格验证IV长度，不匹配时抛出异常</p>
         */
        private Boolean autoAdjustIv = true;

        /**
         * 获取调整后的IV
         */
        public String getAdjustedIv() {
            return autoAdjustIv ? CryptoValidator.adjustIvLength(iv, CryptoType.DES) : iv;
        }
    }

    /**
     * RSA算法配置类
     *
     * <p>RSA算法要求：
     * - 密钥长度：1024位、2048位、4096位等
     * - 不需要IV</p>
     */
    @Data
    public static class RsaConfig {
        /**
         * RSA私钥
         *
         * <p>格式：PEM格式的私钥</p>
         */
        private String privateKey;

        /**
         * RSA公钥
         *
         * <p>格式：PEM格式的公钥</p>
         */
        private String publicKey;
    }

    /**
     * 获取指定算法的加密密钥
     *
     * @param cryptoType 加密算法类型
     * @return 对应的加密密钥
     */
    public String getEncryptKey(CryptoType cryptoType) {
        switch (cryptoType) {
            case AES:
                return aes.getKey();
            case DES:
                return des.getKey();
            case RSA:
                return rsa.getPrivateKey(); // RSA使用私钥进行加密
            default:
                return aes.getKey(); // 默认使用AES
        }
    }

    /**
     * 获取指定算法的解密密钥
     *
     * @param cryptoType 加密算法类型
     * @return 对应的解密密钥
     */
    public String getDecryptKey(CryptoType cryptoType) {
        switch (cryptoType) {
            case AES:
                return aes.getKey(); // 对称加密，解密密钥就是加密密钥
            case DES:
                return des.getKey(); // 对称加密，解密密钥就是加密密钥
            case RSA:
                return rsa.getPublicKey(); // RSA使用公钥进行解密
            default:
                return aes.getKey(); // 默认使用AES
        }
    }

    /**
     * 获取指定算法的初始化向量
     *
     * @param cryptoType 加密算法类型
     * @return 对应的初始化向量
     */
    public String getIv(CryptoType cryptoType) {
        switch (cryptoType) {
            case AES:
                return aes.getAdjustedIv();
            case DES:
                return des.getAdjustedIv();
            case RSA:
                return null; // RSA不需要IV
            default:
                return aes.getAdjustedIv(); // 默认使用AES
        }
    }
}

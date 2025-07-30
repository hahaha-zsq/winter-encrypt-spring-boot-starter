package com.zsq.winter.encrypt.entity;

import com.zsq.winter.encrypt.enums.CryptoType;
import com.zsq.winter.encrypt.util.CryptoValidator;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 加密配置属性类
 *
 * <p>包含了项目中所有加密算法的配置参数。</p>
 *
 * <h3>🔧 配置示例：</h3>
 * <pre>{@code
 * winter-crypto:
 *   # AES对称加密配置
 *   aes:
 *     key: "1234567890123456"          # 16字节密钥
 *     iv: "1234567890123456"           # 16字节初始化向量
 *     auto-adjust-iv: true             # 自动调整IV长度
 *   
 *   # DES对称加密配置
 *   des:
 *     key: "12345678"                  # 8字节密钥
 *     iv: "87654321"                   # 8字节初始化向量
 *     auto-adjust-iv: true             # 自动调整IV长度
 *   
 *   # RSA非对称加密配置 - 推荐使用环境变量（最安全）
 *   rsa:
 *     private-key: ${RSA_PRIVATE_KEY}  # 从环境变量读取（Base64格式）
 *     public-key: ${RSA_PUBLIC_KEY}    # 从环境变量读取（Base64格式）
 *
 *   # RSA配置 - 直接配置（不推荐用于生产环境）
 *   # Base64格式（Hutool原生支持，无标识符）：
 *   # rsa:
 *   #   private-key: "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCB..."
 *   #   public-key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMI..."
 *   
 *   # 通用配置
 *   is-print: true                     # 是否显示启动banner
 * }</pre>
 *
 * <h3>🔒 RSA密钥格式说明：</h3>
 * <ul>
 *   <li><strong>仅支持Base64格式</strong>：纯Base64编码的密钥字符串</li>
 *   <li><strong>密钥生成</strong>：可使用 {@code CryptoUtil.winterGenerateRsAKey()} 生成</li>
 *   <li><strong>文件格式</strong>：密钥文件应包含纯Base64字符串，无其他标识符</li>
 * </ul>
 *
 * <h3>⚙️ 配置方式：</h3>
 * <ol>
 *   <li>环境变量方式：通过 ${RSA_PRIVATE_KEY} 和 ${RSA_PUBLIC_KEY}（推荐）</li>
 *   <li>直接配置方式：private-key 和 public-key（不推荐用于生产环境）</li>
 * </ol>
 *
 * @author dadandiaoming
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
     * 
     * <p>安全配置方式（按优先级排序）：</p>
     * <ol>
     *   <li>环境变量方式：通过 ${RSA_PRIVATE_KEY} 和 ${RSA_PUBLIC_KEY}（推荐）</li>
     *   <li>直接配置方式：private-key 和 public-key（不推荐用于生产环境）</li>
     * </ol>
     */
    @Data
    public static class RsaConfig {
        /**
         * RSA私钥
         *
         * <p>仅支持Base64字符串（PKCS#8格式，无PEM头尾），建议用{@code CryptoUtil.winterGenerateRsAKey()}生成。</p>
         * <p>安全建议：生产环境请使用环境变量：${RSA_PRIVATE_KEY}</p>
         */
        private String privateKey;

        /**
         * RSA公钥
         *
         * <p>仅支持Base64字符串（X.509格式，无PEM头尾），建议用{@code CryptoUtil.winterGenerateRsAKey()}生成。</p>
         * <p>安全建议：生产环境请使用环境变量：${RSA_PUBLIC_KEY}</p>
         */
        private String publicKey;



        /**
         * 获取实际的私钥内容
         *
         * @return 私钥内容
         */
        public String getActualPrivateKey() {
            return privateKey;
        }

        /**
         * 获取实际的公钥内容
         *
         * @return 公钥内容
         */
        public String getActualPublicKey() {
            return publicKey;
        }
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
                return rsa.getActualPrivateKey(); // RSA使用私钥进行加密
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
                return aes.getKey();
            case DES:
                return des.getKey();
            case RSA:
                return rsa.getActualPublicKey(); // RSA使用公钥进行解密
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

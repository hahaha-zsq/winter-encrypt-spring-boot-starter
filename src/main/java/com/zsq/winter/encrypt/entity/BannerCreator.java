package com.zsq.winter.encrypt.entity;


import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.util.ObjectUtils;

/**
 * banner创建
 * 是一个接口，常用于项目启动后，（也就是ApringApplication.run()执行结束），立马执行某些逻辑。可用于项目的准备工作，比如加载配置文件，加载执行流，定时任务等等
 *
 * @author zero
 * @date 2024/05/15
 */
@Slf4j
// 实现ApplicationRunner接口，允许在Spring Boot应用启动后执行特定的操作
public class BannerCreator implements ApplicationRunner {
    // 注入CryptoProperties配置类，用于获取配置信息
    private final CryptoProperties cryptoProperties;

    // 构造器注入cryptoProperties
    public BannerCreator(CryptoProperties cryptoProperties) {
        this.cryptoProperties = cryptoProperties;
    }

    // 实现ApplicationRunner接口的run方法
    @Override
    public void run(ApplicationArguments args) throws Exception {
        // https://www.bootschool.net/ascii
        // 定义一个字符串，包含ASCII艺术形式的横幅
        // 这个横幅在程序启动时根据配置决定是否打印
        String str = "" +
                " ___       __   ___  ________   _________  _______   ________                 ________  ________      ___    ___ ________  _________  ________     \n" +
                "|\\  \\     |\\  \\|\\  \\|\\   ___  \\|\\___   ___\\\\  ___ \\ |\\   __  \\               |\\   ____\\|\\   __  \\    |\\  \\  /  /|\\   __  \\|\\___   ___\\\\   __  \\    \n" +
                "\\ \\  \\    \\ \\  \\ \\  \\ \\  \\\\ \\  \\|___ \\  \\_\\ \\   __/|\\ \\  \\|\\  \\  ____________\\ \\  \\___|\\ \\  \\|\\  \\   \\ \\  \\/  / | \\  \\|\\  \\|___ \\  \\_\\ \\  \\|\\  \\   \n" +
                " \\ \\  \\  __\\ \\  \\ \\  \\ \\  \\\\ \\  \\   \\ \\  \\ \\ \\  \\_|/_\\ \\   _  _\\|\\____________\\ \\  \\    \\ \\   _  _\\   \\ \\    / / \\ \\   ____\\   \\ \\  \\ \\ \\  \\\\\\  \\  \n" +
                "  \\ \\  \\|\\__\\_\\  \\ \\  \\ \\  \\\\ \\  \\   \\ \\  \\ \\ \\  \\_|\\ \\ \\  \\\\  \\\\|____________|\\ \\  \\____\\ \\  \\\\  \\|   \\/  /  /   \\ \\  \\___|    \\ \\  \\ \\ \\  \\\\\\  \\ \n" +
                "   \\ \\____________\\ \\__\\ \\__\\\\ \\__\\   \\ \\__\\ \\ \\_______\\ \\__\\\\ _\\               \\ \\_______\\ \\__\\\\ _\\ __/  / /      \\ \\__\\        \\ \\__\\ \\ \\_______\\\n" +
                "    \\|____________|\\|__|\\|__| \\|__|    \\|__|  \\|_______|\\|__|\\|__|               \\|_______|\\|__|\\|__|\\___/ /        \\|__|         \\|__|  \\|_______|\n"
                + "\r\n" + CryptoConstants.DEV_DOC_URL
                + " (" + CryptoConstants.VERSION_NO + ")";
        // 根据cryptoProperties中的配置决定是否打印横幅
        if (!ObjectUtils.isEmpty(cryptoProperties.getIsPrint()) && cryptoProperties.getIsPrint()) {
            // 如果配置允许打印，则通过日志输出横幅
            log.info(str);
        }
    }
}


#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// 移除原有的 #pragma push_macro 逻辑
#undef LIBXML_ATTR_FORMAT  // 先强制清除宏定义

// 包含头文件（此时宏定义由头文件生成）
#include <libxml/xmlexports.h>
#include <libxml/xmlversion.h>

// 关键：锁定宏定义，避免后续冲突（以最后一次定义为准）
#ifndef LIBXML_ATTR_FORMAT
#define LIBXML_ATTR_FORMAT(fmt, args) __attribute__((format(printf, fmt, args)))
#endif

// 继续包含其他头文件
#include <libxml/parser.h>
#include <libxml/xmlregexp.h>
#include <libxml/xmlreader.h>
#include <sanitizer/coverage_interface.h>

// 全局初始化标记（避免重复初始化 libxml2）
static int g_libxml2_initialized = 0;

// 自定义memmem实现，兼容不支持该函数的环境
static void *custom_memmem(const void *haystack, size_t haystack_len,
                           const void *needle, size_t needle_len) {
    if (needle_len == 0 || needle_len > haystack_len) {
        return NULL;
    }
    const unsigned char *h = (const unsigned char *)haystack;
    const unsigned char *n = (const unsigned char *)needle;
    for (size_t i = 0; i <= haystack_len - needle_len; ++i) {
        if (memcmp(&h[i], n, needle_len) == 0) {
            return (void *)&h[i];
        }
    }
    return NULL;
}

/**
 * @brief LibFuzzer 初始化函数（仅执行一次）
 */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (!g_libxml2_initialized) {
        xmlInitParser();          
        g_libxml2_initialized = 1;
    }
    return 0;
}

/**
 * @brief 输入过滤：更精准的输入筛选
 */
static int filter_invalid_input(const uint8_t *data, size_t size) {
    if (size == 0 || size > 1024 * 1024) { // 保持长度限制
        return 0;
    }
    
// 检查是否包含过长的属性值模式（如连续100个以上相同字符）
    if (size > 1024) {
        for (size_t i = 0; i < size - 100; ++i) {
            bool long_run = true;
            for (size_t j = 1; j < 100; ++j) {
                if (data[i] != data[i + j]) {
                    long_run = false;
                    break;
                }
            }
            if (long_run) {
                return 0; // 过滤包含超长重复字符的输入
            }
        }
    }

        // 过滤包含正则特殊字符的非法标签名
    const char *invalid_chars = "^[]+*?";
    for (size_t i = 0; i < strlen(invalid_chars); i++) {
        if (custom_memmem(data, size, &invalid_chars[i], 1)) {
            return 0;
        }
    }

    // 使用自定义memmem替代系统函数
    return (custom_memmem(data, size, "<", 1) != NULL && custom_memmem(data, size, ">", 1) != NULL) ||
           (custom_memmem(data, size, "*", 1) != NULL || custom_memmem(data, size, "+", 1) != NULL ||
            custom_memmem(data, size, "?", 1) != NULL || custom_memmem(data, size, "(", 1) != NULL);
}

/**
 * @brief 测试 xmlReadMemory（增加选项覆盖）
 */
static void fuzz_xmlReadMemory(const uint8_t *data, size_t size) {
    // 扩展选项集，覆盖更多解析模式
    int options[] = {
        0,  // 默认模式
        XML_PARSE_RECOVER,
        XML_PARSE_NODICT,
        XML_PARSE_DTDLOAD,
        XML_PARSE_NOENT,
        XML_PARSE_DTDVALID
    };
    int opt = options[rand() % (sizeof(options)/sizeof(options[0]))];

    xmlDocPtr doc = xmlReadMemory((const char*)data, size, 
                                 "fuzz.xml", "UTF-8", opt);
    if (doc) {
        // 增加文档操作，覆盖更多代码路径
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if (root) {
            xmlNodeGetContent(root);  // 访问节点内容
        }
        xmlFreeDoc(doc);
    }
}

/**
 * @brief 测试 xmlRegexpCompile（增加使用场景）
 */
static void fuzz_xmlRegexpCompile(const uint8_t *data, size_t size) {
    // 避免过长正则表达式导致性能问题
    if (size > 4096) return;

    char *regex_str = (char*)malloc(size + 1);
    if (!regex_str) return;
    memcpy(regex_str, data, size);
    regex_str[size] = '\0';

    xmlRegexpPtr regex = xmlRegexpCompile((const xmlChar*)regex_str);
    if (regex) {
        // 修正数组初始化方式，使用正确的字符串转换
        const xmlChar* test_str = BAD_CAST "test string for regex match";
        xmlRegexpExec(regex, test_str);
        xmlRegFreeRegexp(regex);
    }
    free(regex_str);
}

/**
 * @brief 测试 xmlTextReaderRead（增强分支覆盖）
 */
static void fuzz_xmlTextReaderRead(const uint8_t *data, size_t size) {
    int options[] = {0, XML_PARSE_RECOVER, XML_PARSE_NOENT};
    int opt = options[rand() % (sizeof(options)/sizeof(options[0]))];

    xmlTextReaderPtr reader = xmlReaderForMemory((const char*)data, size,
                                                "fuzz.xml", "UTF-8", opt);
    if (!reader) return;

    int ret;
    while ((ret = xmlTextReaderRead(reader)) == 1) {
        // 增加更多阅读器操作，覆盖不同API
        switch (rand() % 5) {
            case 0:
                xmlTextReaderGetAttribute(reader, (const xmlChar*)"attr");
                break;
            case 1:
                xmlTextReaderName(reader);
                break;
            case 2:
                xmlTextReaderValue(reader);
                break;
            case 3:
                xmlTextReaderDepth(reader);
                break;
            case 4:
                xmlTextReaderNodeType(reader);
                break;
        }
    }
    xmlFreeTextReader(reader);
}

/**
 * @brief LibFuzzer 核心入口函数
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!filter_invalid_input(data, size)) {
        return 0;
    }

    // 使用确定性随机数生成器，提高测试可重复性
    uint32_t seed = 0;
    memcpy(&seed, data, sizeof(seed));  // 基于输入数据生成种子
    srand(seed);

    // 增加权重分配，对复杂函数增加测试概率
    int r = rand() % 100;
    if (r < 40) {
        fuzz_xmlReadMemory(data, size);
    } else if (r < 70) {
        fuzz_xmlTextReaderRead(data, size);
    } else {
        fuzz_xmlRegexpCompile(data, size);
    }

    // 线程安全的清理方式
    if (g_libxml2_initialized) {
        xmlCleanupParser();
        xmlResetLastError();  // 重置错误状态，避免状态污染
    }
    
    // 替换为覆盖率接口中定义的函数
    //__sanitizer_cov_reset();
    void(0); // 占位，避免未使用警告
    return 0;
}
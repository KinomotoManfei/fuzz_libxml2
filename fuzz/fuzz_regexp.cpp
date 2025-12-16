#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
// 适配脚本中 -I./libxml2/include 路径
#include <libxml/parser.h>
#include <libxml/xmlregexp.h>
#include <libxml/xmlreader.h>
#include <libxml/xmllint.h>

// 全局初始化标记（避免重复初始化 libxml2）
static int g_libxml2_initialized = 0;

/**
 * @brief LibFuzzer 初始化函数（仅执行一次）
 * 适配脚本中模糊测试的全局初始化需求
 */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (!g_libxml2_initialized) {
        xmlInitParser();          // 初始化 libxml2 解析器
        xmlInitThreads();         // 线程安全初始化（适配多进程 fuzz）
        g_libxml2_initialized = 1;
    }
    return 0;
}

/**
 * @brief 输入过滤：拒绝无效输入，减少无意义测试
 * @param data 模糊测试输入字节流
 * @param size 输入长度
 * @return 1-有效输入 0-无效输入
 */
static int filter_invalid_input(const uint8_t *data, size_t size) {
    if (size == 0 || size > 1024 * 1024) { // 拒绝空输入/超长输入（>1MB）
        return 0;
    }
    // 基础 XML/正则特征校验（避免纯随机乱码）
    return (memmem(data, size, "<", 1) != NULL ||  // XML 标签特征
            memmem(data, size, "*", 1) != NULL ||  // 正则量词特征
            memmem(data, size, "+", 1) != NULL);   // 正则量词特征
}

/**
 * @brief 测试 xmlReadMemory（核心目标：parser.c #13441）
 */
static void fuzz_xmlReadMemory(const uint8_t *data, size_t size) {
    // 随机选择解析选项（覆盖不同解析场景）
    int options[] = {XML_PARSE_RECOVER, XML_PARSE_STRICT, XML_PARSE_DTDLOAD};
    int opt = options[rand() % 3];

    // 调用目标函数
    xmlDocPtr doc = xmlReadMemory((const char*)data, size, 
                                  "fuzz.xml", "UTF-8", opt);
    if (doc) {
        xmlFreeDoc(doc); // 释放资源，避免内存泄漏
    }
}

/**
 * @brief 测试 xmlRegexpCompile（核心目标：xmlregexp.c #5438）
 */
static void fuzz_xmlRegexpCompile(const uint8_t *data, size_t size) {
    // 构造以 \0 结尾的字符串（适配正则编译函数入参要求）
    char *regex_str = (char*)malloc(size + 1);
    if (!regex_str) return;
    memcpy(regex_str, data, size);
    regex_str[size] = '\0';

    // 调用目标函数
    xmlRegexpPtr regex = xmlRegexpCompile((const xmlChar*)regex_str);
    if (regex) {
        xmlRegexpFree(regex); // 释放正则对象
    }
    free(regex_str);
}

/**
 * @brief 测试 xmlTextReaderRead（核心目标：xmlreader.c #1200-）
 */
static void fuzz_xmlTextReaderRead(const uint8_t *data, size_t size) {
    // 创建内存阅读器实例
    xmlTextReaderPtr reader = xmlReaderForMemory((const char*)data, size,
                                                 "fuzz.xml", "UTF-8",
                                                 XML_PARSE_RECOVER);
    if (!reader) return;

    // 循环读取节点（模拟增量解析场景）
    int ret;
    while ((ret = xmlTextReaderRead(reader)) == 1) {
        // 随机调用 xmlTextReader* 辅助函数（覆盖更多分支）
        if (rand() % 2 == 0) {
            xmlTextReaderGetAttribute(reader, (const xmlChar*)"attr");
        } else {
            xmlTextReaderNext(reader);
        }
    }
    xmlFreeTextReader(reader); // 释放阅读器
}

/**
 * @brief LibFuzzer 核心入口函数
 * 适配脚本中 DRIVER_FILE 指向的驱动程序入口
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 输入过滤：拒绝无效输入
    if (!filter_invalid_input(data, size)) {
        return 0;
    }

    // 随机选择测试目标（覆盖所有推荐函数）
    int target = rand() % 3;
    switch (target) {
        case 0:
            fuzz_xmlReadMemory(data, size);
            break;
        case 1:
            fuzz_xmlRegexpCompile(data, size);
            break;
        case 2:
            fuzz_xmlTextReaderRead(data, size);
            break;
        default:
            break;
    }

    // 轻量级清理（避免内存泄漏影响 fuzz 稳定性）
    xmlCleanupParser();
    xmlMemoryDump(); // 检测内存泄漏（适配 ASAN 检测）
    return 0;
}
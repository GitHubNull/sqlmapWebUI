#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnShop 日志模块

使用Python内置logging库，支持：
- 同时输出到控制台和文件
- 滚动日志文件（RotatingFileHandler）
- 通过JSON配置文件进行配置
- 多个日志器：主日志、访问日志、SQL日志、错误日志
"""

import os
import json
import logging
import logging.config
import logging.handlers
from pathlib import Path


# 日志目录
LOG_DIR = Path(__file__).parent / "logs"
CONFIG_FILE = Path(__file__).parent / "logging_config.json"

# 默认配置（当配置文件不存在时使用）
DEFAULT_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "[%(asctime)s] %(levelname)-8s %(name)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S"
        },
        "detailed": {
            "format": "[%(asctime)s] %(levelname)-8s [%(name)s:%(funcName)s:%(lineno)d] - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S"
        },
        "access": {
            "format": "[%(asctime)s] %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "standard",
            "stream": "ext://sys.stdout"
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "detailed",
            "filename": str(LOG_DIR / "vulnshop.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "encoding": "utf-8"
        },
        "access_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "INFO",
            "formatter": "access",
            "filename": str(LOG_DIR / "access.log"),
            "maxBytes": 10485760,
            "backupCount": 5,
            "encoding": "utf-8"
        },
        "error_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "ERROR",
            "formatter": "detailed",
            "filename": str(LOG_DIR / "error.log"),
            "maxBytes": 5242880,  # 5MB
            "backupCount": 3,
            "encoding": "utf-8"
        }
    },
    "loggers": {
        "vulnshop": {
            "level": "DEBUG",
            "handlers": ["console", "file"],
            "propagate": False
        },
        "vulnshop.access": {
            "level": "INFO",
            "handlers": ["console", "access_file"],
            "propagate": False
        },
        "vulnshop.sql": {
            "level": "DEBUG",
            "handlers": ["console", "file"],
            "propagate": False
        },
        "vulnshop.error": {
            "level": "ERROR",
            "handlers": ["console", "error_file"],
            "propagate": False
        }
    },
    "root": {
        "level": "INFO",
        "handlers": ["console", "file"]
    }
}


def _ensure_log_dir():
    """确保日志目录存在"""
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def _fix_log_paths(config: dict) -> dict:
    """修正配置中的日志文件路径为绝对路径"""
    handlers = config.get("handlers", {})
    for handler_name, handler_config in handlers.items():
        if "filename" in handler_config:
            filename = handler_config["filename"]
            # 如果是相对路径，转换为绝对路径
            if not os.path.isabs(filename):
                handler_config["filename"] = str(LOG_DIR / os.path.basename(filename))
    return config


def load_config() -> dict:
    """加载日志配置"""
    _ensure_log_dir()
    
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
            return _fix_log_paths(config)
        except Exception as e:
            print(f"[WARNING] Failed to load logging config: {e}, using default config")
            return _fix_log_paths(DEFAULT_CONFIG.copy())
    else:
        return _fix_log_paths(DEFAULT_CONFIG.copy())


def setup_logging():
    """初始化日志系统"""
    config = load_config()
    logging.config.dictConfig(config)


def get_logger(name: str = "vulnshop") -> logging.Logger:
    """
    获取日志器
    
    Args:
        name: 日志器名称
            - "vulnshop": 主日志器
            - "vulnshop.access": 访问日志器
            - "vulnshop.sql": SQL日志器
            - "vulnshop.error": 错误日志器
    
    Returns:
        logging.Logger: 日志器实例
    """
    return logging.getLogger(name)


# 便捷函数
def get_main_logger() -> logging.Logger:
    """获取主日志器"""
    return get_logger("vulnshop")


def get_access_logger() -> logging.Logger:
    """获取访问日志器"""
    return get_logger("vulnshop.access")


def get_sql_logger() -> logging.Logger:
    """获取SQL日志器"""
    return get_logger("vulnshop.sql")


def get_error_logger() -> logging.Logger:
    """获取错误日志器"""
    return get_logger("vulnshop.error")


# 模块加载时自动初始化日志系统
setup_logging()

# 导出的日志器实例
logger = get_main_logger()
access_logger = get_access_logger()
sql_logger = get_sql_logger()
error_logger = get_error_logger()

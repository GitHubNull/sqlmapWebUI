

# 创建一个字典来映射数字到 CONTENT_TYPE 的名称
from third_lib.sqlmap.lib.core.enums import CONTENT_TYPE


CONTENT_TYPE_MAP = {value: key for key, value in CONTENT_TYPE.__dict__.items() if not key.startswith('__') and isinstance(value, int)}


def get_content_type_by_number(number):
    """通过数字获取对应的 CONTENT_TYPE 名称"""
    return CONTENT_TYPE_MAP.get(number, "Unknown Content Type")

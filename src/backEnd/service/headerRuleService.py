# 使用标准库的logging模块
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import status

from model.BaseResponseMsg import BaseResponseMsg
from model.DataStore import DataStore
from model.Database import Database
from model.HeaderBatch import (
    HeaderBatchParseRequest,
    HeaderBatchCreateRequest,
    ParsedHeaderBatchCreateRequest,
    HeaderBatchResult,
    TargetType,
    ParsedHeaderItem
)
from model.PersistentHeaderRule import (
    PersistentHeaderRule,
    PersistentHeaderRuleCreate,
    PersistentHeaderRuleUpdate,
    PersistentHeaderRuleResponse
)
from model.SessionHeader import SessionHeaderCreate
from utils.header_parser import HeaderParser
from utils.header_processor import HeaderProcessor

logger = logging.getLogger(__name__)


class HeaderRuleService:
    """请求头规则服务层 - 处理持久化规则和会话性请求头的业务逻辑"""
    
    def __init__(self):
        self.db = DataStore.header_db
        
    def _get_db(self) -> Database:
        """获取数据库连接，确保连接有效"""
        if DataStore.header_db is None:
            raise RuntimeError("请求头数据库连接未初始化")
        return DataStore.header_db
        
    def _check_db_connection(self) -> bool:
        """检查数据库连接是否有效"""
        try:
            db = self._get_db()
            if db is None or db.connection is None:
                return False
            # 执行一个简单的查询来测试连接
            db.execute("SELECT 1")
            return True
        except Exception as e:
            logger.error(f"Database connection check failed: {e}")
            return False
        
    def _get_current_time(self) -> str:
        """获取当前时间字符串"""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def _validate_rule_data(self, rule_data: PersistentHeaderRuleCreate) -> Optional[str]:
        """验证规则数据的有效性"""
        if not rule_data.name.strip():
            return "规则名称不能为空"
        
        if not HeaderProcessor.validate_header_name(rule_data.header_name):
            return "请求头名称格式无效"
        
        if not rule_data.header_value.strip():
            return "请求头值不能为空"
        
        return None

    async def create_persistent_rule(self, rule_data: PersistentHeaderRuleCreate) -> BaseResponseMsg:
        """创建持久化请求头规则"""
        try:
            # 检查数据库连接
            if not self._check_db_connection():
                logger.error("Database connection is not available")
                return BaseResponseMsg(
                    data=None, 
                    msg="数据库连接不可用，请稍后重试", 
                    success=False, 
                    code=status.HTTP_503_SERVICE_UNAVAILABLE
                )
            
            db = self._get_db()
            
            # 验证数据
            validation_error = self._validate_rule_data(rule_data)
            if validation_error:
                return BaseResponseMsg(
                    data=None, 
                    msg=validation_error, 
                    success=False, 
                    code=status.HTTP_400_BAD_REQUEST
                )
            
            # 检查规则名称是否已存在
            existing_rule = db.execute(
                "SELECT id FROM persistent_header_rules WHERE name = ?", 
                (rule_data.name,)
            )
            
            if existing_rule:
                return BaseResponseMsg(
                    data=None, 
                    msg=f"规则名称 '{rule_data.name}' 已存在", 
                    success=False, 
                    code=status.HTTP_400_BAD_REQUEST
                )
            
            current_time = self._get_current_time()
            
            # 序列化scope配置
            scope_config_json = None
            if rule_data.scope is not None:
                import json
                scope_config_json = json.dumps(rule_data.scope.to_dict(), ensure_ascii=False)
            
            # 插入新规则
            cursor = db.only_execute("""
                INSERT INTO persistent_header_rules 
                (name, header_name, header_value, replace_strategy, match_condition, priority, is_active, scope_config, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_data.name,
                rule_data.header_name,
                rule_data.header_value,
                rule_data.replace_strategy.value,
                rule_data.match_condition,
                rule_data.priority,
                1 if rule_data.is_active else 0,
                scope_config_json,
                current_time,
                current_time
            ))
            
            rule_id = cursor.lastrowid
            
            if rule_id is None:
                raise RuntimeError("插入规则失败，未获取到规则ID")
            
            # 构造响应数据
            response_data = PersistentHeaderRuleResponse(
                id=rule_id,
                name=rule_data.name,
                header_name=rule_data.header_name,
                header_value=rule_data.header_value,
                replace_strategy=rule_data.replace_strategy.value,
                match_condition=rule_data.match_condition,
                priority=rule_data.priority,
                is_active=rule_data.is_active,
                scope=rule_data.scope.to_dict() if rule_data.scope else None,
                created_at=current_time,
                updated_at=current_time
            )
            
            logger.info(f"Created persistent header rule: {rule_data.name} (ID: {rule_id})")
            
            return BaseResponseMsg(
                data=response_data.dict(), 
                msg="持久化请求头规则创建成功", 
                success=True, 
                code=status.HTTP_201_CREATED
            )
            
        except Exception as e:
            logger.error(f"Failed to create persistent rule: {e}")
            return BaseResponseMsg(
                data=None, 
                msg=f"创建规则失败: {str(e)}", 
                success=False, 
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    async def get_persistent_rules(self, active_only: bool = True) -> BaseResponseMsg:
        """获取持久化请求头规则列表"""
        try:
            # 检查数据库连接
            if not self._check_db_connection():
                logger.error("Database connection is not available")
                return BaseResponseMsg(
                    data=None, 
                    msg="数据库连接不可用，请稍后重试", 
                    success=False, 
                    code=status.HTTP_503_SERVICE_UNAVAILABLE
                )
            
            db = self._get_db()
            
            if active_only:
                query = """
                    SELECT id, name, header_name, header_value, replace_strategy, 
                           match_condition, priority, is_active, scope_config, created_at, updated_at
                    FROM persistent_header_rules 
                    WHERE is_active = 1
                    ORDER BY priority DESC, created_at DESC
                """
                rules_data = db.execute(query)
            else:
                query = """
                    SELECT id, name, header_name, header_value, replace_strategy, 
                           match_condition, priority, is_active, scope_config, created_at, updated_at
                    FROM persistent_header_rules 
                    ORDER BY priority DESC, created_at DESC
                """
                rules_data = db.execute(query)
            
            if rules_data is None:
                rules_data = []
            
            rules = []
            for row in rules_data:
                # 解析scope_config
                scope_dict = None
                if row[8]:  # scope_config字段
                    try:
                        import json
                        from model.HeaderScope import HeaderScope
                        scope_data = json.loads(row[8])
                        scope_obj = HeaderScope.from_dict(scope_data)
                        scope_dict = scope_obj.to_dict() if scope_obj else None
                    except Exception as e:
                        logger.warning(f"解析scope_config失败: {e}")
                        scope_dict = None
                
                rule_response = PersistentHeaderRuleResponse(
                    id=row[0],
                    name=row[1],
                    header_name=row[2],
                    header_value=row[3],
                    replace_strategy=row[4],
                    match_condition=row[5],
                    priority=row[6],
                    is_active=bool(row[7]),
                    scope=scope_dict,
                    created_at=row[9],
                    updated_at=row[10]
                )
                rules.append(rule_response.dict())
            
            return BaseResponseMsg(
                data={
                    "rules": rules,
                    "total_count": len(rules)
                }, 
                msg="查询成功", 
                success=True, 
                code=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Failed to get persistent rules: {e}")
            return BaseResponseMsg(
                data=None, 
                msg=f"查询规则失败: {str(e)}", 
                success=False, 
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    async def get_persistent_rule_by_id(self, rule_id: int) -> BaseResponseMsg:
        """根据ID获取持久化请求头规则"""
        try:
            # 检查数据库连接
            if not self._check_db_connection():
                logger.error("Database connection is not available")
                return BaseResponseMsg(
                    data=None, 
                    msg="数据库连接不可用，请稍后重试", 
                    success=False, 
                    code=status.HTTP_503_SERVICE_UNAVAILABLE
                )
            
            db = self._get_db()
            
            query = """
                SELECT id, name, header_name, header_value, replace_strategy, 
                       match_condition, priority, is_active, scope_config, created_at, updated_at
                FROM persistent_header_rules 
                WHERE id = ?
            """
            
            rule_data = db.execute(query, (rule_id,))
            
            if not rule_data:
                return BaseResponseMsg(
                    data=None, 
                    msg=f"规则ID {rule_id} 不存在", 
                    success=False, 
                    code=status.HTTP_404_NOT_FOUND
                )
            
            row = rule_data[0]
            # 解析scope_config
            scope_dict = None
            if row[8]:  # scope_config字段
                try:
                    import json
                    from model.HeaderScope import HeaderScope
                    scope_data = json.loads(row[8])
                    scope_obj = HeaderScope.from_dict(scope_data)
                    scope_dict = scope_obj.to_dict() if scope_obj else None
                except Exception as e:
                    logger.warning(f"解析scope_config失败: {e}")
                    scope_dict = None
            
            rule_response = PersistentHeaderRuleResponse(
                id=row[0],
                name=row[1],
                header_name=row[2],
                header_value=row[3],
                replace_strategy=row[4],
                match_condition=row[5],
                priority=row[6],
                is_active=bool(row[7]),
                scope=scope_dict,
                created_at=row[9],
                updated_at=row[10]
            )
            
            return BaseResponseMsg(
                data=rule_response.dict(), 
                msg="查询成功", 
                success=True, 
                code=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Failed to get persistent rule {rule_id}: {e}")
            return BaseResponseMsg(
                data=None, 
                msg=f"查询规则失败: {str(e)}", 
                success=False, 
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    async def update_persistent_rule(self, rule_id: int, update_data: PersistentHeaderRuleUpdate) -> BaseResponseMsg:
        """更新持久化请求头规则"""
        try:
            # 检查数据库连接
            if not self._check_db_connection():
                logger.error("Database connection is not available")
                return BaseResponseMsg(
                    data=None, 
                    msg="数据库连接不可用，请稍后重试", 
                    success=False, 
                    code=status.HTTP_503_SERVICE_UNAVAILABLE
                )
            
            db = self._get_db()
            
            # 检查规则是否存在
            existing_rule = db.execute(
                "SELECT id, name FROM persistent_header_rules WHERE id = ?", 
                (rule_id,)
            )
            
            if not existing_rule:
                return BaseResponseMsg(
                    data=None, 
                    msg=f"规则ID {rule_id} 不存在", 
                    success=False, 
                    code=status.HTTP_404_NOT_FOUND
                )
            
            # 构建更新SQL
            update_fields = []
            update_values = []
            
            if update_data.name is not None:
                # 检查新名称是否已被其他规则使用
                name_check = db.execute(
                    "SELECT id FROM persistent_header_rules WHERE name = ? AND id != ?", 
                    (update_data.name, rule_id)
                )
                if name_check:
                    return BaseResponseMsg(
                        data=None, 
                        msg=f"规则名称 '{update_data.name}' 已被其他规则使用", 
                        success=False, 
                        code=status.HTTP_400_BAD_REQUEST
                    )
                update_fields.append("name = ?")
                update_values.append(update_data.name)
            
            if update_data.header_name is not None:
                if not HeaderProcessor.validate_header_name(update_data.header_name):
                    return BaseResponseMsg(
                        data=None, 
                        msg="请求头名称格式无效", 
                        success=False, 
                        code=status.HTTP_400_BAD_REQUEST
                    )
                update_fields.append("header_name = ?")
                update_values.append(update_data.header_name)
            
            if update_data.header_value is not None:
                update_fields.append("header_value = ?")
                update_values.append(update_data.header_value)
            
            if update_data.replace_strategy is not None:
                update_fields.append("replace_strategy = ?")
                update_values.append(update_data.replace_strategy.value)
            
            if update_data.match_condition is not None:
                update_fields.append("match_condition = ?")
                update_values.append(update_data.match_condition)
            
            if update_data.priority is not None:
                update_fields.append("priority = ?")
                update_values.append(update_data.priority)
            
            if update_data.is_active is not None:
                update_fields.append("is_active = ?")
                update_values.append(1 if update_data.is_active else 0)
            
            if update_data.scope is not None:
                # 序列化scope配置
                import json
                scope_config_json = None
                if update_data.scope is not None:
                    scope_config_json = json.dumps(update_data.scope.to_dict(), ensure_ascii=False)
                update_fields.append("scope_config = ?")
                update_values.append(scope_config_json)
            
            if not update_fields:
                return BaseResponseMsg(
                    data=None, 
                    msg="没有提供要更新的字段", 
                    success=False, 
                    code=status.HTTP_400_BAD_REQUEST
                )
            
            # 添加更新时间
            update_fields.append("updated_at = ?")
            update_values.append(self._get_current_time())
            update_values.append(rule_id)
            
            # 执行更新
            update_sql = f"""
                UPDATE persistent_header_rules 
                SET {', '.join(update_fields)}
                WHERE id = ?
            """
            
            db.execute(update_sql, update_values)
            
            # 获取更新后的规则
            updated_rule_response = await self.get_persistent_rule_by_id(rule_id)
            
            # 提取响应数据
            response_data = None
            if hasattr(updated_rule_response, 'body'):
                import json
                try:
                    response_content = json.loads(updated_rule_response.body.decode())
                    if response_content.get('success', False):
                        response_data = response_content.get('data')
                except Exception as e:
                    logger.warning(f"Failed to parse updated rule response: {e}")
            
            logger.info(f"Updated persistent header rule: {rule_id}")
            
            return BaseResponseMsg(
                data=response_data, 
                msg="持久化请求头规则更新成功", 
                success=True, 
                code=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Failed to update persistent rule {rule_id}: {e}")
            return BaseResponseMsg(
                data=None, 
                msg=f"更新规则失败: {str(e)}", 
                success=False, 
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    async def delete_persistent_rule(self, rule_id: int) -> BaseResponseMsg:
        """删除持久化请求头规则"""
        try:
            # 检查数据库连接
            if not self._check_db_connection():
                logger.error("Database connection is not available")
                return BaseResponseMsg(
                    data=None, 
                    msg="数据库连接不可用，请稍后重试", 
                    success=False, 
                    code=status.HTTP_503_SERVICE_UNAVAILABLE
                )
            
            db = self._get_db()
            
            # 检查规则是否存在
            existing_rule = db.execute(
                "SELECT id, name FROM persistent_header_rules WHERE id = ?", 
                (rule_id,)
            )
            
            if not existing_rule:
                return BaseResponseMsg(
                    data=None, 
                    msg=f"规则ID {rule_id} 不存在", 
                    success=False, 
                    code=status.HTTP_404_NOT_FOUND
                )
            
            rule_name = existing_rule[0][1]
            
            # 删除规则
            db.execute("DELETE FROM persistent_header_rules WHERE id = ?", (rule_id,))
            
            logger.info(f"Deleted persistent header rule: {rule_name} (ID: {rule_id})")
            
            return BaseResponseMsg(
                data=None, 
                msg=f"持久化请求头规则 '{rule_name}' 删除成功", 
                success=True, 
                code=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Failed to delete persistent rule {rule_id}: {e}")
            return BaseResponseMsg(
                data=None, 
                msg=f"删除规则失败: {str(e)}", 
                success=False, 
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get_active_persistent_rules_for_processing(self) -> List[PersistentHeaderRule]:
        """获取用于处理的活跃持久化规则列表（内部使用）"""
        try:
            # 检查数据库连接
            if not self._check_db_connection():
                logger.error("Database connection is not available for processing")
                return []
            
            db = self._get_db()
            
            query = """
                SELECT id, name, header_name, header_value, replace_strategy, 
                       match_condition, priority, is_active, scope_config, created_at, updated_at
                FROM persistent_header_rules 
                WHERE is_active = 1
                ORDER BY priority DESC
            """
            
            rules_data = db.execute(query)
            
            if rules_data is None:
                rules_data = []
                
            rules = []
            
            for row in rules_data:
                # 构建数据字典包含所有字段
                rule_dict = {
                    'id': row[0],
                    'name': row[1],
                    'header_name': row[2],
                    'header_value': row[3],
                    'replace_strategy': row[4],
                    'match_condition': row[5],
                    'priority': row[6],
                    'is_active': bool(row[7]),
                    'scope_config': row[8],  # scope_config JSON字符串
                    'created_at': row[9],
                    'updated_at': row[10]
                }
                
                # 使用PersistentHeaderRule.from_db_row方法创建对象，该方法会处理scope_config的反序列化
                rule = PersistentHeaderRule.from_db_row(rule_dict)
                rules.append(rule)
            
            return rules
            
        except Exception as e:
            logger.error(f"Failed to get active persistent rules for processing: {e}")
            return []

    async def preview_header_processing(self, headers: List[str], client_ip: str, target_url: Optional[str] = None) -> BaseResponseMsg:
        """
        预览请求头处理结果
        
        参数:
            headers: 原始请求头列表
            client_ip: 客户端IP
            target_url: 目标URL，用于作用域匹配（可选）
        """
        try:
            # 获取持久化规则
            persistent_rules = self.get_active_persistent_rules_for_processing()
            
            # 获取会话性请求头
            session_manager = DataStore.get_session_header_manager()
            if session_manager is None:
                session_headers = {}
            else:
                session_headers = session_manager.get_session_headers(client_ip, active_only=True)
            
            # 预览处理结果（传递target_url用于作用域匹配）
            preview_result = HeaderProcessor.preview_header_processing(
                headers, persistent_rules, session_headers, target_url
            )
            
            return BaseResponseMsg(
                data=preview_result, 
                msg="预览成功", 
                success=True, 
                code=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Failed to preview header processing: {e}")
            return BaseResponseMsg(
                data=None, 
                msg=f"预览失败: {str(e)}", 
                success=False, 
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    # ===========================================
    # 批量操作方法
    # ===========================================
    
    async def parse_headers_batch(self, request: HeaderBatchParseRequest) -> BaseResponseMsg:
        """批量解析请求头"""
        try:
            # 使用HeaderParser解析请求头
            parse_result = HeaderParser.parse_raw_text(
                text=request.raw_text,
                format_hint=request.format_hint,
                default_priority=request.default_priority
            )
            
            if not parse_result.success:
                return BaseResponseMsg(
                    data=None,
                    msg=f"解析失败: {'; '.join(parse_result.errors)}",
                    success=False,
                    code=status.HTTP_400_BAD_REQUEST
                )
            
            # 验证解析结果
            validation_result = HeaderParser.validate_parsed_headers(parse_result.parsed_headers)
            if validation_result["errors"]:
                return BaseResponseMsg(
                    data=None,
                    msg=f"验证失败: {'; '.join(validation_result['errors'])}",
                    success=False,
                    code=status.HTTP_400_BAD_REQUEST
                )
            
            # 添加验证警告到解析结果
            parse_result.warnings.extend(validation_result["warnings"])
            
            logger.info(f"Parsed {parse_result.total_count} headers successfully")
            
            return BaseResponseMsg(
                data=parse_result.dict(),
                msg="解析成功",
                success=True,
                code=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Failed to parse headers batch: {e}")
            return BaseResponseMsg(
                data=None,
                msg=f"解析失败: {str(e)}",
                success=False,
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    async def create_persistent_rules_batch(self, request: ParsedHeaderBatchCreateRequest) -> BaseResponseMsg:
        """批量创建持久化请求头规则"""
        try:
            if not request.rule_config:
                return BaseResponseMsg(
                    data=None,
                    msg="缺少持久化规则配置",
                    success=False,
                    code=status.HTTP_400_BAD_REQUEST
                )
            
            # 检查数据库连接
            if not self._check_db_connection():
                logger.error("Database connection is not available")
                return BaseResponseMsg(
                    data=None, 
                    msg="数据库连接不可用，请稍后重试", 
                    success=False, 
                    code=status.HTTP_503_SERVICE_UNAVAILABLE
                )
            
            db = self._get_db()
            current_time = self._get_current_time()
            created_items = []
            failed_items = []
            warnings = []
            
            for i, header_item in enumerate(request.headers):
                try:
                    # 生成规则名称
                    rule_name = f"{request.rule_config.name_prefix}{header_item.header_name}_{current_time.replace(':', '').replace('-', '').replace(' ', '_')}"
                    
                    # 检查名称是否已存在，如果存在则添加序号
                    base_name = rule_name
                    counter = 1
                    while True:
                        existing_rule = db.execute(
                            "SELECT id FROM persistent_header_rules WHERE name = ?", 
                            (rule_name,)
                        )
                        if not existing_rule:
                            break
                        rule_name = f"{base_name}_{counter}"
                        counter += 1
                    
                    # 创建规则数据
                    rule_data = PersistentHeaderRuleCreate(
                        name=rule_name,
                        header_name=header_item.header_name,
                        header_value=header_item.header_value,
                        replace_strategy=request.rule_config.replace_strategy,
                        priority=max(header_item.priority, request.rule_config.default_priority),
                        is_active=request.rule_config.is_active
                    )
                    
                    # 验证数据
                    validation_error = self._validate_rule_data(rule_data)
                    if validation_error:
                        failed_items.append({
                            "header_name": header_item.header_name,
                            "reason": validation_error,
                            "source_line": header_item.source_line
                        })
                        continue
                    
                    # 插入新规则
                    cursor = db.only_execute("""
                        INSERT INTO persistent_header_rules 
                        (name, header_name, header_value, replace_strategy, match_condition, priority, is_active, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        rule_data.name,
                        rule_data.header_name,
                        rule_data.header_value,
                        rule_data.replace_strategy.value,
                        rule_data.match_condition,
                        rule_data.priority,
                        1 if rule_data.is_active else 0,
                        current_time,
                        current_time
                    ))
                    
                    rule_id = cursor.lastrowid
                    
                    if rule_id is None:
                        failed_items.append({
                            "header_name": header_item.header_name,
                            "reason": "插入规则失败，未获取到规则ID",
                            "source_line": header_item.source_line
                        })
                        continue
                    
                    created_items.append({
                        "id": rule_id,
                        "name": rule_data.name,
                        "header_name": rule_data.header_name,
                        "header_value": rule_data.header_value,
                        "source_line": header_item.source_line
                    })
                    
                    logger.debug(f"Created persistent rule: {rule_data.name} (ID: {rule_id})")
                    
                except Exception as e:
                    failed_items.append({
                        "header_name": header_item.header_name,
                        "reason": f"创建失败: {str(e)}",
                        "source_line": header_item.source_line
                    })
            
            # 构造返回结果
            result = HeaderBatchResult(
                success=len(created_items) > 0,
                total_count=len(request.headers),
                success_count=len(created_items),
                failed_count=len(failed_items),
                created_items=created_items,
                failed_items=failed_items,
                warnings=warnings
            )
            
            if result.success_count == 0:
                msg = "批量创建失败，所有项目都未能成功创建"
                status_code = status.HTTP_400_BAD_REQUEST
            elif result.failed_count == 0:
                msg = f"批量创建成功，共创建 {result.success_count} 个持久化规则"
                status_code = status.HTTP_201_CREATED
            else:
                msg = f"批量创建部分成功，成功 {result.success_count} 个，失败 {result.failed_count} 个"
                status_code = status.HTTP_206_PARTIAL_CONTENT
            
            logger.info(f"Batch created persistent rules: {result.success_count}/{result.total_count} successful")
            
            return BaseResponseMsg(
                data=result.dict(),
                msg=msg,
                success=result.success,
                code=status_code
            )
            
        except Exception as e:
            logger.error(f"Failed to create persistent rules batch: {e}")
            return BaseResponseMsg(
                data=None,
                msg=f"批量创建失败: {str(e)}",
                success=False,
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    async def create_session_headers_batch(self, request: ParsedHeaderBatchCreateRequest, client_ip: str) -> BaseResponseMsg:
        """批量创建会话性请求头"""
        try:
            if not request.session_config:
                return BaseResponseMsg(
                    data=None,
                    msg="缺少会话配置",
                    success=False,
                    code=status.HTTP_400_BAD_REQUEST
                )
            
            session_manager = DataStore.get_session_header_manager()
            created_items = []
            failed_items = []
            warnings = []
            
            for header_item in request.headers:
                try:
                    # 创建会话头数据
                    session_header_data = SessionHeaderCreate(
                        header_name=header_item.header_name,
                        header_value=header_item.header_value,
                        priority=max(header_item.priority, request.session_config.default_priority),
                        ttl=request.session_config.default_ttl
                    )
                    
                    # 设置会话头
                    success = session_manager.set_session_header(
                        client_ip=client_ip,
                        header_create=session_header_data
                    )
                    
                    if success:
                        created_items.append({
                            "header_name": header_item.header_name,
                            "header_value": header_item.header_value,
                            "priority": session_header_data.priority,
                            "ttl": session_header_data.ttl,
                            "source_line": header_item.source_line
                        })
                        logger.debug(f"Created session header: {header_item.header_name}")
                    else:
                        failed_items.append({
                            "header_name": header_item.header_name,
                            "reason": "设置会话头失败",
                            "source_line": header_item.source_line
                        })
                        
                except Exception as e:
                    failed_items.append({
                        "header_name": header_item.header_name,
                        "reason": f"创建失败: {str(e)}",
                        "source_line": header_item.source_line
                    })
            
            # 构造返回结果
            result = HeaderBatchResult(
                success=len(created_items) > 0,
                total_count=len(request.headers),
                success_count=len(created_items),
                failed_count=len(failed_items),
                created_items=created_items,
                failed_items=failed_items,
                warnings=warnings
            )
            
            if result.success_count == 0:
                msg = "批量创建失败，所有项目都未能成功创建"
                status_code = status.HTTP_400_BAD_REQUEST
            elif result.failed_count == 0:
                msg = f"批量创建成功，共创建 {result.success_count} 个会话头"
                status_code = status.HTTP_201_CREATED
            else:
                msg = f"批量创建部分成功，成功 {result.success_count} 个，失败 {result.failed_count} 个"
                status_code = status.HTTP_206_PARTIAL_CONTENT
            
            logger.info(f"Batch created session headers for {client_ip}: {result.success_count}/{result.total_count} successful")
            
            return BaseResponseMsg(
                data=result.dict(),
                msg=msg,
                success=result.success,
                code=status_code
            )
            
        except Exception as e:
            logger.error(f"Failed to create session headers batch: {e}")
            return BaseResponseMsg(
                data=None,
                msg=f"批量创建失败: {str(e)}",
                success=False,
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    async def create_headers_batch(self, request: HeaderBatchCreateRequest, client_ip: str) -> BaseResponseMsg:
        """一体化批量创建请求头（解析+创建）"""
        try:
            # 1. 解析请求头
            parse_request = HeaderBatchParseRequest(
                raw_text=request.raw_text,
                format_hint=request.format_hint,
                default_priority=request.rule_config.default_priority if request.rule_config else 0
            )
            
            parse_response = await self.parse_headers_batch(parse_request)
            if hasattr(parse_response, 'body'):
                import json
                try:
                    response_content = json.loads(parse_response.body)
                    if not response_content.get('success', False):
                        return parse_response
                except Exception as e:
                    logger.error(f"Failed to parse response: {e}")
                    return parse_response
            else:
                # Fallback
                return parse_response
            
            parsed_headers = []
            for header_data in response_content["data"]["parsed_headers"]:
                parsed_headers.append(ParsedHeaderItem(**header_data))
            
            # 2. 创建批量创建请求
            batch_create_request = ParsedHeaderBatchCreateRequest(
                headers=parsed_headers,
                target_type=request.target_type,
                rule_config=request.rule_config,
                session_config=request.session_config
            )
            
            # 3. 根据目标类型执行批量创建
            if request.target_type == TargetType.PERSISTENT:
                return await self.create_persistent_rules_batch(batch_create_request)
            elif request.target_type == TargetType.SESSION:
                return await self.create_session_headers_batch(batch_create_request, client_ip)
            else:
                return BaseResponseMsg(
                    data=None,
                    msg=f"不支持的目标类型: {request.target_type}",
                    success=False,
                    code=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            logger.error(f"Failed to create headers batch: {e}")
            return BaseResponseMsg(
                data=None,
                msg=f"批量创建失败: {str(e)}",
                success=False,
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
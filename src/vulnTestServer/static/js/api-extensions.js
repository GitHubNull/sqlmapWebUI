/**
 * VulnShop 购物功能扩展 - 正常购物网站功能页面
 * 包含会员中心、评价中心、优惠券中心等功能
 */

// ==================== 优惠券模块 API ====================
const couponApi = {
    // 查询优惠券
    async queryCoupon(couponCode, category = '') {
        const innerData = { coupon_code: couponCode };
        if (category) innerData.category = category;
        
        const encodedData = btoa(JSON.stringify(innerData));
        return api.post('/api/coupon/query', {
            req_id: `REQ_${Date.now()}`,
            data: encodedData
        });
    },

    // 搜索优惠券
    async searchCoupon(keyword, category = '') {
        const innerData = { 
            keyword: keyword,
            status: 'active'
        };
        if (category) innerData.category = category;
        
        const encodedData = btoa(JSON.stringify(innerData));
        return api.post('/api/coupon/search', {
            req_id: `REQ_${Date.now()}`,
            data: encodedData
        });
    },

    // 按分类查询优惠券
    async getCouponsByCategory(category, minDiscount = 0) {
        const innerData = { 
            category: category,
            min_discount: minDiscount
        };
        
        const encodedData = btoa(JSON.stringify(innerData));
        return api.post('/api/coupon/category', {
            req_id: `REQ_${Date.now()}`,
            data: encodedData
        });
    },

    // 调试：解码
    async debugDecode(encodedData) {
        return api.post('/api/coupon/debug/decode', { data: encodedData });
    },

    // 调试：编码
    async debugEncode(data) {
        return api.post('/api/coupon/debug/encode', { data: data });
    },

    // 解码响应数据（正确处理 UTF-8 编码的 Base64）
    decodeResponse(response) {
        if (response.success && response.data) {
            try {
                // 使用 TextDecoder 正确处理 UTF-8 编码的 Base64
                const binaryString = atob(response.data);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                const decoder = new TextDecoder('utf-8');
                const jsonString = decoder.decode(bytes);
                return JSON.parse(jsonString);
            } catch (e) {
                console.error('Decode response error:', e);
                return response;
            }
        }
        return response;
    }
};

// ==================== 会员中心模块 ====================
const memberCenter = {
    // 显示会员中心弹窗
    show() {
        const modal = document.createElement('div');
        modal.id = 'memberCenterModal';
        modal.className = 'modal show';
        modal.innerHTML = `
            <div class="modal-content modal-lg">
                <div class="modal-header">
                    <h3>👤 会员中心</h3>
                    <button class="cart-close" onclick="document.getElementById('memberCenterModal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="member-tabs">
                        <button class="member-tab active" data-tab="level">会员等级</button>
                        <button class="member-tab" data-tab="points">积分查询</button>
                        <button class="member-tab" data-tab="history">消费记录</button>
                    </div>
                    <div class="member-content">
                        <div id="tab-level" class="member-tab-content active">
                            ${this.getLevelContent()}
                        </div>
                        <div id="tab-points" class="member-tab-content">
                            ${this.getPointsContent()}
                        </div>
                        <div id="tab-history" class="member-tab-content">
                            ${this.getHistoryContent()}
                        </div>
                    </div>
                    <div id="memberResult" class="result-area"></div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        this.initEvents();
    },

    getLevelContent() {
        return `
            <div class="function-section">
                <h4>🏅 会员等级查询</h4>
                <p class="function-desc">查询您的会员等级和专属权益</p>
                <div class="function-form">
                    <div class="form-group">
                        <label>用户名</label>
                        <input type="text" id="memberLevelUsername" placeholder="输入用户名">
                    </div>
                    <button class="btn btn-primary" onclick="memberCenter.queryLevel()">查询等级</button>
                </div>
                <div class="vuln-hint">
                    <strong>💡 提示:</strong> 此功能用于查询会员等级信息
                    <code>输入用户名查看会员权益</code>
                </div>
            </div>
        `;
    },

    getPointsContent() {
        return `
            <div class="function-section">
                <h4>💎 积分查询</h4>
                <p class="function-desc">查询您的账户积分和兑换记录</p>
                <div class="function-form">
                    <div class="form-group">
                        <label>用户ID</label>
                        <input type="text" id="memberPointsUserId" placeholder="输入用户ID">
                    </div>
                    <button class="btn btn-primary" onclick="memberCenter.queryPoints()">查询积分</button>
                </div>
                <div class="vuln-hint">
                    <strong>💡 提示:</strong> 查询用户账户余额和消费积分
                    <code>用户余额即会员积分</code>
                </div>
            </div>
        `;
    },

    getHistoryContent() {
        return `
            <div class="function-section">
                <h4>📊 消费记录</h4>
                <p class="function-desc">查看您的消费统计和历史订单</p>
                <div class="function-form">
                    <div class="form-group">
                        <label>用户ID</label>
                        <input type="text" id="memberHistoryUserId" placeholder="输入用户ID">
                    </div>
                    <div class="form-group">
                        <label>统计方式</label>
                        <select id="memberHistoryGroupBy">
                            <option value="status">按状态</option>
                            <option value="month">按月份</option>
                            <option value="product">按商品</option>
                        </select>
                    </div>
                    <button class="btn btn-primary" onclick="memberCenter.queryHistory()">查询记录</button>
                </div>
            </div>
        `;
    },

    initEvents() {
        document.querySelectorAll('.member-tab').forEach(tab => {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.member-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.member-tab-content').forEach(c => c.classList.remove('active'));
                this.classList.add('active');
                document.getElementById(`tab-${this.dataset.tab}`).classList.add('active');
            });
        });
    },

    async queryLevel() {
        const username = document.getElementById('memberLevelUsername').value;
        if (!username) {
            cart.showToast('请输入用户名', 'warning');
            return;
        }
        const result = await apiExtensions.searchUsers(username, 'username');
        this.showResult(result, '会员等级信息');
    },

    async queryPoints() {
        const userId = document.getElementById('memberPointsUserId').value;
        if (!userId) {
            cart.showToast('请输入用户ID', 'warning');
            return;
        }
        const result = await api.getProfile(userId);
        this.showResult(result, '积分余额信息');
    },

    async queryHistory() {
        const userId = document.getElementById('memberHistoryUserId').value;
        const groupBy = document.getElementById('memberHistoryGroupBy').value;
        if (!userId) {
            cart.showToast('请输入用户ID', 'warning');
            return;
        }
        const result = await apiExtensions.getOrdersStats(groupBy, '');
        this.showResult(result, '消费统计');
    },

    showResult(result, title) {
        const panel = document.getElementById('memberResult');
        const isError = !result.success;
        
        let html = `<div class="result-${isError ? 'error' : 'success'}">`;
        html += `<h4>${isError ? '❌' : '✅'} ${title}</h4>`;
        
        if (result.success && result.data) {
            html += `<pre>${JSON.stringify(result.data, null, 2)}</pre>`;
        } else {
            html += `<p>${result.message || '查询失败'}</p>`;
            if (result.debug && result.debug.sql_error) {
                html += `<pre class="sql-error">${result.debug.sql_error}</pre>`;
            }
        }
        html += '</div>';
        panel.innerHTML = html;
    }
};

// ==================== 优惠券中心模块 ====================
const couponCenter = {
    // 显示优惠券中心弹窗
    show() {
        const modal = document.createElement('div');
        modal.id = 'couponCenterModal';
        modal.className = 'modal show';
        modal.innerHTML = `
            <div class="modal-content modal-lg">
                <div class="modal-header">
                    <h3>🎫 优惠券中心</h3>
                    <button class="cart-close" onclick="document.getElementById('couponCenterModal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="coupon-tabs">
                        <button class="coupon-tab active" data-tab="query">优惠券查询</button>
                        <button class="coupon-tab" data-tab="search">优惠券搜索</button>
                        <button class="coupon-tab" data-tab="category">分类优惠券</button>
                        <button class="coupon-tab" data-tab="debug">编码工具</button>
                    </div>
                    <div class="coupon-content">
                        <div id="tab-query" class="coupon-tab-content active">
                            ${this.getQueryContent()}
                        </div>
                        <div id="tab-search" class="coupon-tab-content">
                            ${this.getSearchContent()}
                        </div>
                        <div id="tab-category" class="coupon-tab-content">
                            ${this.getCategoryContent()}
                        </div>
                        <div id="tab-debug" class="coupon-tab-content">
                            ${this.getDebugContent()}
                        </div>
                    </div>
                    <div id="couponResult" class="result-area"></div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        this.initEvents();
    },

    getQueryContent() {
        return `
            <div class="function-section">
                <h4>🔍 优惠券查询</h4>
                <p class="function-desc">输入优惠券代码查询优惠详情</p>
                <div class="function-form">
                    <div class="form-group">
                        <label>优惠券代码</label>
                        <input type="text" id="couponQueryCode" placeholder="如: SAVE10">
                    </div>
                    <div class="form-group">
                        <label>分类筛选（可选）</label>
                        <select id="couponQueryCategory">
                            <option value="">全部分类</option>
                            <option value="electronics">电子产品</option>
                            <option value="fashion">服装配饰</option>
                            <option value="books">图书音像</option>
                            <option value="home">家居家装</option>
                        </select>
                    </div>
                    <button class="btn btn-primary" onclick="couponCenter.queryCoupon()">查询优惠券</button>
                </div>
                <div class="vuln-hint">
                    <strong>💡 提示:</strong> 输入优惠券代码查询可用优惠
                    <code>可用优惠券: SAVE10, NEWUSER20, VIP30, FLASH50, BOOKS15</code>
                </div>
            </div>
        `;
    },

    getSearchContent() {
        return `
            <div class="function-section">
                <h4>🔎 优惠券搜索</h4>
                <p class="function-desc">搜索可用的优惠券</p>
                <div class="function-form">
                    <div class="form-group">
                        <label>搜索关键词</label>
                        <input type="text" id="couponSearchKeyword" placeholder="输入关键词搜索">
                    </div>
                    <div class="form-group">
                        <label>分类筛选（可选）</label>
                        <select id="couponSearchCategory">
                            <option value="">全部分类</option>
                            <option value="electronics">电子产品</option>
                            <option value="fashion">服装配饰</option>
                            <option value="books">图书音像</option>
                        </select>
                    </div>
                    <button class="btn btn-primary" onclick="couponCenter.searchCoupon()">搜索优惠券</button>
                </div>
            </div>
        `;
    },

    getCategoryContent() {
        return `
            <div class="function-section">
                <h4>📁 分类优惠券</h4>
                <p class="function-desc">按商品分类查看可用优惠券</p>
                <div class="function-form">
                    <div class="form-group">
                        <label>商品分类</label>
                        <select id="couponCategorySelect">
                            <option value="electronics">电子产品</option>
                            <option value="fashion">服装配饰</option>
                            <option value="books">图书音像</option>
                            <option value="home">家居家装</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>最低折扣（可选）</label>
                        <input type="number" id="couponMinDiscount" placeholder="最低折扣百分比" value="0">
                    </div>
                    <button class="btn btn-primary" onclick="couponCenter.getByCategory()">查询分类优惠券</button>
                </div>
            </div>
        `;
    },

    getDebugContent() {
        return `
            <div class="function-section">
                <h4>🔧 编码工具</h4>
                <p class="function-desc">编码/解码优惠券查询参数</p>
                <div class="debug-section">
                    <h5>编码参数</h5>
                    <div class="form-group">
                        <label>原始数据 (JSON)</label>
                        <textarea id="debugEncodeInput" rows="4" placeholder='{"coupon_code": "SAVE10"}'></textarea>
                    </div>
                    <button class="btn btn-outline" onclick="couponCenter.debugEncode()">编码</button>
                    <div class="form-group">
                        <label>编码结果</label>
                        <input type="text" id="debugEncodeOutput" readonly>
                    </div>
                </div>
                <div class="debug-section">
                    <h5>解码参数</h5>
                    <div class="form-group">
                        <label>编码数据</label>
                        <input type="text" id="debugDecodeInput" placeholder="Base64 编码的字符串">
                    </div>
                    <button class="btn btn-outline" onclick="couponCenter.debugDecode()">解码</button>
                    <div class="form-group">
                        <label>解码结果</label>
                        <textarea id="debugDecodeOutput" rows="4" readonly></textarea>
                    </div>
                </div>
            </div>
        `;
    },

    initEvents() {
        document.querySelectorAll('.coupon-tab').forEach(tab => {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.coupon-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.coupon-tab-content').forEach(c => c.classList.remove('active'));
                this.classList.add('active');
                document.getElementById(`tab-${this.dataset.tab}`).classList.add('active');
            });
        });
    },

    async queryCoupon() {
        const code = document.getElementById('couponQueryCode').value;
        const category = document.getElementById('couponQueryCategory').value;
        if (!code) {
            cart.showToast('请输入优惠券代码', 'warning');
            return;
        }
        const result = await couponApi.queryCoupon(code, category);
        this.showResult(result, '优惠券信息');
    },

    async searchCoupon() {
        const keyword = document.getElementById('couponSearchKeyword').value;
        const category = document.getElementById('couponSearchCategory').value;
        if (!keyword) {
            cart.showToast('请输入搜索关键词', 'warning');
            return;
        }
        const result = await couponApi.searchCoupon(keyword, category);
        this.showResult(result, '搜索结果');
    },

    async getByCategory() {
        const category = document.getElementById('couponCategorySelect').value;
        const minDiscount = document.getElementById('couponMinDiscount').value || 0;
        const result = await couponApi.getCouponsByCategory(category, minDiscount);
        this.showResult(result, '分类优惠券');
    },

    async debugEncode() {
        const input = document.getElementById('debugEncodeInput').value;
        try {
            const data = JSON.parse(input);
            const result = await couponApi.debugEncode(data);
            if (result.success) {
                document.getElementById('debugEncodeOutput').value = result.encoded;
            } else {
                cart.showToast(result.message || '编码失败', 'error');
            }
        } catch (e) {
            cart.showToast('请输入有效的JSON格式', 'error');
        }
    },

    async debugDecode() {
        const input = document.getElementById('debugDecodeInput').value;
        if (!input) {
            cart.showToast('请输入编码数据', 'warning');
            return;
        }
        const result = await couponApi.debugDecode(input);
        if (result.success) {
            document.getElementById('debugDecodeOutput').value = JSON.stringify(result.decoded, null, 2);
        } else {
            cart.showToast(result.message || '解码失败', 'error');
        }
    },

    showResult(result, title) {
        const panel = document.getElementById('couponResult');
        const isError = !result.success;
        
        let html = `<div class="result-${isError ? 'error' : 'success'}">`;
        html += `<h4>${isError ? '❌' : '✅'} ${title}</h4>`;
        
        // 尝试解码响应数据
        const decodedData = couponApi.decodeResponse(result);
        
        if (result.success) {
            if (decodedData.coupons && decodedData.coupons.length > 0) {
                html += '<div class="coupon-list">';
                decodedData.coupons.forEach(coupon => {
                    const discountText = coupon.discount_type === 'percent' 
                        ? `${coupon.discount_value}% 折扣` 
                        : `¥${coupon.discount_value} 立减`;
                    html += `
                        <div class="coupon-item">
                            <div class="coupon-code">${coupon.coupon_code}</div>
                            <div class="coupon-discount">${discountText}</div>
                            <div class="coupon-info">
                                满¥${coupon.min_purchase}可用
                                ${coupon.max_discount ? ` | 最高减¥${coupon.max_discount}` : ''}
                            </div>
                            <div class="coupon-category">${coupon.category || '全品类'}</div>
                        </div>
                    `;
                });
                html += '</div>';
            } else {
                html += `<p>${decodedData.message || '未找到匹配的优惠券'}</p>`;
            }
        } else {
            html += `<p>${result.message || '查询失败'}</p>`;
            if (result.debug && result.debug.sql_error) {
                html += `<details><summary>错误详情</summary><pre class="sql-error">${result.debug.sql_error}</pre></details>`;
            }
        }
        html += '</div>';
        panel.innerHTML = html;
    }
};

// ==================== 评价中心模块 ====================
const reviewCenter = {
    // 显示评价中心弹窗
    show() {
        const modal = document.createElement('div');
        modal.id = 'reviewCenterModal';
        modal.className = 'modal show';
        modal.innerHTML = `
            <div class="modal-content modal-lg">
                <div class="modal-header">
                    <h3>⭐ 评价中心</h3>
                    <button class="cart-close" onclick="document.getElementById('reviewCenterModal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="review-tabs">
                        <button class="review-tab active" data-tab="my-reviews">我的评价</button>
                        <button class="review-tab" data-tab="product-reviews">商品评价</button>
                        <button class="review-tab" data-tab="feedback">意见反馈</button>
                    </div>
                    <div class="review-content">
                        <div id="tab-my-reviews" class="review-tab-content active">
                            ${this.getMyReviewsContent()}
                        </div>
                        <div id="tab-product-reviews" class="review-tab-content">
                            ${this.getProductReviewsContent()}
                        </div>
                        <div id="tab-feedback" class="review-tab-content">
                            ${this.getFeedbackContent()}
                        </div>
                    </div>
                    <div id="reviewResult" class="result-area"></div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        this.initEvents();
    },

    getMyReviewsContent() {
        return `
            <div class="function-section">
                <h4>📝 我的评价记录</h4>
                <p class="function-desc">查看您发表的商品评价</p>
                <div class="function-form">
                    <div class="form-group">
                        <label>用户ID</label>
                        <input type="text" id="reviewUserId" placeholder="输入用户ID">
                    </div>
                    <button class="btn btn-primary" onclick="reviewCenter.queryMyReviews()">查看评价</button>
                </div>
                <div class="vuln-hint">
                    <strong>💡 提示:</strong> 查看用户发表的商品评价记录
                    <code>用户ID: 2, 3, 4 有评价记录</code>
                </div>
            </div>
        `;
    },

    getProductReviewsContent() {
        return `
            <div class="function-section">
                <h4>🔍 商品评价搜索</h4>
                <p class="function-desc">搜索商品评价和评分</p>
                <div class="function-form">
                    <div class="form-group">
                        <label>搜索关键词</label>
                        <input type="text" id="reviewSearchKeyword" placeholder="输入评价内容关键词">
                    </div>
                    <div class="form-group">
                        <label>搜索范围</label>
                        <select id="reviewSearchIn">
                            <option value="title">标题</option>
                            <option value="content">内容</option>
                        </select>
                    </div>
                    <button class="btn btn-primary" onclick="reviewCenter.searchReviews()">搜索评价</button>
                </div>
            </div>
        `;
    },

    getFeedbackContent() {
        return `
            <div class="function-section">
                <h4>📬 意见反馈</h4>
                <p class="function-desc">查看反馈列表和状态</p>
                <div class="function-form">
                    <div class="form-group">
                        <label>排序方式</label>
                        <select id="feedbackSortBy">
                            <option value="created_at">按时间</option>
                            <option value="rating">按评分</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>排序方向</label>
                        <select id="feedbackOrder">
                            <option value="DESC">降序</option>
                            <option value="ASC">升序</option>
                        </select>
                    </div>
                    <button class="btn btn-primary" onclick="reviewCenter.queryFeedback()">查看反馈</button>
                </div>
            </div>
        `;
    },

    initEvents() {
        document.querySelectorAll('.review-tab').forEach(tab => {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.review-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.review-tab-content').forEach(c => c.classList.remove('active'));
                this.classList.add('active');
                document.getElementById(`tab-${this.dataset.tab}`).classList.add('active');
            });
        });
    },

    async queryMyReviews() {
        const userId = document.getElementById('reviewUserId').value;
        if (!userId) {
            cart.showToast('请输入用户ID', 'warning');
            return;
        }
        // 使用反馈列表接口模拟评价查询
        const result = await apiExtensions.getFeedbackList('created_at', 'DESC', 10);
        this.showResult(result, '我的评价');
    },

    async searchReviews() {
        const keyword = document.getElementById('reviewSearchKeyword').value;
        const searchIn = document.getElementById('reviewSearchIn').value;
        if (!keyword) {
            cart.showToast('请输入搜索关键词', 'warning');
            return;
        }
        const result = await apiExtensions.searchFeedback(keyword, searchIn, 1);
        this.showResult(result, '评价搜索结果');
    },

    async queryFeedback() {
        const sortBy = document.getElementById('feedbackSortBy').value;
        const order = document.getElementById('feedbackOrder').value;
        const result = await apiExtensions.getFeedbackList(sortBy, order, 10);
        this.showResult(result, '反馈列表');
    },

    showResult(result, title) {
        const panel = document.getElementById('reviewResult');
        const isError = !result.success;
        
        let html = `<div class="result-${isError ? 'error' : 'success'}">`;
        html += `<h4>${isError ? '❌' : '✅'} ${title}</h4>`;
        
        if (result.success && result.data) {
            html += `<pre>${JSON.stringify(result.data, null, 2)}</pre>`;
        } else {
            html += `<p>${result.message || '查询失败'}</p>`;
            if (result.debug && result.debug.sql_error) {
                html += `<pre class="sql-error">${result.debug.sql_error}</pre>`;
            }
        }
        html += '</div>';
        panel.innerHTML = html;
    }
};

// ==================== 样式定义 ====================
const shoppingStyles = `
<style>
/* 功能模块通用样式 */
.function-section {
    margin-bottom: 25px;
    padding: 20px;
    background: var(--bg-input);
    border-radius: 10px;
    border: 1px solid var(--border-color);
}

.function-section h4 {
    font-size: 16px;
    color: var(--text-primary);
    margin-bottom: 8px;
}

.function-desc {
    font-size: 13px;
    color: var(--text-muted);
    margin-bottom: 15px;
}

.function-form {
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
    align-items: flex-end;
}

.function-form .form-group {
    margin-bottom: 0;
    flex: 1;
    min-width: 150px;
}

.function-form .form-group label {
    display: block;
    margin-bottom: 6px;
    color: var(--text-secondary);
    font-size: 13px;
}

.function-form .form-group input,
.function-form .form-group select,
.function-form .form-group textarea {
    width: 100%;
    padding: 10px 14px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 14px;
}

.function-form .form-group input:focus,
.function-form .form-group select:focus,
.function-form .form-group textarea:focus {
    outline: none;
    border-color: var(--primary);
}

.function-form button {
    height: fit-content;
}

/* 标签页样式 */
.member-tabs,
.coupon-tabs,
.review-tabs {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 10px;
    flex-wrap: wrap;
}

.member-tab,
.coupon-tab,
.review-tab {
    padding: 10px 20px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    cursor: pointer;
    color: var(--text-secondary);
    font-size: 14px;
    transition: all 0.2s;
}

.member-tab:hover,
.coupon-tab:hover,
.review-tab:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
}

.member-tab.active,
.coupon-tab.active,
.review-tab.active {
    background: var(--primary);
    color: #fff;
    border-color: var(--primary);
}

.member-tab-content,
.coupon-tab-content,
.review-tab-content {
    display: none;
}

.member-tab-content.active,
.coupon-tab-content.active,
.review-tab-content.active {
    display: block;
}

/* 优惠券列表样式 */
.coupon-list {
    display: grid;
    gap: 15px;
    margin-top: 15px;
}

.coupon-item {
    display: grid;
    grid-template-columns: auto 1fr auto;
    gap: 15px;
    padding: 15px 20px;
    background: linear-gradient(135deg, rgba(233, 69, 96, 0.1) 0%, rgba(233, 69, 96, 0.05) 100%);
    border: 1px dashed var(--primary);
    border-radius: 10px;
    align-items: center;
}

.coupon-code {
    font-size: 18px;
    font-weight: 700;
    color: var(--primary);
    font-family: 'Consolas', monospace;
}

.coupon-discount {
    font-size: 24px;
    font-weight: 700;
    color: var(--success);
}

.coupon-info {
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 5px;
}

.coupon-category {
    padding: 4px 12px;
    background: var(--bg-input);
    border-radius: 20px;
    font-size: 12px;
    color: var(--text-secondary);
}

/* 调试工具样式 */
.debug-section {
    margin-bottom: 20px;
    padding: 15px;
    background: var(--bg-card);
    border-radius: 8px;
    border: 1px solid var(--border-color);
}

.debug-section h5 {
    font-size: 14px;
    color: var(--text-primary);
    margin-bottom: 12px;
}

.debug-section textarea {
    font-family: 'Consolas', monospace;
    font-size: 13px;
}

/* 结果区域样式 */
.result-area {
    margin-top: 20px;
    padding: 15px;
    background: var(--bg-input);
    border-radius: 8px;
    border: 1px solid var(--border-color);
}

.result-success,
.result-error {
    padding: 15px;
    border-radius: 8px;
}

.result-success {
    background: rgba(46, 204, 113, 0.1);
    border: 1px solid var(--success);
}

.result-success h4 {
    color: var(--success);
    margin-bottom: 10px;
}

.result-error {
    background: rgba(231, 76, 60, 0.1);
    border: 1px solid var(--danger);
}

.result-error h4 {
    color: var(--danger);
    margin-bottom: 10px;
}

.result-area pre {
    background: var(--code-bg);
    padding: 12px;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 12px;
    margin-top: 10px;
}

.sql-error {
    color: var(--danger);
    background: rgba(231, 76, 60, 0.1) !important;
}

/* 响应式 */
@media (max-width: 768px) {
    .function-form {
        flex-direction: column;
    }
    
    .function-form .form-group {
        width: 100%;
    }
    
    .coupon-item {
        grid-template-columns: 1fr;
        text-align: center;
    }
}
</style>
`;

// 添加样式到页面
document.head.insertAdjacentHTML('beforeend', shoppingStyles);

// 导出到全局
window.couponApi = couponApi;
window.memberCenter = memberCenter;
window.couponCenter = couponCenter;
window.reviewCenter = reviewCenter;


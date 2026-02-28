/**
 * VulnShop API Extensions - 新增接口前端功能
 * 为新增的27个CRUD接口提供前端支持
 */

// ==================== 扩展API调用 ====================
const apiExtensions = {
    // 用户模块扩展
    async deleteUser(userId, reason = '') {
        const xmlData = `<?xml version="1.0" encoding="UTF-8"?>
<request>
    <user_id>${userId}</user_id>
    <reason>${reason}</reason>
    <session_id>sess_${Date.now()}</session_id>
    <auth_token>${Math.random().toString(36).substring(7)}</auth_token>
</request>`;
        return api.request('/api/user/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/xml' },
            body: xmlData
        });
    },

    async changePassword(userId, oldPassword, newPassword) {
        return api.post('/api/user/change-password', {
            user_id: userId,
            old_password: oldPassword,
            new_password: newPassword,
            session_id: `sess_${Date.now()}`,
            auth_token: Math.random().toString(36).substring(7)
        });
    },

    async getUserList(sortBy = 'id', order = 'ASC', limit = 10) {
        return api.post('/api/user/list', {
            sort_by: sortBy,
            order: order,
            limit: limit,
            session_id: `sess_${Date.now()}`
        });
    },

    async searchUsers(keyword, searchBy = 'username') {
        return api.post('/api/user/search', {
            keyword: keyword,
            search_by: searchBy,
            session_id: `sess_${Date.now()}`
        });
    },

    // 商品模块扩展
    async createProduct(productData) {
        return api.post('/api/products/create', {
            ...productData,
            session_id: `sess_${Date.now()}`,
            auth_token: Math.random().toString(36).substring(7)
        });
    },

    async updateProduct(productData) {
        return api.post('/api/products/update', {
            ...productData,
            session_id: `sess_${Date.now()}`,
            auth_token: Math.random().toString(36).substring(7)
        });
    },

    async deleteProduct(productId, reason = '') {
        const xmlData = `<?xml version="1.0" encoding="UTF-8"?>
<request>
    <product_id>${productId}</product_id>
    <reason>${reason}</reason>
    <session_id>sess_${Date.now()}</session_id>
    <auth_token>${Math.random().toString(36).substring(7)}</auth_token>
</request>`;
        return api.request('/api/products/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/xml' },
            body: xmlData
        });
    },

    async getProductsByCategory(category, sortBy = 'id', order = 'ASC') {
        return api.post('/api/products/category', {
            category: category,
            sort_by: sortBy,
            order: order,
            session_id: `sess_${Date.now()}`
        });
    },

    async getProductsByPriceRange(minPrice, maxPrice, category = '') {
        return api.post('/api/products/price-range', {
            min_price: minPrice,
            max_price: maxPrice,
            category: category,
            session_id: `sess_${Date.now()}`
        });
    },

    // 订单模块扩展
    async updateOrderStatus(orderId, status, trackingNumber = '') {
        return api.post('/api/orders/update-status', {
            order_id: orderId,
            status: status,
            tracking_number: trackingNumber,
            session_id: `sess_${Date.now()}`,
            auth_token: Math.random().toString(36).substring(7)
        });
    },

    async deleteOrder(orderId, reason = '') {
        const xmlData = `<?xml version="1.0" encoding="UTF-8"?>
<request>
    <order_id>${orderId}</order_id>
    <reason>${reason}</reason>
    <session_id>sess_${Date.now()}</session_id>
    <auth_token>${Math.random().toString(36).substring(7)}</auth_token>
</request>`;
        return api.request('/api/orders/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/xml' },
            body: xmlData
        });
    },

    async getOrdersStats(groupBy = 'status', statusFilter = '') {
        return api.post('/api/orders/stats', {
            group_by: groupBy,
            status: statusFilter,
            session_id: `sess_${Date.now()}`
        });
    },

    async advancedSearchOrders(searchParams) {
        return api.post('/api/orders/advanced-search', {
            ...searchParams,
            session_id: `sess_${Date.now()}`
        });
    },

    // 购物车模块扩展
    async deleteCartItem(cartId, reason = '') {
        const xmlData = `<?xml version="1.0" encoding="UTF-8"?>
<request>
    <cart_id>${cartId}</cart_id>
    <reason>${reason}</reason>
    <session_id>sess_${Date.now()}</session_id>
    <csrf_token>${Math.random().toString(36).substring(7)}</csrf_token>
</request>`;
        return api.request('/api/cart/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/xml' },
            body: xmlData
        });
    },

    async clearCart(userId) {
        return api.post('/api/cart/clear', {
            user_id: userId,
            session_id: `sess_${Date.now()}`,
            csrf_token: Math.random().toString(36).substring(7)
        });
    },

    async queryCart(userId, sessionId = '') {
        return api.post('/api/cart/query', {
            user_id: userId,
            session_id: sessionId
        });
    },

    // 反馈模块扩展
    async updateFeedback(feedbackId, updateData) {
        return api.post('/api/feedback/update', {
            feedback_id: feedbackId,
            ...updateData,
            session_id: `sess_${Date.now()}`,
            token: Math.random().toString(36).substring(7)
        });
    },

    async deleteFeedback(feedbackId, reason = '') {
        const xmlData = `<?xml version="1.0" encoding="UTF-8"?>
<request>
    <feedback_id>${feedbackId}</feedback_id>
    <reason>${reason}</reason>
    <session_id>sess_${Date.now()}</session_id>
    <token>${Math.random().toString(36).substring(7)}</token>
</request>`;
        return api.request('/api/feedback/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/xml' },
            body: xmlData
        });
    },

    async getFeedbackList(sortBy = 'created_at', order = 'DESC', limit = 10) {
        return api.post('/api/feedback/list', {
            sort_by: sortBy,
            order: order,
            limit: limit,
            session_id: `sess_${Date.now()}`
        });
    },

    async searchFeedback(keyword, searchIn = 'title', minRating = 1) {
        return api.post('/api/feedback/search', {
            keyword: keyword,
            search_in: searchIn,
            min_rating: minRating,
            session_id: `sess_${Date.now()}`
        });
    },

    // 敏感信息模块
    async createSecret(flag, description = '') {
        return api.post('/api/secrets/create', {
            flag: flag,
            description: description,
            session_id: `sess_${Date.now()}`,
            auth_token: Math.random().toString(36).substring(7)
        });
    },

    async updateSecret(secretId, updateData) {
        return api.post('/api/secrets/update', {
            secret_id: secretId,
            ...updateData,
            session_id: `sess_${Date.now()}`,
            auth_token: Math.random().toString(36).substring(7)
        });
    },

    async deleteSecret(secretId, reason = '') {
        const xmlData = `<?xml version="1.0" encoding="UTF-8"?>
<request>
    <secret_id>${secretId}</secret_id>
    <reason>${reason}</reason>
    <session_id>sess_${Date.now()}</session_id>
    <auth_token>${Math.random().toString(36).substring(7)}</auth_token>
</request>`;
        return api.request('/api/secrets/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/xml' },
            body: xmlData
        });
    },

    async querySecret(secretId) {
        return api.post('/api/secrets/query', {
            id: secretId,
            session_id: `sess_${Date.now()}`
        });
    },

    async searchSecrets(keyword, searchIn = 'flag', limit = 10) {
        return api.post('/api/secrets/search', {
            keyword: keyword,
            search_in: searchIn,
            limit: limit,
            session_id: `sess_${Date.now()}`
        });
    }
};

// ==================== 扩展UI功能 ====================
const uiExtensions = {
    // 显示API测试面板
    showApiTestPanel() {
        const modal = document.createElement('div');
        modal.id = 'apiTestModal';
        modal.className = 'modal show';
        modal.innerHTML = `
            <div class="modal-content modal-xl">
                <div class="modal-header">
                    <h3>🔧 API接口测试面板</h3>
                    <button class="cart-close" onclick="document.getElementById('apiTestModal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="api-test-tabs">
                        <button class="api-tab active" data-tab="users">用户管理</button>
                        <button class="api-tab" data-tab="products">商品管理</button>
                        <button class="api-tab" data-tab="orders">订单管理</button>
                        <button class="api-tab" data-tab="cart">购物车</button>
                        <button class="api-tab" data-tab="feedback">反馈管理</button>
                        <button class="api-tab" data-tab="secrets">敏感信息</button>
                    </div>
                    <div class="api-test-content">
                        <div id="tab-users" class="api-tab-content active">
                            ${this.getUsersTabContent()}
                        </div>
                        <div id="tab-products" class="api-tab-content">
                            ${this.getProductsTabContent()}
                        </div>
                        <div id="tab-orders" class="api-tab-content">
                            ${this.getOrdersTabContent()}
                        </div>
                        <div id="tab-cart" class="api-tab-content">
                            ${this.getCartTabContent()}
                        </div>
                        <div id="tab-feedback" class="api-tab-content">
                            ${this.getFeedbackTabContent()}
                        </div>
                        <div id="tab-secrets" class="api-tab-content">
                            ${this.getSecretsTabContent()}
                        </div>
                    </div>
                    <div id="apiTestResult" class="api-result-panel"></div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        this.initApiTestTabs();
        this.initApiTestEvents();
    },

    getUsersTabContent() {
        return `
            <div class="api-section">
                <h4>用户列表查询 (SQL注入)</h4>
                <div class="api-form">
                    <input type="text" id="userListSort" placeholder="排序字段 (如: id, username)" value="id">
                    <input type="text" id="userListOrder" placeholder="排序方向 (ASC/DESC)" value="ASC">
                    <input type="number" id="userListLimit" placeholder="数量限制" value="10">
                    <button class="btn btn-danger" onclick="uiExtensions.testUserList()">测试SQL注入</button>
                </div>
                <code class="payload-hint">payload: username' UNION SELECT * FROM secrets--</code>
            </div>
            <div class="api-section">
                <h4>用户搜索 (SQL注入)</h4>
                <div class="api-form">
                    <input type="text" id="userSearchKeyword" placeholder="搜索关键词">
                    <select id="userSearchBy">
                        <option value="username">用户名</option>
                        <option value="email">邮箱</option>
                        <option value="phone">电话</option>
                    </select>
                    <button class="btn btn-danger" onclick="uiExtensions.testUserSearch()">测试SQL注入</button>
                </div>
                <code class="payload-hint">payload: admin' OR '1'='1</code>
            </div>
            <div class="api-section">
                <h4>修改密码 (安全接口)</h4>
                <div class="api-form">
                    <input type="number" id="changePwdUserId" placeholder="用户ID">
                    <input type="password" id="changePwdOld" placeholder="旧密码">
                    <input type="password" id="changePwdNew" placeholder="新密码">
                    <button class="btn btn-primary" onclick="uiExtensions.testChangePassword()">修改密码</button>
                </div>
            </div>
        `;
    },

    getProductsTabContent() {
        return `
            <div class="api-section">
                <h4>按分类查询 (SQL注入)</h4>
                <div class="api-form">
                    <input type="text" id="productCategory" placeholder="分类 (如: electronics)">
                    <input type="text" id="productCatSort" placeholder="排序字段" value="id">
                    <button class="btn btn-danger" onclick="uiExtensions.testProductsByCategory()">测试SQL注入</button>
                </div>
                <code class="payload-hint">payload: electronics' UNION SELECT * FROM secrets--</code>
            </div>
            <div class="api-section">
                <h4>按价格范围查询 (SQL注入)</h4>
                <div class="api-form">
                    <input type="number" id="productMinPrice" placeholder="最低价格">
                    <input type="number" id="productMaxPrice" placeholder="最高价格">
                    <input type="text" id="productPriceCat" placeholder="分类 (可选)">
                    <button class="btn btn-danger" onclick="uiExtensions.testProductsByPrice()">测试SQL注入</button>
                </div>
                <code class="payload-hint">payload: 0' OR '1'='1</code>
            </div>
            <div class="api-section">
                <h4>创建商品 (安全接口)</h4>
                <div class="api-form">
                    <input type="text" id="createProductName" placeholder="商品名称">
                    <input type="text" id="createProductDesc" placeholder="商品描述">
                    <input type="number" id="createProductPrice" placeholder="价格">
                    <input type="number" id="createProductStock" placeholder="库存">
                    <input type="text" id="createProductCategory" placeholder="分类">
                    <button class="btn btn-primary" onclick="uiExtensions.testCreateProduct()">创建商品</button>
                </div>
            </div>
        `;
    },

    getOrdersTabContent() {
        return `
            <div class="api-section">
                <h4>订单统计 (SQL注入)</h4>
                <div class="api-form">
                    <input type="text" id="ordersStatsGroup" placeholder="分组字段 (如: status)" value="status">
                    <input type="text" id="ordersStatsStatus" placeholder="状态过滤 (可选)">
                    <button class="btn btn-danger" onclick="uiExtensions.testOrdersStats()">测试SQL注入</button>
                </div>
                <code class="payload-hint">payload: status' UNION SELECT * FROM secrets--</code>
            </div>
            <div class="api-section">
                <h4>高级搜索 (SQL注入)</h4>
                <div class="api-form">
                    <input type="number" id="ordersSearchUserId" placeholder="用户ID">
                    <input type="text" id="ordersSearchStatus" placeholder="订单状态">
                    <input type="number" id="ordersSearchMinPrice" placeholder="最低金额">
                    <input type="number" id="ordersSearchMaxPrice" placeholder="最高金额">
                    <button class="btn btn-danger" onclick="uiExtensions.testOrdersAdvancedSearch()">测试SQL注入</button>
                </div>
            </div>
            <div class="api-section">
                <h4>更新订单状态 (安全接口)</h4>
                <div class="api-form">
                    <input type="number" id="updateStatusOrderId" placeholder="订单ID">
                    <select id="updateStatusValue">
                        <option value="pending">待处理</option>
                        <option value="processing">处理中</option>
                        <option value="shipped">已发货</option>
                        <option value="delivered">已送达</option>
                        <option value="cancelled">已取消</option>
                    </select>
                    <button class="btn btn-primary" onclick="uiExtensions.testUpdateOrderStatus()">更新状态</button>
                </div>
            </div>
        `;
    },

    getCartTabContent() {
        return `
            <div class="api-section">
                <h4>购物车查询 (SQL注入)</h4>
                <div class="api-form">
                    <input type="number" id="cartQueryUserId" placeholder="用户ID">
                    <input type="text" id="cartQuerySession" placeholder="会话ID (可选)">
                    <button class="btn btn-danger" onclick="uiExtensions.testCartQuery()">测试SQL注入</button>
                </div>
                <code class="payload-hint">payload: 1' OR '1'='1</code>
            </div>
            <div class="api-section">
                <h4>清空购物车 (安全接口)</h4>
                <div class="api-form">
                    <input type="number" id="cartClearUserId" placeholder="用户ID">
                    <button class="btn btn-warning" onclick="uiExtensions.testCartClear()">清空购物车</button>
                </div>
            </div>
        `;
    },

    getFeedbackTabContent() {
        return `
            <div class="api-section">
                <h4>反馈列表 (SQL注入)</h4>
                <div class="api-form">
                    <input type="text" id="feedbackListSort" placeholder="排序字段" value="created_at">
                    <input type="text" id="feedbackListOrder" placeholder="排序方向" value="DESC">
                    <input type="number" id="feedbackListLimit" placeholder="数量限制" value="10">
                    <button class="btn btn-danger" onclick="uiExtensions.testFeedbackList()">测试SQL注入</button>
                </div>
            </div>
            <div class="api-section">
                <h4>反馈搜索 (SQL注入)</h4>
                <div class="api-form">
                    <input type="text" id="feedbackSearchKeyword" placeholder="搜索关键词">
                    <select id="feedbackSearchIn">
                        <option value="title">标题</option>
                        <option value="content">内容</option>
                    </select>
                    <button class="btn btn-danger" onclick="uiExtensions.testFeedbackSearch()">测试SQL注入</button>
                </div>
            </div>
        `;
    },

    getSecretsTabContent() {
        return `
            <div class="api-section">
                <h4>敏感信息查询 (SQL注入 - 可获取Flag)</h4>
                <div class="api-form">
                    <input type="number" id="secretsQueryId" placeholder="敏感信息ID">
                    <button class="btn btn-danger" onclick="uiExtensions.testSecretsQuery()">测试SQL注入</button>
                </div>
                <code class="payload-hint">payload: 1 UNION SELECT * FROM users--</code>
            </div>
            <div class="api-section">
                <h4>敏感信息搜索 (SQL注入 - 可搜索Flag)</h4>
                <div class="api-form">
                    <input type="text" id="secretsSearchKeyword" placeholder="搜索关键词 (如: FLAG)">
                    <select id="secretsSearchIn">
                        <option value="flag">Flag</option>
                        <option value="description">描述</option>
                    </select>
                    <button class="btn btn-danger" onclick="uiExtensions.testSecretsSearch()">测试SQL注入</button>
                </div>
                <code class="payload-hint">payload: FLAG{sql' OR '1'='1</code>
            </div>
            <div class="api-section">
                <h4>创建敏感信息 (安全接口)</h4>
                <div class="api-form">
                    <input type="text" id="createSecretFlag" placeholder="Flag (如: FLAG{xxx})">
                    <input type="text" id="createSecretDesc" placeholder="描述">
                    <button class="btn btn-primary" onclick="uiExtensions.testCreateSecret()">创建</button>
                </div>
            </div>
        `;
    },

    initApiTestTabs() {
        document.querySelectorAll('.api-tab').forEach(tab => {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.api-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.api-tab-content').forEach(c => c.classList.remove('active'));
                this.classList.add('active');
                document.getElementById(`tab-${this.dataset.tab}`).classList.add('active');
            });
        });
    },

    initApiTestEvents() {
        // 事件已在HTML中通过onclick绑定
    },

    // 测试方法
    async testUserList() {
        const sortBy = document.getElementById('userListSort').value;
        const order = document.getElementById('userListOrder').value;
        const limit = document.getElementById('userListLimit').value;
        const result = await apiExtensions.getUserList(sortBy, order, limit);
        this.showApiResult(result);
    },

    async testUserSearch() {
        const keyword = document.getElementById('userSearchKeyword').value;
        const searchBy = document.getElementById('userSearchBy').value;
        const result = await apiExtensions.searchUsers(keyword, searchBy);
        this.showApiResult(result);
    },

    async testChangePassword() {
        const userId = document.getElementById('changePwdUserId').value;
        const oldPwd = document.getElementById('changePwdOld').value;
        const newPwd = document.getElementById('changePwdNew').value;
        const result = await apiExtensions.changePassword(userId, oldPwd, newPwd);
        this.showApiResult(result);
    },

    async testProductsByCategory() {
        const category = document.getElementById('productCategory').value;
        const sortBy = document.getElementById('productCatSort').value;
        const result = await apiExtensions.getProductsByCategory(category, sortBy);
        this.showApiResult(result);
    },

    async testProductsByPrice() {
        const minPrice = document.getElementById('productMinPrice').value;
        const maxPrice = document.getElementById('productMaxPrice').value;
        const category = document.getElementById('productPriceCat').value;
        const result = await apiExtensions.getProductsByPriceRange(minPrice, maxPrice, category);
        this.showApiResult(result);
    },

    async testCreateProduct() {
        const data = {
            name: document.getElementById('createProductName').value,
            description: document.getElementById('createProductDesc').value,
            price: document.getElementById('createProductPrice').value,
            stock: document.getElementById('createProductStock').value,
            category: document.getElementById('createProductCategory').value
        };
        const result = await apiExtensions.createProduct(data);
        this.showApiResult(result);
    },

    async testOrdersStats() {
        const groupBy = document.getElementById('ordersStatsGroup').value;
        const status = document.getElementById('ordersStatsStatus').value;
        const result = await apiExtensions.getOrdersStats(groupBy, status);
        this.showApiResult(result);
    },

    async testOrdersAdvancedSearch() {
        const params = {
            user_id: document.getElementById('ordersSearchUserId').value,
            status: document.getElementById('ordersSearchStatus').value,
            min_price: document.getElementById('ordersSearchMinPrice').value,
            max_price: document.getElementById('ordersSearchMaxPrice').value
        };
        const result = await apiExtensions.advancedSearchOrders(params);
        this.showApiResult(result);
    },

    async testUpdateOrderStatus() {
        const orderId = document.getElementById('updateStatusOrderId').value;
        const status = document.getElementById('updateStatusValue').value;
        const result = await apiExtensions.updateOrderStatus(orderId, status);
        this.showApiResult(result);
    },

    async testCartQuery() {
        const userId = document.getElementById('cartQueryUserId').value;
        const sessionId = document.getElementById('cartQuerySession').value;
        const result = await apiExtensions.queryCart(userId, sessionId);
        this.showApiResult(result);
    },

    async testCartClear() {
        const userId = document.getElementById('cartClearUserId').value;
        if (confirm(`确定要清空用户 ${userId} 的购物车吗？`)) {
            const result = await apiExtensions.clearCart(userId);
            this.showApiResult(result);
        }
    },

    async testFeedbackList() {
        const sortBy = document.getElementById('feedbackListSort').value;
        const order = document.getElementById('feedbackListOrder').value;
        const limit = document.getElementById('feedbackListLimit').value;
        const result = await apiExtensions.getFeedbackList(sortBy, order, limit);
        this.showApiResult(result);
    },

    async testFeedbackSearch() {
        const keyword = document.getElementById('feedbackSearchKeyword').value;
        const searchIn = document.getElementById('feedbackSearchIn').value;
        const result = await apiExtensions.searchFeedback(keyword, searchIn);
        this.showApiResult(result);
    },

    async testSecretsQuery() {
        const id = document.getElementById('secretsQueryId').value;
        const result = await apiExtensions.querySecret(id);
        this.showApiResult(result);
    },

    async testSecretsSearch() {
        const keyword = document.getElementById('secretsSearchKeyword').value;
        const searchIn = document.getElementById('secretsSearchIn').value;
        const result = await apiExtensions.searchSecrets(keyword, searchIn);
        this.showApiResult(result);
    },

    async testCreateSecret() {
        const flag = document.getElementById('createSecretFlag').value;
        const desc = document.getElementById('createSecretDesc').value;
        const result = await apiExtensions.createSecret(flag, desc);
        this.showApiResult(result);
    },

    showApiResult(result) {
        const panel = document.getElementById('apiTestResult');
        const isError = !result.success;
        panel.innerHTML = `
            <div class="api-result ${isError ? 'error' : 'success'}">
                <h4>${isError ? '❌ 错误' : '✅ 成功'}</h4>
                <pre>${JSON.stringify(result, null, 2)}</pre>
            </div>
        `;
    }
};

// ==================== 添加到侧边栏 ====================
function addApiTestMenuItem() {
    const sidebarMenu = document.querySelector('.sidebar-menu');
    if (sidebarMenu) {
        const apiTestItem = document.createElement('li');
        apiTestItem.innerHTML = `
            <a href="#" id="apiTestLink">
                <span class="icon">🔧</span> API接口测试
            </a>
        `;
        sidebarMenu.appendChild(apiTestItem);
        
        document.getElementById('apiTestLink').addEventListener('click', (e) => {
            e.preventDefault();
            uiExtensions.showApiTestPanel();
        });
    }
}

// ==================== 样式 ====================
const apiTestStyles = `
<style>
.api-test-tabs {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
    border-bottom: 1px solid var(--border-color, #333);
    padding-bottom: 10px;
    flex-wrap: wrap;
}
.api-tab {
    padding: 8px 16px;
    background: var(--card-bg, #1a1a2e);
    border: 1px solid var(--border-color, #333);
    border-radius: 6px;
    cursor: pointer;
    color: var(--text-color, #fff);
    transition: all 0.3s;
}
.api-tab:hover {
    background: var(--primary-color, #e94560);
}
.api-tab.active {
    background: var(--primary-color, #e94560);
    border-color: var(--primary-color, #e94560);
}
.api-tab-content {
    display: none;
}
.api-tab-content.active {
    display: block;
}
.api-section {
    margin-bottom: 20px;
    padding: 15px;
    background: var(--card-bg, #1a1a2e);
    border-radius: 8px;
    border: 1px solid var(--border-color, #333);
}
.api-section h4 {
    margin-bottom: 10px;
    color: var(--primary-color, #e94560);
}
.api-form {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
}
.api-form input, .api-form select {
    padding: 8px 12px;
    background: var(--input-bg, #0f0f1a);
    border: 1px solid var(--border-color, #333);
    border-radius: 4px;
    color: var(--text-color, #fff);
    min-width: 120px;
}
.api-form button {
    padding: 8px 16px;
}
.payload-hint {
    display: block;
    margin-top: 8px;
    padding: 8px;
    background: rgba(231, 76, 60, 0.1);
    border-left: 3px solid #e74c3c;
    border-radius: 4px;
    font-size: 12px;
}
.api-result-panel {
    margin-top: 20px;
    max-height: 300px;
    overflow-y: auto;
}
.api-result {
    padding: 15px;
    border-radius: 8px;
}
.api-result.success {
    background: rgba(46, 204, 113, 0.1);
    border: 1px solid #2ecc71;
}
.api-result.error {
    background: rgba(231, 76, 60, 0.1);
    border: 1px solid #e74c3c;
}
.api-result pre {
    margin-top: 10px;
    padding: 10px;
    background: rgba(0,0,0,0.3);
    border-radius: 4px;
    overflow-x: auto;
    font-size: 12px;
}
.modal-xl {
    max-width: 900px;
    width: 90%;
}
</style>
`;

// 添加样式到页面
document.head.insertAdjacentHTML('beforeend', apiTestStyles);

// 页面加载完成后添加菜单项
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(addApiTestMenuItem, 100);
});

// 导出到全局
window.apiExtensions = apiExtensions;
window.uiExtensions = uiExtensions;

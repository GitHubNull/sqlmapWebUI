/**
 * VulnShop - SQL注入测试靶场前端应用
 * 仅供安全测试和教育目的使用
 */

// ==================== 全局状态 ====================
const state = {
    currentUser: null,
    currentPage: 'home',
    cart: [],
    config: {
        difficulty: 'easy',
        version: '1.0.0'
    },
    products: [],
    currentCategory: '',
    theme: 'light'  // 默认亮色主题
};

// ==================== 主题管理 ====================
const theme = {
    // 初始化主题
    init() {
        // 从本地存储加载主题，默认亮色
        const savedTheme = localStorage.getItem('vulnshop_theme') || 'light';
        this.setTheme(savedTheme);
    },
    
    // 设置主题
    setTheme(themeName) {
        state.theme = themeName;
        
        if (themeName === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
        
        // 保存到本地存储
        localStorage.setItem('vulnshop_theme', themeName);
    },
    
    // 切换主题
    toggle() {
        const newTheme = state.theme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);
        
        // 显示提示
        const themeName = newTheme === 'dark' ? '暗色模式' : '亮色模式';
        cart.showToast(`已切换到${themeName}`, 'success');
    },
    
    // 获取当前主题
    getCurrent() {
        return state.theme;
    }
};

// ==================== API调用 ====================
const api = {
    baseUrl: '',
    
    async request(path, options = {}) {
        try {
            const response = await fetch(this.baseUrl + path, {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            });
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            return { success: false, message: error.message };
        }
    },
    
    async get(path) {
        return this.request(path, { method: 'GET' });
    },
    
    async post(path, data) {
        return this.request(path, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },
    
    // 用户相关
    async login(username, password) {
        return this.post('/api/user/login', { username, password });
    },
    
    async register(username, password, email) {
        return this.post('/api/user/register', { username, password, email });
    },
    
    async getProfile(userId) {
        return this.get(`/api/user/profile?id=${encodeURIComponent(userId)}`);
    },
    
    // 商品相关
    async getProducts() {
        return this.get('/api/products');
    },
    
    async searchProducts(keyword, category) {
        let url = `/api/products/search?keyword=${encodeURIComponent(keyword)}`;
        if (category) {
            url += `&category=${encodeURIComponent(category)}`;
        }
        return this.get(url);
    },
    
    async getProductDetail(productId) {
        return this.get(`/api/products/detail?id=${encodeURIComponent(productId)}`);
    },
    
    // 订单相关
    async queryOrder(orderNo, userId) {
        if (orderNo) {
            return this.get(`/api/orders/query?order_no=${encodeURIComponent(orderNo)}`);
        } else if (userId) {
            return this.get(`/api/orders/query?user_id=${encodeURIComponent(userId)}`);
        }
    },
    
    async createOrder(orderData) {
        return this.post('/api/orders/create', orderData);
    },
    
    async cancelOrder(orderId, reason) {
        // XML格式请求
        const xmlData = `<?xml version="1.0" encoding="UTF-8"?>
<request>
    <order_id>${orderId}</order_id>
    <reason>${reason || ''}</reason>
    <session_id>${Date.now()}</session_id>
    <auth_token>${Math.random().toString(36).substring(7)}</auth_token>
</request>`;
        return this.request('/api/orders/cancel', {
            method: 'POST',
            headers: { 'Content-Type': 'application/xml' },
            body: xmlData
        });
    },
    
    // 系统相关
    async getInfo() {
        return this.get('/api/info');
    },
    
    async getConfig() {
        return this.get('/api/config');
    },
    
    async setConfig(config) {
        return this.post('/api/config', config);
    },
    
    async resetDatabase() {
        return this.post('/api/database/reset', {});
    },
    
    // 日志相关
    async getLogs(logType = 'vulnshop', lines = 100) {
        return this.get(`/api/logs?type=${encodeURIComponent(logType)}&lines=${encodeURIComponent(lines)}`);
    }
};

// ==================== 购物车管理 ====================
const cart = {
    // 添加商品到购物车
    add(product, quantity = 1) {
        const existingItem = state.cart.find(item => item.id === product.id);
        
        if (existingItem) {
            existingItem.quantity += quantity;
        } else {
            state.cart.push({
                ...product,
                quantity: quantity
            });
        }
        
        this.saveToStorage();
        this.updateUI();
        this.showToast(`已添加 ${product.name} 到购物车`, 'success');
    },
    
    // 从购物车移除商品
    remove(productId) {
        const index = state.cart.findIndex(item => item.id === productId);
        if (index > -1) {
            const item = state.cart[index];
            state.cart.splice(index, 1);
            this.saveToStorage();
            this.updateUI();
            this.showToast(`已移除 ${item.name}`, 'warning');
        }
    },
    
    // 更新商品数量
    updateQuantity(productId, quantity) {
        const item = state.cart.find(item => item.id === productId);
        if (item) {
            if (quantity <= 0) {
                this.remove(productId);
            } else {
                item.quantity = quantity;
                this.saveToStorage();
                this.updateUI();
            }
        }
    },
    
    // 获取购物车总价
    getTotal() {
        return state.cart.reduce((total, item) => total + (item.price * item.quantity), 0);
    },
    
    // 获取购物车商品数量
    getCount() {
        return state.cart.reduce((count, item) => count + item.quantity, 0);
    },
    
    // 清空购物车
    clear() {
        state.cart = [];
        this.saveToStorage();
        this.updateUI();
    },
    
    // 保存到本地存储
    saveToStorage() {
        localStorage.setItem('vulnshop_cart', JSON.stringify(state.cart));
    },
    
    // 从本地存储加载
    loadFromStorage() {
        const saved = localStorage.getItem('vulnshop_cart');
        if (saved) {
            try {
                state.cart = JSON.parse(saved);
            } catch (e) {
                state.cart = [];
            }
        }
    },
    
    // 更新UI
    updateUI() {
        // 更新购物车数量
        const countEl = document.getElementById('cartCount');
        if (countEl) {
            countEl.textContent = this.getCount();
        }
        
        // 更新购物车面板内容
        this.renderCartItems();
        
        // 更新总价
        const totalEl = document.getElementById('cartTotal');
        if (totalEl) {
            totalEl.textContent = `¥${this.getTotal().toFixed(2)}`;
        }
        
        // 更新结算页总价
        const checkoutTotalEl = document.getElementById('checkoutTotal');
        if (checkoutTotalEl) {
            checkoutTotalEl.textContent = `¥${this.getTotal().toFixed(2)}`;
        }
    },
    
    // 渲染购物车商品列表
    renderCartItems() {
        const container = document.getElementById('cartItems');
        if (!container) return;
        
        if (state.cart.length === 0) {
            container.innerHTML = `
                <div class="cart-empty">
                    <div class="icon">🛒</div>
                    <p>购物车是空的</p>
                    <button class="btn btn-primary" onclick="ui.showPage('products');cart.close();">去购物</button>
                </div>
            `;
            return;
        }
        
        container.innerHTML = state.cart.map(item => `
            <div class="cart-item" data-id="${item.id}">
                <div class="cart-item-image">${this.getCategoryIcon(item.category)}</div>
                <div class="cart-item-info">
                    <div class="cart-item-name">${ui.escapeHtml(item.name)}</div>
                    <div class="cart-item-price">¥${item.price.toFixed(2)}</div>
                    <div class="cart-item-qty">
                        <button onclick="cart.updateQuantity(${item.id}, ${item.quantity - 1})">−</button>
                        <span>${item.quantity}</span>
                        <button onclick="cart.updateQuantity(${item.id}, ${item.quantity + 1})">+</button>
                    </div>
                </div>
                <button class="cart-item-remove" onclick="cart.remove(${item.id})">×</button>
            </div>
        `).join('');
    },
    
    // 获取分类图标
    getCategoryIcon(category) {
        const icons = {
            'electronics': '📱',
            'fashion': '👔',
            'books': '📚',
            'home': '🏠',
            'default': '📦'
        };
        return icons[category] || icons.default;
    },
    
    // 打开购物车
    open() {
        document.getElementById('cartPanel').classList.add('open');
        document.getElementById('cartOverlay').classList.add('show');
    },
    
    // 关闭购物车
    close() {
        document.getElementById('cartPanel').classList.remove('open');
        document.getElementById('cartOverlay').classList.remove('show');
    },
    
    // 显示消息提示
    showToast(message, type = 'success') {
        // 移除已有的toast
        const existingToast = document.querySelector('.toast');
        if (existingToast) {
            existingToast.remove();
        }
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <span>${type === 'success' ? '✓' : type === 'error' ? '✗' : '⚠'}</span>
            <span>${message}</span>
        `;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, 3000);
    },
    
    // 复制文本
    copyText(text) {
        navigator.clipboard.writeText(text).then(() => {
            this.showToast('已复制到剪贴板', 'success');
        }).catch(() => {
            this.showToast('复制失败', 'error');
        });
    }
};

// ==================== 物流查询模块 ====================
const shipping = {
    // 获取默认XML模板
    getTemplate() {
        const timestamp = Date.now();
        return `<?xml version="1.0" encoding="UTF-8"?>
<shippingQuery>
    <version>1.0</version>
    <requestId>req_${timestamp}</requestId>
    <timestamp>${timestamp}</timestamp>
    <clientId>web_client_001</clientId>
    <apiKey>ak_live_test123</apiKey>
    <trackingNumber>TRK202403150001</trackingNumber>
    <carrierCode>SF</carrierCode>
    <queryType>realtime</queryType>
    <senderProvince>广东省</senderProvince>
    <senderCity>深圳市</senderCity>
    <senderDistrict>南山区</senderDistrict>
    <receiverProvince>北京市</receiverProvince>
    <receiverCity>北京市</receiverCity>
    <receiverDistrict>朝阳区</receiverDistrict>
    <userId>10001</userId>
    <userName>测试用户</userName>
    <userPhone>138****8888</userPhone>
    <userEmail>test@example.com</userEmail>
    <orderNo>ORD202403150001</orderNo>
    <orderId>100001</orderId>
    <shopId>SHOP001</shopId>
    <deliveryMethod>standard</deliveryMethod>
    <priority>normal</priority>
    <signature>required</signature>
    <insurance>true</insurance>
    <sessionId>sess_${timestamp}</sessionId>
    <deviceFingerprint>fp_win_chrome_test</deviceFingerprint>
    <userAgent>Mozilla/5.0</userAgent>
    <clientIp>127.0.0.1</clientIp>
    <extraData><![CDATA[{"source":"web"}]]></extraData>
</shippingQuery>`;
    },

    // 获取CDATA绕过Payload
    getCdataPayload() {
        const timestamp = Date.now();
        return `<?xml version="1.0" encoding="UTF-8"?>
<shippingQuery>
    <version>1.0</version>
    <requestId>req_${timestamp}</requestId>
    <timestamp>${timestamp}</timestamp>
    <clientId>web_client_001</clientId>
    <apiKey>ak_live_test123</apiKey>
    <trackingNumber><![CDATA[TRK' OR '1'='1']]></trackingNumber>
    <carrierCode>SF</carrierCode>
    <queryType>realtime</queryType>
    <userId>10001</userId>
    <sessionId>sess_${timestamp}</sessionId>
</shippingQuery>`;
    },

    // 获取XML实体编码绕过Payload
    getEntityPayload() {
        const timestamp = Date.now();
        return `<?xml version="1.0" encoding="UTF-8"?>
<shippingQuery>
    <version>1.0</version>
    <requestId>req_${timestamp}</requestId>
    <timestamp>${timestamp}</timestamp>
    <clientId>web_client_001</clientId>
    <apiKey>ak_live_test123</apiKey>
    <trackingNumber>&#84;&#82;&#75;' OR '1'='1'</trackingNumber>
    <carrierCode>SF</carrierCode>
    <queryType>realtime</queryType>
    <userId>10001</userId>
    <sessionId>sess_${timestamp}</sessionId>
</shippingQuery>`;
    },

    // 加载默认模板
    loadTemplate() {
        const textarea = document.getElementById('shippingXmlInput');
        if (textarea) {
            textarea.value = this.getTemplate();
        }
    },

    // 加载CDATA Payload
    loadCdataPayload() {
        const textarea = document.getElementById('shippingXmlInput');
        if (textarea) {
            textarea.value = this.getCdataPayload();
        }
    },

    // 加载实体编码Payload
    loadEntityPayload() {
        const textarea = document.getElementById('shippingXmlInput');
        if (textarea) {
            textarea.value = this.getEntityPayload();
        }
    },

    // 发送查询
    async sendQuery() {
        const textarea = document.getElementById('shippingXmlInput');
        const resultDiv = document.getElementById('shippingResult');

        if (!textarea || !textarea.value.trim()) {
            cart.showToast('请输入XML请求报文', 'warning');
            return;
        }

        const xmlData = textarea.value.trim();

        try {
            resultDiv.innerHTML = '<div style="text-align:center;padding:20px;color:#888;">查询中...</div>';

            const response = await fetch('/api/shipping/query', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/xml'
                },
                body: xmlData
            });

            const result = await response.json();

            // 格式化显示结果
            let html = '<div class="result-success">';

            if (result.success) {
                if (result.data) {
                    html += `<h4>📦 物流信息</h4>`;
                    html += `<div style="background:var(--code-bg);padding:15px;border-radius:8px;margin:10px 0;">`;
                    html += `<p><strong>运单号:</strong> ${result.data.tracking_number || 'N/A'}</p>`;
                    html += `<p><strong>快递公司:</strong> ${result.data.carrier_code || 'N/A'}</p>`;
                    html += `<p><strong>状态:</strong> <span class="status-badge">${result.data.status || 'N/A'}</span></p>`;
                    html += `<p><strong>当前位置:</strong> ${result.data.location || 'N/A'}</p>`;
                    html += `<p><strong>重量:</strong> ${result.data.weight || 'N/A'} kg</p>`;
                    html += `<p><strong>备注:</strong> ${result.data.notes || 'N/A'}</p>`;
                    html += `</div>`;
                    html += `<p style="color:var(--success-color);">✅ 查询成功 - 返回 ${result.count} 条记录</p>`;
                } else {
                    html += `<p style="color:var(--text-muted);">📭 未找到物流信息</p>`;
                    html += `<p style="color:#f39c12;">提示: 这可能是 Boolean-blind 注入条件为假的结果</p>`;
                }

                if (result.request_info) {
                    html += `<details style="margin-top:10px;"><summary>请求信息</summary>`;
                    html += `<pre style="background:var(--code-bg);padding:10px;border-radius:4px;font-size:12px;">`;
                    html += JSON.stringify(result.request_info, null, 2);
                    html += `</pre></details>`;
                }
            } else {
                html = '<div class="result-error">';
                html += `<h4>❌ 错误</h4>`;
                html += `<p style="color:var(--error-color);">${result.message || '未知错误'}</p>`;

                if (result.debug && result.debug.sql_error) {
                    html += `<details open style="margin-top:10px;"><summary style="color:var(--error-color);">SQL错误信息 (Error-based)</summary>`;
                    html += `<pre style="background:#2d1f1f;padding:10px;border-radius:4px;color:#ff6b6b;font-size:12px;overflow-x:auto;">`;
                    html += this.escapeHtml(result.debug.sql_error);
                    html += `</pre></details>`;
                }
            }

            html += '</div>';
            resultDiv.innerHTML = html;

        } catch (error) {
            resultDiv.innerHTML = `<div class="result-error"><p>请求失败: ${error.message}</p></div>`;
        }
    },

    // HTML转义
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

// ==================== UI 操作 ====================
const ui = {
    // 页面切换
    showPage(pageName) {
        document.querySelectorAll('.page').forEach(page => {
            page.classList.remove('active');
        });
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        
        const targetPage = document.getElementById(`page-${pageName}`);
        const targetLink = document.querySelector(`[data-page="${pageName}"]`);
        
        if (targetPage) {
            targetPage.classList.add('active');
        }
        if (targetLink) {
            targetLink.classList.add('active');
        }
        
        state.currentPage = pageName;
        
        // 页面特定的初始化
        if (pageName === 'products') {
            this.loadProducts();
        } else if (pageName === 'config') {
            this.loadConfig();
        } else if (pageName === 'home') {
            this.loadHotProducts();
        } else if (pageName === 'coupons') {
            // 优惠券页面初始化
        }
    },
    
    // 显示模态框
    showModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('show');
        }
    },
    
    // 隐藏模态框
    hideModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('show');
        }
    },
    
    // 隐藏所有模态框
    hideAllModals() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.classList.remove('show');
        });
    },
    
    // 更新用户状态
    updateUserStatus() {
        const statusEl = document.getElementById('userStatus');
        const loginBtn = document.getElementById('loginBtn');
        const logoutBtn = document.getElementById('logoutBtn');
        
        if (state.currentUser) {
            statusEl.textContent = `${state.currentUser.username}${state.currentUser.is_admin ? ' (管理员)' : ''}`;
            loginBtn.style.display = 'none';
            logoutBtn.style.display = 'inline-block';
        } else {
            statusEl.textContent = '未登录';
            loginBtn.style.display = 'inline-block';
            logoutBtn.style.display = 'none';
        }
    },
    
    // 显示消息
    showMessage(elementId, message, isError = false) {
        const el = document.getElementById(elementId);
        if (el) {
            el.textContent = message;
            el.className = `result-message ${isError ? 'error' : 'success'}`;
            el.style.display = 'block';
        }
    },
    
    // 加载系统信息
    async loadSystemInfo() {
        const result = await api.getConfig();
        if (result.success) {
            state.config = result.data;
            
            const versionEl = document.getElementById('sysVersion');
            const debugEl = document.getElementById('sysDebug');
            const diffEl = document.getElementById('sysDifficulty');
            
            if (versionEl) versionEl.textContent = result.data.version;
            if (debugEl) debugEl.textContent = result.data.debug ? '开启' : '关闭';
            
            if (diffEl) {
                diffEl.textContent = result.data.difficulty.toUpperCase();
                diffEl.className = `status-value ${result.data.difficulty}`;
            }
        }
    },
    
    // 加载热门商品
    async loadHotProducts() {
        const container = document.getElementById('hotProducts');
        if (!container) return;
        
        const result = await api.getProducts();
        if (result.success && result.data) {
            const hotProducts = result.data.slice(0, 3);
            container.innerHTML = hotProducts.map(product => `
                <div class="hot-product-item" onclick="ui.showProductDetail(${product.id})">
                    <div class="hot-product-icon">${cart.getCategoryIcon(product.category)}</div>
                    <div class="hot-product-info">
                        <div class="hot-product-name">${this.escapeHtml(product.name)}</div>
                        <div class="hot-product-price">¥${product.price.toFixed(2)}</div>
                    </div>
                    <button class="hot-product-btn" onclick="event.stopPropagation();cart.add({id:${product.id},name:'${this.escapeHtml(product.name).replace(/'/g, "\\'")}',price:${product.price},category:'${product.category}'})">加购</button>
                </div>
            `).join('');
        }
    },
    
    // 加载商品列表
    async loadProducts(keyword = '', category = '') {
        const container = document.getElementById('productList');
        container.innerHTML = '<p style="text-align:center;padding:60px;color:#888;">加载中...</p>';
        
        let result;
        if (keyword || category) {
            result = await api.searchProducts(keyword, category);
        } else {
            result = await api.getProducts();
        }
        
        if (result.success && result.data) {
            state.products = result.data;
            
            if (result.data.length === 0) {
                container.innerHTML = '<p style="text-align:center;padding:60px;color:#888;">未找到商品</p>';
                return;
            }
            
            container.innerHTML = result.data.map(product => `
                <div class="product-card" data-id="${product.id}">
                    <div class="product-image" onclick="ui.showProductDetail(${product.id})">
                        ${cart.getCategoryIcon(product.category)}
                        ${product.stock < 10 ? '<span class="product-badge">库存紧张</span>' : ''}
                    </div>
                    <div class="product-body">
                        <div class="product-name">${this.escapeHtml(product.name)}</div>
                        <div class="product-price">¥${product.price.toFixed(2)}</div>
                        <div class="product-meta">
                            <span class="product-category">${this.escapeHtml(product.category || '未分类')}</span>
                            <span class="product-stock">库存: ${product.stock}</span>
                        </div>
                        <div class="product-actions">
                            <button class="btn btn-outline btn-sm" onclick="ui.showProductDetail(${product.id})">查看详情</button>
                            <button class="btn btn-primary btn-sm" onclick="cart.add({id:${product.id},name:'${this.escapeHtml(product.name).replace(/'/g, "\\'")}',price:${product.price},category:'${product.category}'})">🛒 加入购物车</button>
                        </div>
                    </div>
                </div>
            `).join('');
        } else {
            container.innerHTML = `<p style="text-align:center;padding:60px;color:#e74c3c;">
                ${result.message || '加载失败'}
                ${result.debug ? `<br><code>${this.escapeHtml(JSON.stringify(result.debug))}</code>` : ''}
            </p>`;
        }
    },
    
    // 显示商品详情
    async showProductDetail(productId) {
        const detailEl = document.getElementById('productDetail');
        detailEl.innerHTML = '<p style="text-align:center;padding:40px;">加载中...</p>';
        this.showModal('productModal');
        
        const result = await api.getProductDetail(productId);
        
        if (result.success && result.data) {
            const p = result.data;
            detailEl.innerHTML = `
                <div class="product-detail-layout">
                    <div class="product-detail-image">${cart.getCategoryIcon(p.category)}</div>
                    <div class="product-detail-info">
                        <h3>${this.escapeHtml(p.name)}</h3>
                        <div class="product-detail-price">¥${p.price.toFixed(2)}</div>
                        <p class="product-detail-desc">${this.escapeHtml(p.description || '暂无描述')}</p>
                        <div class="product-detail-meta">
                            <span>分类: ${this.escapeHtml(p.category || '未分类')}</span>
                            <span>库存: ${p.stock}</span>
                        </div>
                        <div class="product-detail-actions">
                            <div class="quantity-selector">
                                <button onclick="this.nextElementSibling.textContent = Math.max(1, parseInt(this.nextElementSibling.textContent) - 1)">−</button>
                                <span id="detailQty">1</span>
                                <button onclick="this.previousElementSibling.textContent = parseInt(this.previousElementSibling.textContent) + 1">+</button>
                            </div>
                            <button class="btn btn-primary btn-lg" onclick="cart.add({id:${p.id},name:'${this.escapeHtml(p.name).replace(/'/g, "\\'")}',price:${p.price},category:'${p.category}'}, parseInt(document.getElementById('detailQty').textContent));ui.hideModal('productModal')">
                                🛒 加入购物车
                            </button>
                        </div>
                        ${result._debug_time ? `<p style="color:#666;font-size:12px;margin-top:15px;">⏱ 查询耗时: ${result._debug_time}s</p>` : ''}
                    </div>
                </div>
            `;
        } else {
            detailEl.innerHTML = `<p style="color:#e74c3c;text-align:center;padding:40px;">
                ${result.message || '加载失败'}
                ${result.debug ? `<br><pre style="text-align:left;margin-top:15px;background:#1a1a2e;padding:15px;border-radius:8px;overflow-x:auto;">${this.escapeHtml(JSON.stringify(result.debug, null, 2))}</pre>` : ''}
            </p>`;
        }
    },
    
    // 加载配置
    async loadConfig() {
        const result = await api.getConfig();
        if (result.success) {
            const difficulty = result.data.difficulty;
            const radio = document.querySelector(`input[name="difficulty"][value="${difficulty}"]`);
            if (radio) {
                radio.checked = true;
                const option = radio.closest('.difficulty-option');
                document.querySelectorAll('.difficulty-option').forEach(el => el.classList.remove('selected'));
                if (option) option.classList.add('selected');
            }
        }
    },
    
    // 执行结算
    checkout() {
        if (state.cart.length === 0) {
            cart.showToast('购物车是空的', 'warning');
            return;
        }
        cart.close();
        this.showModal('checkoutModal');
    },
    
    // 转义HTML
    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },
    
    // 格式化JSON显示
    formatJson(obj) {
        return JSON.stringify(obj, null, 2);
    },
    
    // 显示日志查看器
    showLogViewer() {
        const modal = document.createElement('div');
        modal.id = 'logViewerModal';
        modal.className = 'modal show';
        modal.innerHTML = `
            <div class="modal-content modal-xl">
                <div class="modal-header">
                    <h3>📊 系统日志查看器</h3>
                    <button class="cart-close" onclick="document.getElementById('logViewerModal').remove()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="log-controls">
                        <div class="log-type-selector">
                            <label>日志类型：</label>
                            <select id="logTypeSelect">
                                <option value="vulnshop">应用日志 (vulnshop.log)</option>
                                <option value="access">访问日志 (access.log)</option>
                                <option value="error">错误日志 (error.log)</option>
                            </select>
                        </div>
                        <div class="log-lines-selector">
                            <label>显示行数：</label>
                            <select id="logLinesSelect">
                                <option value="50">50行</option>
                                <option value="100" selected>100行</option>
                                <option value="200">200行</option>
                                <option value="500">500行</option>
                            </select>
                        </div>
                        <button class="btn btn-primary" id="refreshLogsBtn">
                            <span class="refresh-icon">🔄</span> 刷新
                        </button>
                    </div>
                    <div class="log-content-container">
                        <pre id="logContent" class="log-content">加载中...</pre>
                    </div>
                    <div class="log-stats" id="logStats"></div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        
        // 加载日志
        this.loadLogs();
        
        // 绑定事件
        document.getElementById('refreshLogsBtn').addEventListener('click', () => this.loadLogs());
        document.getElementById('logTypeSelect').addEventListener('change', () => this.loadLogs());
        document.getElementById('logLinesSelect').addEventListener('change', () => this.loadLogs());
        
        // 点击模态框外部关闭
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });
    },
    
    // 加载日志内容
    async loadLogs() {
        const logContent = document.getElementById('logContent');
        const logStats = document.getElementById('logStats');
        const logType = document.getElementById('logTypeSelect').value;
        const lines = document.getElementById('logLinesSelect').value;
        
        logContent.textContent = '加载中...';
        logStats.textContent = '';
        
        try {
            const result = await api.getLogs(logType, lines);
            
            if (result.success) {
                logContent.textContent = result.data.content || '日志为空';
                logStats.innerHTML = `
                    <span class="log-stat-item">类型: ${result.data.type}</span>
                    <span class="log-stat-item">显示: ${result.data.lines} 行</span>
                    <span class="log-stat-item">总计: ${result.data.total_lines} 行</span>
                `;
            } else {
                logContent.textContent = `错误: ${result.message || '无法加载日志'}`;
            }
        } catch (error) {
            logContent.textContent = `请求失败: ${error.message}`;
        }
    }
};

// ==================== 事件绑定 ====================
function initEventListeners() {
    // 主题切换按钮
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            theme.toggle();
        });
    }
    
    // 导航链接
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = e.target.dataset.page;
            if (page) {
                ui.showPage(page);
            }
        });
    });
    
    // 登录按钮
    document.getElementById('loginBtn').addEventListener('click', () => {
        ui.showModal('loginModal');
    });
    
    // 退出按钮
    document.getElementById('logoutBtn').addEventListener('click', () => {
        state.currentUser = null;
        ui.updateUserStatus();
        cart.showToast('已退出登录', 'success');
    });
    
    // 购物车图标点击
    document.getElementById('cartToggle').addEventListener('click', () => {
        cart.open();
    });
    
    // 购物车关闭按钮
    document.getElementById('cartClose').addEventListener('click', () => {
        cart.close();
    });
    
    // 购物车遮罩点击
    document.getElementById('cartOverlay').addEventListener('click', () => {
        cart.close();
    });
    
    // 结算按钮
    document.getElementById('checkoutBtn').addEventListener('click', () => {
        ui.checkout();
    });
    
    // 登录表单
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;
        
        const result = await api.login(username, password);
        
        if (result.success) {
            state.currentUser = result.data;
            ui.updateUserStatus();
            ui.hideModal('loginModal');
            cart.showToast('登录成功！欢迎回来', 'success');
        } else {
            ui.showMessage('loginResult', result.message || '登录失败', true);
            // 显示调试信息
            if (result.debug) {
                const debugInfo = document.createElement('pre');
                debugInfo.style.cssText = 'text-align:left;margin-top:10px;background:#1a1a2e;padding:10px;border-radius:6px;overflow-x:auto;font-size:11px;';
                debugInfo.textContent = JSON.stringify(result.debug, null, 2);
                document.getElementById('loginResult').appendChild(debugInfo);
            }
        }
    });
    
    // 显示注册弹窗
    document.getElementById('showRegisterLink').addEventListener('click', (e) => {
        e.preventDefault();
        ui.hideModal('loginModal');
        ui.showModal('registerModal');
    });
    
    // 注册表单
    document.getElementById('registerForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('regUsername').value;
        const password = document.getElementById('regPassword').value;
        const email = document.getElementById('regEmail').value;
        
        const result = await api.register(username, password, email);
        
        if (result.success) {
            ui.showMessage('registerResult', result.message || '注册成功！', false);
        } else {
            ui.showMessage('registerResult', result.message || '注册失败', true);
        }
    });
    
    // 关闭模态框
    document.querySelectorAll('.cart-close').forEach(btn => {
        btn.addEventListener('click', function() {
            const modal = this.closest('.modal');
            if (modal) {
                modal.classList.remove('show');
            }
        });
    });
    
    // 点击模态框外部关闭
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                ui.hideAllModals();
            }
        });
    });
    
    // 商品搜索
    document.getElementById('searchBtn').addEventListener('click', () => {
        const keyword = document.getElementById('searchKeyword').value;
        ui.loadProducts(keyword, state.currentCategory);
    });
    
    document.getElementById('searchKeyword').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            document.getElementById('searchBtn').click();
        }
    });
    
    // 分类筛选
    document.querySelectorAll('.filter-option').forEach(option => {
        option.addEventListener('click', function() {
            document.querySelectorAll('.filter-option').forEach(el => el.classList.remove('active'));
            this.classList.add('active');
            state.currentCategory = this.dataset.category;
            const keyword = document.getElementById('searchKeyword').value;
            ui.loadProducts(keyword, state.currentCategory);
        });
    });
    
    // 订单查询
    document.getElementById('queryOrderBtn').addEventListener('click', async () => {
        const orderNo = document.getElementById('orderNo').value;
        const userId = document.getElementById('orderUserId').value;
        const resultEl = document.getElementById('orderQueryResult');
        
        if (!orderNo && !userId) {
            resultEl.innerHTML = '<p style="color:#f1c40f;text-align:center;">请输入订单号或用户ID</p>';
            return;
        }
        
        resultEl.innerHTML = '<p style="text-align:center;color:#888;">查询中...</p>';
        const result = await api.queryOrder(orderNo, userId);
        
        if (result.success) {
            if (result.data && result.data.length > 0) {
                resultEl.innerHTML = `
                    <div style="background:#1a1a2e;border-radius:8px;padding:15px;margin-top:15px;">
                        <h4 style="margin-bottom:10px;color:#fff;">查询结果</h4>
                        <pre style="color:#3498db;overflow-x:auto;">${ui.formatJson(result.data)}</pre>
                    </div>
                `;
            } else {
                resultEl.innerHTML = '<p style="text-align:center;color:#888;margin-top:15px;">未找到订单</p>';
            }
        } else {
            resultEl.innerHTML = `
                <div style="background:rgba(231,76,60,0.1);border-radius:8px;padding:15px;margin-top:15px;">
                    <p style="color:#e74c3c;">${result.message || '查询失败'}</p>
                    ${result.debug ? `<pre style="color:#3498db;margin-top:10px;">${ui.formatJson(result.debug)}</pre>` : ''}
                </div>
            `;
        }
    });
    
    // 用户资料查询
    document.getElementById('queryProfileBtn').addEventListener('click', async () => {
        const userId = document.getElementById('profileUserId').value;
        
        if (!userId) {
            cart.showToast('请输入用户ID', 'warning');
            return;
        }
        
        const result = await api.getProfile(userId);
        
        if (result.success && result.data) {
            const data = result.data;
            document.getElementById('profileAvatar').textContent = (data.username || '?')[0].toUpperCase();
            document.getElementById('profileName').textContent = data.username || '-';
            document.getElementById('profileEmail').textContent = data.email || '-';
            document.getElementById('profileBalance').textContent = `¥${(data.balance || 0).toFixed(2)}`;
            document.getElementById('infoId').textContent = data.id || '-';
            document.getElementById('infoPhone').textContent = data.phone || '-';
            document.getElementById('infoAddress').textContent = data.address || '-';
        } else {
            cart.showToast(result.message || '查询失败', 'error');
        }
    });
    
    // 保存难度设置
    document.getElementById('saveDifficultyBtn').addEventListener('click', async () => {
        const difficulty = document.querySelector('input[name="difficulty"]:checked')?.value;
        
        if (!difficulty) {
            cart.showToast('请选择难度级别', 'warning');
            return;
        }
        
        const result = await api.setConfig({ difficulty });
        
        if (result.success) {
            cart.showToast('设置已保存！', 'success');
            ui.loadSystemInfo();
        } else {
            cart.showToast(result.message || '保存失败', 'error');
        }
    });
    
    // 难度选项点击
    document.querySelectorAll('.difficulty-option').forEach(option => {
        option.addEventListener('click', function() {
            document.querySelectorAll('.difficulty-option').forEach(el => el.classList.remove('selected'));
            this.classList.add('selected');
            this.querySelector('input').checked = true;
        });
    });
    
    // 重置数据库
    document.getElementById('resetDbBtn').addEventListener('click', async () => {
        if (!confirm('确定要重置数据库吗？这将清除所有数据并恢复到初始状态。')) {
            return;
        }
        
        const result = await api.resetDatabase();
        
        if (result.success) {
            cart.showToast('数据库已重置！', 'success');
        } else {
            cart.showToast(result.message || '重置失败', 'error');
        }
    });
    
    // 侧边栏重置数据库链接
    const resetDbLink = document.getElementById('resetDbLink');
    if (resetDbLink) {
        resetDbLink.addEventListener('click', async (e) => {
            e.preventDefault();
            if (!confirm('确定要重置数据库吗？')) return;
            const result = await api.resetDatabase();
            if (result.success) {
                cart.showToast('数据库已重置！', 'success');
            } else {
                cart.showToast(result.message || '重置失败', 'error');
            }
        });
    }
    
    // 侧边栏查看日志链接
    const viewLogsLink = document.getElementById('viewLogsLink');
    if (viewLogsLink) {
        viewLogsLink.addEventListener('click', (e) => {
            e.preventDefault();
            ui.showLogViewer();
        });
    }

    // 侧边栏会员中心链接
    const memberCenterLink = document.getElementById('memberCenterLink');
    if (memberCenterLink) {
        memberCenterLink.addEventListener('click', (e) => {
            e.preventDefault();
            if (typeof memberCenter !== 'undefined') {
                memberCenter.show();
            }
        });
    }

    // 侧边栏优惠券中心链接
    const couponCenterLink = document.getElementById('couponCenterLink');
    if (couponCenterLink) {
        couponCenterLink.addEventListener('click', (e) => {
            e.preventDefault();
            if (typeof couponCenter !== 'undefined') {
                couponCenter.show();
            }
        });
    }

    // 侧边栏评价中心链接
    const reviewCenterLink = document.getElementById('reviewCenterLink');
    if (reviewCenterLink) {
        reviewCenterLink.addEventListener('click', (e) => {
            e.preventDefault();
            if (typeof reviewCenter !== 'undefined') {
                reviewCenter.show();
            }
        });
    }
    
    // 侧边栏漏洞接口菜单点击
    document.querySelectorAll('.sidebar-menu a[data-api]').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const apiType = this.dataset.api;
            switch(apiType) {
                case 'login':
                    ui.showModal('loginModal');
                    break;
                case 'profile':
                    ui.showPage('profile');
                    break;
                case 'search':
                case 'detail':
                    ui.showPage('products');
                    break;
                case 'order':
                    ui.showPage('orders');
                    break;
                case 'register':
                    ui.showModal('registerModal');
                    break;
                case 'checkout':
                    if (state.cart.length === 0) {
                        cart.showToast('购物车为空，请先添加商品', 'warning');
                        ui.showPage('products');
                    } else {
                        ui.showModal('checkoutModal');
                    }
                    break;
                case 'cart':
                    cart.open();
                    break;
                case 'shipping':
                    ui.showModal('shippingModal');
                    break;
            }
        });
    });
    
    // 结算表单
    document.getElementById('checkoutForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const address = document.getElementById('checkoutAddress').value;
        const phone = document.getElementById('checkoutPhone').value;
        
        if (!address || !phone) {
            cart.showToast('请填写完整信息', 'warning');
            return;
        }
        
        if (state.cart.length === 0) {
            cart.showToast('购物车是空的', 'warning');
            return;
        }
        
        // 获取用户ID（如果已登录）
        const userId = state.currentUser ? state.currentUser.id : 1;
        
        // 为每个购物车商品创建订单
        const orderResults = [];
        let hasError = false;
        
        for (const item of state.cart) {
            const orderData = {
                user_id: userId,
                product_id: item.id,
                quantity: item.quantity,
                shipping_address: `${address} (电话: ${phone})`,
                session_id: `sess_${Date.now()}`,
                token: Math.random().toString(36).substring(7),
                user_agent: navigator.userAgent
            };
            
            const result = await api.createOrder(orderData);
            
            if (result.success) {
                orderResults.push({
                    product: item.name,
                    order_no: result.data.order_no,
                    total_price: result.data.total_price
                });
            } else {
                hasError = true;
                cart.showToast(`${item.name} 下单失败: ${result.message}`, 'error');
            }
        }
        
        if (orderResults.length > 0) {
            // 显示订单结果
            const orderNos = orderResults.map(o => o.order_no).join(', ');
            const totalAmount = orderResults.reduce((sum, o) => sum + o.total_price, 0);
            ui.showMessage('checkoutResult', 
                `订单创建成功！\n订单号: ${orderNos}\n总金额: ¥${totalAmount.toFixed(2)}`, 
                false
            );
            
            // 清空购物车
            cart.clear();
            
            // 3秒后关闭弹窗
            setTimeout(() => {
                ui.hideModal('checkoutModal');
                document.getElementById('checkoutResult').style.display = 'none';
            }, 3000);
        } else if (!hasError) {
            cart.showToast('订单创建失败', 'error');
        }
    });
    
    // 漏洞卡片点击
    document.querySelectorAll('.vuln-card').forEach(card => {
        card.addEventListener('click', function() {
            const apiType = this.dataset.api;
            // 根据API类型跳转到对应页面
            switch(apiType) {
                case 'login':
                    ui.showModal('loginModal');
                    break;
                case 'profile':
                    ui.showPage('profile');
                    break;
                case 'search':
                case 'detail':
                    ui.showPage('products');
                    break;
                case 'order':
                    ui.showPage('orders');
                    break;
                case 'register':
                    ui.showModal('registerModal');
                    break;
                case 'checkout':
                    // 如果购物车为空，先去购物
                    if (state.cart.length === 0) {
                        cart.showToast('购物车为空，请先添加商品', 'warning');
                        ui.showPage('products');
                    } else {
                        ui.showModal('checkoutModal');
                    }
                    break;
                case 'cart':
                    cart.open();
                    break;
                case 'shipping':
                    ui.showModal('shippingModal');
                    shipping.loadTemplate();
                    break;
                default:
                    break;
            }
        });
    });

    // 物流查询相关事件
    document.getElementById('loadShippingTemplate')?.addEventListener('click', () => {
        shipping.loadTemplate();
    });

    document.getElementById('loadCdataPayload')?.addEventListener('click', () => {
        shipping.loadCdataPayload();
    });

    document.getElementById('loadEntityPayload')?.addEventListener('click', () => {
        shipping.loadEntityPayload();
    });

    document.getElementById('sendShippingQuery')?.addEventListener('click', async () => {
        await shipping.sendQuery();
    });

    // 优惠券查询按钮
    document.getElementById('queryCouponBtn')?.addEventListener('click', async () => {
        const code = document.getElementById('couponCodeInput').value;
        const category = document.getElementById('couponCategorySelect').value;
        const resultEl = document.getElementById('couponQueryResult');
        
        if (!code) {
            cart.showToast('请输入优惠券代码', 'warning');
            return;
        }
        
        resultEl.innerHTML = '<div style="text-align:center;padding:20px;color:#888;">查询中...</div>';
        
        try {
            const result = await couponApi.queryCoupon(code, category);
            const decodedData = couponApi.decodeResponse(result);
            
            if (result.success) {
                let html = '<div class="result-success"><h4>✅ 查询成功</h4>';
                if (decodedData.coupons && decodedData.coupons.length > 0) {
                    html += '<div class="coupon-list">';
                    decodedData.coupons.forEach(coupon => {
                        const discountText = coupon.discount_type === 'percent' 
                            ? coupon.discount_value + '% 折扣' 
                            : '¥' + coupon.discount_value + ' 立减';
                        html += `
                            <div class="coupon-item" style="display:flex;align-items:center;gap:15px;padding:15px;background:rgba(233,69,96,0.1);border-radius:8px;margin:10px 0;">
                                <div style="font-size:24px;font-weight:700;color:#e94560;">${discountText}</div>
                                <div style="flex:1">
                                    <div style="font-weight:600;">${coupon.coupon_code}</div>
                                    <div style="font-size:12px;color:#888;">满¥${coupon.min_purchase}可用${coupon.max_discount ? ' | 最高减¥' + coupon.max_discount : ''}</div>
                                </div>
                            </div>
                        `;
                    });
                    html += '</div>';
                } else {
                    html += '<p>' + (decodedData.message || '未找到匹配的优惠券') + '</p>';
                }
                html += '</div>';
                resultEl.innerHTML = html;
            } else {
                let html = '<div class="result-error"><h4>❌ 查询失败</h4>';
                html += '<p>' + (result.message || '未知错误') + '</p>';
                if (result.debug && result.debug.sql_error) {
                    html += '<details><summary>错误详情</summary><pre style="background:#2d1f1f;padding:10px;border-radius:4px;color:#ff6b6b;font-size:12px;">' + ui.escapeHtml(result.debug.sql_error) + '</pre></details>';
                }
                html += '</div>';
                resultEl.innerHTML = html;
            }
        } catch (error) {
            resultEl.innerHTML = '<div class="result-error"><p>请求失败: ' + error.message + '</p></div>';
        }
    });
}

// ==================== 初始化 ====================
document.addEventListener('DOMContentLoaded', () => {
    // 初始化主题（先于其他操作以避免闪烁）
    theme.init();
    
    // 初始化购物车
    cart.loadFromStorage();
    cart.updateUI();
    
    // 初始化事件监听
    initEventListeners();
    
    // 加载系统信息
    ui.loadSystemInfo();
    ui.updateUserStatus();
    ui.loadHotProducts();
    
    console.log('%c⚠️ VulnShop - SQL Injection Test Lab', 'color: #e94560; font-size: 24px; font-weight: bold;');
    console.log('%c此系统包含故意设置的安全漏洞，仅供教育目的使用！', 'color: #f1c40f; font-size: 14px;');
});

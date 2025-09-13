// 测试用的JavaScript文件，包含各种敏感信息
const config = {
    // API配置
    apiKey: "ak_1234567890abcdef1234567890abcdef",
    secretKey: "sk_abcdef1234567890abcdef1234567890abcdef12",
    accessToken: "at_9876543210fedcba9876543210fedcba9876",
    
    // 数据库连接
    dbUrl: "mongodb://user:password@localhost:27017/mydb",
    mysqlUrl: "mysql://root:123456@192.168.1.100:3306/testdb",
    
    // API接口
    endpoints: {
        userInfo: "/api/user/info",
        login: "/api/auth/login",
        getData: "/api/v1/data/list"
    }
};

// 网络请求示例
function fetchUserData() {
    fetch('/api/users', {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        }
    });
}

// POST请求示例
$.post('/api/submit', {
    email: 'test@example.com',
    phone: '13812345678'
});

// 联系信息
const contacts = {
    email: 'admin@company.com',
    phone: '+86 13987654321',
    support: 'support@test-domain.com'
};

// 服务器配置
const serverConfig = {
    host: '192.168.1.50',
    port: 8080,
    adminEmail: 'webmaster@site.org'
};

// AWS配置
const awsConfig = {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-west-2'
};

// 阿里云配置  
const aliyunConfig = {
    aliyun_access_key: 'LTAI4GKb1234567890123456',
    aliyun_secret_key: 'abcdef1234567890abcdef1234567890'
};

// HTTP请求方法
function apiCall() {
    axios.get('/api/v2/products')
        .then(response => console.log(response.data));
    
    http.post('/api/orders', orderData);
}

// jQuery Ajax
$('#form').submit(function() {
    $.ajax({
        url: '/api/form/submit',
        method: 'POST',
        data: $(this).serialize()
    });
});

// TODO: 修复安全问题
// FIXME: 密码硬编码需要修改
const tempPassword = 'admin123456';

// HACK: 临时绕过验证
const bypassAuth = true; 
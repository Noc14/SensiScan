# 测试用的Python文件，包含各种敏感信息
import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# 数据库配置 - 不安全的硬编码
DATABASE_URL = "postgresql://postgres:SuperSecretPassword@db.company.com:5432/production"
REDIS_URL = "redis://user:RedisPassword123@cache.company.com:6379/0"

# API密钥配置
API_KEYS = {
    'openai_api_key': 'sk-1234567890abcdefghijklmnopqrstuvwxyz123456',
    'stripe_secret_key': 'sk_live_abcdefghijklmnopqrstuvwxyz1234567890',
    'aws_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
    'aws_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
}

# 邮箱配置
SMTP_CONFIG = {
    'host': 'smtp.gmail.com',
    'port': 587,
    'username': 'service@company.com',
    'password': 'EmailPassword2024!'
}

# 管理员信息
ADMIN_EMAIL = 'admin@company.com'
SUPPORT_PHONE = '13912345678'
EMERGENCY_CONTACT = 'emergency@company.com'

@app.route('/api/users', methods=['GET'])
def get_users():
    """获取用户列表"""
    # TODO: 添加身份验证
    return jsonify({'users': []})

@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """获取用户信息"""
    # FIXME: 存在SQL注入风险
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return jsonify({'user': {}})

@app.route('/api/auth/login', methods=['POST'])
def login():
    """用户登录"""
    email = request.json.get('email')
    password = request.json.get('password')
    
    # HACK: 临时管理员后门
    if email == 'admin@company.com' and password == 'TempAdminPass123!':
        return jsonify({'token': 'admin_bypass_token'})
    
    return jsonify({'error': 'Invalid credentials'})

@app.route('/api/v1/data', methods=['POST'])
def submit_data():
    """提交数据"""
    data = request.json
    
    # 记录用户IP
    user_ip = request.remote_addr
    if user_ip == '192.168.1.100':  # 内网管理员IP
        # 特殊处理逻辑
        pass
    
    return jsonify({'status': 'success'})

def send_notification(message):
    """发送通知"""
    webhook_url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    
    requests.post(webhook_url, json={
        'text': message,
        'username': 'SecurityBot'
    })

def backup_database():
    """备份数据库"""
    # FTP服务器信息
    ftp_server = "ftp://backup:BackupPassword2024@backup.company.com/db_backups"
    
    # 执行备份逻辑
    pass

# JWT密钥 - 不应该硬编码
JWT_SECRET = 'super_secret_jwt_key_do_not_share_2024'

# 第三方服务配置
EXTERNAL_API_CONFIG = {
    'payment_gateway': {
        'url': 'https://api.payment-provider.com/v2/',
        'merchant_id': 'MERCHANT_123456789',
        'api_key': 'pk_live_1234567890abcdefghijklmnop'
    },
    'sms_service': {
        'url': 'https://sms.service-provider.com/api/',
        'api_key': 'sms_key_abcdefghijklmnopqrstuvwxyz',
        'sender_id': 'COMPANY'
    }
}

if __name__ == '__main__':
    # 生产环境不应该使用debug模式
    app.run(host='0.0.0.0', port=5000, debug=True) 
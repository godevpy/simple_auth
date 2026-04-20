# tools/test_http_api.py

import requests

# 配置
BASE_URL = "http://localhost:8000"  # 请根据实际情况修改为您的服务地址
USERNAME = "alice"
PASSWORD = "abcd1235"
COOKIE_NAME = "auth_session"

AUTH_VERIFY_URL = f"{BASE_URL}/_auth/verify"
ME_URL = f"{BASE_URL}/_auth/me"
LOGOUT_URL = f"{BASE_URL}/_auth/logout"


def login_and_cookie_header():
    """Login and return an explicit Cookie header.

    本地 BASE_URL 使用 http://localhost:8000，而服务配置 secure_cookie=true。
    requests 会保存 Secure Cookie，但不会在 HTTP 请求中自动发送它，所以测试里需要
    显式把登录响应里的 Cookie 填到请求头。
    """
    session = requests.Session()
    login_data = {
        'username': USERNAME,
        'password': PASSWORD,
        'redirect': '/private/page'
    }
    response = session.post(f"{BASE_URL}/login", data=login_data, allow_redirects=False)
    assert response.status_code == 302, f"Unexpected login status code: {response.status_code}"

    cookie_value = response.cookies.get(COOKIE_NAME) or session.cookies.get(COOKIE_NAME)
    assert cookie_value, f"Expected {COOKIE_NAME} cookie after login"
    return session, {'Cookie': f'{COOKIE_NAME}={cookie_value}'}

def test_login_page():
    # 测试登录页 - 没有提供redirect参数
    response = requests.get(f"{BASE_URL}/login")
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"

    # 测试登录页 - 提供有效的redirect参数
    response = requests.get(f"{BASE_URL}/login?redirect=/private/page")
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"

def test_login():
    # 测试有效的用户名和密码登录
    data = {
        'username': USERNAME,
        'password': PASSWORD,
        'redirect': '/private/page'
    }
    response = requests.post(f"{BASE_URL}/login", data=data, allow_redirects=False)
    assert response.status_code == 302, f"Unexpected status code: {response.status_code}"
    assert 'Set-Cookie' in response.headers, "Expected Set-Cookie header not found"

    # 测试无效的用户名或密码
    data['password'] = 'wrong'
    response = requests.post(f"{BASE_URL}/login", data=data)
    assert response.status_code == 401, f"Unexpected status code: {response.status_code}"

def test_auth_verify():
    # 获取有效 session，并显式透传 Cookie。Secure Cookie 在 HTTP 下不会被 requests 自动发送。
    session, cookie_header = login_and_cookie_header()

    # 已登录用户访问受保护资源
    headers = {
        **cookie_header,
        'X-Original-Host': 'localhost',
        'X-Original-URI': '/admin/page?x=1',
        'X-Original-Method': 'GET'
    }
    response = session.get(AUTH_VERIFY_URL, headers=headers)
    assert response.status_code == 204, f"Unexpected status code: {response.status_code}"

    # 未登录用户尝试访问受保护资源
    headers_without_cookie = dict(headers)
    headers_without_cookie.pop('Cookie', None)
    response = requests.get(AUTH_VERIFY_URL, headers=headers_without_cookie)
    assert response.status_code == 401, f"Unexpected status code: {response.status_code}"

    # 已登录但无权限访问特定路径
    headers['X-Original-URI'] = '/forbidden/path'
    response = session.get(AUTH_VERIFY_URL, headers=headers)
    assert response.status_code == 403, f"Unexpected status code: {response.status_code}"

def test_me():
    # 获取有效 session，并显式透传 Cookie。Secure Cookie 在 HTTP 下不会被 requests 自动发送。
    session, cookie_header = login_and_cookie_header()

    # 已登录用户请求个人信息
    response = session.get(ME_URL, headers=cookie_header)
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
    assert 'user_id' in response.json(), "Expected 'user_id' in response JSON"

    # 未登录用户请求个人信息
    response = requests.get(ME_URL)
    assert response.status_code == 401, f"Unexpected status code: {response.status_code}"

def test_logout():
    # 获取有效 session，并显式透传 Cookie。Secure Cookie 在 HTTP 下不会被 requests 自动发送。
    session, cookie_header = login_and_cookie_header()

    # 成功登出
    response = session.post(LOGOUT_URL, headers=cookie_header, allow_redirects=False)
    assert response.status_code == 302, f"Unexpected status code: {response.status_code}"
    assert 'Set-Cookie' in response.headers, "Expected Set-Cookie header not found"
    assert response.headers['Location'] == "/login", f"Unexpected Location: {response.headers['Location']}"

if __name__ == "__main__":
    test_login_page()
    test_login()
    test_auth_verify()
    test_me()
    test_logout()
    print("All tests passed!")

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "==> 检查环境依赖"
command -v node >/dev/null 2>&1 || { echo "缺少 Node.js，请先执行：brew install node"; exit 1; }
PY=python3
command -v python3.12 >/dev/null 2>&1 && PY=python3.12

echo "==> 拉取第三方签名/登录实现 Spider_XHS（MIT，仅本地依赖，不入库）"
if [ ! -d vendor/Spider_XHS ]; then
  git clone --depth 1 https://github.com/cv-cat/Spider_XHS.git vendor/Spider_XHS
fi
(cd vendor/Spider_XHS && npm install --omit=dev)

echo "==> 创建虚拟环境并安装 Python 依赖"
[ -d venv ] || "$PY" -m venv venv
./venv/bin/pip install -q --upgrade pip
./venv/bin/pip install -q -r requirements.txt

echo
echo "==> 完成"
echo "启动主程序：./venv/bin/python app.py   （浏览器打开 http://127.0.0.1:8787）"
echo "抓包工具：  brew install mitmproxy，然后 ./venv/bin/python capture.py start | stop"

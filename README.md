# RED LAND 抢票助手

小红书 RED LAND 开放世界冒险岛（活动内部预约）的本地辅助工具：多账号扫码登录、预约情报总览、门票绑定辅助、App 身份令牌复用。

> 仅用于个人学习与自用，请遵守平台规则，不要用于代抢、倒卖等行为。

## 功能

| 模块 | 说明 |
| --- | --- |
| 多账号扫码登录 | 浏览器里扫码（纯 HTTP 登录，无需浏览器内核跑登录页），支持多账号保存、切换、校验、逐账号查票 |
| 预约列表 | 全部需预约展位活动总览：状态（未开始/可预约/已约满/已结束）、开约时间、预约页直达，每分钟自动刷新 |
| 自动预约任务 | 到开约时间自动执行：演练模式只跑到提交前一步；正式模式真实提交，带重试、实时日志与浏览器通知 |
| App 身份令牌 | 独立抓包工具从电脑版小红书 App 提取会话令牌，PC 上即可查询「我的门票」与预约资格 |
| 绑定门票辅助 | 保存票单号/姓名/证件信息（本地），一键打开 App 绑定页，抓包自动读回绑定结果 |

## 目录结构

```
app.py              主程序（Flask，网页控制台 + JSON 接口）
ui.html             页面模板（由 app.py 动态读取）
capture.py          独立的抓包工具（mitmproxy + 系统代理切换 + 令牌提取）
requirements.txt    Python 依赖
setup.sh            一键环境准备（venv + 依赖 + Spider_XHS）
vendor/Spider_XHS   第三方依赖，由 setup.sh 克隆（MIT），不入库
data/               用户数据目录（登录凭证/门票信息/抓包记录），已 gitignore
```

## 环境要求

- macOS（抓包/代理切换依赖 `networksetup`，仅 macOS）
- Python 3.10+（推荐 3.12）
- Node.js 20+（第三方签名实现需要）
- mitmproxy（仅抓包时需要）：`brew install mitmproxy`

## 安装

```bash
./setup.sh
```

或手动：

```bash
git clone --depth 1 https://github.com/cv-cat/Spider_XHS.git vendor/Spider_XHS
(cd vendor/Spider_XHS && npm install --omit=dev)
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
```

## 运行

```bash
./venv/bin/python app.py            # 默认 http://127.0.0.1:8787
# 建议把运行日志写进 data/：./venv/bin/python app.py > data/server.log 2>&1
```

打开页面后：

1. 右上角「添加账号」扫码登录（支持多个账号）；
2. 「预约列表」查看全部可预约活动与开约时间；
3. 「App 身份」可导入/验证令牌（可选，用于查询门票与预约资格）。

## 抓包工具（可选）

用于从电脑版小红书 App 获取会话令牌（App 的 POST 接口有原生签名，纯 HTTP 无法自行调用）：

```bash
./venv/bin/python capture.py start    # 启动抓包（自动切系统代理，串联原代理）
# 在电脑版小红书 App 里操作：主会场 → 我的 → 我的门票（或绑定页提交）
./venv/bin/python capture.py stop     # 停止、恢复代理、提取令牌并验证
./venv/bin/python capture.py status   # 查看状态
```

## 数据与隐私

- 所有用户数据都在 `data/`（**已加入 .gitignore，不会被提交**）：
  - `accounts.json`：账号 cookies（含 `web_session`）
  - `app_identity.json`：App 会话令牌与设备参数
  - `ticket.json`：票单号/姓名/证件（页面展示时自动打码）
  - `last_capture.json`、`captures/`：抓包记录
- 这些文件包含敏感凭证，请勿分享、上传或提交到任何仓库；本项目不会上传任何数据到第三方服务。

## 免责声明

- 本项目仅用于学习与个人自用，请遵守小红书/大麦的平台规则与相关法律法规；
- 门票绑定为不可逆操作，请自行确认信息后再提交；
- 使用本工具产生的任何后果由使用者自行承担。

## 致谢

- [Spider_XHS](https://github.com/cv-cat/Spider_XHS)（MIT）：小红书 PC 端登录与签名实现
- [mitmproxy](https://mitmproxy.org/)：抓包

## License

[MIT](LICENSE)

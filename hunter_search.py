#!/usr/bin/env python3
"""
鹰图 Hunter (https://hunter.qianxin.com) API 数据获取脚本

默认每次只搜索 10 条数据（硬限制），除非使用者明确指定 --page-size 参数。
"""

import argparse
import base64
import json
import os
import sys
import time
from datetime import datetime, timedelta

import requests


# ============================================================
# 配置
# ============================================================
DEFAULT_PAGE_SIZE = 10  # ⚠️ 硬限制：默认每页 10 条
DEFAULT_DELAY = 1.0
API_BASE = "https://hunter.qianxin.com/openApi/search"


def base64url_encode(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")


def build_search_params(
    api_key: str, search: str, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE,
    is_web: int = 3, start_time: str = "", end_time: str = "",
    status_code: str = "", port_filter: bool = False,
) -> dict:
    params = {
        "api-key": api_key,
        "search": base64url_encode(search),
        "page": page,
        "page_size": page_size,
        "is_web": is_web,
        "port_filter": "true" if port_filter else "false",
    }
    if not start_time:
        start_time = (datetime.now() - timedelta(days=365)).strftime("%Y-%m-%d")
    if not end_time:
        end_time = datetime.now().strftime("%Y-%m-%d")
    params["start_time"] = start_time
    params["end_time"] = end_time
    if status_code:
        params["status_code"] = status_code
    return params


def fetch_page(params: dict, timeout: int = 30) -> dict:
    resp = requests.get(API_BASE, params=params, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def print_summary(result: dict, page: int, page_size: int):
    code = result.get("code")
    msg = result.get("msg", "")
    data = result.get("data", {})
    total = data.get("total", 0)
    page_total = len(data.get("arr", []))
    print(f"  └─ [第 {page} 页] 返回 {page_total}/{page_size} 条，累计共 {total} 条匹配 | code={code} msg={msg}")


def print_asset(index: int, asset: dict):
    ip = asset.get("ip", "-")
    port = asset.get("port", "-")
    domain = asset.get("domain", "") or "-"
    title = (asset.get("web_title", "") or "")[:40]
    status = asset.get("status_code", "-")
    url = asset.get("url", "") or ""
    print(f"  [{index:>3}] {ip}:{port:<6} | {status:<4} | {domain:<30} | {title}")


def export_to_file(results: list, search: str, output_dir: str, fmt: str = "json"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = search.replace('"', "").replace("=", "_").replace(" ", "_")[:40]
    basename = f"hunter_{safe_name}_{timestamp}"

    if fmt == "json":
        filepath = os.path.join(output_dir, f"{basename}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n📁 已导出 JSON ({len(results)} 条): {filepath}")
    elif fmt == "txt":
        filepath = os.path.join(output_dir, f"{basename}.txt")
        with open(filepath, "w", encoding="utf-8") as f:
            for asset in results:
                ip = asset.get("ip", "")
                port = asset.get("port", "")
                domain = asset.get("domain", "")
                url = asset.get("url", "")
                line = f"{ip}:{port}"
                if domain: line += f" | {domain}"
                if url: line += f" | {url}"
                f.write(line + "\n")
        print(f"\n📁 已导出 TXT ({len(results)} 条): {filepath}")
    elif fmt == "csv":
        filepath = os.path.join(output_dir, f"{basename}.csv")
        with open(filepath, "w", encoding="utf-8-sig") as f:
            keys = ["ip", "port", "domain", "url", "protocol", "status_code",
                    "web_title", "country", "city", "isp", "os", "app_name", "app_version"]
            f.write(",".join(keys) + "\n")
            for asset in results:
                row = [str(asset.get(k, "")).replace(",", "，") for k in keys]
                f.write(",".join(row) + "\n")
        print(f"\n📁 已导出 CSV ({len(results)} 条): {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="🔍 鹰图 Hunter API 数据获取工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
使用示例:
  %(prog)s -k YOUR_KEY -s 'web.body="nps" && ip.country="CN"'
  %(prog)s -k YOUR_KEY -s 'ip="1.1.1.1/24"' -p 3
  %(prog)s -k YOUR_KEY -s 'web.title="后台管理"' --page-size 50
  %(prog)s -k YOUR_KEY -s 'app.name="nginx"' --all
  %(prog)s -k YOUR_KEY -s 'web.title="登录"' --export csv --output ./results
        """,
    )

    parser.add_argument("-k", "--api-key", dest="api_key",
                        help="鹰图 API Key（也可通过环境变量 HUNTER_API_KEY 设置）")
    parser.add_argument("-s", "--search", required=True, help="搜索语法")
    parser.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE,
                        help=f"每页条数（默认 {DEFAULT_PAGE_SIZE}）")
    parser.add_argument("-p", "--pages", type=int, default=1, help="要获取的页数（默认 1 页）")
    parser.add_argument("--all", action="store_true", help="翻完所有页（慎用！）")
    parser.add_argument("--is-web", type=int, default=3, choices=[1, 2, 3],
                        help="资产类型: 1=Web 2=非Web 3=全部")
    parser.add_argument("--start-time", default="", help="开始时间 yyyy-MM-dd")
    parser.add_argument("--end-time", default="", help="结束时间 yyyy-MM-dd")
    parser.add_argument("--status-code", default="", help="状态码过滤，逗号分隔")
    parser.add_argument("--port-filter", action="store_true", help="开启端口过滤")
    parser.add_argument("--export", choices=["json", "txt", "csv", "none"],
                        default="json", help="导出格式（默认 json）")
    parser.add_argument("--output", default="./hunter_output", help="导出目录")
    parser.add_argument("--no-print", action="store_true", help="不打印详细结果")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help=f"翻页间隔（默认 {DEFAULT_DELAY}s）")

    args = parser.parse_args()

    # ---- API Key ----
    api_key = args.api_key or os.environ.get("HUNTER_API_KEY")
    if not api_key:
        print("❌ 请提供 API Key（-k 参数或设置 HUNTER_API_KEY 环境变量）")
        sys.exit(1)

    # ---- 检查 page_size ----
    if args.page_size != DEFAULT_PAGE_SIZE:
        print(f"⚠️  用户明确指定 page_size={args.page_size}，覆盖默认 {DEFAULT_PAGE_SIZE}")
    else:
        print(f"ℹ️  使用默认每页 {DEFAULT_PAGE_SIZE} 条（配额保护）")

    # ---- 构建参数 ----
    params_base = build_search_params(
        api_key=api_key, search=args.search, page_size=args.page_size,
        is_web=args.is_web, start_time=args.start_time, end_time=args.end_time,
        status_code=args.status_code, port_filter=args.port_filter,
    )

    print(f"\n{'='*60}")
    print(f"🔍 鹰图 Hunter API 查询")
    print(f"{'='*60}")
    print(f"  搜索语法: {args.search}")
    print(f"  每页条数: {args.page_size}")
    print(f"  获取页数: {'全部' if args.all else args.pages}")

    # ---- 第 1 页 ----
    print(f"\n📡 获取第 1 页...")
    try:
        first_result = fetch_page(params_base)
    except requests.exceptions.RequestException as e:
        print(f"❌ 网络请求失败: {e}")
        sys.exit(1)

    code = first_result.get("code")
    msg = first_result.get("msg", "")

    if code != 200:
        print(f"❌ API 返回错误: code={code} msg={msg}")
        sys.exit(1)

    data = first_result.get("data", {})
    total = data.get("total", 0)
    rest_quota = first_result.get("parameters", {}).get("total_free_quota", "未知")
    print(f"  ├─ 匹配总数: {total}")
    print(f"  ├─ 剩余配额: {rest_quota}")
    print_summary(first_result, 1, args.page_size)

    all_results = data.get("arr", [])

    # ---- 计算总页数 ----
    if args.all:
        if total == 0:
            pages_to_get = 1
        else:
            pages_to_get = (total + args.page_size - 1) // args.page_size
            max_pages = 50
            if pages_to_get > max_pages:
                print(f"\n⚠️  总页数 {pages_to_get} 超过上限 {max_pages}，只获取前 {max_pages} 页")
                pages_to_get = max_pages
    else:
        pages_to_get = args.pages

    # ---- 后续页面 ----
    for page in range(2, pages_to_get + 1):
        if total > 0 and len(all_results) >= total:
            print(f"\n✅ 已获取全部 {total} 条，停止翻页")
            break
        time.sleep(args.delay)
        print(f"\n📡 获取第 {page} 页...")
        try:
            result = fetch_page({**params_base, "page": page})
        except requests.exceptions.RequestException as e:
            print(f"  ⚠️  第 {page} 页失败: {e}")
            continue
        code = result.get("code")
        if code != 200:
            print(f"  ⚠️  第 {page} 页错误: code={code} {result.get('msg', '')}")
            continue
        page_arr = result.get("data", {}).get("arr", [])
        all_results.extend(page_arr)
        print_summary(result, page, args.page_size)

    # ---- 汇总 ----
    print(f"\n{'='*60}")
    print(f"📊 汇总")
    print(f"{'='*60}")
    print(f"  搜索语法: {args.search}")
    print(f"  实际获取: {len(all_results)} 条")

    # ---- 打印 ----
    if not args.no_print and all_results:
        print(f"\n{'─'*60}")
        print(f"  #   IP:Port           状态  Domain                          Title")
        print(f"{'─'*60}")
        for idx, asset in enumerate(all_results, 1):
            print_asset(idx, asset)
        print(f"{'─'*60}")

    # ---- 导出 ----
    if args.export != "none" and all_results:
        export_to_file(all_results, args.search, args.output, args.export)
    elif not all_results:
        print("\n⚠️  没有获取到任何数据")

    print(f"\n✅ 完成！\n")


if __name__ == "__main__":
    main()

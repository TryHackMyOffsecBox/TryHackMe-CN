# Basic libraries
import logging
import os

# Data fetch libraries
from bs4 import BeautifulSoup, Tag
from playwright.sync_api import sync_playwright, Page

# page parsing libraries
from markdownify import markdownify
import mdformat


# 配置日志记录器
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(module)s:%(lineno)d - %(levelname)s - %(message)s"
)

if __name__ == "__main__":
    with sync_playwright() as p:
        # 启动浏览器
        browser = p.chromium.launch(headless=False, proxy={"server": "http://127.0.0.1:7890"})
        # 创建新页面
        page = browser.new_page()

        page.goto("https://tryhackme.com/room/offensivesecurityintro")
        page.wait_for_load_state("load")

        while input("Press any key to continue...") != "q":

            # 获取页面的 HTML 内容
            html_content = page.content()
            soup = BeautifulSoup(html_content, "html.parser")

            # 获取房间信息
            div_room_banner = soup.find("nav", {"aria-label": "breadcrumb"})
            if div_room_banner:
                # 提取所有的<li>标签
                li_tags = div_room_banner.find_all("li")  # type: ignore
                # 提取<li>标签中的文本内容
                breadcrumb_list = [li.get_text(strip=True) for li in li_tags]

                logging.info(f"房间信息: {breadcrumb_list}")

                # 递归创建文件夹
                path = os.path.join(*breadcrumb_list)
                os.makedirs(path, exist_ok=True)

                logging.info(f"创建文件夹: {path}")

                # 创建index.md文件
                index_file_path = os.path.join(path, "index.md")
                with open(index_file_path, "w") as f:
                    f.write("# " + breadcrumb_list[-1])

                logging.info(f"创建文件: {index_file_path}")

            else:
                print("没有找到匹配的<nav>元素")
                continue

            # 查找具有特定ID的<div>元素
            div_room_content = soup.find("div", {"id": "room_content"})

            if div_room_content:
                pass
                md_room_content = markdownify(div_room_content.prettify())  # type: ignore
                md_room_content = mdformat.text(md_room_content)
                with open(index_file_path, "w") as f:
                    f.write(md_room_content)

                logging.info(f"写入房间信息: {index_file_path}")

            else:
                print("没有找到匹配的<div>元素")
                continue

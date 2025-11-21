# Basic libraries
import logging
import os
import re
import shutil
import urllib.parse

# Data fetch libraries
from bs4 import BeautifulSoup, Tag
from playwright.sync_api import sync_playwright, Page, BrowserContext
import requests
from pjstealth import stealth_sync

# page parsing libraries
from markdownify import MarkdownConverter
import mdformat


# 配置日志记录器
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(module)s:%(lineno)d - %(levelname)s - %(message)s")


# 配置语言解析
def lang_callback(el):
    lang = el.get("class", [""])[0] if el.has_attr("class") else None
    return lang.split("-")[-1] if lang else None


# 解析 task
def parse_content_header(md_content: str) -> str:
    # Task<空格><从1递增数字><任意长度字符串>
    md_content_splited = md_content.splitlines()
    index_flag = 1
    for i, line in enumerate(md_content_splited):
        if line.startswith(f"Task {index_flag}"):
            # ##<空格>Task<空格><从1递增数字><空格><任意长度字符串>
            line_title_content = line.split(f"{index_flag}")[1]
            md_content_splited[i] = f"## Task {index_flag} {line_title_content}"
            index_flag += 1
    md_content = "\n".join(md_content_splited)
    return md_content


# 解析 Markdown 代码块
def parse_content_code_blocks(md_content: str) -> str:
    md_content_splited = md_content.splitlines()
    # 找到所有特定值的索引
    indices = [i for i, line in enumerate(md_content_splited) if line.startswith("```")]
    blank_indices = []
    print(indices)
    # 取每个代码块标记符号的第一个
    for i in range(0, len(indices), 2):
        if md_content_splited[indices[i] - 1].strip() != "":
            code_block_title = md_content_splited[indices[i] - 1].strip()
            md_content_splited[indices[i] - 1] = ""
            md_content_splited[indices[i]] += f' title="{code_block_title}"'
            md_content_splited[indices[i] + 1] = md_content_splited[indices[i] + 1].strip()
    # 取每个代码块标记符号的第二个
    for i in range(1, len(indices), 2):
        current_index = indices[i]
        while True:
            current_index -= 1
            if md_content_splited[current_index].strip() == "":
                blank_indices.append(current_index)
            else:
                break
    # 删除空行
    print(blank_indices)
    for i in blank_indices:
        md_content_splited.pop(i)
    md_content = "\n".join(md_content_splited)
    return md_content


# 调整 Markdown 标题级别
def adjust_markdown_headers(md_content: str) -> str:
    # 调整 Markdown 的标题级别，确保只有一个一级标题
    md_content_splited = md_content.splitlines()
    for i, line in enumerate(md_content_splited):
        # 判断是否是 Markdown 标题
        if line.startswith("#") and line.split(" ", 1)[0].replace("#", "") == "":
            # 计算当前标题的级别
            header_level = len(line.split(" ")[0])
            md_content_splited[i] = f"{'#' * (header_level + 1)} {line.split(' ', 1)[1]}"
    md_content = "\n".join(md_content_splited)
    return md_content


def parse_article_images(md_content: str):
    md_content_splited = md_content.split("\n")
    for line_index in range(len(md_content_splited)):
        if "![]" in md_content_splited[line_index] and "http" in md_content_splited[line_index]:
            # print(markdown_text[line_index])
            image_url = md_content_splited[line_index].strip().split("![](")[-1].split(")")[0].strip()
            space_index = md_content_splited[line_index].index("![]")
            image_filename = image_url.split("/")[-1].split("#")[0]
            logging.info(f"parse image {image_url}")
            try:
                if "xzfile.aliyuncs.com" in image_url:
                    with open(f"./docs/images/{image_filename}", "wb+") as f:
                        image_response = requests.get(image_url, stream=True)
                        if image_response.status_code == 200:
                            image_response.raw.decode_content = True
                            shutil.copyfileobj(image_response.raw, f)
                else:
                    image_filename = urllib.parse.quote(image_url, safe="")
                    image_filename = re.sub(r'[<>:"/\\|?*]', "_", image_filename)
                    with open(f"./docs/images/{image_filename}", "wb+") as f:
                        image_response = requests.get(image_url, stream=True)
                        if image_response.status_code == 200:
                            image_response.raw.decode_content = True
                            shutil.copyfileobj(image_response.raw, f)
            except:
                logging.error(f"图像获取失败 {md_content_splited[line_index].strip()}")
                continue
            md_content_splited[line_index] = md_content_splited[line_index][:space_index] + f"![{image_filename}]({f"./images/{image_filename}"})"
    return "\n".join(md_content_splited)


if __name__ == "__main__":
    with sync_playwright() as p:
        # 启动本地 Firefox 浏览器
        browser = p.firefox.launch_persistent_context(
            user_data_dir="./firefox_profile",
            headless=False,
            proxy={"server": "http://127.0.0.1:7890"}
        )
        # 获取页面
        page = browser.pages[0] if browser.pages else browser.new_page()

        page.goto("https://tryhackme.com/room/windowspowershell")
        page.wait_for_load_state("load")

        while input("按下回车键以解析当前页面") != "q":

            # 获取页面的 HTML 内容
            html_content = page.content()
            soup = BeautifulSoup(html_content, "html.parser")

            # 获取房间路径层次
            div_room_banner = soup.find("nav", {"aria-label": "breadcrumb"})
            if div_room_banner:
                # 提取所有的<li>标签
                li_tags = div_room_banner.find_all("li")  # type: ignore

                # 提取<li>标签中的文本内容
                breadcrumb_list = [li.get_text(strip=True) for li in li_tags]
                room_title = breadcrumb_list[-1]
                logging.info(f"房间信息: {breadcrumb_list}")

                # 递归创建文件夹
                path = os.path.join(*breadcrumb_list)
                os.makedirs(path, exist_ok=True)
                path_img = os.path.join(path, "img")
                os.makedirs(path_img, exist_ok=True)
                logging.info(f"创建文件夹: {path}")

                # 创建index.md文件
                index_file_path = os.path.join(path, "index.md")
                logging.info(f"创建文件: {index_file_path}")

            else:
                print("没有找到匹配的<nav>元素")
                continue

            # 获取房间内容
            # TODO 由于网站改版导致内容解析规则需要修改
            div_room_content = soup.find("div", {"data-sentry-component": "Tasks"})
            if div_room_content:
                # 移除特定的<section>元素
                for section in div_room_content.find_all("section", {"data-sentry-component": "QuestionAndAnswerSection"}):  # type: ignore
                    section.decompose()

                # 将房间内容转换为 Markdown 格式
                converter = MarkdownConverter(code_language_callback=lang_callback)
                md_room_content = converter.convert_soup(div_room_content)

                # 处理 Markdown 代码块
                md_room_content = parse_content_code_blocks(md_room_content)

                # 调整 Markdown 格式
                md_room_content = mdformat.text(md_room_content)

                # 调整 Markdown 的标题级别
                md_room_content = adjust_markdown_headers(md_room_content)

                # 处理 Markdown 二级标题
                md_room_content = parse_content_header(md_room_content)

                # Markdown 格式化处理
                md_room_content = mdformat.text(md_room_content)

                with open(index_file_path, "w") as f:
                    f.write(md_room_content)
                logging.info(f"写入房间内容: {index_file_path}")

            else:
                print("没有找到匹配的<div>元素")
                continue

# 妙妙小工具

## crawler.py

这是一个基于 playwright 进行浏览器控制，并使用 BeautifulSoup4 进行 HTML 内容解析，并采用 markdownify 和 mdformat 转换为 Markdown 的脚本

为了获得完整的数据，脚本未使用任何预定义的 Cookie 信息，而是让操作者手动进行登录后再进行数据获取并解析，这也一定程度上避免了对网站的恶意访问行为和避免出发 Tryhackme 和 Cloudflare 的安全防护机制

```shell
# install dependence
pip install beautifulsoup4 markdownify playwright mdformat
# install playwright dependence (if not install it before)
playwright install
```

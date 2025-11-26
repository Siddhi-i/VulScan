import urllib.parse as urlparse
from collections import deque
import requests
from bs4 import BeautifulSoup

class PageForm:
    def __init__(self, url, method, action, inputs):
        self.url = url
        self.method = method.upper()
        self.action = action
        self.inputs = inputs  # list of input names


def is_same_domain(base, target):
    b = urlparse.urlparse(base)
    t = urlparse.urlparse(target)
    return b.netloc == t.netloc


def normalize_url(base, link):
    return urlparse.urljoin(base, link)


def crawl(start_url, max_pages=30):
    visited = set()
    queue = deque([start_url])
    pages = []
    forms = []

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = requests.get(url, timeout=5)
        except Exception:
            continue

        soup = BeautifulSoup(resp.text, "lxml")
        pages.append(url)

        # collect forms
        for form in soup.find_all("form"):
            method = form.get("method", "GET")
            action = form.get("action") or url
            action_url = normalize_url(url, action)
            inputs = []
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    inputs.append(name)

            forms.append(PageForm(url=url, method=method,
                                  action=action_url, inputs=inputs))

        # follow links
        for a in soup.find_all("a", href=True):
            link = normalize_url(url, a["href"])
            if link.startswith("http") and is_same_domain(start_url, link):
                if link not in visited:
                    queue.append(link)

    return pages, forms

"""Build a self-contained snapshot of the live results page for screenshotting.

Fetches the real index.html (so markup + CSS + app.js are identical to production),
rewrites /static/ paths to absolute URLs, and injects the captured scan payload +
a call to the real render() function so the screenshot shows the actual UI.
"""
import json
import urllib.request

BASE = "http://127.0.0.1:5000"

html = urllib.request.urlopen(BASE + "/").read().decode("utf-8")
html = html.replace('"/static/', f'"{BASE}/static/')

data = open("scan_result.json").read()
inject = f"""
<script>
window.addEventListener('load', function () {{
  var DATA = {data};
  window.__SENTINEL_render(DATA);
  // open the first two cards so the screenshot shows the expanded detail view
  setTimeout(function () {{
    document.querySelectorAll('.threat').forEach(function (t, i) {{ if (i < 2) t.classList.add('open'); }});
  }}, 300);
}});
</script>
</body>"""
html = html.replace("</body>", inject)
open("/tmp/snap.html", "w").write(html)
print("wrote /tmp/snap.html")

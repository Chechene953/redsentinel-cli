# redsentinel/reporter.py
from jinja2 import Template
from redsentinel.utils import now_iso

HTML_TMPL = """
<html>
<head><meta charset="utf-8"><title>Report {{ target }}</title></head>
<body>
<h1>Automated Report — {{ target }}</h1>
<p>Generated: {{ generated }}</p>

<h2>Subdomains ({{ subdomains|length }})</h2>
<ul>{% for s in subdomains %}<li>{{ s }}</li>{% endfor %}</ul>

<h2>Open ports</h2>
<ul>
{% for p,o in ports.items() %}
  <li>{{ p }} — {{ "open" if o else "closed" }}</li>
{% endfor %}
</ul>

<h2>HTTP Checks</h2>
{% for h in http %}
  <h3>{{ h.url }}</h3>
  <p>Status: {{ h.status if h.status is defined else h.error }}</p>
  <pre>{{ h.headers }}</pre>
{% endfor %}
</body>
</html>
"""

def render_report(target, subdomains, ports, http_checks):
    tpl = Template(HTML_TMPL)
    return tpl.render(target=target, subdomains=subdomains, ports=ports, http=http_checks, generated=now_iso())

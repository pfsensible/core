#!/usr/bin/python3

import argparse
import datetime
import git
import jinja2
import lxml.etree as ET
import lxml.html
from paramiko import SSHClient
import re
import requests
from scp import SCPClient
import sys
from urllib.parse import urlparse

gitconfig = git.GitConfigParser()
author_name = gitconfig.get_value('user', 'name')
author_email = gitconfig.get_value('user', 'email')

parser = argparse.ArgumentParser(description='Generate a pfsensible module.')
parser.add_argument('--url', help='The URL to scrape')
parser.add_argument('--urlfile', help='A local file copy of the URL to scrape')
parser.add_argument('--user', default='admin', help='The user to connect as')
parser.add_argument('--password', default='changeme', help='The password of user')
parser.add_argument('--author_name', default=author_name, help='The full name of the module author')
parser.add_argument('--author_email', default=author_email, help='The email address of the module author')
parser.add_argument('--author_handle', default='', help='The github handle of the module author')
parser.add_argument('--module_name', help='The name of the module to generate - defaults to being based on the url')
parser.add_argument('--item_min', default='item_min', help='The name of the minimally configured item to search for in config.xml')
parser.add_argument('--item_full', default='item_full',
                    help='The name of the fully configured item to search for in config.xml, will be used for exmaples in the documentation')

args = parser.parse_args()

if args.url is not None:
    parsed_uri = urlparse(args.url)

    # Login using just the base URL
    login_url = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)

    # Collect to host for later use to scp config.xml
    host = f'{parsed_uri.netloc}'

    # Construct a likely module name from the URL
    if args.module_name is None:
        module_name = re.sub(r'^/(?:firewall_)?(.*)(?:_edit)\.php.*$', r'pfsense_\1', parsed_uri.path)
        module_name = re.sub(r'ses$', 's', module_name)
    else:
        module_name = args.module_name

    # We likely don't have a valid certificate
    requests.packages.urllib3.disable_warnings()

    # Start our session (need cookies for login)
    client = requests.Session()

    # Retrieve the CSRF token first
    r = client.get(login_url, verify=False)
    csrf = re.search(".*name='__csrf_magic' value=\"([^\"]+)\".*", r.text, flags=re.MULTILINE).group(1)

    # Login to the web interface
    login_data = dict(login='Login', usernamefld=args.user, passwordfld=args.password, __csrf_magic=csrf)
    r = client.post(login_url, data=login_data, verify=False)
    csrf = re.search(".*name='__csrf_magic' value=\"([^\"]+)\".*", r.text, flags=re.MULTILINE).group(1)

    # Retrieve the configuration web page and parse it
    r = client.get(args.url, verify=False)
    html = lxml.html.fromstring(r.text)

elif args.urlfile is not None:
    # Use a cached copy of the web page - get rid of this?  Need to specify host and module name
    html = lxml.html.parse(args.urlfile)
    host = '192.168.100.2'
    module_name = 'pfsense_nat_1to1'

else:
    sys.exit('You must specify one of --url or --urlfile')

# The web page should have a single form
if len(html.forms) != 1:
    sys.exit(f'Found {len(html.forms)} forms instead of a single one!')

# Collected parameters from the web form
params = dict()

# Collect the input elements
for input in html.forms[0].inputs:
    # Skip internal items
    if input.name == '__csrf_magic':
        continue

    param = dict()
    print(f'attrib={input.attrib}')
    if isinstance(input, lxml.html.InputElement):
        print(f'input name={input.name} id={input.get("id")} type={input.type} value={input.value} '
              'text={input.text} title={input.get("title")} tail={input.tail}')
        if input.type == 'checkbox':
            param['type'] = 'bool'
            param['value'] = input.attrib['value']
            param['example'] = 'true'
        elif input.type == 'text':
            param['type'] = 'str'
        # Text sometimes is after the input element inside the enclosing <label>
        if input.tail:
            param['description'] = input.tail.strip()
    elif isinstance(input, lxml.html.SelectElement):
        print(f'select name={input.name} value={input.value} value_options={input.value_options} multiple={input.multiple}')
        if input.value_options is not None:
            param['choices'] = input.value_options
            if input.multiple:
                param['type'] = 'list'
            else:
                param['type'] = 'str'
            param['multiple'] = input.multiple
    params[input.name] = param

# Debug
print(f'Web paramters: {params.keys()}')

# Collect the /cf/conf/config.xml file
ssh = SSHClient()
ssh.load_system_host_keys()
ssh.connect(host, username='root', password=args.password)
scp = SCPClient(ssh.get_transport())
scp.get('/cf/conf/config.xml')
scp.close()

# Parse the config.xml file
root = ET.parse('config.xml').getroot()

# Search for any element with our target text, make sure we found only one
xpath = f'.//*[.="{args.item_min}"]'
key_elts = root.findall(xpath)
if len(key_elts) > 1:
    sys.exit(f'Found {len(key_elts)} items with path "{xpath}"')
elif len(key_elts) == 0:
    sys.exit(f'Cannot find minimally configured item with path "{xpath}"')
else:
    key_elt = key_elts[0]

# This element should be the key for the items
module_key = key_elt.tag

# Key is handled separately from other parameters so remove it
del params[module_key]

# The full node configuration element will be the parent
node_elt = key_elt.find('..')
module_node = node_elt.tag

# The "root" for this type of element is above that
root_elt = node_elt.find('..')
module_root = root_elt.tag

# Debug
print('item_min:\t' + ET.tostring(node_elt).decode())

# Let's use our node and key as a check
full_elt = root.find(f'.//{module_node}[{module_key}="{args.item_full}"]')
if full_elt is None:
    sys.exit(f'Cannot find fully configured item with path ".//{module_node}[{module_key}="{args.item_full}"]"')

# Debug
print('item_full:\t' + ET.tostring(full_elt).decode())

# Collect the items for comparison with web elements and example values
params_full = dict()
for elt in full_elt:
    if elt.tag == '':
        continue
    params_full[elt.tag] = elt.text


print('')
params_web_only = list(set(params.keys()) - set(params_full.keys()))
print('Web parameters not in xml: ' + str(params_web_only))

# Cleanup extra web parameters
for param in params_web_only:
    # See if the items are numbered, likely maps to an unnumbered XML tag
    newp = re.sub(r'0$', '', param)
    if newp != param:
        if newp in params_full.keys():
            print(f'Renaming {param} to {newp}')
            params[newp] = params.pop(param)
            continue

    # Common renamings
    for f, t in [('dst', 'destination'), ('src', 'source')]:
        if param == f and t in params_full.keys():
            print(f'Renaming {f} to {t}')
            params[t] = params.pop(f)
            break
    else:
        # Otherwise, drop - probably just used to construct the final elements
        if param in params:
            print(f'Removing {param}')
            del params[param]

# Create some sample descriptions and example values
for name, param in params.items():
    if 'description' not in param or param['description'] == '':
        param['description'] = f'The {name} of the {module_node}'
    if 'example' not in param or param['example'] == '':
        if name in params_full and params_full[name] != '' and params_full[name] is not None:
            param['example'] = params_full[name]

# Template variables
context = dict(
    module_name=module_name,
    module_root=module_root,
    module_node=module_node,
    module_key=module_key,
    params=params,
    author_name=args.author_name,
    author_email=args.author_email,
    author_handle=args.author_handle,
    year=datetime.date.today().year,
)

# Render our module!
environment = jinja2.Environment(loader=jinja2.FileSystemLoader("misc/"), trim_blocks=True, keep_trailing_newline=True)
template = environment.get_template("pfsense_module.py.j2")

# Todo - prompt for overwrite
print(f'Writing plugins/modules/{module_name}.py with {context}')
f = open(f'plugins/modules/{module_name}.py', 'w')
f.write(template.render(context))
f.close()

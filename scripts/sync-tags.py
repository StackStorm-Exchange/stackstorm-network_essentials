import os
import glob
import json
from ruamel.yaml import YAML

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
GROUPS_FILE = os.path.join(CURRENT_DIR, '../groups.json')

with open(GROUPS_FILE, 'r') as fp:
    content = fp.read()

groups = json.loads(content)

pack_metadata_file = os.path.join(CURRENT_DIR, '../pack.yaml')

with open(pack_metadata_file, 'r') as fp:
    content = fp.read()

yaml = YAML()
yaml.default_flow_style = False
content = yaml.load(content)

pack_name = content['ref'] or content['name']

actions_path = os.path.join(CURRENT_DIR, '../actions/')
action_metadata_files = glob.glob(actions_path + '/*.yaml')

for action_metadata_file in action_metadata_files:
    file_name, file_ext = os.path.splitext(action_metadata_file)

    with open(action_metadata_file, 'r') as fp:
        content = fp.read()

    yaml = YAML()
    yaml.default_flow_style = False
    yaml.allow_duplicate_keys = True
    yaml.explicit_start = True
    yaml.indent(sequence=4, offset=2)
    content = yaml.load(content)

    if 'name' not in content:
        continue

    action_name = content['name']

    ref = pack_name + '.' + action_name

    print(ref)

    tags = []

    for group in groups:
        actions = set(group['actions'])
        if ref in group['actions']:
            actions.remove(ref)
            group['actions'] = list(actions)
            print('  group: ' + group['name'])
            print('  suite: ' + ', '.join(group['suites']))

            tags.append({
                'name': 'group',
                'value': group['name']
            })

            for suite in group['suites']:
                try:
                    next(x for x in tags if x['name'] == 'suite' and x['value'] == suite)
                except StopIteration:
                    tags.append({
                        'name': 'suite',
                        'value': suite
                    })

    if tags:
        content['tags'] = tags

    with open(action_metadata_file, 'w') as fp:
        yaml.dump(content, fp)


print('Actions left unsynced: ')
for group in groups:
    if len(group['actions']):
        print('  ' + group['name'])
    for action in group['actions']:
        print('    ' + action)

import json
with open('config_input.json', 'r') as f:
  print(json.loads(f.read()))

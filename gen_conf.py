import os
import yaml

exclude_list = ["HOSTNAME","LANG","GPG_KEY","PYTHON_VERSION","PYTHON_SHA256","HOME"]

def generate(config_path):
  config = None
  for env, value in os.environ.items():
    if env not in exclude_list:
      print(env.split("-")
    
